## Overview
GitLab v2 is The DevOps platform that empowers organizations to maximize the overall return on software development by delivering software faster and efficiently while strengthening security and compliance.

## Use Cases
This integration enables you to:
- Create, close, or update a GitLab issue.
- Get a list of all GitLab issues you have access to.
- Create, close, update and delete a GitLab issue note.
- Get a list of all the notes related to an issue.
- Create, delete and search a branch in GitLab.
- Get a list of all GitLab branches in your project.
- Get a list of the projects' commits.
- Create, update a GitLab merge requests or get a list of all the merge requests.
- Create, close, update and delete a merge request's note.
- Create, upload ,delete and update a file in the GitLab project.
- Get a list of files in the GitLab project.
- Get the contents and details of a file in GitLab.
- Search for code in the GitLab project.
- Trigger a pipeline in the GitLab project.

#### Create a Personal Access Token 
Personal access tokens (PATs) are an alternative to using passwords for authentication to GitLab when using the GitLab API. 
To generate a new token:
1. Navigate to the upper-right corner of any page and click your **profile photo**. 
2. In the left sidebar, click **Preferences**. 
3. In the left sidebar, click **Access tokens**.
4. Give your token a descriptive name. 
5. To give your token an expiration, select the **Expiration drop-down** menu, then click a default or use the calendar picker. 
6. Select the **scopes**, or **permissions**, you want to grant this token. The minimum is read-only on repo.
7. Click **Create personal access token** and copy the api key generated.-+

#### Create a Trigger Token
Trigger tokens allow you to trigger a pipeline for a branch using it to authenticate on an API call.

**Prerequisite:**

You must have at least the Maintainer role for the project.

**To generate a new token:**

1. Navigate to your project.
2. Select **Settings** > **CI/CD**.
3. Expand Pipeline triggers.
4. Enter a description and select **Add trigger**.
   - You can view and copy the full token for all triggers you have created.
   - You can only see the first 4 characters for tokens created by other project members.

#### Get Project ID
1. Go to the desired project example gitlab.com/username/project1.
2. Under the project name get the argument project_id

## Configure GitLab on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GitLab.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://gitlab.com/api/v4) |  | False |
    | API Key | The API Key to use for connection | True |
    | Trigger Token | The trigger token to run pipelines | False |
    | Project ID |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gitlab-version-get
***
Retrieve version information for this GitLab instance.


#### Base Command

`gitlab-version-get`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Version.version | String | The version of this GitLab instance. | 
| GitLab.Version.revision | String | The revision of this GitLab instance. | 

#### Command example
```!gitlab-version-get```
#### Context Example
```json
{
    "GitLab": {
        "Version": {
            "revision": "4cfc3f317b2",
            "version": "15.5.0-pre"
        }
    }
}
```

#### Human Readable Output

>GitLab version 15.5.0-pre
> reversion: 4cfc3f317b2 

### gitlab-file-get
***
Allows to receive information about file in repository like name, size, content.


#### Base Command

`gitlab-file-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The file path. | Optional | 
| ref | The name of branch, tag or commit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.File.file_name | String | The file name. | 
| GitLab.File.file_path | String | The path of the file. | 
| GitLab.File.size | Number | The size of the file. | 
| GitLab.File.encoding | String | the encoding of the file.' | 
| GitLab.File.content | String | File content. | 
| GitLab.File.content_sha256 | String | The file after hashing the content. | 
| GitLab.File.ref | String | The branch the file's content was taken from. | 
| GitLab.File.blob_id | String | The blob id. | 
| GitLab.File.commit_id | String | The commit id of the file. | 
| GitLab.File.last_commit_id | String | The last commit id of the file. | 
| GitLab.File.execute_filemode | Boolean | If the file is excute in filemode \(Bool\) | 

### gitlab-file-create
***
This allows you to create a single file. File path or entry_id must be specified.


#### Base Command

`gitlab-file-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry id of the file. | Optional | 
| file_path | URL-encoded full path to new file. | Optional | 
| file_content | The file's content. | Optional | 
| branch | Name of the new branch to create. The commit is added to this branch. | Required | 
| author_email | The commit author's email address. | Optional | 
| author_name | The commit author's name. | Optional | 
| commit_message | The commit message. | Required | 
| execute_filemode | Enables or disables the execute flag on the file. Can be true or false. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.File.file_path | String | URL-encoded full path of the new file. | 
| GitLab.File.branch | String | Name of the new branch to create. | 

#### Command Example
`!gitlab-file-create file_path=path branch=main entry_id=.gitlab-ci.yml author_email=email@google.com author_name=authorName file_content='cfgdfr' commit_message=addFile execute_filemode=True`

#### Human Readable Output
> File created successfully.


#### Base Command

`gitlab-file-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | URL-encoded full path to new file. | Required | 
| branch | Name of the new branch to create. The commit is added to this branch. | Required | 
| start_branch | Name of the base branch to create the new branch from. | Optional | 
| encoding | Change encoding to base64. Default is text. Possible values are: text, base64. Default is text. | Optional | 
| author_email | The commit author email address. | Optional | 
| author_name | The commit author name address. | Optional | 
| entry_id | Entry id of the file.if the user uploaded a file, he can provide the entry id. If he did, we need to read the content from the file and set the value in the file_content argument. | Optional | 
| file_content | The file content. | Required | 
| commit_message | The commit message. | Required | 
| last_commit_id | Last known file commit ID. | Optional | 
| execute_filemode | Enables or disables the execute flag on the file. Can be true or false. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.File.file_path | String | The file path. | 
| GitLab.File.branch | String | The name of the branch. | 

#### Command Example
`!gitlab-file-update file_path=./gitlabca branch=thisbranch start_branch=main encoding=base64 author_email=author@email.com author_name=name entry_id=.gitlab-ci.yml file_content="contant of file" commit_message=commit last_commit_id=5 execute_filemode=True`

#### Human Readable Output
> File updated successfully.

### gitlab-file-delete
***
Editing existing file in repository.


#### Base Command

`gitlab-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | URL-encoded full path of the file. | Required | 
| branch | Name of the new branch to delete. | Required | 
| commit_message | The commit message. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!gitlab-file-delete branch=main file file_path=./gitlabca commit_message=deleteFile`

#### Human Readable Output
> File deleted successfully.

### gitlab-issue-list
***
Get a list of a project's issues.


#### Base Command

`gitlab-issue-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assignee_id | Return issues assigned to the given user id. The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| assignee_username | Return issues assigned to the given username. | Optional | 
| author_id | Return issues created by the given user id. | Optional | 
| author_username | Return issues created by the given username. | Optional | 
| confidential | Filter confidential or public issues. | Optional | 
| created_after | Return issues created on or after the given time. Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| created_before | Return issues created on or before the given time. Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| due_date | Return issues that have no due date, are overdue, or whose due date is this week, this month, or between two weeks ago and next month. Possible values are: 0 (no due date), any, today, tomorrow, overdue, week, month, next_month_and_previous_two_weeks. | Optional | 
| epic_id | Return issues associated with the given epic ID. None returns issues that are not associated with an epic. | Optional | 
| issue_type | Filter to a given type of issue. One of issue, incident, or test_case. Possible values are: issue, incident, test_case. | Optional | 
| labels | Comma-separated list of label names, issues must have all labels to be returned. None lists all issues with no labels. | Optional | 
| milestone | The milestone title. None lists all issues with no milestone. Any lists all issues that have an assigned milestone. | Optional | 
| order_by | Return issues ordered by created_at, updated_at, priority, due_date, relative_position, label_priority, milestone_due, popularity, weight fields. Default is created_at. Possible values are: created_at, updated_at, priority, due_date, relative_position, label_priority, milestone_due, popularity, weight. Default is created_at. | Optional | 
| scope | Return issues for the given scope. Possible values are: created_by_me, assigned_to_me, all. Default is all. | Optional | 
| search | Search project issues against their title and description. | Optional | 
| sort | Return issues sorted in asc or desc order. Default is desc. Possible values are: desc, asc. Default is desc. | Optional | 
| state | Return all issues or just those that are opened or closed. Possible values are: opened, closed. | Optional | 
| updated_after | Return issues updated on or after the given time. | Optional | 
| updated_before | Return issues updated on or before the given time. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The number of page to retrieve results from. Default is 1. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Issue.iid | Number | The issue internal Id. | 
| GitLab.Issue.title | String | The title of the issue. | 
| GitLab.Issue.response.created_at | Date | The date of creation. | 
| GitLab.Issue.author.name | String | The name of the issue's author. | 
| GitLab.Issue.response.updated_at | Date | The date of the last update. | 
| GitLab.Issue.milestone.title | Number | The milestone title. | 
| GitLab.Issue.state | String | The state of the issue\(closed or opened\). | 
| GitLab.Issue.assignee.name | String | The name of the assignee. | 

#### Command Example
`!gitlab-issue-list limit=1 page=1 assignee_id=1 assignee_username=Assignusername author_id=4 author_username=usernameAuthoe confidential=False created_after=2000-09-15T17:22:42.246Z created_before=2022-09-15T17:22:42.246Z due_date=2023-09-15T17:22:42.246Z epic_id=1 issue_type=Issue labels=label2 milestone=PR order_by=Weight partial_response=false`

#### Human Readable Output
## List Issues:
|Issue_iid|Title|CreatedAt|CreatedBy|UpdatedAt|State|Assignee|
|---|---|---|---|---|---|---|
|4|issueExample|2000-09-15T17:22:42.246Z|demo-user|2000-09-15T17:23:42.246Z|Open|demoAssignee|

### gitlab-issue-update
***
Updates an existing project issue. This call is also used to mark an issue as closed. The iid can be taken from gitlab-issue-list.

#### Base Command

`gitlab-issue-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_iid | The internal ID of a project's issue. | Required | 
| add_labels | Comma-separated label names to add to an issue. | Optional | 
| assignee_ids | The ID of the users to assign the issue to.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| confidential | Updates an issue to be confidential. | Optional | 
| description | The description of an issue. | Optional | 
| discussion_locked | Flag indicating if the issue's discussion is locked. If the discussion is locked only project members can add or edit comments. | Optional | 
| due_date | The due date. Date time string in the format YYYY-MM-DD, for example 2016-03-11. | Optional | 
| epic_id | ID of the epic to add the issue to. Valid values are greater than or equal to 0. | Optional | 
| epic_iid | IID of the epic to add the issue to. Valid values are greater than or equal to 0. | Optional | 
| issue_type | Updates the type of issue. One of issue, incident, or test_case. Possible values are: issue, incident, test_case. | Optional | 
| milestone_id | The global ID of a milestone to assign the issue to. Set to 0 or provide an empty value to unassign a milestone. | Optional | 
| remove_labels | Comma-separated label names to remove from an issue. | Optional | 
| state_event | The state event of an issue. Set close to close the issue and reopen to reopen it. | Optional | 
| title | The title of an issue. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Issue.id | Number | The issue id. | 
| GitLab.Issue.iid | Number | The issue's iid. | 
| GitLab.Issue.project_id | Number | The project ID. | 
| GitLab.Issue.title | unknown | The title of the project. | 
| GitLab.Issue.description | Unknown | The project description. | 
| GitLab.Issue.state | unknown | The state of the project. | 
| GitLab.Issue.created_at | Date | Issue creation time. | 
| GitLab.Issue.updated_at | Date | The date of the last update. | 
| GitLab.Issue.closed_at | Date | The time of closing the project. | 
| GitLab.Issue.labels | unknown | The labels of the project. | 
| GitLab.Issue.author.name | unknown | The author name. | 
| GitLab.Issue.author.avatar_url | Unknown | The avatar url. | 
| GitLab.Issue.author.username | unknown | The username of the author. | 
| GitLab.Issue.author.id | Number | The author ID. | 
| GitLab.Issue.author.state | unknown | The state of the issue. | 
| GitLab.Issue.author.web_url | unknown | The author url. | 
| GitLab.Issue.closed_by.state | unknown | The state of the project at closing time. | 
| GitLab.Issue.closed_by.web_url | unknown | The web url of the author who closed the project. | 
| GitLab.Issue.closed_by.avatar_url | Unknown | The avatar url of the author who closed the project. | 
| GitLab.Issue.closed_by.username | unknown | The username of the author who closed the project. | 
| GitLab.Issue.closed_by.id | Number | The id of the author who closed the project. | 
| GitLab.Issue.closed_by.name | unknown | The name of the author who closed the project. | 
| GitLab.Issue.upvotes | Number | The upvotes of the project. | 
| GitLab.Issue.downvotes | Number | The downvotes of the project. | 
| GitLab.Issue.merge_requests_count | Number | The project merge requests count. | 
| GitLab.Issue.assignee | Unknown | The assignee of the project. | 
| GitLab.Issue.milestone | Unknown | The projects milestones. | 
| GitLab.Issue.subscribed | Boolean | if the user is subscribed to the project. | 
| GitLab.Issue.user_notes_count | Number | The user notes count. | 
| GitLab.Issue.due_date | Date | The due date of the project. | 
| GitLab.Issue.web_url | unknown | The project web url. | 
| GitLab.Issue.references.short | unknown | The issue's refrences's short ID. | 
| GitLab.Issue.references.relative | unknown | The number of relatives of the project. | 
| GitLab.Issue.references.full | unknown | The number of reference. | 
| GitLab.Issue.time_stats.time_estimate | Number | The total time estimate to the project. | 
| GitLab.Issue.time_stats.total_time_spent | Number | The total time spent on the project. | 
| GitLab.Issue.time_stats.human_time_estimate | unknown | The time estimate for the project. | 
| GitLab.Issue.time_stats.human_total_time_spent | Unknown | The total time estimate to the project. | 
| GitLab.Issue.confidential | Boolean | If the project confidential. | 
| GitLab.Issue.discussion_locked | Boolean | If the discussion is locked. | 
| GitLab.Issue.issue_type | unknown | The issue type. | 
| GitLab.Issue.severity | unknown | The severity of the project. | 
| GitLab.Issue._links.self | unknown | dictionary  of links. | 
| GitLab.Issue._links.notes | unknown | Notes of links. | 
| GitLab.Issue._links.award_emoji | unknown | Award emoji of the project. | 
| GitLab.Issue._links.project | unknown | Link to the project. | 
| GitLab.Issue._links.closed_as_duplicate_of | unknown | Link to closed duplicate of the project. | 
| GitLab.Issue.task_completion_status.count | Number | Dictionray of completion status. | 
| GitLab.Issue.task_completion_status.completed_count | Number | dictionary of status. | 

#### Command Example
`!gitlab-issue-update issue_iid=20 add_labels=label3 assignee_ids=2 confidential=False description=UpdateDesc discussion_locked=False due_date=2022-09-15T17:22:42.246Z epic_id=1 epic_iid=2 issue_type=Issue milestone_id=16 remove_labels=label1 state_event=Close title=updateTitle partial_response=false`

#### Human Readable Output
## Update Issue:
|Iid|Title|CreatedAt|CreatedBy|UpdatedAt|Milstone|State|Assignee|
|---|---|---|---|---|---|---|---|
|4|iisueExample|2000-09-15T17:22:42.246Z|demo-user|2000-09-15T17:23:42.246Z|16|Open|demoAssignee|

### gitlab-commit-list
***
Get a list of repository commits in a project.


#### Base Command

`gitlab-commit-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| commit_id | If the user provided a value, a specific commit will be retrieved. otherwise, all the commits will be retrieved(sha). | Optional | 
| ref_name | The name of a repository branch, tag or revision range, or if not given the default branch. | Optional | 
| created_before | Only commits before or on this date are returned (until). Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| created_after | Only commits after or on this date are returned(since). Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| path | The file path. | Optional | 
| all | Retrieve every commit from the repository. | Optional | 
| with_stats | Stats about each commit are added to the response. | Optional | 
| first_parent | Follow only the first parent commit upon seeing a merge commit. | Optional | 
| order | List commits in order. Possible values- default, topo. Defaults to default, the commits are shown in reverse chronological order. Possible values are: default, topo. | Optional | 
| limit | Total commits to show. Default is 50. | Optional | 
| page | Present commits from page. Default is 1. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Command Example
`!gitlab-commit-list limit=1 page=1 commit_id=c156b66b ref_name=main created_before=2022-09-15T17:22:42.246Z created_after=2000-09-15T17:22:42.246Z path=./ all=True with_stats=True first_parent=True order=Default partial_response=false`

#### Human Readable Output
## List Commits:
|Title|Message|ShortId|Author|CreatedAt|
|---|---|---|---|---|
|commitExample|this is example|c156b66b|demo-user|2000-09-15T17:22:42.246Z|

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Commit.id | String | The commit ID. | 
| GitLab.Commit.short_id | String | The commit short ID. | 
| GitLab.Commit.title | String | The title of the commit. | 
| GitLab.Commit.author_name | String | The commit's author's. | 
| GitLab.Commit.author_email | String | The commit's author's email. | 
| GitLab.Commit.authored_date | Date | The commit authored date. | 
| GitLab.Commit.committer_name | String | The commit commiter's name. | 
| GitLab.Commit.committer_email | String | The commit commiter's email. | 
| GitLab.Commit.committed_date | Date | The commit committed date. | 
| GitLab.Commit.created_at | Date | When the commit was created. | 
| GitLab.Commit.message | String | The message attached to the commit. | 
| GitLab.Commit.parent_ids | String | The commit's parent ids. | 
| GitLab.Commit.web_url | String | The commit's web url. | 


### gitlab-merge-request-list
***
Get all merge requests for this project.


#### Base Command

`gitlab-merge-request-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | Return all merge requests or just those that are opened, closed, locked, or merged. Possible values are: opened, closed, locked, merged. | Optional | 
| order_by | Return requests ordered by created_at, title or updated_at fields. Default is created_at. Possible values are: created_at, updated_at, title. Default is created_at. | Optional | 
| sort | Return requests sorted in asc or desc order. Default is desc. Possible values are: asc, desc. Default is desc. | Optional | 
| milestone | Return merge requests for a specific milestone. None returns merge requests with no milestone. Any returns merge requests that have an assigned milestone. | Optional | 
| labels | Return merge requests matching a comma-separated list of labels. None lists all merge requests with no labels. Any lists all merge requests with at least one label. Predefined names are case-insensitive. | Optional | 
| created_after | Return merge requests created on or after the given time. Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| created_before | Return merge requests created on or before the given time. Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| updated_after | Return merge requests updated on or after the given time. Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| updated_before | Return merge requests updated on or before the given time. Expected in ISO 8601 format (2019-03-15T08:00:00Z). | Optional | 
| scope | Return merge requests for the given scope- created_by_me, assigned_to_me, or all. Possible values are: created_by_me, assigned_to_me, all. | Optional | 
| author_id | Returns merge requests created by the given user id. Mutually exclusive with author_username. | Optional | 
| author_username | Returns merge requests created by the given username. Mutually exclusive with author_id. | Optional | 
| assignee_id | Returns merge requests assigned to the given user id.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| reviewer_id | Returns merge requests which have the user as a reviewer with the given user id.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| reviewer_username | Returns merge requests which have the user as a reviewer with the given username.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| source_branch | Return merge requests with the given source branch. | Optional | 
| target_branch | Return merge requests with the given target branch. | Optional | 
| search | Search merge requests against their title and description. | Optional | 
| limit | Total merge requests to show. Default is 50. | Optional | 
| page | Present merge requests from page. Default is 1. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.MergeRequest.iid | Number | The internal ID of the merge request. | 
| GitLab.MergeRequest.title | String | The merge requests't title. | 
| GitLab.MergeRequest.created_at | String | When the merge request's creation time. | 
| GitLab.MergeRequest.created_by | Date | The request's author. | 
| GitLab.MergeRequest.updated_at | Date | When the merge request was update. | 
| GitLab.MergeRequest.status | Unknown | The status of the merge request. | 
| GitLab.MergeRequest.merge_by | Unknown | The merge request's author. | 
| GitLab.MergeRequest.merged_at | Unknown | When the merge request was merged. | 
| GitLab.MergeRequest.reviewers | Number | The reviewer of the merge requests. | 

#### Command Example
`!gitlab-merge-request-list limit=1 page=1 state=Opened order_by=title sort=asc milestone=Any labels=label1 created_before=2022-11-15T17:22:42.246Z created_after=2000-09-15T17:22:42.246Z updated_after=2000-09-15T17:22:42.246Z updated_before=2022-09-15T17:22:42.246Z scope=All author_id=1 author_username=usernameAuthor assignee_id=1 reviewer_id=6 reviewer_username=username source_branch=sourceBranceName target_branch=main search=gitlab partial_response=false`

#### Human Readable Output
## List Merge requests :
|Iid|Title|CreatedAt|CreatedBy|UpdatedAt|Status|MergeBy|MergedAt|Reviewers|
|---|---|---|---|---|---|---|---|---|
|444|MergeExample|2022-10-15T17:22:42.246Z|demo-user|2022-11-15T17:23:42.246Z|Open|demoMerge|2022-10-15T17:22:42.246Z|demoReviewer|

### gitlab-merge-request-create
***
Creates a new merge request.


#### Base Command

`gitlab-merge-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_branch | The merge request source branch. | Required | 
| target_branch | The merge request target branch. | Required | 
| title | The merge request title. | Required | 
| assignee_ids | The ID of the users to assign the MR to.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| reviewer_ids | The ID of the users added as a reviewer to the MR.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| description | description of MR. Limited to 1,048,576 characters. | Optional | 
| target_project_id | The target project (numeric ID). | Optional | 
| labels | The global ID of a milestone. | Optional | 
| milestone_id | Labels for MR as a comma-separated list. | Optional | 
| remove_source_branch | Flag indicating if a merge request should remove the source branch when merging. | Optional | 
| allow_collaboration | Allow commits from members who can merge to the target branch. | Optional | 
| allow_maintainer_to_push | Alias of allow_collaboration. | Optional | 
| approvals_before_merge | Number of approvals required before this can be merged. | Optional | 
| squash | Squash commits into a single commit when merging. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.MergeRequest.id | Number | The merge request ID. Alias of allow_collaboration. | 
| GitLab.MergeRequest.iid | Number | The merge request IID. | 
| GitLab.MergeRequest.project_id | Number | The project ID of the merge request. | 
| GitLab.MergeRequest.title | String | The merge request title. | 
| GitLab.MergeRequest.description | Unknown | The merge request description. | 
| GitLab.MergeRequest.state | String | The merge request state. | 
| GitLab.MergeRequest.created_at | Date | The time the merge request was created. | 
| GitLab.MergeRequest.updated_at | Date | The time the merge request was updated. | 
| GitLab.MergeRequest.merged_by | Unknown | The time the merge request was merged. | 
| GitLab.MergeRequest.merge_user | Unknown | The user who closed the merge request. | 
| GitLab.MergeRequest.merged_at | Unknown | The time the merge request was closed. | 
| GitLab.MergeRequest.closed_by | Unknown | The user who closed the merge request. | 
| GitLab.MergeRequest.closed_at | Unknown | The time the merge request was closed. | 
| GitLab.MergeRequest.target_branch | String | The merge request source branch. | 
| GitLab.MergeRequest.source_branch | String | The merge request source branch. | 
| GitLab.MergeRequest.user_notes_count | Number | The merge request user notes count. | 
| GitLab.MergeRequest.upvotes | Number | The merge request upvotes. | 
| GitLab.MergeRequest.downvotes | Number | The merge request downvotes. | 
| GitLab.MergeRequest.author.id | Number | The merge request author's id. | 
| GitLab.MergeRequest.author.username | String | The merge request author's username. | 
| GitLab.MergeRequest.author.name | String | The merge request author's name. | 
| GitLab.MergeRequest.author.state | String | The merge request author's state. | 
| GitLab.MergeRequest.author.avatar_url | String | The merge request author's avatar url. | 
| GitLab.MergeRequest.author.web_url | String | The merge request author's web url. | 
| GitLab.MergeRequest.assignees.id | Number | The merge request assignees's id. | 
| GitLab.MergeRequest.assignees.username | String | The merge request assignees's username. | 
| GitLab.MergeRequest.assignees.name | String | The merge request assignees's name. | 
| GitLab.MergeRequest.assignees.state | String | The merge request assignees's state. | 
| GitLab.MergeRequest.assignees.avatar_url | String | The merge request assignees's avatar url. | 
| GitLab.MergeRequest.assignees.web_url | String | The merge request assignees's web url. | 
| GitLab.MergeRequest.assignee.id | Number | The merge request assignees's id. | 
| GitLab.MergeRequest.assignee.username | String | The merge request assignees's username. | 
| GitLab.MergeRequest.assignee.name | String | The merge request assignees's name. | 
| GitLab.MergeRequest.assignee.state | String | The merge request assignees's state. | 
| GitLab.MergeRequest.assignee.avatar_url | String | The merge request assignees's avatar_url. | 
| GitLab.MergeRequest.assignee.web_url | String | The merge request assignees's web_url. | 
| GitLab.MergeRequest.source_project_id | Number | The merge request source project id. | 
| GitLab.MergeRequest.target_project_id | Number | The merge request target project id. | 
| GitLab.MergeRequest.draft | Boolean | The merge request draft. | 
| GitLab.MergeRequest.work_in_progress | Boolean | The merge request work in progress. | 
| GitLab.MergeRequest.milestone | Unknown | The global ID of a milestone. | 
| GitLab.MergeRequest.merge_when_pipeline_succeeds | Boolean | If to merge when pipeline succeeds. | 
| GitLab.MergeRequest.merge_status | String | The merge status. | 
| GitLab.MergeRequest.sha | String | The request's sha. | 
| GitLab.MergeRequest.merge_commit_sha | Unknown | The merge commit sha. | 
| GitLab.MergeRequest.squash_commit_sha | Unknown | The squash commit sha. | 
| GitLab.MergeRequest.discussion_locked | Unknown | discussion locked value. | 
| GitLab.MergeRequest.should_remove_source_branch | Unknown | If should remove source branch. | 
| GitLab.MergeRequest.force_remove_source_branch | Unknown | If to force remove source branch. | 
| GitLab.MergeRequest.reference | String | The merge request's reference. | 
| GitLab.MergeRequest.references.short | String | The merge requests refrence's short. | 
| GitLab.MergeRequest.references.relative | String | The merge requests refrence's relative. | 
| GitLab.MergeRequest.references.full | String | The merge requests refrence's full. | 
| GitLab.MergeRequest.web_url | String | The merge request web url. | 
| GitLab.MergeRequest.time_stats.time_estimate | Number | The merge requests time estimate. | 
| GitLab.MergeRequest.time_stats.total_time_spent | Number | The merge requests total time spent. | 
| GitLab.MergeRequest.time_stats.human_time_estimate | Unknown | The merge requests human time estimate. | 
| GitLab.MergeRequest.time_stats.human_total_time_spent | Unknown | The merge request's human total time spent. | 
| GitLab.MergeRequest.squash | Boolean | The merge request's squash. | 
| GitLab.MergeRequest.task_completion_status.count | Number | The merge request's task completion status- count. | 
| GitLab.MergeRequest.task_completion_status.completed_count | Number | The merge request's task completion status- completed count. | 
| GitLab.MergeRequest.has_conflicts | Boolean | If the request has conflict. | 
| GitLab.MergeRequest.blocking_discussions_resolved | Boolean | If the merge request blocking discussion are resolved. | 
| GitLab.MergeRequest.approvals_before_merge | Unknown | Th approvals before merge. | 
| GitLab.MergeRequest.subscribed | Boolean | If subscribed. | 
| GitLab.MergeRequest.changes_count | String | Counter of changes. | 
| GitLab.MergeRequest.latest_build_started_at | Unknown | When latest build started at. | 
| GitLab.MergeRequest.latest_build_finished_at | Unknown | When latest build finished at. | 
| GitLab.MergeRequest.first_deployed_to_production_at | Unknown | When is the first deployed to production at. | 
| GitLab.MergeRequest.pipeline | Unknown | The merge request's pipeline. | 
| GitLab.MergeRequest.head_pipeline | Unknown | The merge request's head pipeline. | 
| GitLab.MergeRequest.diff_refs.base_sha | String | The refrence's base sha. | 
| GitLab.MergeRequest.diff_refs.head_sha | String | The refrence's head sha. | 
| GitLab.MergeRequest.diff_refs.start_sha | String | The refrence's start sha. | 
| GitLab.MergeRequest.merge_error | Unknown | If exist, the error of the merge. | 
| GitLab.MergeRequest.user.can_merge | Boolean | If the user can merge. | 

#### Command Example
`!gitlab-merge-request-create  source_branch=NewName target_branch=main title=titleName assignee_ids=1 reviewer_ids2 description=description target_project_id=3320 labels=label1 milestone_id=1 remove_source_branch=False allow_collaboration=False allow_maintainer_to_push=False approvals_before_merge=2 squash=False partial_response=false`

#### Human Readable Output
## Merge request created successfully.

### gitlab-merge-request-update
***
Updates an existing merge request. You can change the target branch, title, or even close the MR.


#### Base Command

`gitlab-merge-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| merge_request_id | The ID of a merge request. Can be taken from gitlab-merge-request-list. | Required | 
| target_branch | The target branch. | Required | 
| title | Title of MR. | Required | 
| assignee_ids | The ID of the users to assign the MR to.  The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| reviewer_ids | The ID of the users set as a reviewer to the MR. The command gitlab-project-user-list gives a list of all relevent users. | Optional | 
| description | description of MR. Limited to 1,048,576 characters. | Optional | 
| target_project_id | The target project id. | Optional | 
| labels | Comma-separated label names for a merge request. Set to an empty string to unassign all labels. | Optional | 
| add_labels | Comma-separated label names to add to a merge request. | Optional | 
| remove_labels | Comma-separated label names to remove from a merge request. | Optional | 
| milestone_id | The global ID of a milestone to assign the merge request to. Set to 0 or provide an empty value to unassign a milestone. | Optional | 
| state_event | New state (close/reopen). | Optional | 
| remove_source_branch | Flag indicating if a merge request should remove the source branch when merging. | Optional | 
| squash | Squash commits into a single commit when merging. | Optional | 
| discussion_locked | Flag indicating if the merge request's discussion is locked. If the discussion is locked only project members can add, edit or resolve comments. | Optional | 
| allow_collaboration | Allow commits from members who can merge to the target branch. | Optional | 
| allow_maintainer_to_push | Alias of allow_collaboration. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.MergeRequest.id | Number | The merge request ID. Alias of allow_collaboration. | 
| GitLab.MergeRequest.iid | Number | The merge request IID. | 
| GitLab.MergeRequest.project_id | Number | The project ID of the merge request. | 
| GitLab.MergeRequest.title | String | The merge request title. | 
| GitLab.MergeRequest.description | Unknown | The merge request description. | 
| GitLab.MergeRequest.state | String | The merge request state. | 
| GitLab.MergeRequest.created_at | Date | The time the merge request was created. | 
| GitLab.MergeRequest.updated_at | Date | The time the merge request was updated. | 
| GitLab.MergeRequest.target_branch | String | The merge request source branch. | 
| GitLab.MergeRequest.source_branch | String | The merge request source branch. | 
| GitLab.MergeRequest.upvotes | Number | The merge request upvotes. | 
| GitLab.MergeRequest.downvotes | Number | The merge request downvotes. | 
| GitLab.MergeRequest.author.id | Number | The merge request author's id. | 
| GitLab.MergeRequest.author.username | String | The merge request author's username. | 
| GitLab.MergeRequest.author.name | String | The merge request author's name. | 
| GitLab.MergeRequest.author.state | String | The merge request author's state. | 
| GitLab.MergeRequest.author.avatar_url | String | The merge request author's avatar url. | 
| GitLab.MergeRequest.author.web_url | String | The merge request author's web url. | 
| GitLab.MergeRequest.assignee.id | Number | The merge request assignees's id. | 
| GitLab.MergeRequest.assignee.name | String | The merge request assignees's name. | 
| GitLab.MergeRequest.assignee.username | String | The merge request assignees's username. | 
| GitLab.MergeRequest.assignee.state | String | The merge request assignees's state. | 
| GitLab.MergeRequest.assignee.avatar_url | String | The merge request assignees's avatar_url. | 
| GitLab.MergeRequest.assignee.web_url | String | The merge request assignees's web_url. | 
| GitLab.MergeRequest.assignees.id | Number | The merge request assignees's id. | 
| GitLab.MergeRequest.assignees.username | String | The merge request assignees's username. | 
| GitLab.MergeRequest.assignees.name | String | The merge request assignees's name. | 
| GitLab.MergeRequest.assignees.state | String | The merge request assignees's state. | 
| GitLab.MergeRequest.assignees.avatar_url | String | The merge request assignees's avatar url. | 
| GitLab.MergeRequest.assignees.web_url | String | The merge request assignees's web url. | 
| GitLab.MergeRequest.reviewers.id | Number | The reviewer's ID. | 
| GitLab.MergeRequest.reviewers.username | String | The reviewer's username. | 
| GitLab.MergeRequest.reviewers.name | String | The reviewer's name. | 
| GitLab.MergeRequest.reviewers.state | String | The reviewer's state. | 
| GitLab.MergeRequest.reviewers.avatar_url | String | The reviewer's avatar_url. | 
| GitLab.MergeRequest.reviewers.web_url | String | The reviewer's web_url. | 
| GitLab.MergeRequest.source_project_id | Number | The merge request source project id. | 
| GitLab.MergeRequest.target_project_id | Number | The merge request target project id. | 
| GitLab.MergeRequest.labels | Unknown | Merge request's labels | 
| GitLab.MergeRequest.draft | Boolean | If the merge request is draft. | 
| GitLab.MergeRequest.work_in_progress | Boolean | If the merge request is draft. | 
| GitLab.MergeRequest.milestone | Unknown | Milestone details. | 
| GitLab.MergeRequest.milestone.id | Integer | Milestone details. | 
| GitLab.MergeRequest.milestone.iid | Integer | Milestone's id. | 
| GitLab.MergeRequest.milestone.project_id | Integer | Milestone's project_id. | 
| GitLab.MergeRequest.milestone.title | String | Milestone's title. | 
| GitLab.MergeRequest.milestone.description | String | Milestone's description. | 
| GitLab.MergeRequest.milestone. | String | Milestone's details. | 
| GitLab.MergeRequest.milestone.state | String | Milestone's state. | 
| GitLab.MergeRequest.milestone.created_at | String | Milestone's created_at date. | 
| GitLab.MergeRequest.milestone.updated_at | String | Milestone's updated_at date. | 
| GitLab.MergeRequest.milestone.due_date | String | Milestone's due_date. | 
| GitLab.MergeRequest.milestone.start_date | String | Milestone's start_date. | 
| GitLab.MergeRequest.milestone.web_url | String | Milestone's web_url. | 
| GitLab.MergeRequest.merge_when_pipeline_succeeds | Boolean | If to merge when pipeline succeeds. | 
| GitLab.MergeRequest.merge_status | String | The merge status. | 
| GitLab.MergeRequest.merge_error | String | The merge error if exist. | 
| GitLab.MergeRequest.sha | String | The request's sha. | 
| GitLab.MergeRequest.merge_commit_sha | Unknown | The merge commit sha. | 
| GitLab.MergeRequest.squash_commit_sha | Unknown | The squash commit sha. | 
| GitLab.MergeRequest.user_notes_count | Integer | The merge request user notes count. | 
| GitLab.MergeRequest.discussion_locked | Unknown | discussion locked value. | 
| GitLab.MergeRequest.should_remove_source_branch | Unknown | If should remove source branch. | 
| GitLab.MergeRequest.force_remove_source_branch | Unknown | If to force remove source branch. | 
| GitLab.MergeRequest.allow_collaboration | Boolean | If to allow collaboration. | 
| GitLab.MergeRequest.allow_maintainer_to_push | Boolean | If to allow maintainer to push. | 
| GitLab.MergeRequest.web_url | String | The merge request web url. | 
| GitLab.MergeRequest.reference | String | The merge request's reference. | 
| GitLab.MergeRequest.references.short | String | The merge requests refrence's short. | 
| GitLab.MergeRequest.references.relative | String | The merge requests refrence's relative. | 
| GitLab.MergeRequest.references.full | String | The merge requests refrence's full. | 
| GitLab.MergeRequest.time_stats.time_estimate | Number | The merge requests time estimate. | 
| GitLab.MergeRequest.time_stats.total_time_spent | Number | The merge requests total time spent. | 
| GitLab.MergeRequest.time_stats.human_time_estimate | Unknown | The merge requests human time estimate. | 
| GitLab.MergeRequest.time_stats.human_total_time_spent | Unknown | The merge request's human total time spent. | 
| GitLab.MergeRequest.squash | Boolean | The merge request's squash. | 
| GitLab.MergeRequest.subscribed | Boolean | If subscribed. | 
| GitLab.MergeRequest.changes_count | Integer | The merge request number of changes. | 
| GitLab.MergeRequest.merge_user.id | Integer | The merge requests merge user's ID. | 
| GitLab.MergeRequest.merge_user.name | String | The merge requests merge user's name. | 
| GitLab.MergeRequest.merge_user.username | String | The merge requests merge user's username. | 
| GitLab.MergeRequest.merge_user.state | String | The merge requests merge user's state. | 
| GitLab.MergeRequest.merge_user.avatar_url | String | The merge requests merge user's .avatar url | 
| GitLab.MergeRequest.merged_at | Date | The merge request was merged. | 
| GitLab.MergeRequest.closed_by | String | who close the request. | 
| GitLab.MergeRequest.closed_at | Date | The merge requests closing time. | 
| GitLab.MergeRequest.latest_build_started_at | Date | When latest build started at. | 
| GitLab.MergeRequest.latest_build_started_at | Date | When latest build started at. | 
| GitLab.MergeRequest.latest_build_finished_at | Date | When latest build finished at. | 
| GitLab.MergeRequest.first_deployed_to_production_at | Date | When is the first deployed to production at. | 
| GitLab.MergeRequest.pipeline.ID | Integer | The merge request's pipeline's ID. | 
| GitLab.MergeRequest.pipeline.sha | String | The merge request's pipeline's sha. | 
| GitLab.MergeRequest.pipeline.ref | String | The merge request's pipeline's reference. | 
| GitLab.MergeRequest.pipeline.status | String | The merge request's pipeline's status. | 
| GitLab.MergeRequest.pipeline.web_url | String | The merge request's pipeline's weburl. | 
| GitLab.MergeRequest.diff_refs.base_sha | String | The refrence's base sha. | 
| GitLab.MergeRequest.diff_refs.head_sha | String | The refrence's head sha. | 
| GitLab.MergeRequest.diff_refs.start_sha | String | The refrence's start sha. | 
| GitLab.MergeRequest.diverged_commits_count | Integer | The number of diverged commits. | 
| GitLab.MergeRequest.task_completion_status.count | Integer | The number of task completion. | 
| GitLab.MergeRequest.task_completion_status.completed_count | Integer | The number of task completed completion. | 

#### Command Example
`!gitlab-merge-request-update merge_request_id target_branch=NewName title=newTitle assignee_ids=1 reviewer_ids=2 description=UpdateDesc target_project_id=3003 add_labels=label2 remove_labels=label1 milestone_id=1 state_event=Close remove_source_branch=True squash=True discussion_locked=True allow_collaboration=True allow_maintainer_to_push=True partial_response=false`

#### Human Readable Output
## Merge request updated successfully.

### gitlab-issue-note-create
***
Creates a new note to a single project issue.


#### Base Command

`gitlab-issue-note-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_iid | The IID of an issue. | Required | 
| body | The content of a note. Limited to 1,000,000 characters. | Required | 
| confidential | will be removed in GitLab 16.0 and renamed to internal. The confidential flag of a note. Default is false. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.IssueNote.id | Number | The issue note ID. | 
| GitLab.IssueNote.type | Unknown | The type of the Project- private, internal, or public. | 
| GitLab.IssueNote.body | String | The issue note's body. | 
| GitLab.IssueNote.attachment | Unknown | The attachment of the issue note. | 
| GitLab.IssueNote.author.id | Number | The issue note's author's ID. | 
| GitLab.IssueNote.author.username | String | The issue note's author's username. | 
| GitLab.IssueNote.author.name | String | The issue note's author's name. | 
| GitLab.IssueNote.author.state | String | The issue note's author's state. | 
| GitLab.IssueNote.author.avatar_url | String | The issue note's author's avatar_url. | 
| GitLab.IssueNote.author.web_url | String | The issue note's author's web_url. | 
| GitLab.IssueNote.created_at | Date | The creation time of the issue note. | 
| GitLab.IssueNote.updated_at | Date | Last update time of the issue note. | 
| GitLab.IssueNote.system | Boolean | If the issue note is a about changes to the project. | 
| GitLab.IssueNote.noteable_id | Number | The noteable id of the issue note. | 
| GitLab.IssueNote.noteable_type | String | The noteable type of the issue note. | 
| GitLab.IssueNote.resolvable | Boolean | If the issue is resolvable. | 
| GitLab.IssueNote.confidential | Boolean | If the issue is confidential. | 
| GitLab.IssueNote.internal | Boolean | If the issue is internal. | 
| GitLab.IssueNote.noteable_iid | Number | The noteable IID. | 

#### Command example
```!gitlab-issue-note-create issue_iid=4 body=body confidential=True partial_response=false```
#### Context Example
```json
{
    "GitLab": {
        "IssueNote": {
            "attachment": null,
            "author": {
                "avatar_url": "https://secure.gravatar.com/avatar/9c7fbddb174ff5468dd993fb6f83b59a?s=80&d=identicon",
                "id": 12665296,
                "name": "Test Account",
                "state": "active",
                "username": "test9308",
                "web_url": "https://gitlab.com/test9308"
            },
            "body": "body",
            "commands_changes": {},
            "confidential": true,
            "created_at": "2022-10-11T09:35:02.558Z",
            "id": 1131185222,
            "internal": true,
            "noteable_id": 116016614,
            "noteable_iid": 4,
            "noteable_type": "Issue",
            "resolvable": false,
            "system": false,
            "type": null,
            "updated_at": "2022-10-11T09:35:02.558Z"
        }
    }
}
```

#### Human Readable Output

>Issue note created successfully

### gitlab-issue-note-delete
***
Deletes an existing note of an issue.


#### Base Command

`gitlab-issue-note-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_iid | The IID of an issue. | Required | 
| note_id | The ID of a note. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.IssueNote.message | String | issue note message | 

#### Command Example
`!gitlab-issue-note-delete issue_iid=4 note_id=1045951925`

#### Human Readable Output
## Issue note deleted successfully

### gitlab-issue-note-update
***
Modify existing note of an issue.


#### Base Command

`gitlab-issue-note-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_iid | The issue internal Id. | Required | 
| note_id | The note Id. | Required | 
| body | The content of a note. | Required | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.IssueNote.id | Number | The issue note ID. | 
| GitLab.IssueNote.type | Unknown | The issue note type. | 
| GitLab.IssueNote.body | String | The content of a note. | 
| GitLab.IssueNote.attachment | Unknown | Attachment to the issue note. | 
| GitLab.IssueNote.author.id | Number | The issue note's author's ID. | 
| GitLab.IssueNote.author.username | String | The issue note's author's username. | 
| GitLab.IssueNote.author.name | String | The issue note's author's name. | 
| GitLab.IssueNote.author.state | String | The issue note's author's state. | 
| GitLab.IssueNote.author.avatar_url | String | The issue note's author's avatar url. | 
| GitLab.IssueNote.author.web_url | String | The issue note's author's web url. | 
| GitLab.IssueNote.created_at | Date | Date time string, date of creating the file. | 
| GitLab.IssueNote.updated_at | Date | Date time string, date of updating the file. | 
| GitLab.IssueNote.system | Boolean | If the note is about changes to the object. | 
| GitLab.IssueNote.noteable_id | Number | The notable ID. | 
| GitLab.IssueNote.noteable_type | String | The notable type. | 
| GitLab.IssueNote.resolvable | Boolean | If the thread is resolvable. | 
| GitLab.IssueNote.confidential | Boolean | If the thread is confidential. | 
| GitLab.IssueNote.internal | Boolean | If the thread is internal. | 
| GitLab.IssueNote.noteable_iid | Number | The notable internal ID. | 

#### Command Example
`!gitlab-issue-note-update issue_iid=4 note_id=1045951925 body=UpdatedBody partial_response=false`

#### Human Readable Output
## Issue note updated was updated successfully.

### gitlab-issue-note-list
***
Gets a list of all notes for a single issue.


#### Base Command

`gitlab-issue-note-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_iid | The IID of an issue in order to get a specific issue note. | Required | 
| order_by | Return issue noted ordered by created_at, updated_at fields. Possible values are: created_at, updated_at. Default is created_at. | Optional | 
| sort | Return issue noted ordered by created_at, updated_at fields. Possible values are: desc, asc. Default is desc. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.IssueNote.id | Number | The issue note ID. | 
| GitLab.IssueNote.type | Unknown | The issue note type. | 
| GitLab.IssueNote.body | String | The content of a note. | 
| GitLab.IssueNote.attachment | Unknown | Attachment to the issue note. | 
| GitLab.IssueNote.author.id | Number | The issue note's author's ID. | 
| GitLab.IssueNote.author.username | String | The issue note's author's username. | 
| GitLab.IssueNote.author.name | String | The issue note's author's name. | 
| GitLab.IssueNote.author.state | String | The issue note's author's state. | 
| GitLab.IssueNote.author.avatar_url | String | The issue note's author's avatar url. | 
| GitLab.IssueNote.author.web_url | String | The issue note's author's web url. | 
| GitLab.IssueNote.created_at | Date | Date time string, date of creating the file. | 
| GitLab.IssueNote.updated_at | Date | Date time string, date of updating the file. | 
| GitLab.IssueNote.system | Boolean | If the note is about changes to the object. | 
| GitLab.IssueNote.noteable_id | Number | The notable ID. | 
| GitLab.IssueNote.noteable_type | String | The notable type. | 
| GitLab.IssueNote.resolvable | Boolean | If the thread is resolvable. | 
| GitLab.IssueNote.confidential | Boolean | If the thread is confidential. | 
| GitLab.IssueNote.internal | Boolean | If the thread is internal. | 
| GitLab.IssueNote.noteable_iid | Number | The notable internal ID. | 

#### Command Example
`!gitlab-issue-note-list limit=1 page=1 partial_response=false`

#### Human Readable Output
## List Issue notes:
|Id|Author|Text|CreatedAt|UpdatedAt|
|---|---|---|---|---|
|4|authorExample|text example|2000-09-15T17:22:42.246Z|2000-09-15T17:23:42.246Z|

### gitlab-merge-request-note-list
***
Gets a list of all notes for a single merge request.


#### Base Command

`gitlab-merge-request-note-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| merge_request_iid | The IID of a project merge request. | Required | 
| sort | Return merge request notes sorted in asc or desc order. Default is desc. Possible values are: desc, asc. Default is desc. | Optional | 
| order_by | Return merge request notes ordered by created_at or updated_at fields. Default is created_at. Possible values are: created_at, updated_at. Default is created_at. | Optional | 
| limit | Total merge requests to show. Default is 50. | Optional | 
| page | Present merge requests from page. Default is 1. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.MergeRequestNote.id | Number | The ID of the merge request note. | 
| GitLab.MergeRequestNote.type | Unknown | The merge request note's type. | 
| GitLab.MergeRequestNote.body | String | The merge request note's body. | 
| GitLab.MergeRequestNote.attachment | Unknown | The merge request note's attachment. | 
| GitLab.MergeRequestNote.author.id | Number | The merge request note's author's ID. | 
| GitLab.MergeRequestNote.author.username | String | The merge request note's author's username. | 
| GitLab.MergeRequestNote.author.name | String | The merge request note's author's name. | 
| GitLab.MergeRequestNote.author.state | String | The merge request note's author's state. | 
| GitLab.MergeRequestNote.author.avatar_url | String | The merge request note's author's avatar url. | 
| GitLab.MergeRequestNote.author.web_url | String | The merge request note's author's web url. | 
| GitLab.MergeRequestNote.created_at | Date | The merge request note's creation time. | 
| GitLab.MergeRequestNote.updated_at | Date | The time of the last update of the merge request note. | 
| GitLab.MergeRequestNote.system | Boolean | If the note is about changes to the object. | 
| GitLab.MergeRequestNote.noteable_id | Number | The merge request's noteable ID. | 
| GitLab.MergeRequestNote.noteable_type | String | The merge request's noteable type. | 
| GitLab.MergeRequestNote.resolvable | Boolean | If the merge request is resolvable. | 
| GitLab.MergeRequestNote.confidential | Boolean | If the merge request is confidential. | 
| GitLab.MergeRequestNote.internal | Boolean | If the merge request is internal. | 
| GitLab.MergeRequestNote.noteable_iid | Number | The merge request's noteable IID. | 

#### Command example
```!gitlab-merge-request-note-list limit=1 page=1 merge_request_iid=5 sort=asc order_by=created_at partial_response=false```
#### Human Readable Output
>### List Merge Issue Notes
|Id|Author|Text|CreatedAt|UpdatedAt|
|---|---|---|---|---|
|41|demoAuthor|example|2000-09-15T17:22:42.246Z|2000-09-15T17:23:42.246Z|

### gitlab-merge-request-note-create
***
Creates a new note for a single merge request.


#### Base Command

`gitlab-merge-request-note-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| merge_request_iid | The IID of a project merge request. | Required | 
| body | The content of a note. Limited to 1,000,000 characters. | Required | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.MergeRequestNote.id | Number | The ID of the merge request note. | 
| GitLab.MergeRequestNote.type | Unknown | The merge request note's type. | 
| GitLab.MergeRequestNote.body | String | The merge request note's body. | 
| GitLab.MergeRequestNote.attachment | Unknown | The merge request note's attachment. | 
| GitLab.MergeRequestNote.author.id | Number | The merge request note's author's ID. | 
| GitLab.MergeRequestNote.author.username | String | The merge request note's author's username. | 
| GitLab.MergeRequestNote.author.name | String | The merge request note's author's name. | 
| GitLab.MergeRequestNote.author.state | String | The merge request note's author's state. | 
| GitLab.MergeRequestNote.author.avatar_url | String | The merge request note's author's avatar url. | 
| GitLab.MergeRequestNote.author.web_url | String | The merge request note's author's web url. | 
| GitLab.MergeRequestNote.created_at | Date | The merge request note's creation time. | 
| GitLab.MergeRequestNote.updated_at | Date | The time of the last update of the merge request note. | 
| GitLab.MergeRequestNote.system | Boolean | If the note is about changes to the object. | 
| GitLab.MergeRequestNote.noteable_id | Number | The merge request's noteable ID. | 
| GitLab.MergeRequestNote.noteable_type | String | The merge request's noteable type. | 
| GitLab.MergeRequestNote.resolvable | Boolean | If the merge request is resolvable. | 
| GitLab.MergeRequestNote.confidential | Boolean | If the merge request is confidential. | 
| GitLab.MergeRequestNote.internal | Boolean | If the merge request is internal. | 
| GitLab.MergeRequestNote.noteable_iid | Number | The merge request's noteable IID. | 

#### Command example
```!gitlab-merge-request-note-create merge_request_iid=5 body=body partial_response=false```
#### Context Example
```json
{
    "GitLab": {
        "MergeRequestNote": {
            "attachment": null,
            "author": {
                "avatar_url": "https://secure.gravatar.com/avatar/9c7fbddb174ff5468dd993fb6f83b59a?s=80&d=identicon",
                "id": 12665296,
                "name": "Test Account",
                "state": "active",
                "username": "test9308",
                "web_url": "https://gitlab.com/test9308"
            },
            "body": "body",
            "commands_changes": {},
            "confidential": false,
            "created_at": "2022-10-11T09:35:10.685Z",
            "id": 1131185415,
            "internal": false,
            "noteable_id": 180503976,
            "noteable_iid": 5,
            "noteable_type": "MergeRequest",
            "resolvable": false,
            "system": false,
            "type": null,
            "updated_at": "2022-10-11T09:35:10.685Z"
        }
    }
}
```

#### Human Readable Output

>Merge request note created successfully.

### gitlab-merge-request-note-update
***
Modify existing note of a merge request.


#### Base Command

`gitlab-merge-request-note-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| merge_request_iid | The IID of a project merge request. | Required | 
| note_id | The ID of a note. | Required | 
| body | The content of a note. Limited to 1,000,000 characters. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.MergeRequestNote.id | Number | The ID of the merge request note. | 
| GitLab.MergeRequestNote.type | Unknown | The merge request note's type. | 
| GitLab.MergeRequestNote.body | String | The merge request note's body. | 
| GitLab.MergeRequestNote.attachment | Unknown | The merge request note's attachment. | 
| GitLab.MergeRequestNote.author.id | Number | The merge request note's author's ID. | 
| GitLab.MergeRequestNote.author.username | String | The merge request note's author's username. | 
| GitLab.MergeRequestNote.author.name | String | The merge request note's author's name. | 
| GitLab.MergeRequestNote.author.state | String | The merge request note's author's state. | 
| GitLab.MergeRequestNote.author.avatar_url | String | The merge request note's author's avatar url. | 
| GitLab.MergeRequestNote.author.web_url | String | The merge request note's author's web url. | 
| GitLab.MergeRequestNote.created_at | Date | The merge request note's creation time. | 
| GitLab.MergeRequestNote.updated_at | Date | The time of the last update of the merge request note. | 
| GitLab.MergeRequestNote.system | Boolean | If the note is about changes to the object. | 
| GitLab.MergeRequestNote.noteable_id | Number | The merge request's noteable ID. | 
| GitLab.MergeRequestNote.noteable_type | String | The merge request's noteable type. | 
| GitLab.MergeRequestNote.resolvable | Boolean | If the merge request is resolvable. | 
| GitLab.MergeRequestNote.confidential | Boolean | If the merge request is confidential. | 
| GitLab.MergeRequestNote.internal | Boolean | If the merge request is internal. | 
| GitLab.MergeRequestNote.noteable_iid | Number | The merge request's noteable IID. | 

#### Command Example
`!gitlab-merge-request-note-update merge_request_iid=5 body=UpdatedBody note_id=1100241092`

#### Human Readable Output
> Merge request note was updated successfully.

### gitlab-merge-request-note-delete
***
Deletes an existing note of a merge request.


#### Base Command

`gitlab-merge-request-note-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| merge_request_iid | The IID of a merge request. | Required | 
| note_id | The ID of a note. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
`!gitlab-merge-request-note-delete merge_request_iid=5 note_id=1100241092`

#### Human Readable Output
> Merge request note was deleted successfully.

### gitlab-issue-create
***
Create an issue.


#### Base Command

`gitlab-issue-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| labels | Comma separated values of labels to add to the issue. | Optional | 
| title | The issue title. | Required | 
| description | The issue description. | Required | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Issue.iid | Number | The issue's IID. | 
| GitLab.Issue.created_at | Date | The issue's creation date. | 
| GitLab.Issue.title | String | The issue's title. | 
| GitLab.Issue.state | String | The issue's state. | 
| GitLab.Issue.assignee | Unknown | The issue's assignee. | 
| GitLab.Issue.type | String | The issue's type. | 
| GitLab.Issue.labels | String | The issue's labels. | 
| GitLab.Issue.upvotes | Number | The issue's upvotes. | 
| GitLab.Issue.downvotes | Number | The issue's downvotes. | 
| GitLab.Issue.merge_requests_count | Number | The issue's number of merge requests. | 
| GitLab.Issue.author.name | String | The issue author's name. | 
| GitLab.Issue.author.avatar_url | Unknown | The issue author's avatar url. | 
| GitLab.Issue.author.state | String | The issue author's state. | 
| GitLab.Issue.author.web_url | String | The issue author's web url. | 
| GitLab.Issue.author.id | Number | The issue author's ID. | 
| GitLab.Issue.author.username | String | The issue author's username. | 
| GitLab.Issue.description | Unknown | The issue's description. | 
| GitLab.Issue.updated_at | Date | The issue's last update date. | 
| GitLab.Issue.closed_at | Unknown | The date that the issue has closed. | 
| GitLab.Issue.closed_by | Unknown | The one who had closed the issue if closed. | 
| GitLab.Issue.milestone | Unknown | The issue's milestone title. | 
| GitLab.Issue.subscribed | Boolean | If the user is subscribed to the issue\(receive notifications about the issue\). | 
| GitLab.Issue.user_notes_count | Number | The number of the user notes. | 
| GitLab.Issue.due_date | Unknown | The due date of the issue. | 
| GitLab.Issue.web_url | String | The issue's web url. | 
| GitLab.Issue.references.short | String | The issue's short refrences. | 
| GitLab.Issue.references.relative | String | The issue's relative refrences. | 
| GitLab.Issue.references.full | String | The issue's full refrences. | 
| GitLab.Issue.time_stats.time_estimate | Number | The time estimate to solve the issue. | 
| GitLab.Issue.time_stats.total_time_spent | Number | The time that had spent to solve the issue. | 
| GitLab.Issue.time_stats.human_time_estimate | Unknown | The human time estimate to solve the issue. | 
| GitLab.Issue.time_stats.human_total_time_spent | Unknown | The human time that had spent to solve the issue. | 
| GitLab.Issue.confidential | Boolean | If the issue is confidential. | 
| GitLab.Issue.discussion_locked | Boolean | If the discussion is locked. | 
| GitLab.Issue.issue_type | String | The issue's type. | 
| GitLab.Issue.severity | String | The issue's severity. | 
| GitLab.Issue._links.self | String | The issue's link. | 
| GitLab.Issue._links.notes | String | The issue's notes' link. | 
| GitLab.Issue._links.award_emoji | String | The issue's award_emoji's link. | 
| GitLab.Issue._links.project | String | The issue's project's link. | 
| GitLab.Issue._links.closed_as_duplicate_of | String | The issue's closed_as_duplicate_of's link. | 
| GitLab.Issue.task_completion_status.count | Number | The issue's completion status counter. | 
| GitLab.Issue.task_completion_status.completed_count | Number | The issue's completion status completed counter. | 

#### Command example
```!gitlab-issue-create description=issueDescription title=issueTitle labels=label1,label2 partial_response=false```
#### Context Example
```json
{
    "GitLab": {
        "Issue": {
            "_links": {
                "award_emoji": "https://gitlab.com/api/v4/projects/39823965/issues/21/award_emoji",
                "closed_as_duplicate_of": null,
                "notes": "https://gitlab.com/api/v4/projects/39823965/issues/21/notes",
                "project": "https://gitlab.com/api/v4/projects/39823965",
                "self": "https://gitlab.com/api/v4/projects/39823965/issues/21"
            },
            "assignee": null,
            "assignees": [],
            "author": {
                "avatar_url": "https://secure.gravatar.com/avatar/9c7fbddb174ff5468dd993fb6f83b59a?s=80&d=identicon",
                "id": 12665296,
                "name": "Test Account",
                "state": "active",
                "username": "test9308",
                "web_url": "https://gitlab.com/test9308"
            },
            "blocking_issues_count": 0,
            "closed_at": null,
            "closed_by": null,
            "confidential": false,
            "created_at": "2022-10-11T09:34:55.292Z",
            "description": "issueDescription",
            "discussion_locked": null,
            "downvotes": 0,
            "due_date": null,
            "has_tasks": false,
            "id": 116652264,
            "iid": 21,
            "issue_type": "issue",
            "labels": [
                "label1",
                "label2"
            ],
            "merge_requests_count": 0,
            "milestone": null,
            "moved_to_id": null,
            "project_id": 39823965,
            "references": {
                "full": "test9308/gitlabtest#21",
                "relative": "#21",
                "short": "#21"
            },
            "service_desk_reply_to": null,
            "severity": "UNKNOWN",
            "state": "opened",
            "subscribed": true,
            "task_completion_status": {
                "completed_count": 0,
                "count": 0
            },
            "time_stats": {
                "human_time_estimate": null,
                "human_total_time_spent": null,
                "time_estimate": 0,
                "total_time_spent": 0
            },
            "title": "issueTitle",
            "type": "ISSUE",
            "updated_at": "2022-10-11T09:34:55.292Z",
            "upvotes": 0,
            "user_notes_count": 0,
            "web_url": "https://gitlab.com/test9308/gitlabtest/-/issues/21"
        }
    }
}
```

#### Human Readable Output

>### Created Issue
>|Iid|Title|CreatedAt|CreatedBy|UpdatedAt|State|
>|---|---|---|---|---|---|
>| 21 | issueTitle | 2022-10-11T09:34:55.292Z | Test Account | 2022-10-11T09:34:55.292Z | opened |


### gitlab-project-list
***
Get a list of all visible projects across GitLab for the authenticated user. When accessed without authentication, only public projects with simple fields are returned.


#### Base Command

`gitlab-project-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership | Limit by projects that the current user is a member of. | Optional | 
| order_by | Return projects ordered by id, name, path, created_at, updated_at, last_activity_at, or similarity fields. repository_size, storage_size, packages_size or wiki_size fields are only allowed for administrators. Possible values are: id, name, path, created_at, updated_at, last_activity_at, similarity. Default is created_at. | Optional | 
| owned | Limit by projects explicitly owned by the current user. | Optional | 
| search | Return list of projects matching the search criteria. | Optional | 
| sort | Return projects sorted in asc or desc order. Possible values are: asc, desc. Default is desc. | Optional | 
| visibility | Limit by visibility public, internal, or private. | Optional | 
| with_issues_enabled | Limit by enabled issues feature. | Optional | 
| with_merge_requests_enabled | Limit by enabled merge requests feature. | Optional | 
| page | The page number. Default is 1. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Project.id | Number | The project's ID. | 
| GitLab.Project.description | Unknown | The project's description. | 
| GitLab.Project.name | String | The project's name. | 
| GitLab.Project.name_with_namespace | String | The project's name with namespace. | 
| GitLab.Project.path | String | The project's path. | 
| GitLab.Project.path_with_namespace | String | The project's path with namespace. | 
| GitLab.Project.created_at | Date | The project's creation date. | 
| GitLab.Project.default_branch | String | The project's default branch. | 
| GitLab.Project.ssh_url_to_repo | String | The project's SSH url to repository. | 
| GitLab.Project.http_url_to_repo | String | The project's http url to repository. | 
| GitLab.Project.web_url | String | The project's web url. | 
| GitLab.Project.readme_url | String | The project's readme url. | 
| GitLab.Project.avatar_url | Unknown | The project's avatar url. | 
| GitLab.Project.forks_count | Number | Number of forks of the project. | 
| GitLab.Project.star_count | Number | Number of star of the project. | 
| GitLab.Project.last_activity_at | Number | The last activity time. | 
| GitLab.Project.namespace.id | Number | Namespace ID. | 
| GitLab.Project.namespace.name | String | The Project's namespace name. | 
| GitLab.Project.namespace.path | String | The Project's namespace path. | 
| GitLab.Project.namespace.kind | String | The Project's namespace kind. | 
| GitLab.Project.namespace.full_path | String | The Project's namespace full path. | 
| GitLab.Project.namespace.parent_id | Unknown | The Project's namespace parent ID. | 
| GitLab.Project.namespace.avatar_url | Unknown | The Project's namespace avatar. | 
| GitLab.Project.namespace.web_url | String | The Project's namespace web url. | 
| GitLab.Project.container_registry_image_prefix | String | The project container registry image prefix. | 
| GitLab.Project._links.self | Dictionary | Dictionary of links for list project. | 
| GitLab.Project._links.issues | String | Link to the issues of the project. | 
| GitLab.Project._links.merge_requests | String | Link to the merge requests of the project. | 
| GitLab.Project._links.repo_branches | String | Link to the repository branches of the project. | 
| GitLab.Project._links.labels | String | Link to the labels of the project. | 
| GitLab.Project._links.events | String | Link to the events of thr project. | 
| GitLab.Project._links.members | String | Link to the members of the project. | 
| GitLab.Project._links.cluster_agents | String | Link to the cluster agents of the project. | 
| GitLab.Project.packages_enabled | String | If the packages are enabled. | 
| GitLab.Project.empty_repo | Boolean | If the repository is empty. | 
| GitLab.Project.archived | Boolean | If the project is archived. | 
| GitLab.Project.visibility | String | The visibility of the project Public, Private or Internal. | 
| GitLab.Project.resolve_outdated_diff_discussions | Boolean | The resolve outdated diff discussions. | 
| GitLab.Project.container_expiration_policy.cadence | String | The cadence of the container expiration policy. | 
| GitLab.Project.container_expiration_policy.enabled | Boolean | If the container expiration policy enabled. | 
| GitLab.Project.container_expiration_policy.keep_n | Number | Keep n value. | 
| GitLab.Project.container_expiration_policy.older_than | String | Number of days of the container expiration policy. | 
| GitLab.Project.container_expiration_policy.name_regex | String | Regex name of the container expiration policy. | 
| GitLab.Project.container_expiration_policy.name_regex_keep | Unknown | Value of regex keep of the container expiration policy. | 
| GitLab.Project.container_expiration_policy.next_run_at | Date | Next run at value of the container expiration policy. | 
| GitLab.Project.issues_enabled | Boolean | Issues enabled list project. | 
| GitLab.Project.merge_requests_enabled | Boolean | If the merge requests are enabled. | 
| GitLab.Project.wiki_enabled | Boolean | If the wiki is enabled. | 
| GitLab.Project.jobs_enabled | Boolean | If the jobs are enabled. | 
| GitLab.Project.snippets_enabled | Boolean | If snippets are enabled. | 
| GitLab.Project.container_registry_enabled | Boolean | The container registry is enabled. | 
| GitLab.Project.service_desk_enabled | Boolean | If the service desk is enabled. | 
| GitLab.Project.service_desk_address | String | The service desk address. | 
| GitLab.Project.can_create_merge_request_in | Boolean | If creating merge request is an option. | 
| GitLab.Project.issues_access_level | String | The access level of the issues. | 
| GitLab.Project.repository_access_level | String | The repository access level. | 
| GitLab.Project.merge_requests_access_level | String | The merge requests access level. | 
| GitLab.Project.forking_access_level | String | The forking access level. | 
| GitLab.Project.wiki_access_level | String | The wiki access level. | 
| GitLab.Project.builds_access_level | String | The builds access level. | 
| GitLab.Project.snippets_access_level | String | The snippets access level. | 
| GitLab.Project.pages_access_level | String | The pages access level. | 
| GitLab.Project.operations_access_level | String | The operations access level. | 
| GitLab.Project.analytics_access_level | String | The analytics access level. | 
| GitLab.Project.container_registry_access_level | String | The container registry access level. | 
| GitLab.Project.security_and_compliance_access_level | String | The security and compliance access level. | 
| GitLab.Project.emails_disabled | Unknown | If the emails are disabled. | 
| GitLab.Project.shared_runners_enabled | Boolean | If shared runners is enabled. | 
| GitLab.Project.lfs_enabled | Boolean | If lfs are enabled. | 
| GitLab.Project.creator_id | Number | The creator ID. | 
| GitLab.Project.import_url | Unknown | The import url pf list project. | 
| GitLab.Project.import_type | Unknown | The import type of the list project. | 
| GitLab.Project.import_status | String | The import status | 
| GitLab.Project.open_issues_count | Number | The open issues count number. | 
| GitLab.Project.ci_default_git_depth | Number | The ci default git depth value | 
| GitLab.Project.ci_forward_deployment_enabled | Boolean | If the ci forward deployment is enabled. | 
| GitLab.Project.ci_job_token_scope_enabled | Boolean | If the ci job token scope is enabled. | 
| GitLab.Project.ci_separated_caches | Boolean | If the ci separated caches is enabled. | 
| GitLab.Project.public_jobs | Boolean | If there is public jobs in the project. | 
| GitLab.Project.build_timeout | Number | The timeout of the build. | 
| GitLab.Project.auto_cancel_pending_pipelines | String | If the auto cancel pending pipelines is enabled. | 
| GitLab.Project.ci_config_path | String | The ci config path of the project list. | 
| GitLab.Project.only_allow_merge_if_pipeline_succeeds | Boolean | Only allow merge if pipeline succeeds. | 
| GitLab.Project.ci_allow_fork_pipelines_to_run_in_parent_project | Boolean | Ci allow fork pipelines to run in parent project. | 
| GitLab.Project.allow_merge_on_skipped_pipeline | Unknown | Allow merge on skipped pipeline. | 
| GitLab.Project.restrict_user_defined_variables | Boolean | If to restrict user defined variables. | 
| GitLab.Project.request_access_enabled | Boolean | If to enable access request. | 
| GitLab.Project.only_allow_merge_if_all_discussions_are_resolved | Boolean | If only allow merge if all discussions are resolved. | 
| GitLab.Project.remove_source_branch_after_merge | Boolean | If to remove source branch after merge. | 
| GitLab.Project.printing_merge_request_link_enabled | Boolean | If printing merge request link is enabled. | 
| GitLab.Project.merge_method | String | The merge method. | 
| GitLab.Project.squash_option | String | The squash option. | 
| GitLab.Project.enforce_auth_checks_on_uploads | Boolean | If to printing merge request link enabled. | 
| GitLab.Project.suggestion_commit_message | Unknown | Suggestion commit message | 
| GitLab.Project.merge_commit_template | Unknown | The merge commit template. | 
| GitLab.Project.squash_commit_template | Unknown | The squash commit template. | 
| GitLab.Project.auto_devops_enabled | Boolean | If the auto devops is enabled. | 
| GitLab.Project.auto_devops_deploy_strategy | String | The auto devops deploy strategy. | 
| GitLab.Project.autoclose_referenced_issues | Boolean | If to autoclose the referenced issues. | 
| GitLab.Project.keep_latest_artifact | Boolean | If to keep the lastest artifact. | 
| GitLab.Project.runner_token_expiration_interval | Unknown | The runner token expiration interval. | 
| GitLab.Project.external_authorization_classification_label | String | The external authorization classification label. | 
| GitLab.Project.requirements_enabled | Boolean | If the requirements enabled. | 
| GitLab.Project.requirements_access_level | String | The requirements access level. | 
| GitLab.Project.security_and_compliance_enabled | Boolean | The requirements access level. | 
| GitLab.Project.permissions.project_access.access_level | Number | The access level of the project. | 
| GitLab.Project.permissions.project_access.notification_level | Unknown | The project notification level. | 
| GitLab.Project.permissions.group_access.access_level | Number | The access level of the group level. | 
| GitLab.Project.permissions.group_access.notification_level | Number | The notification level of the group\(permissions\). | 
| GitLab.Project.permissions.project_access | Unknown | The project access\(permissions\). | 

#### Command Example
`!gitlab-project-list limit=1 page=1 membership=True order_by=Name owned=True sort=desc visibillity=public with_issues_enabled=True with_merge_requests_enabled=True partial_response=false`

#### Human Readable Output
## List Projects:
|Id|Name|Description|Path|
|---|---|---|---|
|11209|first-project-01|this is the first project|first-project-repository|

### gitlab-group-project-list
***
Get the list of projects of a given group.


#### Base Command

`gitlab-group-project-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID from which to retrieve the projects. | Required | 
| limit | Total number of projects for display. Default is 50. | Optional | 
| page | Dispaly projects from this page number. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.GroupProject.id | Number | The project's ID. | 
| GitLab.GroupProject.description | String | The project's description. | 
| GitLab.GroupProject.name | String | The project's name. | 
| GitLab.GroupProject.name_with_namespace | String | The project's name with namespace. | 
| GitLab.GroupProject.path | String | The file's path. | 
| GitLab.GroupProject.path_with_namespace | String | The project's path with namespace. | 
| GitLab.GroupProject.created_at | Date | The project date of creation. | 
| GitLab.GroupProject.default_branch | String | The project default branch. | 
| GitLab.GroupProject.ssh_url_to_repo | String | Group project ssh url to repository. | 
| GitLab.GroupProject.http_url_to_repo | String | Group project http url to repository. | 
| GitLab.GroupProject.web_url | String | Group project web url. | 
| GitLab.GroupProject.readme_url | String | Group project readme url. | 
| GitLab.GroupProject.avatar_url | Unknown | Group project avatar url. | 
| GitLab.GroupProject.forks_count | Number | Group project web url forks count. | 
| GitLab.GroupProject.star_count | Number | Group project web url star count. | 
| GitLab.GroupProject.last_activity_at | Date | The project date of last date of activity. | 
| GitLab.GroupProject.namespace.id | Number | The namespace id. | 
| GitLab.GroupProject.namespace.name | String | The namespace name. | 
| GitLab.GroupProject.namespace.path | String | The namespace path. | 
| GitLab.GroupProject.namespace.kind | String | The namespace kind. | 
| GitLab.GroupProject.namespace.full_path | String | The full path of the namespace. | 
| GitLab.GroupProject.namespace.parent_id | Unknown | The parent id. | 
| GitLab.GroupProject.namespace.avatar_url | Unknown | The avatar url. | 
| GitLab.GroupProject.namespace.web_url | String | The name web url. | 
| GitLab.GroupProject.container_registry_image_prefix | String | The container registry image prefix. | 
| GitLab.GroupProject._links.self | String | The group projects' links. | 
| GitLab.GroupProject._links.issues | String | The group projects' issues. | 
| GitLab.GroupProject._links.merge_requests | String | The group projects' merge requests. | 
| GitLab.GroupProject._links.repo_branches | String | The group projects' repository branches. | 
| GitLab.GroupProject._links.labels | String | The group projects' links labels. | 
| GitLab.GroupProject._links.events | String | The group projects' links events. | 
| GitLab.GroupProject._links.members | String | The group projects' links members. | 
| GitLab.GroupProject._links.cluster_agents | String | The group projects' links cluster agents. | 
| GitLab.GroupProject.packages_enabled | Boolean | If the group projects' packages are enabled. | 
| GitLab.GroupProject.empty_repo | Boolean | The group projects' empty repository. | 
| GitLab.GroupProject.archived | Boolean | The group projects is archived. | 
| GitLab.GroupProject.visibility | String | The group projects' visibility. | 
| GitLab.GroupProject.resolve_outdated_diff_discussions | Boolean | The group projects's resolved outdated different discussions. | 
| GitLab.GroupProject.container_expiration_policy.cadence | String | The group projects' container expiration policy cadence. | 
| GitLab.GroupProject.container_expiration_policy.enabled | Boolean | If the group projects' container expiration policy enabled. | 
| GitLab.GroupProject.container_expiration_policy.keep_n | Number | If to keep the group project expiration policy. | 
| GitLab.GroupProject.container_expiration_policy.older_than | String | If the group project expiration policy is older than X. | 
| GitLab.GroupProject.container_expiration_policy.name_regex | String | What is the group project expiration policy regex name. | 
| GitLab.GroupProject.container_expiration_policy.name_regex_keep | String | If to keep the group project expiration policy regex name. | 
| GitLab.GroupProject.container_expiration_policy.next_run_at | Date | The group project expiration policy next run at. | 
| GitLab.GroupProject.issues_enabled | Boolean | if to enabled issues. | 
| GitLab.GroupProject.merge_requests_enabled | Boolean | If to enable merge requests. | 
| GitLab.GroupProject.wiki_enabled | Boolean | If wiki is enabled. | 
| GitLab.GroupProject.jobs_enabled | Boolean | If jobs are enabled. | 
| GitLab.GroupProject.snippets_enabled | Boolean | If snippets are enabled. | 
| GitLab.GroupProject.container_registry_enabled | Boolean | If the container registry is enabled. | 
| GitLab.GroupProject.service_desk_enabled | Boolean | If service desk is enabled. | 
| GitLab.GroupProject.service_desk_address | String | The group project service desk address. | 
| GitLab.GroupProject.can_create_merge_request_in | Boolean | If the group project can create merge request in. | 
| GitLab.GroupProject.issues_access_level | String | The group project issues access level. | 
| GitLab.GroupProject.repository_access_level | String | The group project repository access level. | 
| GitLab.GroupProject.merge_requests_access_level | String | The group project merge requests access level. | 
| GitLab.GroupProject.forking_access_level | String | The group project forking access level. | 
| GitLab.GroupProject.wiki_access_level | String | The group project wiki access level. | 
| GitLab.GroupProject.builds_access_level | String | The group project builds access level. | 
| GitLab.GroupProject.snippets_access_level | String | The group project snippets access level. | 
| GitLab.GroupProject.pages_access_level | String | The group project pages access level. | 
| GitLab.GroupProject.operations_access_level | String | The group project operations access level. | 
| GitLab.GroupProject.analytics_access_level | String | The group project analytics access level. | 
| GitLab.GroupProject.container_registry_access_level | String | The group project container registry access level. | 
| GitLab.GroupProject.security_and_compliance_access_level | String | The group project security and compliance access level. | 
| GitLab.GroupProject.emails_disabled | Unknown | If group project emails are disabled. | 
| GitLab.GroupProject.shared_runners_enabled | Boolean | If group project shared runners are enabled. | 
| GitLab.GroupProject.lfs_enabled | Boolean | If group project lfs are enabled. | 
| GitLab.GroupProject.creator_id | Number | The group project creator id. | 
| GitLab.GroupProject.import_url | string | The group project import url. | 
| GitLab.GroupProject.import_type | Unknown | The group project import type. | 
| GitLab.GroupProject.import_status | String | The group project import status. | 
| GitLab.GroupProject.open_issues_count | Number | The group project issues count. | 
| GitLab.GroupProject.ci_default_git_depth | Number | The group project default fit depth. | 
| GitLab.GroupProject.ci_forward_deployment_enabled | Boolean | If the ci forward deployment are  enabled. | 
| GitLab.GroupProject.ci_job_token_scope_enabled | Boolean | If the group project ci job token scope is enabled. | 
| GitLab.GroupProject.ci_separated_caches | Boolean | The group project ci separated caches. | 
| GitLab.GroupProject.ci_opt_in_jwt | Boolean | The group project ci opt in jwt value. | 
| GitLab.GroupProject.ci_allow_fork_pipelines_to_run_in_parent_project | Boolean | If group project ci allows fork pipelines to run in parent project. | 
| GitLab.GroupProject.public_jobs | Boolean | The group project import public jobs. | 
| GitLab.GroupProject.build_timeout | Number | The group project build timeout. | 
| GitLab.GroupProject.auto_cancel_pending_pipelines | String | The group project auto cancel pending pipelines. | 
| GitLab.GroupProject.ci_config_path | String | The group project ci config path. | 
| GitLab.GroupProject.only_allow_merge_if_pipeline_succeeds | Boolean | If to only allow merge if pipeline succeeds. | 
| GitLab.GroupProject.allow_merge_on_skipped_pipeline | Boolean | If to only allow merge on skipped pipeline. | 
| GitLab.GroupProject.restrict_user_defined_variables | Boolean | The group project restrict user defined variables. | 
| GitLab.GroupProject.request_access_enabled | Boolean | If the request access enabled. | 
| GitLab.GroupProject.only_allow_merge_if_all_discussions_are_resolved | Boolean | If to only allow merge if all discussions are resolved. | 
| GitLab.GroupProject.remove_source_branch_after_merge | Boolean | If to remove source branch after merge. | 
| GitLab.GroupProject.printing_merge_request_link_enabled | Boolean | If printing merge request link is enabled. | 
| GitLab.GroupProject.merge_method | String | what is the merge method. | 
| GitLab.GroupProject.squash_option | String | What the squash option. | 
| GitLab.GroupProject.enforce_auth_checks_on_uploads | Boolean | If to enforce auth checks on uploads. | 
| GitLab.GroupProject.suggestion_commit_message | Unknown | The suggestion commit message. | 
| GitLab.GroupProject.merge_commit_template | Unknown | The merge commit template. | 
| GitLab.GroupProject.squash_commit_template | Unknown | The squash commit template. | 
| GitLab.GroupProject.auto_devops_enabled | Boolean | The auto devops deploy strategy. | 
| GitLab.GroupProject.auto_devops_deploy_strategy | String | The auto devops deploy strategy | 
| GitLab.GroupProject.autoclose_referenced_issues | Boolean | The autoclose referenced issues. | 
| GitLab.GroupProject.keep_latest_artifact | Boolean | If keeping the lastest artifact is enabled. | 
| GitLab.GroupProject.runner_token_expiration_interval | Unknown | What is runner token expiration interval. | 
| GitLab.GroupProject.external_authorization_classification_label | String | What is the external authorization classification label. | 
| GitLab.GroupProject.requirements_enabled | Boolean | If the requirements are enabled. | 
| GitLab.GroupProject.requirements_access_level | String | The requirements access level. | 
| GitLab.GroupProject.security_and_compliance_enabled | Boolean | If the security and compliance is enabled. | 

#### Command Example 
`!gitlab-group-project-list limit=1 page=1 group_id=1`

#### Human Readable Output
## List of the group projects
|Id|Name|Description|Path|
|---|---|---|---|
|1|GroupProjectExample|this is a group project example|groupproject1|

### gitlab-raw-file-get
***
Get the file in a raw format.

#### Base Command

`gitlab-raw-file-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The file path. | Required | 
| ref | The branch to retrieve the file from. Default is master. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.File.ref | String | The branch the file's content was taken from. | 
| GitLab.File.path | String | The file path. | 
| GitLab.File.content | String | The file content. | 


#### Command Example

```!gitlab-raw-file-get file_path=./gitlabca ref=main```

### gitlab-branch-create
***
Creates a new branch in the repository.


#### Base Command

`gitlab-branch-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch | The name of the branch. | Required | 
| ref | Branch name, or commit SHA to create a branch from. | Required | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Branch.commit.author_email | String | The branch commit's author's email. | 
| GitLab.Branch.commit.author_name | String | The branch commit's author's name. | 
| GitLab.Branch.commit.authored_date | Date | The branch commit's authored date. | 
| GitLab.Branch.commit.committed_date | Date | The branch commit's committed date. | 
| GitLab.Branch.commit.committer_email | String | The branch commit's committer email. | 
| GitLab.Branch.commit.committer_name | String | The branch commit's committer name. | 
| GitLab.Branch.commit.id | String | The branch commit's ID. | 
| GitLab.Branch.commit.short_id | String | The branch commit's short ID. | 
| GitLab.Branch.commit.title | String | The branch commit's title. | 
| GitLab.Branch.commit.message | String | The branch commit's message. | 
| GitLab.Branch.commit.parent_ids | String | The branch commit's parent ID. | 
| GitLab.Branch.name | String | The branch's name. | 
| GitLab.Branch.merged | Boolean | If the branch had merged. | 
| GitLab.Branch.protected | Boolean | If the branch is protected. | 
| GitLab.Branch.default | Boolean | If The branch is the default branch. | 
| GitLab.Branch.developers_can_push | Boolean | If the branch's developers can push. | 
| GitLab.Branch.developers_can_merge | Boolean | If the branch's developers can merge. | 
| GitLab.Branch.can_push | Boolean | If push is possible. | 
| GitLab.Branch.web_url | String | The branch's web url. | 

#### Command example
```!gitlab-branch-create  branch=newBranch ref=main partial_response=true```
#### Context Example
```json
{
    "GitLab": {
        "Branch": {
            "can_push": true,
            "commit": {
                "author_email": "test@demistodev.com",
                "author_name": "Test Account",
                "authored_date": "2022-10-02T10:01:15.000+00:00",
                "committed_date": "2022-10-02T10:01:15.000+00:00",
                "committer_email": "test@demistodev.com",
                "committer_name": "Test Account",
                "created_at": "2022-10-02T10:01:15.000+00:00",
                "id": "eadec97163297620df38f9cbc906eff7fa04eb18",
                "message": "Update CheckRawFileCommand_main",
                "parent_ids": [
                    "c4a4c5d80f9cce20108bf5325b88ec73698f92c8"
                ],
                "short_id": "eadec971",
                "title": "Update CheckRawFileCommand_main",
                "trailers": {},
                "web_url": "https://gitlab.com/test9308/gitlabtest/-/commit/eadec97163297620df38f9cbc906eff7fa04eb18"
            },
            "default": false,
            "developers_can_merge": false,
            "developers_can_push": false,
            "merged": false,
            "name": "newBranch",
            "protected": false,
            "web_url": "https://gitlab.com/test9308/gitlabtest/-/tree/newBranch"
        }
    }
}
```

#### Human Readable Output

>### Create Branch
>|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|
>|---|---|---|---|---|---|
>| newBranch | eadec971 | Update CheckRawFileCommand_main | 2022-10-02T10:01:15.000+00:00 | false | false |


### gitlab-branch-delete
***
Deletes a branch from the repository.


#### Base Command

`gitlab-branch-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch | The name of the branch. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!gitlab-branch-delete branch=new-branch-example```

#### Human Readable Output
Branch deleted successfully

### gitlab-merged-branch-delete
***
Deletes all branches that are merged into the project's default branch.


#### Base Command

`gitlab-merged-branch-delete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!gitlab-merged-branch-delete ```
#### Context Example
```json
{
    "message": "202 Accepted"
}
```

#### Human Readable Output

>Merged branches Deleted successfully

### gitlab-branch-list
***
Get a list of repository branches from a project, sorted by name alphabetically.


#### Base Command

`gitlab-branch-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch_name | optional Url parameter, if the user provided a value a single branch will be returned. | Optional | 
| search | Return list of branches containing the search string. You can use ^term and term$ to find branches that begin and end with term respectively. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The number of results on the page. Default is 1. | Optional | 
| partial_response | Return partial API response in context data if true, otherwise returns full API response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Branch.name | String | The branch's name. | 
| GitLab.Branch.merged | Boolean | If the branch had merged. | 
| GitLab.Branch.protected | Boolean | If the branch is protected. | 
| GitLab.Branch.default | Boolean | If the branch is the default branch of the project. | 
| GitLab.Branch.developers_can_push | Boolean | If developers can push to the branch. | 
| GitLab.Branch.developers_can_merge | Boolean | If developers can merge. | 
| GitLab.Branch.can_push | Boolean | If the branch cab be pushed. | 
| GitLab.Branch.web_url | String | The branch web url. | 
| GitLab.Branch.commit.author_email | String | The branch commit's author's email. | 
| GitLab.Branch.commit.author_name | String | The branch commit's author's name. | 
| GitLab.Branch.commit.authored_date | Date | The branch commit's authored date. | 
| GitLab.Branch.commit.committed_date | Date | The branch commit's committed date. | 
| GitLab.Branch.commit.committer_email | String | The branch commit's committer's email. | 
| GitLab.Branch.commit.committer_name | String | The branch commit's committer's name. | 
| GitLab.Branch.commit.id | String | The branch commit's id. | 
| GitLab.Branch.commit.short_id | String | The branch commit's short id. | 
| GitLab.Branch.commit.title | String | The branch commit's title. | 
| GitLab.Branch.commit.message | String | The branch commit's message. | 
| GitLab.Branch.commit.parent_ids | String | The branch commit's parent ids. | 

#### Command Example
`!gitlab-branch-list limit=1 page=1 branch_name=branchName search=searchString partial_response=false`

#### Human Readable Output
## Branch details:
|Title|CommitShortId|CommitTitle|CreatedAt|IsMerge|IsProtected|
|---|---|---|---|---|---|
|branchName|c1123|CommitTitle|2000-09-15T17:22:42.246Z|true|false|

### gitlab-group-list
***
Get a list of visible groups for the authenticated user. When accessed without authentication, only public groups are returned. By default, this request returns 20 results at a time because the API results are paginated


#### Base Command

`gitlab-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| skip_groups | Skip the group IDs passed. | Optional | 
| all_available | Show all the groups you have access to (defaults to false for authenticated users, true for administrators). | Optional | 
| search | Return the list of authorized groups matching the search criteria. | Optional | 
| order_by | Order groups by name, path, id, or similarity. Possible values are: name, path, similarity. Default is name. | Optional | 
| sort | Order groups in asc or desc order. Possible values are: asc, desc. Default is asc. | Optional | 
| owned | Limit to groups explicitly owned by the current user. | Optional | 
| min_access_level | Limit to groups where current user has at least this access level. | Optional | 
| top_level_only | Limit to top level groups, excluding all subgroups. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The number of results on the page. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Group.id | Number | The group's ID. | 
| GitLab.Group.name | String | The group's name. | 
| GitLab.Group.path | String | The group's path. | 
| GitLab.Group.description | String | The group's description. | 
| GitLab.Group.visibility | String | The group's visibility. | 
| GitLab.Group.share_with_group_lock | Boolean | The group's ID. | 
| GitLab.Group.require_two_factor_authentication | Boolean | If the group require two factor authentication. | 
| GitLab.Group.two_factor_grace_period | Number | The group's two factor grace period. | 
| GitLab.Group.project_creation_level | String | The group's project's creation level. | 
| GitLab.Group.auto_devops_enabled | Unknown | If the group devops is enabled. | 
| GitLab.Group.subgroup_creation_level | String | The group's subgroup creation level. | 
| GitLab.Group.emails_disabled | Unknown | If the group's emails are disabled. | 
| GitLab.Group.mentions_disabled | Unknown | If the group mentions are disabled. | 
| GitLab.Group.lfs_enabled | Boolean | If the group lfs are enabled. | 
| GitLab.Group.default_branch_protection | Number | The group's default branch protection. | 
| GitLab.Group.avatar_url | String | The group's avatar url. | 
| GitLab.Group.web_url | String | The group's web url. | 
| GitLab.Group.request_access_enabled | Boolean | If the group's request access is enabled. | 
| GitLab.Group.full_name | String | The group's full name. | 
| GitLab.Group.full_path | String | The group's full path. | 
| GitLab.Group.file_template_project_id | Number | The group's file template project id. | 
| GitLab.Group.parent_id | Unknown | The group's parent id. | 
| GitLab.Group.created_at | Date | The group's creation time. | 

#### Command Example
`!gitlab-group-list limit=1 page=1 skip_groups=1,2 all_available=False search=string order_by=Name sort=asc owned=True min_access_level=1 top_level_only=False`

#### Human Readable Output
## List Groups:
|Id|Name|Path|Description|CreatedAt|Visibility|
|---|---|---|---|---|---|
|4|groupExample|demgroup|example description|2000-09-15T17:22:42.246Z|private|

### gitlab-group-member-list
***
Gets a list of group or project members viewable by the authenticated user.


#### Base Command

`gitlab-group-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The ID of the group owned by the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Group.id | Number | The ID of the group owned by the authenticated user. | 
| GitLab.Group.username | String | The user's username. | 
| GitLab.Group.name | String | The user's name. | 
| GitLab.Group.state | String | The group's state. | 
| GitLab.Group.avatar_url | String | The group's avatar url. | 
| GitLab.Group.web_url | String | The group's web url. | 
| GitLab.Group.created_at | Date | The group's creation time. | 
| GitLab.Group.created_by.id | Number | The group's creator's ID. | 
| GitLab.Group.created_by.username | String | The group's creator's username. | 
| GitLab.Group.created_by.name | String | The group's creator's name. | 
| GitLab.Group.created_by.state | String | The group's creator's state. | 
| GitLab.Group.created_by.avatar_url | String | The group's creator's avatar url. | 
| GitLab.Group.created_by.web_url | String | The group's creator's web url. | 
| GitLab.Group.expires_at | Date | The group's expertion time. | 
| GitLab.Group.access_level | Number | The group's access level. | 
| GitLab.Group.group_saml_identity.extern_uid | String | The group saml identity extern uid. | 
| GitLab.Group.group_saml_identity.provider | String | The group saml identity provider. | 
| GitLab.Group.group_saml_identity.saml_provider_id | Number | The group saml identity provider id. | 
| GitLab.Group.email | String | The group member email. | 

#### Command Example
`!gitlab-group-member-list group_id=1130`

#### Human Readable Output
## List Group Members:
|Id|Name|UserName|MembershipState|ExpiresAt|
|---|---|---|---|---|
|4|demo|demgroup|Active|2000-09-15T17:22:42.246Z|

### gitlab-code-search
***
Using Scope blobs. Blobs searches are performed on both filenames and contents.


#### Base Command

`gitlab-code-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | The search query. | Required | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The number of results on the page. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Code.basename | String | The base name of the code. | 
| GitLab.Code.data | String | Data of the code. | 
| GitLab.Code.path | String | The code's path. | 
| GitLab.Code.filename | String | the name of the file. | 
| GitLab.Code.id | Unknown | The code Id. | 
| GitLab.Code.ref | String | Branch name. | 
| GitLab.Code.startline | Number | The line which the search code begin. | 
| GitLab.Code.project_id | Number | The project's id. | 


#### Command Example
`!gitlab-code-search search=testSearch limit=1 page=1`

#### Human Readable Output
## Results:
|basename|data|filename|id|path|project_id
|---|---|---|---|---|---|
|README|testSearch|exampleCode|123|README.md|5531|

### gitlab-project-user-list
***
Get the users list of a project.


#### Base Command

`gitlab-project-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Get the users list of a project. | The search query. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| page | The number of results on the page. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.User.id | Number | The user's Id. | 
| GitLab.User.username | String | The user's username. | 
| GitLab.User.name | String | The user's name. | 
| GitLab.User.state | String | The user's state. | 
| GitLab.User.avatar_url | String | The user's avatar url. | 
| GitLab.User.web_url | String | The user's web url. |

#### Command Example
`!gitlab-project-user-list search=DemoName  limit=1 page=1`

#### Human Readable Output
## List Users :
|Id|UserName|Name|State|WebLink|
|---|---|---|---|---|
|123|demoExample|demo user|active|WebLink/demoExample|


## API relevant Scopes for each command
| **api** | **read_api** | **read_user** | **read_repository** | **write_repository** |
| --- | --- | --- | --- | --- |
| gitlab-group-project-list | gitlab-group-project-list | gitlab-version-get | gitlab-raw-file-get | gitlab-file-create |
| gitlab-issue-create | gitlab-raw-file-get |  | gitlab-file-get | gitlab-file-update |
| gitlab-branch-create | gitlab-project-list |  |  | gitlab-file-delete |
| gitlab-branch-delete | gitlab-version-get |  |  |  |
| gitlab-merged-branch-delete | gitlab-issue-list |  |  |  |
| gitlab-raw-file-get | gitlab-file-get |  |  |  |
| gitlab-project-list | gitlab-commit-list |  |  |  |
| gitlab-version-get | gitlab-branch-list |  |  |  |
| gitlab-issue-list | gitlab-merge-request-list |  |  |  |
| gitlab-file-get | gitlab-issue-note-list |  |  |  |
| gitlab-commit-list | gitlab-merge-request-note-list  |  |  |  |
| gitlab-branch-list | gitlab-group-member-list |  |  |  |
| gitlab-group-list | gitlab-code-search  |  |  |  |
| gitlab-issue-update | gitlab-project-user-list |  |  |  |
| gitlab-merge-request-list |  |  |  |  |
| gitlab-issue-note-list |  |  |  |  |
| gitlab-issue-note-create |  |  |  |  |
| gitlab-issue-note-delete |  |  |  |  |
| gitlab-issue-note-update |  |  |  |  |
| gitlab-merge-request-create |  |  |  |  |
| gitlab-merge-request-update |  |  |  |  |
| gitlab-merge-request-note-create |  |  |  |  |
| gitlab-merge-request-note-list |  |  |  |  |
| gitlab-merge-request-note-update |  |  |  |  |
| gitlab-merge-request-note-delete |  |  |  |  |
| gitlab-group-member-list |  |  |  |  |
| gitlab-file-create |  |  |  |  |
| gitlab-file-update |  |  |  |  |
| gitlab-file-delete |  |  |  |  |
| gitlab-code-search |  |  |  |  |
| gitlab-project-user-list |  |  |  |  |
### gitlab-pipelines-list

***
Gets the details of the pipelines.

#### Base Command

`gitlab-pipelines-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID from which to retrieve pipelines. | Optional | 
| pipeline_id | ID of specific pipeline from which to retrieve its details. | Optional | 
| ref | Reference name of the pipelines, e.g., 'master'. | Optional | 
| status | Retrieves pipelines of which status matches the given status. Possible values are: created, waiting_for_resource, preparing, pending, running, success, failed, canceled, skipped, manual, scheduled. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Pipeline.id | Number | Pipeline ID. | 
| GitLab.Pipeline.project_id | Number | Project ID that the pipeline belongs to. | 
| GitLab.Pipeline.status | String | Status of the pipeline. | 
| GitLab.Pipeline.ref | String | Reference of the pipeline. | 
| GitLab.Pipeline.sha | String | SHA of the pipeline. | 
| GitLab.Pipeline.created_at | Date | Time when the pipeline was created. | 
| GitLab.Pipeline.updated_at | Date | Time when the pipeline was last updated. | 
| GitLab.Pipeline.started_at | Date | Time when the pipeline was started. | 
| GitLab.Pipeline.finished_at | Date | Time when the pipeline was finished. | 
| GitLab.Pipeline.duration | Number | Duration of the pipeline in seconds. | 
| GitLab.Pipeline.web_url | String | Web URL of the pipeline. | 
| GitLab.Pipeline.user.name | String | Name of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.username | String | Username that triggered the pipeline. | 
| GitLab.Pipeline.user.id | Number | ID of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.state | String | State of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.avatar_url | String | Avatar URL of the user who trigerred the pipeline. | 
| GitLab.Pipeline.user.web_url | String | Web URL of the user who triggered the pipeline. | 
### gitlab-pipelines-schedules-list

***
Gets the details of the pipeline schedules.

#### Base Command

`gitlab-pipelines-schedules-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID from which to retrieve pipeline schedules. | Optional | 
| pipeline_schedule_id | ID of the specific pipeline schedule from which to retrieve its details. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.PipelineSchedule.id | Number | Pipeline schedule ID. | 
| GitLab.PipelineSchedule.description | String | Pipeline schedule description. | 
| GitLab.PipelineSchedule.ref | String | Pipeline schedule reference. | 
| GitLab.PipelineSchedule.next_run_at | Date | Pipeline schedule next run scheduled time. | 
| GitLab.PipelineSchedule.active | Boolean | Whether pipeline schedule is active. | 
| GitLab.PipelineSchedule.created_at | Date | When pipeline schedule was created. | 
| GitLab.PipelineSchedule.updated_at | Date | When the pipeline schedule was last updated. | 
| GitLab.PipelineSchedule.last_pipeline.id | Number | ID of the last pipeline that was run by the scheduled pipeline. Relevant only when the pipeline schedule ID is given. | 
| GitLab.PipelineSchedule.last_pipeline.sha | String | SHA of the last pipeline that was run by the scheduled pipeline. Relevant only when the pipeline schedule ID is given. | 
| GitLab.PipelineSchedule.last_pipeline.ref | String | Reference of the last pipeline that was run by the scheduled pipeline. Relevant only when the pipeline schedule ID is given. | 
| GitLab.PipelineSchedule.last_pipeline.status | String | Status of the last pipeline that was run by the scheduled pipeline. Relevant only when the pipeline schedule ID is given. | 
### gitlab-jobs-list

***
Gets job details.

#### Base Command

`gitlab-jobs-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID from which to retrieve jobs details. | Optional | 
| pipeline_id | ID of the pipeline from which to retrieve its jobs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Job.status | String | The status of the job. | 
| GitLab.Job.created_at | Date | Time the job was created. | 
| GitLab.Job.started_at | Date | Time the job was started. | 
| GitLab.Job.finished_at | Date | Time the job was finished. | 
| GitLab.Job.duration | Number | Duration of the job in seconds. | 
| GitLab.Job.id | Number | ID of the job. | 
| GitLab.Job.name | String | Name of the job. | 
| GitLab.Job.pipeline.id | Number | Pipeline the job belongs to. | 
| GitLab.Job.pipeline.project_id | Number | Project ID the job belongs to. | 
| GitLab.Job.pipeline.ref | String | Reference of the pipeline the job belongs to. | 
| GitLab.Job.pipeline.sha | String | SHA of the pipeline the job belongs to. | 
| GitLab.Job.pipeline.status | String | Status of the pipeline the job belongs to. | 
| GitLab.Job.ref | String | Reference name of the job. | 
| GitLab.Job.stage | String | Stage of the job. | 
| GitLab.Job.web_url | String | Web URL of the job. | 
### gitlab-artifact-get

***
Gets an artifact from a given artifact path, corresponding to a given job ID.

#### Base Command

`gitlab-artifact-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID from which to retrieve an artifact. | Optional | 
| job_id | ID of a specific job from which to retrieve its artifact. | Required | 
| artifact_path_suffix | Suffix to the path of an artifact from which to retrieve its data. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Artifact.job_id | String | Job ID from which the artifact was taken. | 
| GitLab.Artifact.artifact_path_suffix | String | Suffix of the given artifact path. | 
| GitLab.Artifact.artifact_data | String | Data of the artifact requested. | 

### gitlab-trigger-pipeline

***
Triggers a GitLab pipeline on a selected project and branch.

#### Base Command

`gitlab-trigger-pipeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID on which to run the pipeline. | Optional | 
| ref_branch | The branch on which to run the pipeline. Default is 'master'. | Optional | 
| trigger_variables | JSON containing the pipeline variables. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Pipeline.id | Number | Pipeline ID. | 
| GitLab.Pipeline.project_id | Number | Project ID that the pipeline belongs to. | 
| GitLab.Pipeline.status | String | Status of the pipeline. | 
| GitLab.Pipeline.ref | String | Reference of the pipeline. | 
| GitLab.Pipeline.sha | String | SHA of the pipeline. | 
| GitLab.Pipeline.created_at | Date | Time when the pipeline was created. | 
| GitLab.Pipeline.updated_at | Date | Time when the pipeline was last updated. | 
| GitLab.Pipeline.started_at | Date | Time when the pipeline was started. | 
| GitLab.Pipeline.finished_at | Date | Time when the pipeline was finished. | 
| GitLab.Pipeline.duration | Number | Duration of the pipeline in seconds. | 
| GitLab.Pipeline.web_url | String | Web URL of the pipeline. | 
| GitLab.Pipeline.user.name | String | Name of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.username | String | Username that triggered the pipeline. | 
| GitLab.Pipeline.user.id | Number | ID of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.state | String | State of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.avatar_url | String | Avatar URL of the user who trigerred the pipeline. | 
| GitLab.Pipeline.user.web_url | String | Web URL of the user who triggered the pipeline. | 

### gitlab-cancel-pipeline

***
Cancels a GitLab pipeline.

#### Base Command

`gitlab-cancel-pipeline`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Project ID on which to run the pipeline. | Optional | 
| pipeline_id | The pipline ID to cancel. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Pipeline.id | Number | Pipeline ID. | 
| GitLab.Pipeline.project_id | Number | Project ID that the pipeline belongs to. | 
| GitLab.Pipeline.status | String | Status of the pipeline. | 
| GitLab.Pipeline.ref | String | Reference of the pipeline. | 
| GitLab.Pipeline.sha | String | SHA of the pipeline. | 
| GitLab.Pipeline.created_at | Date | Time when the pipeline was created. | 
| GitLab.Pipeline.updated_at | Date | Time when the pipeline was last updated. | 
| GitLab.Pipeline.started_at | Date | Time when the pipeline was started. | 
| GitLab.Pipeline.finished_at | Date | Time when the pipeline was finished. | 
| GitLab.Pipeline.duration | Number | Duration of the pipeline in seconds. | 
| GitLab.Pipeline.web_url | String | Web URL of the pipeline. | 
| GitLab.Pipeline.user.name | String | Name of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.username | String | Username that triggered the pipeline. | 
| GitLab.Pipeline.user.id | Number | ID of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.state | String | State of the user who triggered the pipeline. | 
| GitLab.Pipeline.user.avatar_url | String | Avatar URL of the user who trigerred the pipeline. | 
| GitLab.Pipeline.user.web_url | String | Web URL of the user who triggered the pipeline. | 
