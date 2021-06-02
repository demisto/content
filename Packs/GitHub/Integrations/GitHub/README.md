Integration to GitHub API.

## Configure GitHub on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GitHub.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Required** |
   | --- | --- |
   | Fetch incidents | False |
   | API Token | False |
   | Credentials | False |
   | Username of the repository owner, for example: github.com/repos/{_owner_}/{repo}/issues | False |
   | The name of the requested repository | False |
   | First fetch interval (in days) | False |
   | Use system proxy settings | False |
   | Trust any certificate (not secure) | False |
   | Incident type | False |
   | GitHub app integration ID | False |
   | GitHub app installation ID | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully
execute a command, a DBot message appears in the War Room with the command details.

### GitHub-create-issue

***
Creates an issue in GitHub.

#### Base Command

`GitHub-create-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the issue. | Required | 
| body | The contents of the issue. | Optional | 
| labels | Labels to associate with this issue. | Optional | 
| assignees | Logins for Users to assign to this issue. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Issue.ID | Number | The ID of the created issue. | 
| GitHub.Issue.Repository | String | The repository of the created issue. | 
| GitHub.Issue.Title | String | The title of the created issue. | 
| GitHub.Issue.Body | Unknown | The body of the created issue. | 
| GitHub.Issue.State | String | The state of the created issue. | 
| GitHub.Issue.Labels | String | Labels applied to the issue. | 
| GitHub.Issue.Assignees | String | Users assigned to this issue. | 
| GitHub.Issue.Created_at | Date | Date when the issue was created. | 
| GitHub.Issue.Updated_at | Date | Date when the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | Date when the issue was closed. | 
| GitHub.Issue.Closed_by | String | User who closed the issue. | 
| GitHub.Issue.Organization | String | The repository owner. | 

#### Command Example

```!GitHub-create-issue title=“newbug” body=“found a new bug” lable=bug,new```

#### Human Readable Output
## Issues:
|ID|Repository|Organization|Title|State|Body|Created_at|Updated_at|
|---|---|---|---|---|---|---|---|
|138|Git-Integration|demisto|“newbug”|open|“found|2019-06-17T15:14:10Z|2019-06-17T15:14:10Z|

### GitHub-close-issue

***
Closes an existing issue.

#### Base Command

`GitHub-close-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ID | The number of the issue to close. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Issue.ID | Number | The ID of the closed issue. | 
| GitHub.Issue.Repository | String | The repository of the closed issue. | 
| GitHub.Issue.Title | String | The title of the closed issue | 
| GitHub.Issue.Body | Unknown | The body of the closed issue. | 
| GitHub.Issue.State | String | The state of the closed issue. | 
| GitHub.Issue.Labels | String | Labels applied to the issue. | 
| GitHub.Issue.Assignees | String | Users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | Date when the issue was created. | 
| GitHub.Issue.Updated_at | Date | Date when the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | Date when the issue was closed. | 
| GitHub.Issue.Closed_by | String | User who closed the issue. | 
| GitHub.Issue.Organization | String | The repository owner. | 

#### Command Example

```!GitHub-close-issue ID=136```

#### Human Readable Output
## Issues:
|ID|Repository|Organization|Title|State|Created_at|Updated_at|Closed_at|Closed_by|Labels|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|136|Git-Integration|demisto|new|closed|2019-06-17T14:48:15Z|2019-06-17T15:14:12Z|2019-06-17T15:14:12Z|roysagi|bug, else, new|

### GitHub-update-issue

***
Updates the parameters of a specified issue.

#### Base Command

`GitHub-update-issue`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ID | The number of the issue to update. | Required | 
| title | The title of the issue. | Optional | 
| body | The contents of the issue. | Optional | 
| state | State of the issue. Either open or closed. | Optional | 
| labels | Labels to apply to this issue. Pass one or more Labels to replace the set of Labels on this Issue. Send an empty array ([]) to clear all Labels from the Issue. . | Optional | 
| assignees | Logins for Users to assign to this issue. Pass one or more user logins to replace the set of assignees on this Issue. Send an empty array ([]) to clear all assignees from the Issue. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Issue.ID | Number | The ID of the updated issue. | 
| GitHub.Issue.Repository | String | The repository of the updated issue. | 
| GitHub.Issue.Title | String | The title of the updated issue. | 
| GitHub.Issue.Body | Unknown | The body of the updated issue. | 
| GitHub.Issue.State | String | The state of the updated issue. | 
| GitHub.Issue.Labels | String | Labels applied to the issue. | 
| GitHub.Issue.Assignees | String | Users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | Date when the issue was created. | 
| GitHub.Issue.Updated_at | Date | Date when the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | Date when the issue was closed. | 
| GitHub.Issue.Closed_by | String | User who closed the issue. | 
| GitHub.Issue.Organization | String | The repository owner. | 

#### Command Example

```!GitHub-update-issue ID=137 title=“new_title” body=“new info” state=open```

#### Human Readable Output
## Issues:
|ID|Repository|Organization|Title|State|Body|Created_at|Updated_at|
|--- |--- |--- |--- |--- |--- |--- |--- |
|137|Git-Integration|demisto|“new_title”|open|“new|2019-06-17T15:09:50Z|2019-06-17T15:14:13Z|


### GitHub-list-all-issues

***
Lists all issues that the user has access to view.

#### Base Command

`GitHub-list-all-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | The state of the issues to return. Can be 'open', 'closed' or 'all'. Default is 'open'. Possible values are: open, closed, all. Default is open. | Required | 
| limit | The number of issues to return. Default is 50. Maximum is 200. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Issue.ID | Number | The ID of the issue. | 
| GitHub.Issue.Repository | String | The repository of the issue. | 
| GitHub.Issue.Title | String | The title of the issue. | 
| GitHub.Issue.Body | Unknown | The body of the issue. | 
| GitHub.Issue.State | String | The state of the issue. | 
| GitHub.Issue.Labels | String | Labels applied to the issue. | 
| GitHub.Issue.Assignees | String | Users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | Date when the issue was created. | 
| GitHub.Issue.Updated_at | Date | Date when the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | Date when the issue was closed. | 
| GitHub.Issue.Closed_by | String | User who closed the issue. | 
| GitHub.Issue.Organization | String | The repository owner. | 

#### Command Example

```!GitHub-list-all-issues state=all limit=2```

#### Human Readable Output
## Issues:
|ID|Repository|Organization|Title|State|Body|Created_at|Updated_at|Closed_at|Labels|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|109|Git-Integration|demisto|"new issue"|closed|"new information"|2019-06-04T11:52:11Z|2019-06-04T11:52:13Z|2019-06-04T11:52:13Z|newbug|
|110|Git-Integration|demisto|"new issue"|closed|"new information"|2019-06-04T11:53:19Z|2019-06-04T11:53:22Z|2019-06-04T11:53:22Z|newbug|


### GitHub-search-code
***
Searches for code in repositories that match a given query.


#### Base Command

`GitHub-search-code`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query line for the search. For more information see the GitHub documentation at https://docs.github.com/en/github/searching-for-information-on-github/searching-code. | Required | 
| page_number | The page number. | Optional | 
| page_size | The size of the requested page. Maximum is 100. | Optional | 
| limit | The number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.CodeSearchResults.name | String | The file name where the code found. | 
| GitHub.CodeSearchResults.path | String | The full file path where the code found. | 
| GitHub.CodeSearchResults.html_url | String | The url to the file. | 
| GitHub.CodeSearchResults.repository.full_name | String | The repository name. | 
| GitHub.CodeSearchResults.repository.html_url | String | The url to the repository. | 
| GitHub.CodeSearchResults.repository.description | String | Repository description. | 
| GitHub.CodeSearchResults.repository.private | Boolean | True if repository is private. and false if public. | 
| GitHub.CodeSearchResults.repository.id | String | The ID of the repository. | 
| GitHub.CodeSearchResults.repository.releases_url | String | The url to the releases of the repository. | 
| GitHub.CodeSearchResults.repository.branches_url | String | The url to the branches of the repository. | 
| GitHub.CodeSearchResults.repository.commits_url | String | The url to the commits of the repository. | 


#### Command Example
```!GitHub-search-code query="create_artifacts+repo:demisto/demisto-sdk" page_size="2" limit="5"```

#### Context Example
```json
{
    "GitHub": {
        "CodeSearchResults": [
            {
                "html_url": "https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/.pre-commit-config.yaml",
                "name": ".pre-commit-config.yaml",
                "path": ".pre-commit-config.yaml",
                "repository": {
                    "branches_url": "https://api.github.com/repos/demisto/demisto-sdk/branches{/branch}",
                    "commits_url": "https://api.github.com/repos/demisto/demisto-sdk/commits{/sha}",
                    "desrciption": "Demisto SDK - Create Demisto Content with ease and efficiency",
                    "full_name": "demisto/demisto-sdk",
                    "html_url": "https://github.com/demisto/demisto-sdk",
                    "id": 219291269,
                    "private": false,
                    "releases_url": "https://api.github.com/repos/demisto/demisto-sdk/releases{/id}"
                }
            },
            {
                "html_url": "https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/tests/integration_tests/content_create_artifacts_integration_test.py",
                "name": "content_create_artifacts_integration_test.py",
                "path": "demisto_sdk/tests/integration_tests/content_create_artifacts_integration_test.py",
                "repository": {
                    "branches_url": "https://api.github.com/repos/demisto/demisto-sdk/branches{/branch}",
                    "commits_url": "https://api.github.com/repos/demisto/demisto-sdk/commits{/sha}",
                    "desrciption": "Demisto SDK - Create Demisto Content with ease and efficiency",
                    "full_name": "demisto/demisto-sdk",
                    "html_url": "https://github.com/demisto/demisto-sdk",
                    "id": 219291269,
                    "private": false,
                    "releases_url": "https://api.github.com/repos/demisto/demisto-sdk/releases{/id}"
                }
            },
            {
                "html_url": "https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/commands/create_artifacts/tests/content_artifacts_creator_test.py",
                "name": "content_artifacts_creator_test.py",
                "path": "demisto_sdk/commands/create_artifacts/tests/content_artifacts_creator_test.py",
                "repository": {
                    "branches_url": "https://api.github.com/repos/demisto/demisto-sdk/branches{/branch}",
                    "commits_url": "https://api.github.com/repos/demisto/demisto-sdk/commits{/sha}",
                    "desrciption": "Demisto SDK - Create Demisto Content with ease and efficiency",
                    "full_name": "demisto/demisto-sdk",
                    "html_url": "https://github.com/demisto/demisto-sdk",
                    "id": 219291269,
                    "private": false,
                    "releases_url": "https://api.github.com/repos/demisto/demisto-sdk/releases{/id}"
                }
            },
            {
                "html_url": "https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/commands/common/content/tests/objects/pack_objects/pack_metadata/pack_metadata_test.py",
                "name": "pack_metadata_test.py",
                "path": "demisto_sdk/commands/common/content/tests/objects/pack_objects/pack_metadata/pack_metadata_test.py",
                "repository": {
                    "branches_url": "https://api.github.com/repos/demisto/demisto-sdk/branches{/branch}",
                    "commits_url": "https://api.github.com/repos/demisto/demisto-sdk/commits{/sha}",
                    "desrciption": "Demisto SDK - Create Demisto Content with ease and efficiency",
                    "full_name": "demisto/demisto-sdk",
                    "html_url": "https://github.com/demisto/demisto-sdk",
                    "id": 219291269,
                    "private": false,
                    "releases_url": "https://api.github.com/repos/demisto/demisto-sdk/releases{/id}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Returned 5 out of 6 total results.
>|Name|Path|Repository Name|Repository Description|Is Repository Private|
>|---|---|---|---|---|
>| [.pre-commit-config.yaml](https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/.pre-commit-config.yaml) | .pre-commit-config.yaml | demisto/demisto-sdk | Demisto SDK - Create Demisto Content with ease and efficiency | false |
>| [content_create_artifacts_integration_test.py](https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/tests/integration_tests/content_create_artifacts_integration_test.py) | demisto_sdk/tests/integration_tests/content_create_artifacts_integration_test.py | demisto/demisto-sdk | Demisto SDK - Create Demisto Content with ease and efficiency | false |
>| [content_artifacts_creator_test.py](https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/commands/create_artifacts/tests/content_artifacts_creator_test.py) | demisto_sdk/commands/create_artifacts/tests/content_artifacts_creator_test.py | demisto/demisto-sdk | Demisto SDK - Create Demisto Content with ease and efficiency | false |
>| [pack_metadata_test.py](https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/commands/common/content/tests/objects/pack_objects/pack_metadata/pack_metadata_test.py) | demisto_sdk/commands/common/content/tests/objects/pack_objects/pack_metadata/pack_metadata_test.py | demisto/demisto-sdk | Demisto SDK - Create Demisto Content with ease and efficiency | false |
>| [content_artifacts_creator_test.py](https://github.com/demisto/demisto-sdk/blob/bfd4c375f9c61d4fdd4974ecf244a4bede13b8ed/demisto_sdk/commands/create_artifacts/tests/content_artifacts_creator_test.py) | demisto_sdk/commands/create_artifacts/tests/content_artifacts_creator_test.py | demisto/demisto-sdk | Demisto SDK - Create Demisto Content with ease and efficiency | false |


### GitHub-search-issues

***
Searches for and returns issues that match a given query.

#### Base Command

`GitHub-search-issues`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query line for the search. For more information see the GitHub documentation at https://help.github.com/en/articles/searching-issues-and-pull-requests. | Required | 
| limit | The number of issues to return. Default is 50. Maximum is 100. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Issue.ID | Number | The ID of the issue. | 
| GitHub.Issue.Repository | String | The repository of the issue. | 
| GitHub.Issue.Title | String | The title of the issue. | 
| GitHub.Issue.Body | Unknown | The body of the issue. | 
| GitHub.Issue.State | String | The state of the issue. | 
| GitHub.Issue.Labels | String | Labels applied to the issue. | 
| GitHub.Issue.Assignees | String | Users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | Date when the issue was created. | 
| GitHub.Issue.Updated_at | Date | Date when the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | Date when the issue was closed. | 
| GitHub.Issue.Closed_by | String | User who closed the issue. | 
| GitHub.Issue.Organization | String | The repository owner. | 

#### Command Example

```!GitHub-search-issues query=“label:bug state:open” limit=1```

#### Human Readable Output
## Issues:
|ID|Repository|Organization|Title|State|Body|Created_at|Updated_at|Closed_at|Assignees|Labels|
|--- |--- |--- |--- |--- |--- |--- |--- |--- | ---|--- |
|109|Git-Integration|demisto|"new issue"|open|"new information"|2019-06-04T11:52:11Z|2019-06-04T11:52:13Z|2019-06-04T11:52:13Z|teizenman|newbug|

### GitHub-get-download-count

***
Returns the total number of downloads for all releases for the specified repository.

#### Base Command

`GitHub-get-download-count`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Release.ID | Number | ID of the release. | 
| GitHub.Release.Download_count | Number | Download count for the release. | 
| GitHub.Release.Name | String | Name of the release. | 
| GitHub.Release.Body | String | Body of the release. | 
| GitHub.Release.Created_at | Date | Date when the release was created. | 
| GitHub.Release.Published_at | Date | Date when the release was published. | 

#### Command Example

```!GitHub-get-download-count```

#### Human Readable Output
## Releases:
|ID|Name|Download_count|Body|Created_at|Published_at|
|--- |--- |--- |--- |--- |--- |
|17519182|anotherone|5|this is another release|2019-05-22T15:00:51Z|2019-05-22T15:06:48Z|
|17519007|test|1|this is a test|2019-05-22T15:00:51Z|2019-05-22T15:02:16Z|


### GitHub-get-stale-prs

***
Get inactive pull requests

#### Base Command

`GitHub-get-stale-prs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stale_time | Time of inactivity after which a PR is considered stale. Default is 3 days. | Required | 
| label | The label used to identify PRs of interest. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.URL | String | The html URL of the PR | 
| GitHub.PR.Number | Number | The GitHub pull request number | 
| GitHub.PR.RequestedReviewer | Unknown | A list of the PR's requested reviewers | 

#### Command Example

``!GitHub-get-stale-prs stale_time="2 days"``

#### Human Readable Output
## Stale PRs:
|Number|URL|
|--- |--- |
|18|https://github.com/example-user1/content/pull/18|
|16|https://github.com/example-user1/content/pull/16|
|15|https://github.com/example-user1/content/pull/15|
|14|https://github.com/example-user1/content/pull/14|

### GitHub-get-branch

***
Get a branch

#### Base Command

`GitHub-get-branch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch_name | The name of the branch to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Branch.Name | String | The name of the branch | 
| GitHub.Branch.CommitSHA | String | The SHA of the commit the branch references | 
| GitHub.Branch.CommitNodeID | String | The Node ID of the commit the branch references | 
| GitHub.Branch.CommitAuthorID | Number | The GitHub ID number of the author of the commit the branch references | 
| GitHub.Branch.CommitAuthorLogin | String | The GitHub login of the author of the commit the branch references | 
| GitHub.Branch.CommitParentSHA | String | The SHAs of parent commits | 
| GitHub.Branch.Protected | Boolean | Whether the branch is a protected one or not | 

#### Command Example

```!GitHub-get-pull-request pull_number=1```

#### Human Readable Output
## Branch "master"
|CommitAuthorID|CommitAuthorLogin|CommitNodeID|CommitParentSHA|CommitSHA|Name|Protected|
|--- |--- |--- |--- |--- |--- |--- |
|55035720|example-user1|MDY6Q29tbWl0MjA3NzQ0Njg1OjhhNjdhMDc4MTM5NDk4ZjNlOGUxYmQyZTI2ZmZjNWEyZmVhMWI5MTg=|d6bafef5a0021a6d9ab0a22e11bd0afd5801d936|8a67a078139498f3e8e1bd2e26ffc5a2fea1b918|master|false|


### GitHub-create-branch

***
Create a new branch

#### Base Command

`GitHub-create-branch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch_name | The name for the new branch. | Required | 
| commit_sha | The SHA hash of the commit to reference. Try executing the 'GitHub-get-branch' command to find a commit SHA hash to reference. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example

```GitHub-create-branch branch_name=new-branch-example commit_sha=8a67a078139498f3e8e1bd2e26ffc5a2fea1b918```

#### Human Readable Output
Branch "new-branch-example" Created Successfully.

### GitHub-get-team-membership

***
Retrieve a user's membership status with a team

#### Base Command

`GitHub-get-team-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | The ID number by which the team is identified. Try executing the 'GitHub-list-teams' command to find team IDs to reference. | Required | 
| user_name | The login of the user whose membership you wish to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Team.Member.Role | String | The user's role on a team | 
| GitHub.Team.Member.State | String | The user's state for a team | 
| GitHub.Team.ID | Number | The ID number of the team | 
| GitHub.Team.Member.Login | String | The login of the team member | 

#### Command Example

```!GitHub-get-team-membership team_id=3043448 user_name=example-user2```

#### Human Readable Output
## Team Membership of example-user2
|ID|Role|State|Login|
|--- |--- |--- |--- |
|3043448|member|active|example-user2|


### GitHub-request-review

***
Request reviews from GitHub users for a given Pull Request

#### Base Command

`GitHub-request-review`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The number of the Pull Request for which you wish to request review. | Required | 
| reviewers | A CSV list of GitHub users to request review from for a Pull Request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.Number | Number | The number of the Pull Request | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review | 
| GitHub.PR.RequestedReviewer.NodeID | String | The node ID of the user requested for review | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site admin or not | 

#### Command Example

```!GitHub-request-review pull_number=1 reviewers=example-user1```

#### Human Readable Output
## Requested Reviewers for #1
|ID|Login|NodeID|SiteAdmin|Type|
|--- |--- |--- |--- |--- |
|30797606|example-user3|MDQ6VXNlcjMwNzk3NjA2|false|User|
|55035720|example-user1|MDQ6VXNlcjU1MDM1NzIw|false|User|

### GitHub-create-comment

***
Create a comment for a given issue

#### Base Command

`GitHub-create-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_number | The number of the issue to comment on. | Required | 
| body | The contents of the comment. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Comment.IssueNumber | Number | The number of the issue to which the comment belongs | 
| GitHub.Comment.ID | Number | The ID of the comment | 
| GitHub.Comment.NodeID | String | The node ID of the comment | 
| GitHub.Comment.Body | String | The body content of the comment | 
| GitHub.Comment.User.Login | String | The login of the user who commented | 
| GitHub.Comment.User.ID | Number | The ID of the user who commented | 
| GitHub.Comment.User.NodeID | String | The node ID of the user who commented | 
| GitHub.Comment.User.Type | String | The type of the user who commented | 
| GitHub.Comment.User.SiteAdmin | Boolean | Whether the user who commented is a site admin or not | 

#### Command Example

```!GitHub-create-comment issue_number=1 body="Look this comment was made using the GitHub integration"```

#### Human Readable Output
## Created Comment
|Body|ID|IssueNumber|NodeID|User|
|--- |--- |--- |--- |--- |
|Look this comment was made using the GitHub integration|532700206|1|MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==|Login: example-user1 ID: 55035720 NodeID: MDQ6VXNlcjU1MDM1NzIw Type: User SiteAdmin: false|


### GitHub-list-issue-comments

***
List comments on an issue

#### Base Command

`GitHub-list-issue-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_number | The number of the issue to list comments for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Comment.IssueNumber | Number | The number of the issue to which the comment belongs | 
| GitHub.Comment.ID | Number | The ID of the comment | 
| GitHub.Comment.NodeID | String | The node ID of the comment | 
| GitHub.Comment.Body | String | The body content of the comment | 
| GitHub.Comment.User.Login | String | The login of the user who commented | 
| GitHub.Comment.User.ID | Number | The ID of the user who commented | 
| GitHub.Comment.User.NodeID | String | The node ID of the user who commented | 
| GitHub.Comment.User.Type | String | The type of the user who commented | 
| GitHub.Comment.User.SiteAdmin | Boolean | Whether the user who commented is a site admin or not | 

#### Command Example

```!GitHub-list-issue-comments issue_number=1```

#### Human Readable Output
## Comments for Issue #1
|Body|ID|IssueNumber|NodeID|User|
|--- |--- |--- |--- |--- |
|Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content wizard @example-user3 will very shortly look over your proposed changes.|530276333|1|MDEyOklzc3VlQ29tbWVudDUzMDI3NjMzMw==|Login: example-user1 ID: 55035720 NodeID: MDQ6VXNlcjU1MDM1NzIw Type: User SiteAdmin: false|
|what about my pr eh|530313678|1|MDEyOklzc3VlQ29tbWVudDUzMDMxMzY3OA==|Login: example-user4 ID: 46294017 NodeID: MDQ6VXNlcjQ2Mjk0MDE3 Type: User SiteAdmin: false|
|@example-user4 can we close?|530774162|1|MDEyOklzc3VlQ29tbWVudDUzMDc3NDE2Mg==|Login: example-user3 ID: 30797606 NodeID: MDQ6VXNlcjMwNzk3NjA2 Type: User SiteAdmin: false|
|Look this comment was made using the GitHub integration|532700206|1|MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==|Login: example-user1 ID: 55035720 NodeID: MDQ6VXNlcjU1MDM1NzIw Type: User SiteAdmin: false|


### GitHub-list-pr-files

***
Lists the pull request files.

#### Base Command

`GitHub-list-pr-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The number of the pull request. | Required | 
| organization | The name of the organization. | Optional | 
| repository | The repository of the pull request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.Number | Number | The number of the pull request | 
| GitHub.PR.File.SHA | String | The SHA hash of the last commit involving the file. | 
| GitHub.PR.File.Name | String | The name of the file. | 
| GitHub.PR.File.Status | String | The status of the file. | 
| GitHub.PR.File.Additions | Number | The number of additions to the file. | 
| GitHub.PR.File.Deletions | Number | The number of deletions in the file. | 
| GitHub.PR.File.Changes | Number | The number of changes made in the file. | 

#### Command Example

```!GitHub-list-pr-files pull_number=1```

#### Human Readable Output
## Pull Request Files for #1
|Additions|Changes|Deletions|Name|SHA|Status|
|--- |--- |--- |--- |--- |--- |
|4|4|0|TEST.md|4e7fd23b44ef46ebd04a9812dda55cecb487fcbe|added|


### GitHub-list-pr-reviews

***
List reviews on a pull request

#### Base Command

`GitHub-list-pr-reviews`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The number of the pull request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.Number | Number | The number of the pull request | 
| GitHub.PR.Review.ID | Number | The ID of the review | 
| GitHub.PR.Review.NodeID | String | The node ID of the review | 
| GitHub.PR.Review.Body | String | The content of the review | 
| GitHub.PR.Review.CommitID | String | The ID of the commit for which the review is applicable | 
| GitHub.PR.Review.State | String | The state of the review | 
| GitHub.PR.Review.User.Login | String | The reviewer's user login | 
| GitHub.PR.Review.User.ID | Number | The reviewer's user ID | 
| GitHub.PR.Review.User.NodeID | String | The reviewer's user node ID | 
| GitHub.PR.Review.User.Type | String | The reviewer user type | 
| GitHub.PR.Review.User.SiteAdmin | Boolean | Whether the reviewer is a site admin or not | 

#### Command Example

```!GitHub-list-pr-reviews pull_number=1```

#### Human Readable Output
## Pull Request Reviews for #1
|Body|CommitID|ID|NodeID|State|User|
|--- |--- |--- |--- |--- |--- |
|review comment|b6cf0431e2aea2b345ea1d66d18aa72be63936a9|287327154|MDE3OlB1bGxSZXF1ZXN0UmV2aWV3Mjg3MzI3MTU0|COMMENTED|Login: example-user2 ID: 31018228 NodeID: MDQ6VXNlcjMxMDE4MjI4 Type: User SiteAdmin: false|


### GitHub-get-commit

***
Get a commit

#### Base Command

`GitHub-get-commit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| commit_sha | The SHA hash of the commit. Try executing the 'GitHub-get-branch' command to find a commit SHA hash to reference. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Commit.SHA | String | The SHA hash of the commit | 
| GitHub.Commit.Author.Date | String | The commit author date | 
| GitHub.Commit.Author.Name | String | The name of the author | 
| GitHub.Commit.Author.Email | String | The email of the author | 
| GitHub.Commit.Committer.Date | String | The date the commiter committed | 
| GitHub.Commit.Committer.Name | String | The name of the committer | 
| GitHub.Commit.Committer.Email | String | The email of the committer | 
| GitHub.Commit.Message | String | The message associated with the commit | 
| GitHub.Commit.Parent | Unknown | List of parent SHA hashes | 
| GitHub.Commit.TreeSHA | String | The SHA hash of the commit's tree | 
| GitHub.Commit.Verification.Verified | Boolean | Whether the commit was verified or not | 
| GitHub.Commit.Verification.Reason | String | The reason why the commit was or was not verified | 
| GitHub.Commit.Verification.Signature | Unknown | The commit verification signature | 
| GitHub.Commit.Verification.Payload | Unknown | The commit verification payload | 

#### Command Example

```!GitHub-get-commit commit_sha=8a67a078139498f3e8e1bd2e26ffc5a2fea1b918```

#### Human Readable Output
## Commit *8a67a07813*
|Author|Committer|Message|Parent|SHA|TreeSHA|Verification|
|--- |--- |--- |--- |--- |--- |--- |
|Date: 2019-09-16T15:42:43Z Name: example-user1 Email: 55035720example.user1@users.noreply.github.com|Date: 2019-09-16T15:42:43Z Name: GitHub Email: noreply@github.com|Update config.yml|{'SHA': 'd6bafef5a0021a6d9ab0a22e11bd0afd5801d936'}|8a67a078139498f3e8e1bd2e26ffc5a2fea1b918|42fdb6c89538099a141e94fabe4bbc58098f4d90|Verified: true Reason: valid Signature: -----BEGIN PGP SIGNATURE-----  wsBcBAABCAAQBQJ****************************sIKrPT2jUSWyzfu5wnu oWz7+2KMdaglV****************************M08HXTm a9eO/ahlodARkgH/bWjulomeO+jDEgbZenlPUrBnX136QzPPqgl4uvxfquAOj1/a a89YtPAFh2X1+1q7pl5dVtZfYpo6mYJoY9dwVpDRbLoVHJRa1wnqEv4kxRHrrRL9 mGWSMHqK8I6j9zXi4niod8pQpl0k4O/2SlNh81RyeILEYb587Zs1XGuIYQEDrcAf u+FURxEHSuT4yaZ+oBwhhcIsmsWQMGkfABbwo1Fi2BMtEgZpzd/TScNg1KeSrVI= =dWrz -----END PGP SIGNATURE-----  Payload: tree 42fdb6c89538099a141e94fabe4bbc58098f4d90 parent d6bafef5a0021a6d9ab0a22e11bd0afd5801d936 author example-user1 <55035720example.user1@users.noreply.github.com> 1568648563 +0300 committer GitHub <noreply@github.com> 1568648563 +0300  Update config.yml|


### GitHub-add-label

***
Add labels to an issue

#### Base Command

`GitHub-add-label`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_number | The number of the issue to add labels to. | Required | 
| labels | A CSV list of labels to add to an issue. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example

```!GitHub-add-label issue_number=1 labels=Content```

#### Human Readable Output
Label "Content" Successfully Added to Issue #1

### GitHub-get-pull-request

***
Get a pull request

#### Base Command

`GitHub-get-pull-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The number of the pull request to retrieve. | Required | 
| organization | The name of the organization. | Optional | 
| repository | The repository of the pull request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.ID | Number | The ID number of the pull request | 
| GitHub.PR.NodeID | String | The node ID of the pull request | 
| GitHub.PR.Number | Number | The issue number of the pull request | 
| GitHub.PR.State | String | The state of the pull request | 
| GitHub.PR.Locked | Boolean | Whether the pull request is locked or not | 
| GitHub.PR.Title | String | The title of the pull request | 
| GitHub.PR.User.Login | String | The login of the user who opened the pull request | 
| GitHub.PR.User.ID | Number | The ID of the user who opened the pull request | 
| GitHub.PR.User.NodeID | String | The node ID of the user who opened the pull request | 
| GitHub.PR.User.Type | String | The type of the user who opened the pull request | 
| GitHub.PR.User.SiteAdmin | Boolean | Whether the user who opened the pull request is a site admin or not | 
| GitHub.PR.Body | String | The body content of the pull request | 
| GitHub.PR.Label.ID | Number | The ID of the label | 
| GitHub.PR.Label.NodeID | String | The node ID of the label | 
| GitHub.PR.Label.Name | String | The name of the label | 
| GitHub.PR.Label.Description | String | The description of the label | 
| GitHub.PR.Label.Color | String | The hex color value of the label | 
| GitHub.PR.Label.Default | Boolean | Whether the label is a default or not | 
| GitHub.PR.Milestone.ID | Number | The ID of the milestone | 
| GitHub.PR.Milestone.NodeID | String | The node ID of the milestone | 
| GitHub.PR.Milestone.Number | Number | The number of the milestone | 
| GitHub.PR.Milestone.State | String | The state of the milestone | 
| GitHub.PR.Milestone.Title | String | The title of the milestone | 
| GitHub.PR.Milestone.Description | String | The description of the milestone | 
| GitHub.PR.Milestone.Creator.Login | String | The login of the milestone creator | 
| GitHub.PR.Milestone.Creator.ID | Number | The ID the milestone creator | 
| GitHub.PR.Milestone.Creator.NodeID | String | The node ID of the milestone creator | 
| GitHub.PR.Milestone.Creator.Type | String | The type of the milestone creator | 
| GitHub.PR.Milestone.Creator.SiteAdmin | Boolean | Whether the milestone creator is a site admin or not | 
| GitHub.PR.Milestone.OpenIssues | Number | The number of open issues with this milestone | 
| GitHub.PR.Milestone.ClosedIssues | Number | The number of closed issues with this milestone | 
| GitHub.PR.Milestone.CreatedAt | String | The date the milestone was created | 
| GitHub.PR.Milestone.UpdatedAt | String | The date the milestone was updated | 
| GitHub.PR.Milestone.ClosedAt | String | The date the milestone was closed | 
| GitHub.PR.Milestone.DueOn | String | The due date for the milestone | 
| GitHub.PR.ActiveLockReason | String | The reason the pull request is locked | 
| GitHub.PR.CreatedAt | String | The date the pull request was created | 
| GitHub.PR.UpdatedAt | String | The date the pull request was updated | 
| GitHub.PR.ClosedAt | String | The date the pull request was closed | 
| GitHub.PR.MergedAt | String | The date the pull request was merged | 
| GitHub.PR.MergeCommitSHA | String | The SHA hash of the pull request's merge commit | 
| GitHub.PR.Assignee.Login | String | The login of the user assigned to the pull request | 
| GitHub.PR.Assignee.ID | Number | The ID of the user assigned to the pull request | 
| GitHub.PR.Assignee.NodeID | String | The node ID of the user assigned to the pull request | 
| GitHub.PR.Assignee.Type | String | The type of the user assigned to the pull request | 
| GitHub.PR.Assignee.SiteAdmin | Boolean | Whether the user assigned to the pull request is a site admin or not | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review | 
| GitHub.PR.RequestedReviewer.NodeID | String | The node ID of the user requested for review | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site admin or not | 
| GitHub.PR.RequestedTeam.ID | Number | The ID of the team requested for review | 
| GitHub.PR.RequestedTeam.NodeID | String | The node ID of the team requested for review | 
| GitHub.PR.RequestedTeam.Name | String | The name of the team requested for review | 
| GitHub.PR.RequestedTeam.Slug | String | The slug of the team requested for review | 
| GitHub.PR.RequestedTeam.Description | String | The description of the team requested for review | 
| GitHub.PR.RequestedTeam.Privacy | String | The privacy setting of the team requested for review | 
| GitHub.PR.RequestedTeam.Permission | String | The permissions of the team requested for review | 
| GitHub.PR.RequestedTeam.Parent | Unknown | The parent of the team requested for review | 
| GitHub.PR.Head.Label | String | The label of the branch that HEAD points to | 
| GitHub.PR.Head.Ref | String | The reference of the branch that HEAD points to | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit that HEAD points to | 
| GitHub.PR.Head.User.Login | String | The login of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.ID | Number | The ID of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.NodeID | String | The node ID of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.Type | String | The type of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.SiteAdmin | Boolean | Whether the committer of the HEAD commit of the checked out branch is a site admin or not | 
| GitHub.PR.Head.Repo.ID | Number | The ID of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.NodeID | String | The node ID of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Name | String | The name of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.FullName | String | The full name of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.Login | String | The user login of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.ID | Number | The user ID of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user node ID of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.Type | String | The user type of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository of the checked out branch is a site admin or not | 
| GitHub.PR.Head.Repo.Private | Boolean | Whether the repository of the checked out branch is private or not | 
| GitHub.PR.Head.Repo.Description | String | The description of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Fork | Boolean | Whether the repository of the checked out branch is a fork or not | 
| GitHub.PR.Head.Repo.Language | Unknown | The language of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.ForksCount | Number | The number of forks of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.StargazersCount | Number | The number of stars of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.WatchersCount | Number | The number of entities watching the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Size | Number | The size of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.DefaultBranch | String | The default branch of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.OpenIssuesCount | Number | The open issues of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Topics | Unknown | Topics listed for the repository of the checked out branch | 
| GitHub.PR.Head.Repo.HasIssues | Boolean | Whether the repository of the checked out branch has issues or not | 
| GitHub.PR.Head.Repo.HasProjects | Boolean | Whether the repository of the checked out branch has projects or not | 
| GitHub.PR.Head.Repo.HasWiki | Boolean | Whether the repository of the checked out branch has a wiki or not | 
| GitHub.PR.Head.Repo.HasPages | Boolean | Whether the repository of the checked out branch has pages or not | 
| GitHub.PR.Head.Repo.HasDownloads | Boolean | Whether the repository of the checked out branch has downloads or not | 
| GitHub.PR.Head.Repo.Archived | Boolean | Whether the repository of the checked out branch has been arvhived or not | 
| GitHub.PR.Head.Repo.Disabled | Boolean | Whether the repository of the checked out branch has been disabled or not | 
| GitHub.PR.Head.Repo.PushedAt | String | The date of the latest push to the repository of the checked out branch | 
| GitHub.PR.Head.Repo.CreatedAt | String | The date of creation of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.UpdatedAt | String | The date the repository of the checked out branch was last updated | 
| GitHub.PR.Head.Repo.AllowRebaseMerge | Boolean | Whether the repository of the checked out branch permits rebase-style merges or not | 
| GitHub.PR.Head.Repo.AllowSquashMerge | Boolean | Whether the repository of the checked out branch permits squash merges or not | 
| GitHub.PR.Head.Repo.AllowMergeCommit | Boolean | Whether the repository of the checked out branch permits merge commits or not | 
| GitHub.PR.Head.Repo.SubscribersCount | Number | The number of entities subscribing to the repository of the checked out branch | 
| GitHub.PR.Base.Label | String | The label of the base branch | 
| GitHub.PR.Base.Ref | String | The reference of the base branch | 
| GitHub.PR.Base.SHA | String | The SHA hash of the base branch | 
| GitHub.PR.Base.User.Login | String | The login of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.NodeID | String | The node ID of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.Type | String | The user type of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit that the base branch points to is a site admin or not | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.NodeID | String | The node ID of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository that the base branch belongs to is a site admin or not | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository that the base branch belongs to is private or not | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository that the base branch belongs to is a fork or not | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times that the repository that the base branch belongs to has been forked | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times that the repository that the base branch belongs to has been starred | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository that the base branch belongs to has issues or not | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository that the base branch belongs to has projects or not | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository that the base branch belongs to has a wiki or not | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository that the base branch belongs to has pages or not | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository that the base branch belongs to has downloads or not | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository that the base branch belongs to is archived or not | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository that the base branch belongs to is disabled or not | 
| GitHub.PR.Base.Repo.PushedAt | String | The date that the repository that the base branch belongs to was last pushed to | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date that the repository that the base branch belongs to was last updated | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository that the base branch belongs to allows rebase-style merges or not | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository that the base branch belongs to allows squash merges or not | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository that the base branch belongs to allows merge commits or not | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities that subscribe to the repository that the base branch belongs to | 
| GitHub.PR.AuthorAssociation | String | The pull request author association | 
| GitHub.PR.Draft | Boolean | Whether the pull request is a draft or not | 
| GitHub.PR.Merged | Boolean | Whether the pull request is merged or not | 
| GitHub.PR.Mergeable | Boolean | Whether the pull request is mergeable or not | 
| GitHub.PR.Rebaseable | Boolean | Whether the pull request is rebaseable or not | 
| GitHub.PR.MergeableState | String | The mergeable state of the pull request | 
| GitHub.PR.MergedBy.Login | String | The login of the user who merged the pull request | 
| GitHub.PR.MergedBy.ID | Number | The ID of the user who merged the pull request | 
| GitHub.PR.MergedBy.NodeID | String | The node ID of the user who merged the pull request | 
| GitHub.PR.MergedBy.Type | String | The type of the user who merged the pull request | 
| GitHub.PR.MergedBy.SiteAdmin | Boolean | Whether the user who merged the pull request is a site admin or not | 
| GitHub.PR.Comments | Number | The number of comments on the pull request | 
| GitHub.PR.ReviewComments | Number | The number of review comments on the pull request | 
| GitHub.PR.MaintainerCanModify | Boolean | Whether the maintainer can modify the pull request or not | 
| GitHub.PR.Commits | Number | The number of commits in the pull request | 
| GitHub.PR.Additions | Number | The number of additions in the pull request | 
| GitHub.PR.Deletions | Number | The number of deletions in the pull request | 
| GitHub.PR.ChangedFiles | Number | The number of changed files in the pull request | 

#### Command Example

```!GitHub-get-pull-request pull_number=1```

#### Human Readable Output
## Pull Request #1
|Additions|AuthorAssociation|Base|Body|ChangedFiles|Comments|Commits|CreatedAt|Deletions|Head|ID|Label|Locked|MaintainerCanModify|MergeCommitSHA|Mergeable|MergeableState|Merged|NodeID|Number|Rebaseable|RequestedReviewer|ReviewComments|State|UpdatedAt|User|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|4|FIRST_TIME_CONTRIBUTOR|Label: example-user1:master Ref: master SHA: b27ea6ac9836d2e756b44eb1d66f02d3d4299362 User: {"Login": "example-user1", "ID": 55035720, "NodeID": "MDQ6VXNlcjU1MDM1NzIw", "Type": "User", "SiteAdmin": false} Repo: {"ID": 207744685, "NodeID": "MDEwOlJlcG9zaXRvcnkyMDc3NDQ2ODU=", "Name": "content", "FullName": "example-user1/content", "Owner": {"Login": "example-user1", "ID": 55035720, "NodeID": "MDQ6VXNlcjU1MDM1NzIw", "Type": "User", "SiteAdmin": false}, "Private": false, "Description": "This repository contains all Demisto content and from here we share content updates", "Fork": true, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 96530, "DefaultBranch": "master", "OpenIssuesCount": 10, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2019-09-18T14:05:43Z", "CreatedAt": "2019-09-11T06:59:20Z", "UpdatedAt": "2019-09-16T15:42:46Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|## Status Ready/In Progress/In Hold(Reason for hold)  ## Related Issues fixes: link to the issue  ## Description A few sentences describing the overall goals of the pull request's commits.  ## Screenshots Paste here any images that will help the reviewer  ## Related PRs List related PRs against other branches:  branch \ PR ------ \ ## Required version of Demistox.x.x ## Does it break backward compatibility?- Yes- Further details:- No ## Must have- [ ] Tests- [ ] Documentation (with link to it)- [ ] Code Review ## DependenciesMention the dependencies of the entity you changed as given from the precommit hooks in checkboxes, and tick after tested them.- [ ] Dependency 1- [ ] Dependency 2- [ ] Dependency 3 ## Additional changesDescribe additional changes done, for example adding a function to common server.|1|5|4|2019-09-11T07:06:26Z|0|Label: example-user4:patch-1 Ref: patch-1 SHA: c01238eea80e35bb76a5c51ac0c95eba4010d8e5 User: {"Login": "example-user4", "ID": 46294017, "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3", "Type": "User", "SiteAdmin": false} Repo: {"ID": 205137013, "NodeID": "MDEwOlJlcG9zaXRvcnkyMDUxMzcwMTM=", "Name": "content", "FullName": "example-user4/content", "Owner": {"Login": "example-user4", "ID": 46294017, "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3", "Type": "User", "SiteAdmin": false}, "Private": false, "Description": "This repository contains all Demisto content and from here we share content updates", "Fork": true, "Language": "Python", "ForksCount": 2, "StargazersCount": 0, "WatchersCount": 0, "Size": 95883, "DefaultBranch": "master", "OpenIssuesCount": 2, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2019-09-16T15:43:54Z", "CreatedAt": "2019-08-29T10:18:15Z", "UpdatedAt": "2019-08-29T10:18:18Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|316303415|'ID': 1563600288, 'NodeID': 'MDU6TGFiZWwxNTYzNjAwMjg4', 'Name': 'Content', 'Description': None, 'Color': None, 'Default': False},{'ID': 1549466359, 'NodeID': 'MDU6TGFiZWwxNTQ5NDY2MzU5', 'Name': 'Contribution', 'Description': None, 'Color': None, 'Default': False},{'ID': 1549411616, 'NodeID': 'MDU6TGFiZWwxNTQ5NDExNjE2', 'Name': 'bug', 'Description': None, 'Color': None, 'Default': True}|false|true|5714b1359b9d7549c89c35fe9fdc266a3db3b766|true|unstable|false|MDExOlB1bGxSZXF1ZXN0MzE2MzAzNDE1|1|true|{'Login': 'example-user3', 'ID': 30797606, 'NodeID': 'MDQ6VXNlcjMwNzk3NjA2', 'Type': 'User', 'SiteAdmin': False}, {'Login': 'example-user1', 'ID': 55035720, 'NodeID': 'MDQ6VXNlcjU1MDM1NzIw', 'Type': 'User', 'SiteAdmin': False}|0|open|2019-09-18T14:05:51Z|Login: example-user4 ID: 46294017 NodeID: MDQ6VXNlcjQ2Mjk0MDE3 Type: User SiteAdmin: false|


### GitHub-list-teams

***
List the teams for an organization. Note that this API call is only available to authenticated members of the organization.

#### Base Command

`GitHub-list-teams`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | The name of the organization. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Team.ID | Number | The ID of the team | 
| GitHub.Team.NodeID | String | The node ID of the team | 
| GitHub.Team.Name | String | The name of the team | 
| GitHub.Team.Slug | String | The slug of the team | 
| GitHub.Team.Description | String | The description of the team | 
| GitHub.Team.Privacy | String | The privacy setting of the team | 
| GitHub.Team.Permission | String | The permissions of the team | 
| GitHub.Team.Parent | Unknown | The parent of the team | 

#### Command Example

```!GitHub-list-teams organization=demisto```

#### Human Readable Output
## Teams for Organization "demisto"
|Description|ID|Name|NodeID|Permission|Privacy|Slug|
|--- |--- |--- |--- |--- |--- |--- |
|Our customer success team|2276690|customer-success|MDQ6VGVhbTIyNzY2NzA=|pull|closed|customer-success|
|Our beloved content team|3043998|Content|MDQ6VGVhbTMwNDM0NDg=|pull|closed|content|


### GitHub-delete-branch

***
Delete a branch

#### Base Command

`GitHub-delete-branch`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch_name | The name of the branch to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example

```!GitHub-delete-branch branch_name=new-branch-example```

#### Human Readable Output
Branch "new-branch-example" Deleted Successfully

### GitHub-list-pr-review-comments

***
Lists all the review comments for a pull request.

#### Base Command

`GitHub-list-pr-review-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The issue number of the pull request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.Number | Number | The issue number of the pull request. | 
| GitHub.PR.ReviewComment.ID | Number | The ID number of the pull request review comment. | 
| GitHub.PR.ReviewComment.NodeID | String | The Node ID of the pull request review comment. | 
| GitHub.PR.ReviewComment.PullRequestReviewID | Number | The ID of the pull request review. | 
| GitHub.PR.ReviewComment.DiffHunk | String | The diff hunk for which the review comment applies. | 
| GitHub.PR.ReviewComment.Path | String | The file path of the proposed file changes for which the review comment applies. | 
| GitHub.PR.ReviewComment.Position | Number | The position of the change for which the review comment applies. | 
| GitHub.PR.ReviewComment.OriginalPosition | Number | The original position of the change for which the review comment applies. | 
| GitHub.PR.ReviewComment.CommitID | String | The commit ID of the proposed change. | 
| GitHub.PR.ReviewComment.OriginalCommitID | String | The commit ID of the commit before the proposed change. | 
| GitHub.PR.ReviewComment.InReplyToID | Number | The reply ID of the comment for which the review comment applies. | 
| GitHub.PR.ReviewComment.User.Login | String | The login of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.ID | Number | The ID of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.NodeID | String | The Node ID of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.Type | String | The type of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.SiteAdmin | Boolean | Whether the user who created the review comment is a site administrator. or not | 
| GitHub.PR.ReviewComment.Body | String | The body content of the review comment. | 
| GitHub.PR.ReviewComment.CreatedAt | String | The time the review comment was created. | 
| GitHub.PR.ReviewComment.UpdatedAt | String | The time the review comment was updated. | 
| GitHub.PR.ReviewComment.AuthorAssociation | String | The association of the user who created the review comment. | 

#### Command Example

```!GitHub-list-pr-review-comments pull_number=1```

#### Human Readable Output
## Pull Request Review Comments for #1
|AuthorAssociation|Body|CommitID|CreatedAt|DiffHunk|ID|NodeID|OriginalCommitID|OriginalPosition|Path|Position|PullRequestReviewID|UpdatedAt|User|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|COLLABORATOR|Change it|1af17e73721dbe0c40011b82ed4bb1a7dbe3ce29|2021-04-08T11:00:21Z|@@ -9,7 +9,7 @@ "url": "some url" } ], -    "another key": [ +    "fixed key": [|609573611|df35047fffd38a65b8fe6963579254e8b09db25e1234567890==|df35047fffd38a65b8fe6963579254e8b09db25e|5|file.json|5|631256917|2021-04-08T11:00:28Z|Login: teizenman ID: 50326704 NodeID: MDQ6VXNlcjUwMzI2NzA0 Type: User SiteAdmin: false|

### GitHub-update-pull-request

***
Updates a pull request in a repository.

#### Base Command

`GitHub-update-pull-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The new title of the pull request. | Optional | 
| body | The new body content of the pull request. | Optional | 
| state | The new state of the pull request. Can be "open", or "closed". Possible values are: open, closed. | Optional | 
| base | The name of the branch that you want your changes pulled, which must be an existing branch in the current repository. You cannot update the base branch in a pull request to point to another repository. | Optional | 
| maintainer_can_modify | Indicates whether maintainers can modify the pull request. Possible values are: true, false. | Optional | 
| pull_number | The issue number of the pull request for which to modify. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.ID | Number | The ID number of the pull request. | 
| GitHub.PR.NodeID | String | The Node ID of the pull request. | 
| GitHub.PR.Number | Number | The issue number of the pull request. | 
| GitHub.PR.State | String | The state of the pull request. | 
| GitHub.PR.Locked | Boolean | Whether the pull request is locked. | 
| GitHub.PR.Title | String | The title of the pull request. | 
| GitHub.PR.User.Login | String | The login of the user who opened the pull request. | 
| GitHub.PR.User.ID | Number | The ID of the user who opened the pull request. | 
| GitHub.PR.User.NodeID | String | The Node ID of the user who opened the pull request. | 
| GitHub.PR.User.Type | String | The type of the user who opened the pull request. | 
| GitHub.PR.User.SiteAdmin | Boolean | Whether the user who opened the pull request is a site administrator. | 
| GitHub.PR.Body | String | The body content of the pull request. | 
| GitHub.PR.Label.ID | Number | The ID of the label. | 
| GitHub.PR.Label.NodeID | String | The Node ID of the label. | 
| GitHub.PR.Label.Name | String | The name of the label. | 
| GitHub.PR.Label.Description | String | The description of the label. | 
| GitHub.PR.Label.Color | String | The hex color value of the label. | 
| GitHub.PR.Label.Default | Boolean | Whether the label is a default. | 
| GitHub.PR.Milestone.ID | Number | The ID of the milestone. | 
| GitHub.PR.Milestone.NodeID | String | The Node ID of the milestone. | 
| GitHub.PR.Milestone.Number | Number | The number of the milestone. | 
| GitHub.PR.Milestone.State | String | The state of the milestone. | 
| GitHub.PR.Milestone.Title | String | The title of the milestone. | 
| GitHub.PR.Milestone.Description | String | The description of the milestone. | 
| GitHub.PR.Milestone.Creator.Login | String | The login of the milestone creator. | 
| GitHub.PR.Milestone.Creator.ID | Number | The ID the milestone creator. | 
| GitHub.PR.Milestone.Creator.NodeID | String | The Node ID of the milestone creator. | 
| GitHub.PR.Milestone.Creator.Type | String | The type of the milestone creator. | 
| GitHub.PR.Milestone.Creator.SiteAdmin | Boolean | Whether the milestone creator is a site administrator. | 
| GitHub.PR.Milestone.OpenIssues | Number | The number of open issues with this milestone. | 
| GitHub.PR.Milestone.ClosedIssues | Number | The number of closed issues with this milestone. | 
| GitHub.PR.Milestone.CreatedAt | String | The date the milestone was created. | 
| GitHub.PR.Milestone.UpdatedAt | String | The date the milestone was updated. | 
| GitHub.PR.Milestone.ClosedAt | String | The date the milestone was closed. | 
| GitHub.PR.Milestone.DueOn | String | The due date for the milestone. | 
| GitHub.PR.ActiveLockReason | String | The reason the pull request is locked. | 
| GitHub.PR.CreatedAt | String | The date the pull request was created. | 
| GitHub.PR.UpdatedAt | String | The date the pull request was updated. | 
| GitHub.PR.ClosedAt | String | The date the pull request was closed. | 
| GitHub.PR.MergedAt | String | The date the pull request was merged. | 
| GitHub.PR.MergeCommitSHA | String | The SHA hash of the pull request's merge commit. | 
| GitHub.PR.Assignee.Login | String | The login of the user assigned to the pull request. | 
| GitHub.PR.Assignee.ID | Number | The ID of the user assigned to the pull request. | 
| GitHub.PR.Assignee.NodeID | String | The Node ID of the user assigned to the pull request. | 
| GitHub.PR.Assignee.Type | String | The type of the user assigned to the pull request. | 
| GitHub.PR.Assignee.SiteAdmin | Boolean | Whether the user assigned to the pull request is a site administrator. not | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review. | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.NodeID | String | The Node ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review. | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site administrator. | 
| GitHub.PR.RequestedTeam.ID | Number | The ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.NodeID | String | The Node ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.Name | String | The name of the team requested for review. | 
| GitHub.PR.RequestedTeam.Slug | String | The slug of the team requested for review. | 
| GitHub.PR.RequestedTeam.Description | String | The description of the team requested for review. | 
| GitHub.PR.RequestedTeam.Privacy | String | The privacy setting of the team requested for review. | 
| GitHub.PR.RequestedTeam.Permission | String | The permissions of the team requested for review. | 
| GitHub.PR.RequestedTeam.Parent | Unknown | The parent of the team requested for review. | 
| GitHub.PR.Head.Label | String | The label of the branch for which the HEAD points. | 
| GitHub.PR.Head.Ref | String | The reference of the branch for which the HEAD points. | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit for which the HEAD points. | 
| GitHub.PR.Head.User.Login | String | The committer login of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.ID | Number | The committer ID of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.NodeID | String | The Node committer ID of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.Type | String | The committer type of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.SiteAdmin | Boolean | Whether the committer of the HEAD commit of the checked out branch is a site administrator. | 
| GitHub.PR.Head.Repo.ID | Number | The ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.NodeID | String | The Node ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Name | String | The name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.FullName | String | The full name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Login | String | The user login of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.ID | Number | The user ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user node ID of the owner of the repository of the checked. out branch | 
| GitHub.PR.Head.Repo.Owner.Type | String | The user type of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository of the checked out branch is a site administrator. | 
| GitHub.PR.Head.Repo.Private | Boolean | Whether the repository of the checked out branch is private. | 
| GitHub.PR.Head.Repo.Description | String | The description of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Fork | Boolean | Whether the repository of the checked out branch is a fork. | 
| GitHub.PR.Head.Repo.Language | Unknown | The language of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.ForksCount | Number | The number of forks of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.StargazersCount | Number | The number of stars of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.WatchersCount | Number | The number of entities watching the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Size | Number | The size of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.DefaultBranch | String | The default branch of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.OpenIssuesCount | Number | The open issues of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Topics | Unknown | Topics listed for the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.HasIssues | Boolean | Whether the repository of the checked out branch has issues. | 
| GitHub.PR.Head.Repo.HasProjects | Boolean | Whether the repository of the checked out branch has projects. | 
| GitHub.PR.Head.Repo.HasWiki | Boolean | Whether the repository of the checked out branch has a wiki. | 
| GitHub.PR.Head.Repo.HasPages | Boolean | Whether the repository of the checked out branch has pages. | 
| GitHub.PR.Head.Repo.HasDownloads | Boolean | Whether the repository of the checked out branch has downloads. | 
| GitHub.PR.Head.Repo.Archived | Boolean | Whether the repository of the checked out branch has been archived. | 
| GitHub.PR.Head.Repo.Disabled | Boolean | Whether the repository of the checked out branch has been disabled. | 
| GitHub.PR.Head.Repo.PushedAt | String | The date of the latest push to the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.CreatedAt | String | The date of creation of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.UpdatedAt | String | The date the repository of the checked out branch was last updated. | 
| GitHub.PR.Head.Repo.AllowRebaseMerge | Boolean | Whether the repository of the checked out branch permits rebase-style merges. | 
| GitHub.PR.Head.Repo.AllowSquashMerge | Boolean | Whether the repository of the checked out branch permits squash merges. | 
| GitHub.PR.Head.Repo.AllowMergeCommit | Boolean | Whether the repository of the checked out branch permits merge commits. | 
| GitHub.PR.Head.Repo.SubscribersCount | Number | The number of entities subscribing to the repository of the checked out branch. | 
| GitHub.PR.Base.Label | String | The label of the base branch. | 
| GitHub.PR.Base.Ref | String | The reference of the base branch. | 
| GitHub.PR.Base.SHA | String | The SHA hash of the base branch. | 
| GitHub.PR.Base.User.Login | String | The committer login of the commit for which the base branch points. | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit for which the base branch points. | 
| GitHub.PR.Base.User.NodeID | String | The committer Node ID of the commit for which the base branch points. | 
| GitHub.PR.Base.User.Type | String | The user committer type of the commit for which the base branch points. | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit for which the base branch points is a site administrator. | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.NodeID | String | The Node ID of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository for which the base branch belongs to is a site administrator. | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository for which the base branch belongs is private. | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository for which the base branch belongs to is a fork. | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times that the repository for which the base branch belongs has been forked. | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times that the repository for which the base branch belongs has been starred. | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository for which the base branch belongs has issues. | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository for which the base branch belongs has projects. | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository for which the base branch belongs has a wiki. | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository for which the base branch belongs to has pages. | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository for which the base branch belongs has downloads. | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository for which the base branch belongs is archived. | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository for which the base branch belongs is disabled. | 
| GitHub.PR.Base.Repo.PushedAt | String | The date that the repository for which the base branch belongs to was last pushed. | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date that the repository for which the base branch belongs was last updated. | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository for which the base branch belongs allows rebase-style merges. | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository for which the base branch belongs allows squash merges. | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository for which the base branch belongs allows merge commits. | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities for which subscribe to the repository that the base branch belongs. | 
| GitHub.PR.AuthorAssociation | String | The pull request author association. | 
| GitHub.PR.Draft | Boolean | Whether the pull request is a draft. | 
| GitHub.PR.Merged | Boolean | Whether the pull request is merged. | 
| GitHub.PR.Mergeable | Boolean | Whether the pull request is mergeable. | 
| GitHub.PR.Rebaseable | Boolean | Whether the pull request is rebaseable. | 
| GitHub.PR.MergeableState | String | The mergeable state of the pull request. | 
| GitHub.PR.MergedBy.Login | String | The login of the user who merged the pull request. | 
| GitHub.PR.MergedBy.ID | Number | The ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.NodeID | String | The Node ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.Type | String | The type of the user who merged the pull request. | 
| GitHub.PR.MergedBy.SiteAdmin | Boolean | Whether the user who merged the pull request is a site administrator. | 
| GitHub.PR.Comments | Number | The number of comments on the pull request. | 
| GitHub.PR.ReviewComments | Number | The number of review comments on the pull request. | 
| GitHub.PR.MaintainerCanModify | Boolean | Whether the maintainer can modify the pull request. | 
| GitHub.PR.Commits | Number | The number of commits in the pull request. | 
| GitHub.PR.Additions | Number | The number of additions in the pull request. | 
| GitHub.PR.Deletions | Number | The number of deletions in the pull request. | 
| GitHub.PR.ChangedFiles | Number | The number of changed files in the pull request. | 

#### Command Example

```!GitHub-update-pull-request pull_number=1 body=Changing```

#### Human Readable Output
## Updated Pull Request #15
|Additions|AuthorAssociation|Base|Body|ChangedFiles|Comments|Commits|CreatedAt|Deletions|Draft|Head|ID|Locked|MaintainerCanModify|MergeCommitSHA|Mergeable|MergeableState|Merged|NodeID|Number|Rebaseable|ReviewComments|State|UpdatedAt|User|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|1|COLLABORATOR|Label: demisto:master Ref: master SHA: 56b289d4b1402b1492dd0cc681325b1f0ae47505 User: {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false} Repo: {"ID": 315109290, "NodeID": "MDEwOlJlcG9zaXRvcnkzMTUxMDkyOTA=", "Name": "content-internal-dist", "FullName": "demisto/content-internal-dist", "Owner": {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false}, "Private": true, "Description": null, "Fork": false, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 226, "DefaultBranch": "master", "OpenIssuesCount": 1, "Topics": null, "HasIssues": true, "HasProjects": true, "HasWiki": true, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2021-04-08T10:59:28Z", "CreatedAt": "2020-11-22T18:51:37Z", "UpdatedAt": "2021-04-07T08:58:02Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|Changing|1|0|1|2021-04-08T10:59:27Z|1|false|Label: demisto:teizenman-gh-test Ref: teizenman-gh-test SHA: 87429cec185dfd82be0f2e6d98b0f5d2d0bb91b0 User: {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false} Repo: {"ID": 315109290, "NodeID": "MDEwOlJlcG9zaXRvcnkzMTUxMDkyOTA=", "Name": "content-internal-dist", "FullName": "demisto/content-internal-dist", "Owner": {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false}, "Private": true, "Description": null, "Fork": false, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 226, "DefaultBranch": "master", "OpenIssuesCount": 1, "Topics": null, "HasIssues": true, "HasProjects": true, "HasWiki": true, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2021-04-08T10:59:28Z", "CreatedAt": "2020-11-22T18:51:37Z", "UpdatedAt": "2021-04-07T08:58:02Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|611450655|false|false|1af17e73721dbe0c40011b82ed4bb1a7dbe3ce29|true|blocked|false|1af17e73721dbe0c40011b82ed4bb1a7|15|true|1|open|2021-04-08T11:08:14Z|Login: teizenman ID: 50326704 NodeID: MDQ6VXNlcjUwMzI2NzA0 Type: User SiteAdmin: false|

### GitHub-is-pr-merged

***
Returns a merged pull request. If the pull request has been merged, the API returns 'Status: 204 No Content'. If the pull request
has not been merged the API returns 'Status: 404 Not Found'

#### Base Command

`GitHub-is-pr-merged`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The issue number of the pull request to check. | Required | 

#### Context Output

There is no context output for this command.

#### Command Example

```!GitHub-is-pr-merged pull_number=1```

#### Human Readable Output
Pull Request #1 was Merged

### GitHub-create-pull-request

***
Creates a new pull request.

#### Base Command

`GitHub-create-pull-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the pull request. | Required | 
| head | The name of the branch where the changes are made. | Required | 
| base | The name of the branch you want the changes pulled into, which must be an existing branch on the current repository. | Required | 
| body | The contents of the pull request. | Optional | 
| maintainer_can_modify | Indicates whether maintainers can modify the pull request. Possible values are: true, false. | Optional | 
| draft | Indicates whether the pull request is a draft. For more information, see https://help.github.com/en/articles/about-pull-requests#draft-pull-requests. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.ID | Number | The ID number of the pull request. | 
| GitHub.PR.NodeID | String | The Node ID of the pull request. | 
| GitHub.PR.Number | Number | The issue number of the pull request. | 
| GitHub.PR.State | String | The state of the pull request. | 
| GitHub.PR.Locked | Boolean | Whether the pull request is locked. | 
| GitHub.PR.Title | String | The title of the pull request. | 
| GitHub.PR.User.Login | String | The login of the user who opened the pull request. | 
| GitHub.PR.User.ID | Number | The ID of the user who opened the pull request. | 
| GitHub.PR.User.NodeID | String | The Node ID of the user who opened the pull request. | 
| GitHub.PR.User.Type | String | The user type who opened the pull request. | 
| GitHub.PR.User.SiteAdmin | Boolean | Whether the user who opened the pull request is a site administrator. | 
| GitHub.PR.Body | String | The body content of the pull request. | 
| GitHub.PR.Label.ID | Number | The ID of the label. | 
| GitHub.PR.Label.NodeID | String | The Node ID of the label. | 
| GitHub.PR.Label.Name | String | The name of the label. | 
| GitHub.PR.Label.Description | String | The description of the label. | 
| GitHub.PR.Label.Color | String | The hex color value of the label. | 
| GitHub.PR.Label.Default | Boolean | Whether the label is a default. | 
| GitHub.PR.Milestone.ID | Number | The ID of the milestone. | 
| GitHub.PR.Milestone.NodeID | String | The Node ID of the milestone. | 
| GitHub.PR.Milestone.Number | Number | The number of the milestone. | 
| GitHub.PR.Milestone.State | String | The state of the milestone. | 
| GitHub.PR.Milestone.Title | String | The title of the milestone. | 
| GitHub.PR.Milestone.Description | String | The description of the milestone. | 
| GitHub.PR.Milestone.Creator.Login | String | The login of the milestone creator. | 
| GitHub.PR.Milestone.Creator.ID | Number | The ID the milestone creator. | 
| GitHub.PR.Milestone.Creator.NodeID | String | The Node ID of the milestone creator. | 
| GitHub.PR.Milestone.Creator.Type | String | The type of the milestone creator. | 
| GitHub.PR.Milestone.Creator.SiteAdmin | Boolean | Whether the milestone creator is a site administrator. | 
| GitHub.PR.Milestone.OpenIssues | Number | The number of open issues with this milestone. | 
| GitHub.PR.Milestone.ClosedIssues | Number | The number of closed issues with this milestone. | 
| GitHub.PR.Milestone.CreatedAt | String | The date the milestone was created. | 
| GitHub.PR.Milestone.UpdatedAt | String | The date the milestone was updated. | 
| GitHub.PR.Milestone.ClosedAt | String | The date the milestone was closed. | 
| GitHub.PR.Milestone.DueOn | String | The due date for the milestone. | 
| GitHub.PR.ActiveLockReason | String | The reason the pull request is locked. | 
| GitHub.PR.CreatedAt | String | The date the pull request was created. | 
| GitHub.PR.UpdatedAt | String | The date the pull request was updated. | 
| GitHub.PR.ClosedAt | String | The date the pull request was closed. | 
| GitHub.PR.MergedAt | String | The date the pull request was merged. | 
| GitHub.PR.MergeCommitSHA | String | The SHA hash of the pull request's merge commit. | 
| GitHub.PR.Assignee.Login | String | The login of the user assigned to the pull request. | 
| GitHub.PR.Assignee.ID | Number | The ID of the user assigned to the pull request. | 
| GitHub.PR.Assignee.NodeID | String | The Node ID of the user assigned to the pull request. | 
| GitHub.PR.Assignee.Type | String | The type of the user assigned to the pull request. | 
| GitHub.PR.Assignee.SiteAdmin | Boolean | Whether the user assigned to the pull request is a site administrator. | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review. | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.NodeID | String | The Node ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review. | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site administrator. | 
| GitHub.PR.RequestedTeam.ID | Number | The ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.NodeID | String | The Node ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.Name | String | The name of the team requested for review. | 
| GitHub.PR.RequestedTeam.Slug | String | The slug of the team requested for review. | 
| GitHub.PR.RequestedTeam.Description | String | The description of the team requested for review. | 
| GitHub.PR.RequestedTeam.Privacy | String | The privacy setting of the team requested for review. | 
| GitHub.PR.RequestedTeam.Permission | String | The permissions of the team requested for review. | 
| GitHub.PR.RequestedTeam.Parent | Unknown | The parent of the team requested for review. | 
| GitHub.PR.Head.Label | String | The label of the branch for which the HEAD points. | 
| GitHub.PR.Head.Ref | String | The reference of the branch for which the HEAD points. | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit for which the HEAD points. | 
| GitHub.PR.Head.User.Login | String | The committer login of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.ID | Number | The committer ID of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.NodeID | String | The Node ID of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.Type | String | The committer type of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.SiteAdmin | Boolean | Whether the committer of the HEAD commit of the checked out branch is a site administrator. | 
| GitHub.PR.Head.Repo.ID | Number | The ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.NodeID | String | The Node ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Name | String | The name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.FullName | String | The full name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Login | String | The user login of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.ID | Number | The user ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user Node ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Type | String | The user type of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository of the checked out branch is a site administrator. | 
| GitHub.PR.Head.Repo.Private | Boolean | Whether the repository of the checked out branch is private. | 
| GitHub.PR.Head.Repo.Description | String | The description of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Fork | Boolean | Whether the repository of the checked out branch is a fork. | 
| GitHub.PR.Head.Repo.Language | Unknown | The language of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.ForksCount | Number | The number of forks of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.StargazersCount | Number | The number of stars of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.WatchersCount | Number | The number of entities watching the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Size | Number | The size of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.DefaultBranch | String | The default branch of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.OpenIssuesCount | Number | The open issues of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Topics | Unknown | Topics listed for the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.HasIssues | Boolean | Whether the repository of the checked out branch has issues. | 
| GitHub.PR.Head.Repo.HasProjects | Boolean | Whether the repository of the checked out branch has projects. | 
| GitHub.PR.Head.Repo.HasWiki | Boolean | Whether the repository of the checked out branch has a wiki. | 
| GitHub.PR.Head.Repo.HasPages | Boolean | Whether the repository of the checked out branch has pages. | 
| GitHub.PR.Head.Repo.HasDownloads | Boolean | Whether the repository of the checked out branch has downloads. | 
| GitHub.PR.Head.Repo.Archived | Boolean | Whether the repository of the checked out branch has been archived. | 
| GitHub.PR.Head.Repo.Disabled | Boolean | Whether the repository of the checked out branch has been disabled. | 
| GitHub.PR.Head.Repo.PushedAt | String | The date of the latest push to the repository of the checked out. | 
| GitHub.PR.Head.Repo.CreatedAt | String | The date of creation of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.UpdatedAt | String | The date the repository of the checked out branch was last updated. | 
| GitHub.PR.Head.Repo.AllowRebaseMerge | Boolean | Whether the repository of the checked out branch permits rebase-style merges. | 
| GitHub.PR.Head.Repo.AllowSquashMerge | Boolean | Whether the repository of the checked out branch permits squash merges. | 
| GitHub.PR.Head.Repo.AllowMergeCommit | Boolean | Whether the repository of the checked out branch permits merge commits. | 
| GitHub.PR.Head.Repo.SubscribersCount | Number | The number of entities subscribing to the repository of the checked out. | 
| GitHub.PR.Base.Label | String | The label of the base branch. | 
| GitHub.PR.Base.Ref | String | The reference of the base branch. | 
| GitHub.PR.Base.SHA | String | The SHA hash of the base branch. | 
| GitHub.PR.Base.User.Login | String | The committer login of the commit for which the base branch points. | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit for which the base branch points. to | 
| GitHub.PR.Base.User.NodeID | String | The committer Node ID of the commit for which the base branch points. | 
| GitHub.PR.Base.User.Type | String | The user type of the committer for which the commit base branch points. | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit for which the base branch points to is a site administrator. | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.NodeID | String | The Node ID of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository that the base branch belongs to is a site administrator. | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository for which the base branch belongs to is private. | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository that the base branch belongs to is a fork. | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times that the repository for which the base branch belongs has been forked. | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times that the repository that the base branch belongs to has been starred. | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository for which the base branch belongs to has issues. | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository for which the base branch belongs to has projects. | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository for which the base branch belongs to has a wiki. | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository for which the base branch belongs to has pages. | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository for which the base branch belongs to has downloads. | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository for which the base branch belongs to is archived. | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository for which the base branch belongs to is disabled. | 
| GitHub.PR.Base.Repo.PushedAt | String | The date that the repository for which the base branch belongs was last pushed. | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository for which the base branch belongs. | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date that the repository for which the base branch belongs was last updated. | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository for which the base branch belongs allows rebase-style merges. | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository for which the base branch belongs allows squash merges. | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository for which the base branch belongs allows merge commits. | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities that subscribe to the repository for which the base branch belongs. | 
| GitHub.PR.AuthorAssociation | String | The pull request author association. | 
| GitHub.PR.Draft | Boolean | Whether the pull request is a draft. | 
| GitHub.PR.Merged | Boolean | Whether the pull request is merged. | 
| GitHub.PR.Mergeable | Boolean | Whether the pull request is mergeable. | 
| GitHub.PR.Rebaseable | Boolean | Whether the pull request is rebaseable. | 
| GitHub.PR.MergeableState | String | The mergeable state of the pull request. | 
| GitHub.PR.MergedBy.Login | String | The login of the user who merged the pull request. | 
| GitHub.PR.MergedBy.ID | Number | The ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.NodeID | String | The Node ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.Type | String | The user type who merged the pull request. | 
| GitHub.PR.MergedBy.SiteAdmin | Boolean | Whether the user who merged the pull request is a site administrator. | 
| GitHub.PR.Comments | Number | The number of comments on the pull request. | 
| GitHub.PR.ReviewComments | Number | The number of review comments on the pull request. | 
| GitHub.PR.MaintainerCanModify | Boolean | Whether the maintainer can modify the pull request. | 
| GitHub.PR.Commits | Number | The number of commits in the pull request. | 
| GitHub.PR.Additions | Number | The number of additions in the pull request. | 
| GitHub.PR.Deletions | Number | The number of deletions in the pull request. | 
| GitHub.PR.ChangedFiles | Number | The number of changed files in the pull request. | 

#### Command Example

```!GitHub-create-pull-request base=master head=branch-test title=Testing```

#### Human Readable Output
## Created Pull Request #16

|Additions|AuthorAssociation|Base|ChangedFiles|Comments|Commits|CreatedAt|Deletions|Draft|Head|ID|Locked|MaintainerCanModify|MergeableState|Merged|NodeID|Number|ReviewComments|State|UpdatedAt|User|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|1|COLLABORATOR|Label: demisto:master Ref: master SHA: 1af17e73721dbe0c40011b82ed4bb1a7dbe3ce29 User: {"Login": "demisto", "ID": XXXXX, "NodeID": "1af17e73721dbe0c40011b82ed4bb1a7", "Type": "Organization", "SiteAdmin": false} Repo: {"ID": 12345, "NodeID": "1af17e73721dbe0c40011b82ed4bb1a=", "Name": "repo", "FullName": "owner/repo", "Owner": {"Login": "login", "ID": 1234, "NodeID": "1af17e73721dbe0c40011b82ed4bb1a7", "Type": "Organization", "SiteAdmin": false}, "Private": true, "Description": null, "Fork": false, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 229, "DefaultBranch": "master", "OpenIssuesCount": 1, "Topics": null, "HasIssues": true, "HasProjects": true, "HasWiki": true, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2021-04-08T10:59:28Z", "CreatedAt": "2020-11-22T18:51:37Z", "UpdatedAt": "2021-04-07T08:58:02Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|1|0|1|2021-04-08T13:13:31Z|1|true|Label: demisto:branch-test Ref: branch-test SHA: 1af17e73721dbe0c40011b82ed4bb1a7dbe3ce29 User: {"Login": "login", "ID": 12345, "NodeID": "1af17e73721dbe0c40011b82ed4bb1a7", "Type": "Organization", "SiteAdmin": false} Repo: {"ID": 12345, "NodeID": "1af17e73721dbe0c40011b82ed4bb1a=", "Name": "repo", "FullName": "owner/repo", "Owner": {"Login": "login", "ID": 12345, "NodeID": "1af17e73721dbe0c40011b82ed4bb1a7", "Type": "Organization", "SiteAdmin": false}, "Private": true, "Description": null, "Fork": false, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 229, "DefaultBranch": "master", "OpenIssuesCount": 1, "Topics": null, "HasIssues": true, "HasProjects": true, "HasWiki": true, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2021-04-08T10:59:28Z", "CreatedAt": "2020-11-22T18:51:37Z", "UpdatedAt": "2021-04-07T08:58:02Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|611546693|false|false|draft|false|1af17e73721dbe0c40011b82ed4bb1a7|16|0|open|2021-04-08T13:13:31Z|Login: teizenman ID: 1234 NodeID: 1af17e73721dbe0c4001 Type: User SiteAdmin: false|

### Github-get-github-actions-usage

***
Gets the usage details of GitHub action workflows of private repositories, by repository owner.

#### Base Command

`Github-get-github-actions-usage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| owner | The repository owner. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.ActionsUsage.RepositoryName | String | The name of the private repository. | 
| GitHub.ActionsUsage.WorkflowID | Number | The workflow ID of the GitHub action. | 
| GitHub.ActionsUsage.WorkflowName | String | The display name of the GitHub action workflow. | 
| GitHub.ActionsUsage.WorkflowUsage | Unknown | GitHub action worflow usage on different OS. | 

#### Command Example

```!Github-get-github-actions-usage owner=user```

#### Human Readable Output
## Github Actions Usage
|Repositoryname|Workflowid|Workflowname|Workflowusage|
|---|---|---|---|
|Git-Repo|12345|An Action|UBUNTU: {"total_ms": 12345}|

### GitHub-get-file-content

***
Gets the content of a file from GitHub.

#### Base Command

`GitHub-get-file-content`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file_path | The path of the file. | Required | 
| branch_name | The branch name from which to get the file. | Optional | 
| media_type | The media type in which the file contents will be fetched. Possible values are: "raw" and "html". Default value is "raw". Possible values are: raw, html. Default is raw. | Optional | 
| create_file_from_content | Whether to create a file entry in the War Room with the file contents. Possible values are: "true" and "false". Default value is "false". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.FileContent.Path | String | The path of the file. | 
| GitHub.FileContent.Content | Number | The content of the file. | 
| GitHub.FileContent.MediaType | String | The media type in which the file was fetched. | 
| GitHub.FileContent.Branch | Unknown | The branch from which the file was fetched. | 

#### Command Example

```!GitHub-get-file-content file_path=file.json branch_name=branch-test```

#### Human Readable Output
## File file.json successfully fetched.
|Branch|Content|MediaType|Path|
|---|---|---|---|
|branch-test|This is the content of the file|raw|file.json| 

### Github-list-files
***
Get list of files from the given path in the repository.


#### Base Command

`Github-list-files`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path in the branch to get the files from. | Optional | 
| organization | The name of the organization. | Optional | 
| repository | The name of the repository. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.File.Name | String | The name of the file. | 
| GitHub.File.Type | String | Whether the item is file or directory. | 
| GitHub.File.Size | Number | The size of the file in bytes. | 
| GitHub.File.Path | String | The file path inside the repository. | 
| GitHub.File.DownloadUrl | String | Link to download the file content. | 
| GitHub.File.SHA | String | The SHA of the file. | 

#### Command Example
```!Github-list-files path=Index```

#### Human Readable Output
## Files in path: Index
|Name|Path|Type|Size|DownloadUrl|
|--- |--- |--- |--- |--- |
|README.md|Index/README.md|file|1500|https://raw.githubusercontent.com/demisto/hello-world/master/index/README.md|
|images|Index/images|dir|0||

### GitHub-list-team-members
***
List team members.
#### Base Command
`GitHub-list-team-members`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | The name of the organization. | Required | 
| team_slug | The name of the team under the organiztion. | Required | 
| maximum_users | The maximum number of users to return | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.TeamMember.ID | String | The ID of the team member. | 
| GitHub.TeamMember.Login | String | The login name of the team member. |
| GitHub.TeamMember.Team | String | The user's team. |
#### Command Example
```!GitHub-list-team-members organization=demisto team_slug=content maximum_users=20```

##### Context Example
```
{
    "GitHub.GitHub": [
        {
            "ID": 1234567, 
            "Login": "user1", 
            "Team": "content", 
        }
    ]
}
```

#### Human Readable Output
## Team Member of team content in organization demisto
|ID|Login|Team|
|--- |---|---|
|1234567|user1|content|

### GitHub-list-branch-pull-requests
***
Get pull requests corresponding to the given branch name.


#### Base Command

`GitHub-list-branch-pull-requests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| branch_name | The branch name from which to retrieve pull requests. | Required | 
| organization | The name of the organization. | Optional | 
| repository | The repository for the pull request. Defaults to the repository parameter if not provided. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.ID | Number | The ID number of the pull request | 
| GitHub.PR.NodeID | String | The node ID of the pull request | 
| GitHub.PR.Number | Number | The issue number of the pull request | 
| GitHub.PR.State | String | The state of the pull request | 
| GitHub.PR.Locked | Boolean | Whether the pull request is locked or not | 
| GitHub.PR.User.Login | String | The login of the user who opened the pull request | 
| GitHub.PR.User.ID | Number | The ID of the user who opened the pull request | 
| GitHub.PR.User.NodeID | String | The node ID of the user who opened the pull request | 
| GitHub.PR.User.Type | String | The type of the user who opened the pull request | 
| GitHub.PR.User.SiteAdmin | Boolean | Whether the user who opened the pull request is a site admin or not | 
| GitHub.PR.Body | String | The body content of the pull request | 
| GitHub.PR.Label.ID | Number | The ID of the label | 
| GitHub.PR.Label.NodeID | String | The node ID of the label | 
| GitHub.PR.Label.Name | String | The name of the label | 
| GitHub.PR.Label.Description | String | The description of the label | 
| GitHub.PR.Label.Color | String | The hex color value of the label | 
| GitHub.PR.Label.Default | Boolean | Whether the label is a default or not | 
| GitHub.PR.Milestone.ID | Number | The ID of the milestone | 
| GitHub.PR.Milestone.NodeID | String | The node ID of the milestone | 
| GitHub.PR.Milestone.Number | Number | The number of the milestone | 
| GitHub.PR.Milestone.State | String | The state of the milestone | 
| GitHub.PR.Milestone.Title | String | The title of the milestone | 
| GitHub.PR.Milestone.Description | String | The description of the milestone | 
| GitHub.PR.Milestone.Creator.Login | String | The login of the milestone creator | 
| GitHub.PR.Milestone.Creator.ID | Number | The ID the milestone creator | 
| GitHub.PR.Milestone.Creator.NodeID | String | The node ID of the milestone creator | 
| GitHub.PR.Milestone.Creator.Type | String | The type of the milestone creator | 
| GitHub.PR.Milestone.Creator.SiteAdmin | Boolean | Whether the milestone creator is a site admin or not | 
| GitHub.PR.Milestone.OpenIssues | Number | The number of open issues with this milestone | 
| GitHub.PR.Milestone.ClosedIssues | Number | The number of closed issues with this milestone | 
| GitHub.PR.Milestone.CreatedAt | String | The date the milestone was created | 
| GitHub.PR.Milestone.UpdatedAt | String | The date the milestone was updated | 
| GitHub.PR.Milestone.ClosedAt | String | The date the milestone was closed | 
| GitHub.PR.Milestone.DueOn | String | The due date for the milestone | 
| GitHub.PR.ActiveLockReason | String | The reason the pull request is locked | 
| GitHub.PR.CreatedAt | String | The date the pull request was created | 
| GitHub.PR.UpdatedAt | String | The date the pull request was updated | 
| GitHub.PR.ClosedAt | String | The date the pull request was closed | 
| GitHub.PR.MergedAt | String | The date the pull request was merged | 
| GitHub.PR.MergeCommitSHA | String | The SHA hash of the pull request's merge commit | 
| GitHub.PR.Assignee.Login | String | The login of the user assigned to the pull request | 
| GitHub.PR.Assignee.ID | Number | The ID of the user assigned to the pull request | 
| GitHub.PR.Assignee.NodeID | String | The node ID of the user assigned to the pull request | 
| GitHub.PR.Assignee.Type | String | The type of the user assigned to the pull request | 
| GitHub.PR.Assignee.SiteAdmin | Boolean | Whether the user assigned to the pull request is a site admin or not | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review | 
| GitHub.PR.RequestedReviewer.NodeID | String | The node ID of the user requested for review | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site admin or not | 
| GitHub.PR.RequestedTeam.ID | Number | The ID of the team requested for review | 
| GitHub.PR.RequestedTeam.NodeID | String | The node ID of the team requested for review | 
| GitHub.PR.RequestedTeam.Name | String | The name of the team requested for review | 
| GitHub.PR.RequestedTeam.Slug | String | The slug of the team requested for review | 
| GitHub.PR.RequestedTeam.Description | String | The description of the team requested for review | 
| GitHub.PR.RequestedTeam.Privacy | String | The privacy setting of the team requested for review | 
| GitHub.PR.RequestedTeam.Permission | String | The permissions of the team requested for review | 
| GitHub.PR.RequestedTeam.Parent | Unknown | The parent of the team requested for review | 
| GitHub.PR.Head.Label | String | The label of the branch that HEAD points to | 
| GitHub.PR.Head.Ref | String | The reference of the branch that HEAD points to | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit that HEAD points to | 
| GitHub.PR.Head.User.Login | String | The login of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.ID | Number | The ID of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.NodeID | String | The node ID of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.Type | String | The type of the committer of the HEAD commit of the checked out branch | 
| GitHub.PR.Head.User.SiteAdmin | Boolean | Whether the committer of the HEAD commit of the checked out branch is a site admin or not | 
| GitHub.PR.Head.Repo.ID | Number | The ID of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.NodeID | String | The node ID of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Name | String | The name of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.FullName | String | The full name of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.Login | String | The user login of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.ID | Number | The user ID of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user node ID of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.Type | String | The user type of the owner of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository of the checked out branch is a site admin or not | 
| GitHub.PR.Head.Repo.Private | Boolean | Whether the repository of the checked out branch is private or not | 
| GitHub.PR.Head.Repo.Description | String | The description of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Fork | Boolean | Whether the repository of the checked out branch is a fork or not | 
| GitHub.PR.Head.Repo.Language | Unknown | The language of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.ForksCount | Number | The number of forks of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.StargazersCount | Number | The number of stars of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.WatchersCount | Number | The number of entities watching the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Size | Number | The size of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.DefaultBranch | String | The default branch of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.OpenIssuesCount | Number | The open issues of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.Topics | Unknown | Topics listed for the repository of the checked out branch | 
| GitHub.PR.Head.Repo.HasIssues | Boolean | Whether the repository of the checked out branch has issues or not | 
| GitHub.PR.Head.Repo.HasProjects | Boolean | Whether the repository of the checked out branch has projects or not | 
| GitHub.PR.Head.Repo.HasWiki | Boolean | Whether the repository of the checked out branch has a wiki or not | 
| GitHub.PR.Head.Repo.HasPages | Boolean | Whether the repository of the checked out branch has pages or not | 
| GitHub.PR.Head.Repo.HasDownloads | Boolean | Whether the repository of the checked out branch has downloads or not | 
| GitHub.PR.Head.Repo.Archived | Boolean | Whether the repository of the checked out branch has been arvhived or not | 
| GitHub.PR.Head.Repo.Disabled | Boolean | Whether the repository of the checked out branch has been disabled or not | 
| GitHub.PR.Head.Repo.PushedAt | String | The date of the latest push to the repository of the checked out branch | 
| GitHub.PR.Head.Repo.CreatedAt | String | The date of creation of the repository of the checked out branch | 
| GitHub.PR.Head.Repo.UpdatedAt | String | The date the repository of the checked out branch was last updated | 
| GitHub.PR.Head.Repo.AllowRebaseMerge | Boolean | Whether the repository of the checked out branch permits rebase-style merges or not | 
| GitHub.PR.Head.Repo.AllowSquashMerge | Boolean | Whether the repository of the checked out branch permits squash merges or not | 
| GitHub.PR.Head.Repo.AllowMergeCommit | Boolean | Whether the repository of the checked out branch permits merge commits or not | 
| GitHub.PR.Head.Repo.SubscribersCount | Number | The number of entities subscribing to the repository of the checked out branch | 
| GitHub.PR.Base.Label | String | The label of the base branch | 
| GitHub.PR.Base.Ref | String | The reference of the base branch | 
| GitHub.PR.Base.SHA | String | The SHA hash of the base branch | 
| GitHub.PR.Base.User.Login | String | The login of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.NodeID | String | The node ID of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.Type | String | The user type of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit that the base branch points to is a site admin or not | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.NodeID | String | The node ID of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository that the base branch belongs to is a site admin or not | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository that the base branch belongs to is private or not | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository that the base branch belongs to is a fork or not | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times that the repository that the base branch belongs to has been forked | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times that the repository that the base branch belongs to has been starred | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository that the base branch belongs to has issues or not | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository that the base branch belongs to has projects or not | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository that the base branch belongs to has a wiki or not | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository that the base branch belongs to has pages or not | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository that the base branch belongs to has downloads or not | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository that the base branch belongs to is archived or not | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository that the base branch belongs to is disabled or not | 
| GitHub.PR.Base.Repo.PushedAt | String | The date that the repository that the base branch belongs to was last pushed to | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository that the base branch belongs to | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date that the repository that the base branch belongs to was last updated | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository that the base branch belongs to allows rebase-style merges or not | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository that the base branch belongs to allows squash merges or not | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository that the base branch belongs to allows merge commits or not | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities that subscribe to the repository that the base branch belongs to | 
| GitHub.PR.AuthorAssociation | String | The pull request author association | 
| GitHub.PR.Draft | Boolean | Whether the pull request is a draft or not | 
| GitHub.PR.Merged | Boolean | Whether the pull request is merged or not | 
| GitHub.PR.Mergeable | Boolean | Whether the pull request is mergeable or not | 
| GitHub.PR.Rebaseable | Boolean | Whether the pull request is rebaseable or not | 
| GitHub.PR.MergeableState | String | The mergeable state of the pull request | 
| GitHub.PR.MergedBy.Login | String | The login of the user who merged the pull request | 
| GitHub.PR.MergedBy.ID | Number | The ID of the user who merged the pull request | 
| GitHub.PR.MergedBy.NodeID | String | The node ID of the user who merged the pull request | 
| GitHub.PR.MergedBy.Type | String | The type of the user who merged the pull request | 
| GitHub.PR.MergedBy.SiteAdmin | Boolean | Whether the user who merged the pull request is a site admin or not | 
| GitHub.PR.Comments | Number | The number of comments on the pull request | 
| GitHub.PR.ReviewComments | Number | The number of review comments on the pull request | 
| GitHub.PR.MaintainerCanModify | Boolean | Whether the maintainer can modify the pull request or not | 
| GitHub.PR.Commits | Number | The number of commits in the pull request | 
| GitHub.PR.Additions | Number | The number of additions in the pull request | 
| GitHub.PR.Deletions | Number | The number of deletions in the pull request | 
| GitHub.PR.ChangedFiles | Number | The number of changed files in the pull request | 


#### Command Example
```!GitHub-list-branch-pull-requests branch_name=Update-Docker-Image```

#### Context Example
```json
{
 "GitHub": {
     "PR": {
         "ActiveLockReason": null,
         "Additions": null,
         "AuthorAssociation": "MEMBER",
         "Base": {
             "Label": "demisto:master",
             "Ref": "master",
             "Repo": {
                 "AllowMergeCommit": null,
                 "AllowRebaseMerge": null,
                 "AllowSquashMerge": null,
                 "Archived": false,
                 "CreatedAt": "2016-06-06T12:17:02Z",
                 "DefaultBranch": "master",
                 "Description": "Demisto is now Cortex XSOAR. Automate and orchestrate your Security Operations with Cortex XSOAR's ever-growing Content Repository. Pull Requests are always welcome and highly appreciated! ",
                 "Disabled": false,
                 "Fork": false,
                 "ForksCount": 678,
                 "FullName": "demisto/content",
                 "HasDownloads": true,
                 "HasIssues": false,
                 "HasPages": false,
                 "HasProjects": true,
                 "HasWiki": false,
                 "ID": 60525392,
                 "Language": "Python",
                 "Name": "content",
                 "NodeID": "MDEwOlJlcG9zaXRvcnk2MDUyNTM5Mg==",
                 "OpenIssuesCount": 181,
                 "Owner": {
                     "ID": 11011767,
                     "Login": "demisto",
                     "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3",
                     "SiteAdmin": false,
                     "Type": "Organization"
                 },
                 "Private": false,
                 "PushedAt": "2021-05-06T11:49:07Z",
                 "Size": 371861,
                 "StargazersCount": 635,
                 "SucscribersCount": null,
                 "Topics": null,
                 "UpdatedAt": "2021-05-06T11:41:27Z",
                 "WatchersCount": 635
             },
             "SHA": "9adf770fb981ec8bc9d6e87669be75da23176693",
             "User": {
                 "ID": 11011767,
                 "Login": "demisto",
                 "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3",
                 "SiteAdmin": false,
                 "Type": "Organization"
             }
         },
         "Body": "Updated Docker Images For Integrations",
         "ChangedFiles": null,
         "ClosedAt": null,
         "Comments": null,
         "Commits": null,
         "CreatedAt": "2021-05-03T14:29:25Z",
         "Deletions": null,
         "Draft": false,
         "Head": {
             "Label": "demisto:Update-Docker-Image",
             "Ref": "Update-Docker-Image",
             "Repo": {
                 "AllowMergeCommit": null,
                 "AllowRebaseMerge": null,
                 "AllowSquashMerge": null,
                 "Archived": false,
                 "CreatedAt": "2016-06-06T12:17:02Z",
                 "DefaultBranch": "master",
                 "Description": "Demisto is now Cortex XSOAR. Automate and orchestrate your Security Operations with Cortex XSOAR's ever-growing Content Repository. Pull Requests are always welcome and highly appreciated! ",
                 "Disabled": false,
                 "Fork": false,
                 "ForksCount": 678,
                 "FullName": "demisto/content",
                 "HasDownloads": true,
                 "HasIssues": false,
                 "HasPages": false,
                 "HasProjects": true,
                 "HasWiki": false,
                 "ID": 60525392,
                 "Language": "Python",
                 "Name": "content",
                 "NodeID": "MDEwOlJlcG9zaXRvcnk2MDUyNTM5Mg==",
                 "OpenIssuesCount": 181,
                 "Owner": {
                     "ID": 11011767,
                     "Login": "demisto",
                     "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3",
                     "SiteAdmin": false,
                     "Type": "Organization"
                 },
                 "Private": false,
                 "PushedAt": "2021-05-06T11:49:07Z",
                 "Size": 371861,
                 "StargazersCount": 635,
                 "SucscribersCount": null,
                 "Topics": null,
                 "UpdatedAt": "2021-05-06T11:41:27Z",
                 "WatchersCount": 635
             },
             "SHA": "baee6e30aaa0f52e676987c1968ffd3ce11d7e57",
             "User": {
                 "ID": 11011767,
                 "Login": "demisto",
                 "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3",
                 "SiteAdmin": false,
                 "Type": "Organization"
             }
         },
         "ID": 629143674,
         "Label": [
             {
                 "Color": null,
                 "Default": false,
                 "Description": "",
                 "ID": 1523790036,
                 "Name": "docs-approved",
                 "NodeID": "MDU6TGFiZWwxNTIzNzkwMDM2"
             }
         ],
         "Locked": false,
         "MaintainerCanModify": null,
         "MergeCommitSHA": "5854633d909c5672ba6ccf118c4dae68eb4e38c0",
         "Mergeable": null,
         "MergeableState": null,
         "Merged": null,
         "MergedAt": null,
         "NodeID": "MDExOlB1bGxSZXF1ZXN0NjI5MTQzNjc0",
         "Number": 12510,
         "Rebaseable": null,
         "ReviewComments": null,
         "State": "open",
         "UpdatedAt": "2021-05-03T14:48:58Z",
         "User": {
             "ID": 55035720,
             "Login": "content-bot",
             "NodeID": "MDQ6VXNlcjU1MDM1NzIw",
             "SiteAdmin": false,
             "Type": "User"
         }
     }
  }
}
```

#### Human Readable Output

>### Pull Request For Branch #Update-Docker-Image
>|AuthorAssociation|Base|Body|CreatedAt|Draft|Head|ID|Label|Locked|MergeCommitSHA|NodeID|Number|State|UpdatedAt|User|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| MEMBER | Label: demisto:master<br/>Ref: master<br/>SHA: 9adf770fb981ec8bc9d6e87669be75da23176693<br/>User: {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false}<br/>Repo: {"ID": 60525392, "NodeID": "MDEwOlJlcG9zaXRvcnk2MDUyNTM5Mg==", "Name": "content", "FullName": "demisto/content", "Owner": {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false}, "Private": false, "Description": "Demisto is now Cortex XSOAR. Automate and orchestrate your Security Operations with Cortex XSOAR's ever-growing Content Repository. Pull Requests are always welcome and highly appreciated! ", "Fork": false, "Language": "Python", "ForksCount": 678, "StargazersCount": 635, "WatchersCount": 635, "Size": 371861, "DefaultBranch": "master", "OpenIssuesCount": 181, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2021-05-06T11:49:07Z", "CreatedAt": "2016-06-06T12:17:02Z", "UpdatedAt": "2021-05-06T11:41:27Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null} | Updated Docker Images For Integrations | 2021-05-03T14:29:25Z | false | Label: demisto:Update-Docker-Image<br/>Ref: Update-Docker-Image<br/>SHA: baee6e30aaa0f52e676987c1968ffd3ce11d7e57<br/>User: {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false}<br/>Repo: {"ID": 60525392, "NodeID": "MDEwOlJlcG9zaXRvcnk2MDUyNTM5Mg==", "Name": "content", "FullName": "demisto/content", "Owner": {"Login": "demisto", "ID": 11011767, "NodeID": "MDEyOk9yZ2FuaXphdGlvbjExMDExNzY3", "Type": "Organization", "SiteAdmin": false}, "Private": false, "Description": "Demisto is now Cortex XSOAR. Automate and orchestrate your Security Operations with Cortex XSOAR's ever-growing Content Repository. Pull Requests are always welcome and highly appreciated! ", "Fork": false, "Language": "Python", "ForksCount": 678, "StargazersCount": 635, "WatchersCount": 635, "Size": 371861, "DefaultBranch": "master", "OpenIssuesCount": 181, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2021-05-06T11:49:07Z", "CreatedAt": "2016-06-06T12:17:02Z", "UpdatedAt": "2021-05-06T11:41:27Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null} | 629143674 | {'ID': 1523790036, 'NodeID': 'MDU6TGFiZWwxNTIzNzkwMDM2', 'Name': 'docs-approved', 'Description': '', 'Color': None, 'Default': False} | false | 5854633d909c5672ba6ccf118c4dae68eb4e38c0 | MDExOlB1bGxSZXF1ZXN0NjI5MTQzNjc0 | 12510 | open | 2021-05-03T14:48:58Z | Login: content-bot<br/>ID: 55035720<br/>NodeID: MDQ6VXNlcjU1MDM1NzIw<br/>Type: User<br/>SiteAdmin: false |

### Github-commit-file
***
Commits a given file.


#### Base Command

`Github-commit-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| commit_message | Commit message. | Required | 
| path_to_file | Path to the file in the Github repo (including file name and file ending). | Required | 
| entry_id | Entry ID for the file to commit. Either "entry_id" or "file_text" must be provided. | Optional | 
| file_text | Plain text for the file to commit. Either "entry_id" or "file_text" must be provided. | Optional | 
| branch_name | The branch name. | Required | 
| file_sha | The blob SHA of the file being replaced. Use the Github-list-files command to get the SHA value of the file.  Required if you are updating a file. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!Github-commit-file commit_message="test commit" path_to_file="TEST.md" branch_name=branch-for-pr file_sha=hjashd878ad file_text=Test```

#### Human Readable Output
The file TEST.md committed successfully. Link to the commit: https://github.com/content-bot/hello-world/commit/7678213ghg72136

### GitHub-create-release
***
Create a release.


#### Base Command

`GitHub-create-release`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the release. | Optional | 
| tag_name | The name of the releae tag. | Required | 
| body | Text describing the contents of the tag. | Optional | 
| draft | True to create a draft (unpublished) release, false to create a published one. Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Release.draft | Boolean | Whether the release is draft or not | 
| GitHub.Release.html_url | String | The release URL. | 
| GitHub.Release.id | Number | The ID of the release. | 
| GitHub.Release.url | String | Github API url link to the release. | 


#### Command Example
```!GitHub-create-release tag_name=1.0.0 body=`First release` draft=True name=1.0.0```

##### Context Example
```
{
    "GitHub.Release": [
        {
            "draft": true,
            "html_url": "https://github.com/demisto/sdk/releases/tag/1.0.0",
            "id": 4785254,
            "url": "https://api.github.com/repos/demisto/sdk/releases/1.0.0"
        }
    ]
}
```

#### Human Readable Output
Release 1.0.0 created successfully for repo sdk: https://github.com/demisto/sdk/releases/tag/1.0.0