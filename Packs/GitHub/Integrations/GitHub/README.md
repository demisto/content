## Overview
[GitHub](https://github.com/about) is an internet hosting provider that uses Git for software development and version control. It offers the distributed version control and source code management (SCM) functionality of Git, plus its own features. It provides access control and collaboration features such as bug tracking, feature requests, task management, continuous integration, and wikis for every project.

## Use Cases
This integration enables you to:
- Create, close, or update a GitHub issue.
- Get a list of all GitHub issues you have access to.
- Create a branch in GitHub.
- Get a list of a GitHub issue comments.
- Create or update a GitHub pull request.
- Search for a GitHub pull request.
- Get a list of files for a GitHub pull request.
- Get a list of inactive GitHub pull requests.
- Get the contents of a file in GitHub.
- Create a release.

## Configuration
To configure the GitHub integration on Cortex XSOAR you need to do the following (see below for more details):
1. Configure access to GitHub.
2. Configure integration parameters.

### Configure Access to GitHub

You can configure access to GitHub by either creating a personal access token or by creating a new GitHub app for Cortex XSOAR.

#### Create a Personal Access Token 
Personal access tokens (PATs) are an alternative to using passwords for authentication to GitHub when using the GitHub API. 
To generate a new token:
1. Navigate to the upper-right corner of any page and click your **profile photo**. 
2. In the left sidebar, click **Developer settings**. 
3. In the left sidebar, click **Personal access tokens** and click **Generate new token**. 
4. Give your token a descriptive name. 
5. To give your token an expiration, select the **Expiration drop-down** menu, then click a default or use the calendar picker. 
6. Select the **scopes**, or **permissions**, you want to grant this token. The minimum is read-only on repo.
7. Click **Generate token** and copy the token generated.

#### Create a new GitHub App for Cortex XSOAR

Another authentication option is to create and register a GitHub app under your personal account or under any organization you have administrative access to.
1. Navigate to the upper-right corner of any page and click your **profile photo**:
   - For a personal account owned app, go to your **Account Settings**.
   - For an organization owned app, click Your organizations. To the right of the organization, click **Settings**.
2. In the left sidebar, click **Developer settings**, from the sub-menu, click **GitHub Apps**.
3. Click **New GitHub App**. 
   - In **GitHub App name**, type the name of your app. 
   - In **Homepage URL**, type any URL (this field is required).
   - Deselect the **Active** option under the **Webhook settings**.
   - In **Permissions**, choose the permissions your app will request. For each type of permission, use the drop-down menu and click Read-only, Read & write, or No access. The minimum is read-only permissions for **Pull requests**, **Checks**, **Pull requests**, **Security events**, and **Commit statuses**.
   - Click **Create GitHub App**. 
   - Click to generate a **private key** to install your GitHub app.
4. Once you create a private GitHub app, you can install it on one of your org or user repositories.
   - From the **GitHub Apps settings** page, select your app.
   - In the left sidebar, click **Install App**.
   - Click **Install** next to the organization or user account containing the correct repository.
   - Install the app on all repositories or on selected repositories. 
   - Once installed, you will see configuration options for the app on your selected account. 
5. Copy the **private key** generated above to a new credentials object.

### Configure Integration Parameters

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GitHub.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                                                                                                    | **Required** |
    | --- | --- |
    | Fetch incidents                                                                                                  | False |
    | Select an Issue or Pull requests to Fetch                                                                        | False |
    | API Token, use the personal token created above                                                                                                        | False |
    | Credentials, use the credentials object created above                                                                                                     | False |
    | Username of the repository owner or the ogranization name, for example: github.com/repos/{_owner_}/{repo}/issues | False |
    | The name of the requested repository                                                                             | False |
    | First fetch interval (in days)                                                                                   | False |
    | Use system proxy settings                                                                                        | False |
    | Trust any certificate (not secure)                                                                               | False |
    | Incident type                                                                                                    | False |
    | GitHub app integration ID                                                                                        | False |
    | GitHub app installation ID                                                                                       | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI as part of an automation or in a playbook. After you successfully
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
| GitHub.Issue.Labels | String | The labels applied to the issue. | 
| GitHub.Issue.Assignees | String | The users assigned to this issue. | 
| GitHub.Issue.Created_at | Date | The date the issue was created. | 
| GitHub.Issue.Updated_at | Date | The date the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | The date the issue was closed. | 
| GitHub.Issue.Closed_by | String | The user who closed the issue. | 
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
| GitHub.Issue.Labels | String | The labels applied to the issue. | 
| GitHub.Issue.Assignees | String | The users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | The date the issue was created. | 
| GitHub.Issue.Updated_at | Date | The date the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | The date the issue was closed. | 
| GitHub.Issue.Closed_by | String | The user who closed the issue. | 
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
| GitHub.Issue.Labels | String | The labels applied to the issue. | 
| GitHub.Issue.Assignees | String | The users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | The date the issue was created. | 
| GitHub.Issue.Updated_at | Date | The date the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | The date the issue was closed. | 
| GitHub.Issue.Closed_by | String | The user who closed the issue. | 
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
| limit | The number of issues to return. Default is 50. Maximum is 200. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Issue.ID | Number | The ID of the issue. | 
| GitHub.Issue.Repository | String | The repository of the issue. | 
| GitHub.Issue.Title | String | The title of the issue. | 
| GitHub.Issue.Body | Unknown | The body of the issue. | 
| GitHub.Issue.State | String | The state of the issue. | 
| GitHub.Issue.Labels | String | The labels applied to the issue. | 
| GitHub.Issue.Assignees | String | The users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | The date the issue was created. | 
| GitHub.Issue.Updated_at | Date | The date the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | The date the issue was closed. | 
| GitHub.Issue.Closed_by | String | The user who closed the issue. | 
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
| query | The query line for the search. For more information see the [GitHub documentation](https://docs.github.com/en/github/searching-for-information-on-github/searching-code). | Required | 
| page_number | The page number. | Optional | 
| page_size | The size of the requested page. Maximum is 100. | Optional | 
| limit | The number of results to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.CodeSearchResults.name | String | The file name where the code is found. | 
| GitHub.CodeSearchResults.path | String | The full file path where the code is found. | 
| GitHub.CodeSearchResults.html_url | String | The URL to the file. | 
| GitHub.CodeSearchResults.repository.full_name | String | The repository name. | 
| GitHub.CodeSearchResults.repository.html_url | String | The URL to the repository. | 
| GitHub.CodeSearchResults.repository.description | String | The repository description. | 
| GitHub.CodeSearchResults.repository.private | Boolean | True if the repository is private, false if public. | 
| GitHub.CodeSearchResults.repository.id | String | The ID of the repository. | 
| GitHub.CodeSearchResults.repository.releases_url | String | The URL to the releases of the repository. | 
| GitHub.CodeSearchResults.repository.branches_url | String | The URL to the branches of the repository. | 
| GitHub.CodeSearchResults.repository.commits_url | String | The URL to the commits of the repository. | 


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
| GitHub.Issue.Labels | String | The labels applied to the issue. | 
| GitHub.Issue.Assignees | String | The users assigned to the issue. | 
| GitHub.Issue.Created_at | Date | The date the issue was created. | 
| GitHub.Issue.Updated_at | Date | The date the issue was last updated. | 
| GitHub.Issue.Closed_at | Date | The date the issue was closed. | 
| GitHub.Issue.Closed_by | String | The user who closed the issue. | 
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
| GitHub.Release.ID | Number | The ID of the release. | 
| GitHub.Release.Download_count | Number | The download count for the release. | 
| GitHub.Release.Name | String | The name of the release. | 
| GitHub.Release.Body | String | The body of the release. | 
| GitHub.Release.Created_at | Date | The date the release was created. | 
| GitHub.Release.Published_at | Date | The date the release was published. | 

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
Gets inactive pull requests.

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
| GitHub.Branch.Name | String | The name of the branch. | 
| GitHub.Branch.CommitSHA | String | The SHA of the commit the branch references. | 
| GitHub.Branch.CommitNodeID | String | The Node ID of the commit the branch references. | 
| GitHub.Branch.CommitAuthorID | Number | The GitHub ID number of the author of the commit the branch references. | 
| GitHub.Branch.CommitAuthorLogin | String | The GitHub login of the author of the commit the branch references. | 
| GitHub.Branch.CommitParentSHA | String | The SHAs of parent commits. | 
| GitHub.Branch.Protected | Boolean | Whether the branch is protected. | 

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
Retrieves a user membership status with a team.

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
| GitHub.Team.Member.Role | String | The user's role on a team .| 
| GitHub.Team.Member.State | String | The user's state for a team. | 
| GitHub.Team.ID | Number | The ID number of the team. | 
| GitHub.Team.Member.Login | String | The login of the team member. | 

#### Command Example

```!GitHub-get-team-membership team_id=3043448 user_name=example-user2```

#### Human Readable Output
## Team Membership of example-user2
|ID|Role|State|Login|
|--- |--- |--- |--- |
|3043448|member|active|example-user2|


### GitHub-request-review

***
Requests reviews from GitHub users for a given pull request.

#### Base Command

`GitHub-request-review`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The number of the pull request you want to request review for. | Required | 
| reviewers | A CSV list of GitHub users to request review from for a pull request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.Number | Number | The number of the pull request. | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review. | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.NodeID | String | The node ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review. | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site admin. | 

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
Creates a comment for a given issue.

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
| GitHub.Comment.IssueNumber | Number | The number of the issue to which the comment belongs. | 
| GitHub.Comment.ID | Number | The ID of the comment. | 
| GitHub.Comment.NodeID | String | The node ID of the comment. | 
| GitHub.Comment.Body | String | The body content of the comment. | 
| GitHub.Comment.User.Login | String | The login of the user who commented. | 
| GitHub.Comment.User.ID | Number | The ID of the user who commented. | 
| GitHub.Comment.User.NodeID | String | The node ID of the user who commented. | 
| GitHub.Comment.User.Type | String | The type of the user who commented. | 
| GitHub.Comment.User.SiteAdmin | Boolean | Whether the user who commented is a site admin. | 

#### Command Example

```!GitHub-create-comment issue_number=1 body="Look this comment was made using the GitHub integration"```

#### Human Readable Output
## Created Comment
|Body|ID|IssueNumber|NodeID|User|
|--- |--- |--- |--- |--- |
|This comment was made using the GitHub integration|532700206|1|MDEyOklzc3VlQ29tbWVudDUzMjcwMDIwNg==|Login: example-user1 ID: 55035720 NodeID: MDQ6VXNlcjU1MDM1NzIw Type: User SiteAdmin: false|


### GitHub-list-issue-comments

***
Lists comments on an issue.

#### Base Command

`GitHub-list-issue-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_number | The number of the issue to list comments for. | Required |
| since | Only show notifications updated after the given time. This is a timestamp in ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Comment.IssueNumber | Number | The number of the issue to which the comment belongs. | 
| GitHub.Comment.ID | Number | The ID of the comment. | 
| GitHub.Comment.NodeID | String | The node ID of the comment. | 
| GitHub.Comment.Body | String | The body content of the comment. | 
| GitHub.Comment.User.Login | String | The login of the user who commented. | 
| GitHub.Comment.User.ID | Number | The ID of the user who commented. | 
| GitHub.Comment.User.NodeID | String | The node ID of the user who commented. | 
| GitHub.Comment.User.Type | String | The type of the user who commented. | 
| GitHub.Comment.User.SiteAdmin | Boolean | Whether the user who commented is a site admin. | 

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
| GitHub.PR.Number | Number | The number of the pull request. | 
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
Lists reviews on a pull request.

#### Base Command

`GitHub-list-pr-reviews`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The number of the pull request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PR.Number | Number | The number of the pull request. | 
| GitHub.PR.Review.ID | Number | The ID of the review. | 
| GitHub.PR.Review.NodeID | String | The node ID of the review. | 
| GitHub.PR.Review.Body | String | The content of the review. | 
| GitHub.PR.Review.CommitID | String | The ID of the commit the review is for. | 
| GitHub.PR.Review.State | String | The state of the review. | 
| GitHub.PR.Review.User.Login | String | The reviewer's user login. | 
| GitHub.PR.Review.User.ID | Number | The reviewer's user ID. | 
| GitHub.PR.Review.User.NodeID | String | The reviewer's user node ID. | 
| GitHub.PR.Review.User.Type | String | The reviewer user type. | 
| GitHub.PR.Review.User.SiteAdmin | Boolean | Whether the reviewer is a site admin. | 

#### Command Example

```!GitHub-list-pr-reviews pull_number=1```

#### Human Readable Output
## Pull Request Reviews for #1
|Body|CommitID|ID|NodeID|State|User|
|--- |--- |--- |--- |--- |--- |
|review comment|b6cf0431e2aea2b345ea1d66d18aa72be63936a9|287327154|MDE3OlB1bGxSZXF1ZXN0UmV2aWV3Mjg3MzI3MTU0|COMMENTED|Login: example-user2 ID: 31018228 NodeID: MDQ6VXNlcjMxMDE4MjI4 Type: User SiteAdmin: false|


### GitHub-get-commit

***
Gets a commit.

#### Base Command

`GitHub-get-commit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| commit_sha | The SHA hash of the commit. Try executing the 'GitHub-get-branch' command to find a commit SHA hash to reference. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Commit.SHA | String | The SHA hash of the commit. | 
| GitHub.Commit.Author.Date | String | The commit author date. | 
| GitHub.Commit.Author.Name | String | The name of the author. | 
| GitHub.Commit.Author.Email | String | The email of the author. | 
| GitHub.Commit.Committer.Date | String | The date the committer committed. | 
| GitHub.Commit.Committer.Name | String | The name of the committer. | 
| GitHub.Commit.Committer.Email | String | The email of the committer.| 
| GitHub.Commit.Message | String | The message associated with the commit. | 
| GitHub.Commit.Parent | Unknown | List of parent SHA hashes. | 
| GitHub.Commit.TreeSHA | String | The SHA hash of the commit's tree. | 
| GitHub.Commit.Verification.Verified | Boolean | Whether the commit was verified. | 
| GitHub.Commit.Verification.Reason | String | The reason why the commit was or was not verified. | 
| GitHub.Commit.Verification.Signature | Unknown | The commit verification signature. | 
| GitHub.Commit.Verification.Payload | Unknown | The commit verification payload. | 

#### Command Example

```!GitHub-get-commit commit_sha=8a67a078139498f3e8e1bd2e26ffc5a2fea1b918```

#### Human Readable Output
## Commit *8a67a07813*
|Author|Committer|Message|Parent|SHA|TreeSHA|Verification|
|--- |--- |--- |--- |--- |--- |--- |
|Date: 2019-09-16T15:42:43Z Name: example-user1 Email: 55035720example.user1@users.noreply.github.com|Date: 2019-09-16T15:42:43Z Name: GitHub Email: noreply@github.com|Update config.yml|{'SHA': 'd6bafef5a0021a6d9ab0a22e11bd0afd5801d936'}|8a67a078139498f3e8e1bd2e26ffc5a2fea1b918|42fdb6c89538099a141e94fabe4bbc58098f4d90|Verified: true Reason: valid Signature: -----BEGIN PGP SIGNATURE-----  wsBcBAABCAAQBQJ****************************sIKrPT2jUSWyzfu5wnu oWz7+2KMdaglV****************************M08HXTm a9eO/ahlodARkgH/bWjulomeO+jDEgbZenlPUrBnX136QzPPqgl4uvxfquAOj1/a a89YtPAFh2X1+1q7pl5dVtZfYpo6mYJoY9dwVpDRbLoVHJRa1wnqEv4kxRHrrRL9 mGWSMHqK8I6j9zXi4niod8pQpl0k4O/2SlNh81RyeILEYb587Zs1XGuIYQEDrcAf u+FURxEHSuT4yaZ+oBwhhcIsmsWQMGkfABbwo1Fi2BMtEgZpzd/TScNg1KeSrVI= =dWrz -----END PGP SIGNATURE-----  Payload: tree 42fdb6c89538099a141e94fabe4bbc58098f4d90 parent d6bafef5a0021a6d9ab0a22e11bd0afd5801d936 author example-user1 <55035720example.user1@users.noreply.github.com> 1568648563 +0300 committer GitHub <noreply@github.com> 1568648563 +0300  Update config.yml|


### GitHub-add-label

***
Adds labels to an issue.

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
Gets a pull request.

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
| GitHub.PR.ID | Number | The ID number of the pull request. | 
| GitHub.PR.NodeID | String | The node ID of the pull request. | 
| GitHub.PR.Number | Number | The issue number of the pull request. | 
| GitHub.PR.State | String | The state of the pull request. | 
| GitHub.PR.Locked | Boolean | Whether the pull request is locked. | 
| GitHub.PR.Title | String | The title of the pull request. | 
| GitHub.PR.User.Login | String | The login of the user who opened the pull request. | 
| GitHub.PR.User.ID | Number | The ID of the user who opened the pull request. | 
| GitHub.PR.User.NodeID | String | The node ID of the user who opened the pull request. | 
| GitHub.PR.User.Type | String | The type of the user who opened the pull request. | 
| GitHub.PR.User.SiteAdmin | Boolean | Whether the user who opened the pull request is a site admin. | 
| GitHub.PR.Body | String | The body content of the pull request. | 
| GitHub.PR.Label.ID | Number | The ID of the label. | 
| GitHub.PR.Label.NodeID | String | The node ID of the label. | 
| GitHub.PR.Label.Name | String | The name of the label. | 
| GitHub.PR.Label.Description | String | The description of the label. | 
| GitHub.PR.Label.Color | String | The hex color value of the label. | 
| GitHub.PR.Label.Default | Boolean | Whether the label is a default. | 
| GitHub.PR.Milestone.ID | Number | The ID of the milestone. | 
| GitHub.PR.Milestone.NodeID | String | The node ID of the milestone. | 
| GitHub.PR.Milestone.Number | Number | The number of the milestone. | 
| GitHub.PR.Milestone.State | String | The state of the milestone. | 
| GitHub.PR.Milestone.Title | String | The title of the milestone. | 
| GitHub.PR.Milestone.Description | String | The description of the milestone. | 
| GitHub.PR.Milestone.Creator.Login | String | The login of the milestone creator. | 
| GitHub.PR.Milestone.Creator.ID | Number | The ID the milestone creator. | 
| GitHub.PR.Milestone.Creator.NodeID | String | The node ID of the milestone creator. | 
| GitHub.PR.Milestone.Creator.Type | String | The type of the milestone creator. | 
| GitHub.PR.Milestone.Creator.SiteAdmin | Boolean | Whether the milestone creator is a site admin. | 
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
| GitHub.PR.Assignee.NodeID | String | The node ID of the user assigned to the pull request. | 
| GitHub.PR.Assignee.Type | String | The type of the user assigned to the pull request. | 
| GitHub.PR.Assignee.SiteAdmin | Boolean | Whether the user assigned to the pull request is a site admin. | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review. | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.NodeID | String | The node ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review. | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site admin. | 
| GitHub.PR.RequestedTeam.ID | Number | The ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.NodeID | String | The node ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.Name | String | The name of the team requested for review. | 
| GitHub.PR.RequestedTeam.Slug | String | The slug of the team requested for review. | 
| GitHub.PR.RequestedTeam.Description | String | The description of the team requested for review. | 
| GitHub.PR.RequestedTeam.Privacy | String | The privacy setting of the team requested for review. | 
| GitHub.PR.RequestedTeam.Permission | String | The permissions of the team requested for review. | 
| GitHub.PR.RequestedTeam.Parent | Unknown | The parent of the team requested for review. | 
| GitHub.PR.Head.Label | String | The label of the branch that HEAD points to. | 
| GitHub.PR.Head.Ref | String | The reference of the branch that HEAD points to. | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit that HEAD points to. | 
| GitHub.PR.Head.User.Login | String | The login of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.ID | Number | The ID of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.NodeID | String | The node ID of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.Type | String | The type of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.SiteAdmin | Boolean | Whether the committer of the HEAD commit of the checked out branch is a site admin. | 
| GitHub.PR.Head.Repo.ID | Number | The ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.NodeID | String | The node ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Name | String | The name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.FullName | String | The full name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Login | String | The user login of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.ID | Number | The user ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user node ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Type | String | The user type of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository of the checked out branch is a site admin. | 
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
| GitHub.PR.Base.User.Login | String | The login of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.NodeID | String | The node ID of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.Type | String | The user type of the committer of the commit that the base branch points to | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit that the base branch points to is a site admin. | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.NodeID | String | The node ID of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository that the base branch belongs to is a site admin. | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository that the base branch belongs to is private. | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository that the base branch belongs to is a fork. | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times that the repository that the base branch belongs to has been forked. | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times that the repository that the base branch belongs to has been starred. | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository that the base branch belongs to has issues. | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository that the base branch belongs to has projects. | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository that the base branch belongs to has a wiki. | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository that the base branch belongs to has pages. | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository that the base branch belongs to has downloads. | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository that the base branch belongs to is archived. | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository that the base branch belongs to is disabled. | 
| GitHub.PR.Base.Repo.PushedAt | String | The date that the repository that the base branch belongs to was last pushed to. | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date that the repository that the base branch belongs to was last updated. | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository that the base branch belongs to allows rebase-style merges. | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository that the base branch belongs to allows squash merges. | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository that the base branch belongs to allows merge commits. | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities that subscribe to the repository that the base branch belongs to. | 
| GitHub.PR.AuthorAssociation | String | The pull request author association. | 
| GitHub.PR.Draft | Boolean | Whether the pull request is a draft. | 
| GitHub.PR.Merged | Boolean | Whether the pull request is merged. | 
| GitHub.PR.Mergeable | Boolean | Whether the pull request is mergeable. | 
| GitHub.PR.Rebaseable | Boolean | Whether the pull request is rebaseable. | 
| GitHub.PR.MergeableState | String | The mergeable state of the pull request. | 
| GitHub.PR.MergedBy.Login | String | The login of the user who merged the pull request. | 
| GitHub.PR.MergedBy.ID | Number | The ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.NodeID | String | The node ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.Type | String | The type of the user who merged the pull request. | 
| GitHub.PR.MergedBy.SiteAdmin | Boolean | Whether the user who merged the pull request is a site admin. | 
| GitHub.PR.Comments | Number | The number of comments on the pull request. | 
| GitHub.PR.ReviewComments | Number | The number of review comments on the pull request. | 
| GitHub.PR.MaintainerCanModify | Boolean | Whether the maintainer can modify the pull request. | 
| GitHub.PR.Commits | Number | The number of commits in the pull request. | 
| GitHub.PR.Additions | Number | The number of additions in the pull request. | 
| GitHub.PR.Deletions | Number | The number of deletions in the pull request. | 
| GitHub.PR.ChangedFiles | Number | The number of changed files in the pull request. | 

#### Command Example

```!GitHub-get-pull-request pull_number=1```

#### Human Readable Output
## Pull Request #1
|Additions|AuthorAssociation|Base|Body|ChangedFiles|Comments|Commits|CreatedAt|Deletions|Head|ID|Label|Locked|MaintainerCanModify|MergeCommitSHA|Mergeable|MergeableState|Merged|NodeID|Number|Rebaseable|RequestedReviewer|ReviewComments|State|UpdatedAt|User|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|4|FIRST_TIME_CONTRIBUTOR|Label: example-user1:master Ref: master SHA: b27ea6ac9836d2e756b44eb1d66f02d3d4299362 User: {"Login": "example-user1", "ID": 55035720, "NodeID": "MDQ6VXNlcjU1MDM1NzIw", "Type": "User", "SiteAdmin": false} Repo: {"ID": 207744685, "NodeID": "MDEwOlJlcG9zaXRvcnkyMDc3NDQ2ODU=", "Name": "content", "FullName": "example-user1/content", "Owner": {"Login": "example-user1", "ID": 55035720, "NodeID": "MDQ6VXNlcjU1MDM1NzIw", "Type": "User", "SiteAdmin": false}, "Private": false, "Description": "This repository contains all Demisto content and from here we share content updates", "Fork": true, "Language": "Python", "ForksCount": 0, "StargazersCount": 0, "WatchersCount": 0, "Size": 96530, "DefaultBranch": "master", "OpenIssuesCount": 10, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2019-09-18T14:05:43Z", "CreatedAt": "2019-09-11T06:59:20Z", "UpdatedAt": "2019-09-16T15:42:46Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|## Status Ready/In Progress/In Hold(Reason for hold)  ## Related Issues fixes: link to the issue  ## Description A few sentences describing the overall goals of the pull request's commits.  ## Screenshots Paste here any images that will help the reviewer  ## Related PRs List related PRs against other branches:  branch \ PR ------ \ ## Required version of Demistox.x.x ## Does it break backward compatibility?- Yes- Further details:- No ## Must have- [ ] Tests- [ ] Documentation (with link to it)- [ ] Code Review ## DependenciesMention the dependencies of the entity you changed as given from the precommit hooks in checkboxes, and tick after tested them.- [ ] Dependency 1- [ ] Dependency 2- [ ] Dependency 3 ## Additional changesDescribe additional changes done, for example adding a function to common server.|1|5|4|2019-09-11T07:06:26Z|0|Label: example-user4:patch-1 Ref: patch-1 SHA: c01238eea80e35bb76a5c51ac0c95eba4010d8e5 User: {"Login": "example-user4", "ID": 46294017, "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3", "Type": "User", "SiteAdmin": false} Repo: {"ID": 205137013, "NodeID": "MDEwOlJlcG9zaXRvcnkyMDUxMzcwMTM=", "Name": "content", "FullName": "example-user4/content", "Owner": {"Login": "example-user4", "ID": 46294017, "NodeID": "MDQ6VXNlcjQ2Mjk0MDE3", "Type": "User", "SiteAdmin": false}, "Private": false, "Description": "This repository contains all Demisto content and from here we share content updates", "Fork": true, "Language": "Python", "ForksCount": 2, "StargazersCount": 0, "WatchersCount": 0, "Size": 95883, "DefaultBranch": "master", "OpenIssuesCount": 2, "Topics": null, "HasIssues": false, "HasProjects": true, "HasWiki": false, "HasPages": false, "HasDownloads": true, "Archived": false, "Disabled": false, "PushedAt": "2019-09-16T15:43:54Z", "CreatedAt": "2019-08-29T10:18:15Z", "UpdatedAt": "2019-08-29T10:18:18Z", "AllowRebaseMerge": null, "AllowSquashMerge": null, "AllowMergeCommit": null, "SucscribersCount": null}|316303415|'ID': 1563600288, 'NodeID': 'MDU6TGFiZWwxNTYzNjAwMjg4', 'Name': 'Content', 'Description': None, 'Color': None, 'Default': False},{'ID': 1549466359, 'NodeID': 'MDU6TGFiZWwxNTQ5NDY2MzU5', 'Name': 'Contribution', 'Description': None, 'Color': None, 'Default': False},{'ID': 1549411616, 'NodeID': 'MDU6TGFiZWwxNTQ5NDExNjE2', 'Name': 'bug', 'Description': None, 'Color': None, 'Default': True}|false|true|5714b1359b9d7549c89c35fe9fdc266a3db3b766|true|unstable|false|MDExOlB1bGxSZXF1ZXN0MzE2MzAzNDE1|1|true|{'Login': 'example-user3', 'ID': 30797606, 'NodeID': 'MDQ6VXNlcjMwNzk3NjA2', 'Type': 'User', 'SiteAdmin': False}, {'Login': 'example-user1', 'ID': 55035720, 'NodeID': 'MDQ6VXNlcjU1MDM1NzIw', 'Type': 'User', 'SiteAdmin': False}|0|open|2019-09-18T14:05:51Z|Login: example-user4 ID: 46294017 NodeID: MDQ6VXNlcjQ2Mjk0MDE3 Type: User SiteAdmin: false|


### GitHub-list-teams

***
Lists the teams for an organization. Note that this API call is only available to authenticated members of the organization.

#### Base Command

`GitHub-list-teams`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | The name of the organization. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Team.ID | Number | The ID of the team. | 
| GitHub.Team.NodeID | String | The node ID of the team. | 
| GitHub.Team.Name | String | The name of the team. | 
| GitHub.Team.Slug | String | The slug of the team. | 
| GitHub.Team.Description | String | The description of the team. | 
| GitHub.Team.Privacy | String | The privacy setting of the team. | 
| GitHub.Team.Permission | String | The permissions of the team. | 
| GitHub.Team.Parent | Unknown | The parent of the team. | 

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
Deletes a branch.

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
| GitHub.PR.ReviewComment.DiffHunk | String | The diff hunk the review comment applies to. | 
| GitHub.PR.ReviewComment.Path | String | The file path of the proposed file changes the review comment applies to. | 
| GitHub.PR.ReviewComment.Position | Number | The position of the change the review comment applies to. | 
| GitHub.PR.ReviewComment.OriginalPosition | Number | The original position of the change the review comment applies to. | 
| GitHub.PR.ReviewComment.CommitID | String | The commit ID of the proposed change. | 
| GitHub.PR.ReviewComment.OriginalCommitID | String | The commit ID of the commit before the proposed change. | 
| GitHub.PR.ReviewComment.InReplyToID | Number | The reply ID of the comment the review comment applies to. | 
| GitHub.PR.ReviewComment.User.Login | String | The login of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.ID | Number | The ID of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.NodeID | String | The Node ID of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.Type | String | The type of the user who created the review comment. | 
| GitHub.PR.ReviewComment.User.SiteAdmin | Boolean | Whether the user who created the review comment is a site administrator. | 
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
| state | The new state of the pull request. Possible values are: open, closed. | Optional | 
| base | The name of the branch to pull your changes from. It must be an existing branch in the current repository. You cannot update the base branch in a pull request to point to another repository. | Optional | 
| maintainer_can_modify | Indicates whether maintainers can modify the pull request. | Optional | 
| pull_number | The issue number of the pull request to modify. | Required | 

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
| GitHub.PR.Head.Label | String | The label of the branch the HEAD points to. | 
| GitHub.PR.Head.Ref | String | The reference of the branch the HEAD points to. | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit the HEAD points to. | 
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
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user node ID of the owner of the repository of the checked out branch. | 
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
| GitHub.PR.Base.User.Login | String | The committer login of the commit the base branch points to. | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit the base branch points to. | 
| GitHub.PR.Base.User.NodeID | String | The committer Node ID of the commit the base branch points to. | 
| GitHub.PR.Base.User.Type | String | The user committer type of the commit the base branch points to. | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit the base branch points to is a site administrator. | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.NodeID | String | The Node ID of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository the base branch belongs to is a site administrator. | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository the base branch belongs to is private. | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository the base branch to belongs to is a fork. | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times the repository the base branch belongs to has been forked. | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times the repository the base branch belongs to has been starred. | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository the base branch belongs to has issues. | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository the base branch belongs to has projects. | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository the base branch belongs to has a wiki. | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository the base branch belongs to has pages. | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository the base branch belongs to has downloads. | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository the base branch belongs to is archived. | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository the base branch belongs to is disabled. | 
| GitHub.PR.Base.Repo.PushedAt | String | The date the repository the base branch belongs to was last pushed. | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date the repository the base branch belongs to was last updated. | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository the base branch belongs to allows rebase-style merges. | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository the base branch belongs to allows squash merges. | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository the base branch belongs to allows merge commits. | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities to subscribe to the repository that the base branch belongs to. | 
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
has not been merged, the API returns 'Status: 404 Not Found'

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
| maintainer_can_modify | Indicates whether maintainers can modify the pull request. | Optional | 
| draft | Indicates whether the pull request is a draft. For more information, see https://help.github.com/en/articles/about-pull-requests#draft-pull-requests. | Optional | 

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
| GitHub.PR.Head.Label | String | The label of the branch the HEAD points to. | 
| GitHub.PR.Head.Ref | String | The reference of the branch the HEAD points to. | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit the HEAD points to. | 
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
| GitHub.PR.Base.User.Login | String | The committer login of the commit the base branch points to. | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit the base branch points to. | 
| GitHub.PR.Base.User.NodeID | String | The committer Node ID of the commit the base branch points to. | 
| GitHub.PR.Base.User.Type | String | The user type of the committer the commit base branch points to. | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit the base branch points to is a site administrator. | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.NodeID | String | The Node ID of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository the base branch belongs to is a site administrator. | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository the base branch belongs to is private. | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository the base branch belongs to is a fork. | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times the repository the base branch belongs to has been forked. | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times the repository the base branch belongs to has been starred. | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository the base branch belongs to has issues. | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository the base branch belongs to has projects. | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository the base branch belongs to has a wiki. | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository the base branch belongs to has pages. | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository the base branch belongs to has downloads. | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository the base branch belongs to is archived. | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository the base branch belongs to is disabled. | 
| GitHub.PR.Base.Repo.PushedAt | String | The date the repository the base branch belongs to was last pushed. | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository the base branch belongs to. | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date the repository the base branch belongs to was last updated. | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository the base branch belongs to allows rebase-style merges. | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository the base branch belongs to allows squash merges. | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository the base branch belongs to allows merge commits. | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities that subscribe to the repository the base branch belongs to. | 
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
Gets the usage details of GitHub action workflows of private repositories by repository owner.

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
| GitHub.ActionsUsage.WorkflowUsage | Unknown | The GitHub action workflow usage on different OS. | 

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
| branch_name | The branch name to get the file from. | Optional | 
| media_type | The media type in which the file contents will be fetched. Possible values are: "raw" and "html". Default value is "raw". | Optional | 
| create_file_from_content | Whether to create a file entry in the War Room with the file contents. Default value is "false". | Optional | 
| organization | The name of the organization. | Optional | 
| repository | The name of the repository. | Optional | 

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
Gets a list of files from the given path in the repository.


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
| GitHub.File.DownloadUrl | String | The link to download the file content. | 
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
| team_slug | The name of the team under the organization. | Required | 
| maximum_users | The maximum number of users to return. | Optional | 
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
## Team Member of team content in organization XSOAR
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
| GitHub.PR.ID | Number | The ID number of the pull request. | 
| GitHub.PR.NodeID | String | The node ID of the pull request. | 
| GitHub.PR.Number | Number | The issue number of the pull request. | 
| GitHub.PR.State | String | The state of the pull request. | 
| GitHub.PR.Locked | Boolean | Whether the pull request is locked. | 
| GitHub.PR.User.Login | String | The login of the user who opened the pull request. | 
| GitHub.PR.User.ID | Number | The ID of the user who opened the pull request. | 
| GitHub.PR.User.NodeID | String | The node ID of the user who opened the pull request. | 
| GitHub.PR.User.Type | String | The type of the user who opened the pull request. | 
| GitHub.PR.User.SiteAdmin | Boolean | Whether the user who opened the pull request is a site admin. | 
| GitHub.PR.Body | String | The body content of the pull request. | 
| GitHub.PR.Label.ID | Number | The ID of the label. | 
| GitHub.PR.Label.NodeID | String | The node ID of the label. | 
| GitHub.PR.Label.Name | String | The name of the label. | 
| GitHub.PR.Label.Description | String | The description of the label. | 
| GitHub.PR.Label.Color | String | The hex color value of the label. | 
| GitHub.PR.Label.Default | Boolean | Whether the label is a default. | 
| GitHub.PR.Milestone.ID | Number | The ID of the milestone. | 
| GitHub.PR.Milestone.NodeID | String | The node ID of the milestone. | 
| GitHub.PR.Milestone.Number | Number | The number of the milestone. | 
| GitHub.PR.Milestone.State | String | The state of the milestone. | 
| GitHub.PR.Milestone.Title | String | The title of the milestone. | 
| GitHub.PR.Milestone.Description | String | The description of the milestone. | 
| GitHub.PR.Milestone.Creator.Login | String | The login of the milestone creator. | 
| GitHub.PR.Milestone.Creator.ID | Number | The ID the milestone creator. | 
| GitHub.PR.Milestone.Creator.NodeID | String | The node ID of the milestone creator. | 
| GitHub.PR.Milestone.Creator.Type | String | The type of the milestone creator. | 
| GitHub.PR.Milestone.Creator.SiteAdmin | Boolean | Whether the milestone creator is a site admin. | 
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
| GitHub.PR.Assignee.NodeID | String | The node ID of the user assigned to the pull request. | 
| GitHub.PR.Assignee.Type | String | The type of the user assigned to the pull request. | 
| GitHub.PR.Assignee.SiteAdmin | Boolean | Whether the user assigned to the pull request is a site admin. | 
| GitHub.PR.RequestedReviewer.Login | String | The login of the user requested for review. | 
| GitHub.PR.RequestedReviewer.ID | Number | The ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.NodeID | String | The node ID of the user requested for review. | 
| GitHub.PR.RequestedReviewer.Type | String | The type of the user requested for review. | 
| GitHub.PR.RequestedReviewer.SiteAdmin | Boolean | Whether the user requested for review is a site admin. | 
| GitHub.PR.RequestedTeam.ID | Number | The ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.NodeID | String | The node ID of the team requested for review. | 
| GitHub.PR.RequestedTeam.Name | String | The name of the team requested for review. | 
| GitHub.PR.RequestedTeam.Slug | String | The slug of the team requested for review. | 
| GitHub.PR.RequestedTeam.Description | String | The description of the team requested for review. | 
| GitHub.PR.RequestedTeam.Privacy | String | The privacy setting of the team requested for review. | 
| GitHub.PR.RequestedTeam.Permission | String | The permissions of the team requested for review. | 
| GitHub.PR.RequestedTeam.Parent | Unknown | The parent of the team requested for review. | 
| GitHub.PR.Head.Label | String | The label of the branch the HEAD points to. | 
| GitHub.PR.Head.Ref | String | The reference of the branch the HEAD points to. | 
| GitHub.PR.Head.SHA | String | The SHA hash of the commit the HEAD points to. | 
| GitHub.PR.Head.User.Login | String | The login of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.ID | Number | The ID of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.NodeID | String | The node ID of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.Type | String | The type of the committer of the HEAD commit of the checked out branch. | 
| GitHub.PR.Head.User.SiteAdmin | Boolean | Whether the committer of the HEAD commit of the checked out branch is a site admin. | 
| GitHub.PR.Head.Repo.ID | Number | The ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.NodeID | String | The node ID of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Name | String | The name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.FullName | String | The full name of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Login | String | The user login of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.ID | Number | The user ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.NodeID | String | The user node ID of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.Type | String | The user type of the owner of the repository of the checked out branch. | 
| GitHub.PR.Head.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository of the checked out branch is a site admin. | 
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
| GitHub.PR.Head.Repo.Topics | Unknown | The topics listed for the repository of the checked out branch. | 
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
| GitHub.PR.Base.User.Login | String | The login of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.ID | Number | The ID of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.NodeID | String | The node ID of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.Type | String | The user type of the committer of the commit that the base branch points to. | 
| GitHub.PR.Base.User.SiteAdmin | Boolean | Whether the committer of the commit that the base branch points to is a site admin. | 
| GitHub.PR.Base.Repo.ID | Number | The ID of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.NodeID | String | The node ID of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Name | String | The name of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.FullName | String | The full name of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Login | String | The user login of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.ID | Number | The user ID of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.NodeID | String | The user node ID of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.Type | String | The user type of the owner of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Owner.SiteAdmin | Boolean | Whether the owner of the repository that the base branch belongs to is a site admin. | 
| GitHub.PR.Base.Repo.Private | Boolean | Whether the repository that the base branch belongs to is private. | 
| GitHub.PR.Base.Repo.Description | String | The description of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Fork | Boolean | Whether the repository that the base branch belongs to is a fork. | 
| GitHub.PR.Base.Repo.Language | Unknown | The language of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.ForksCount | Number | The number of times the repository that the base branch belongs to has been forked. | 
| GitHub.PR.Base.Repo.StargazersCount | Number | The number of times the repository that the base branch belongs to has been starred. | 
| GitHub.PR.Base.Repo.WatchersCount | Number | The number of entities watching the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Size | Number | The size of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.DefaultBranch | String | The default branch of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.OpenIssuesCount | Number | The number of open issues in the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.Topics | String | Topics listed for the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.HasIssues | Boolean | Whether the repository that the base branch belongs to has issues. | 
| GitHub.PR.Base.Repo.HasProjects | Boolean | Whether the repository that the base branch belongs to has projects. | 
| GitHub.PR.Base.Repo.HasWiki | Boolean | Whether the repository that the base branch belongs to has a wiki. | 
| GitHub.PR.Base.Repo.HasPages | Boolean | Whether the repository that the base branch belongs to has pages. | 
| GitHub.PR.Base.Repo.HasDownloads | Boolean | Whether the repository that the base branch belongs to has downloads. | 
| GitHub.PR.Base.Repo.Archived | Boolean | Whether the repository that the base branch belongs to is archived. | 
| GitHub.PR.Base.Repo.Disabled | Boolean | Whether the repository that the base branch belongs to is disabled. | 
| GitHub.PR.Base.Repo.PushedAt | String | The date the repository the base branch belongs to was last pushed to. | 
| GitHub.PR.Base.Repo.CreatedAt | String | The date of creation of the repository that the base branch belongs to. | 
| GitHub.PR.Base.Repo.UpdatedAt | String | The date the repository the base branch belongs to was last updated. | 
| GitHub.PR.Base.Repo.AllowRebaseMerge | Boolean | Whether the repository the base branch belongs to allows rebase-style merges. | 
| GitHub.PR.Base.Repo.AllowSquashMerge | Boolean | Whether the repository the base branch belongs to allows squash merges. | 
| GitHub.PR.Base.Repo.AllowMergeCommit | Boolean | Whether the repository the base branch belongs to allows merge commits. | 
| GitHub.PR.Base.Repo.SubscribersCount | Number | The number of entities that subscribe to the repository the base branch belongs to. | 
| GitHub.PR.AuthorAssociation | String | The pull request author association. | 
| GitHub.PR.Draft | Boolean | Whether the pull request is a draft. | 
| GitHub.PR.Merged | Boolean | Whether the pull request is merged. | 
| GitHub.PR.Mergeable | Boolean | Whether the pull request is mergeable. | 
| GitHub.PR.Rebaseable | Boolean | Whether the pull request is rebaseable. | 
| GitHub.PR.MergeableState | String | The mergeable state of the pull request. | 
| GitHub.PR.MergedBy.Login | String | The login of the user who merged the pull request. | 
| GitHub.PR.MergedBy.ID | Number | The ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.NodeID | String | The node ID of the user who merged the pull request. | 
| GitHub.PR.MergedBy.Type | String | The type of the user who merged the pull request. | 
| GitHub.PR.MergedBy.SiteAdmin | Boolean | Whether the user who merged the pull request is a site admin. | 
| GitHub.PR.Comments | Number | The number of comments on the pull request. | 
| GitHub.PR.ReviewComments | Number | The number of review comments on the pull request. | 
| GitHub.PR.MaintainerCanModify | Boolean | Whether the maintainer can modify the pull request. | 
| GitHub.PR.Commits | Number | The number of commits in the pull request. | 
| GitHub.PR.Additions | Number | The number of additions in the pull request. | 
| GitHub.PR.Deletions | Number | The number of deletions in the pull request. | 
| GitHub.PR.ChangedFiles | Number | The number of changed files in the pull request. | 


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
| path_to_file | The path to the file in the GitHub repo (including file name and file ending). | Required | 
| entry_id | The entry ID for the file to commit. Either "entry_id" or "file_text" must be provided. | Optional | 
| file_text | The plain text for the file to commit. Either "entry_id" or "file_text" must be provided. | Optional | 
| branch_name | The branch name. | Required | 
| file_sha | The blob SHA of the file being replaced. Use the GitHub-list-files command to get the SHA value of the file.  Required if you are updating a file. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!Github-commit-file commit_message="test commit" path_to_file="TEST.md" branch_name=branch-for-pr file_sha=hjashd878ad file_text=Test```

#### Human Readable Output
The file TEST.md committed successfully. Link to the commit: https://github.com/content-bot/hello-world/commit/7678213ghg72136

### GitHub-create-release
***
Creates a release.


#### Base Command

`GitHub-create-release`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the release. | Optional | 
| tag_name | The name of the release tag. | Required | 
| body | Text describing the contents of the tag. | Optional | 
| draft | Set to true to create a draft (unpublished) release, set to false to create a published one. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Release.draft | Boolean | Whether the release is a draft. | 
| GitHub.Release.html_url | String | The release URL. | 
| GitHub.Release.id | Number | The ID of the release. | 
| GitHub.Release.url | String | GitHub API URL link to the release. | 


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
> Release 1.0.0 created successfully for repo sdk: https:<span>//github</span>.com/demisto/sdk/releases/tag/1.0.0


### Github-list-issue-events
***
Returns events corresponding to the given issue.


#### Base Command

`Github-list-issue-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_number | The issue number to retrieve events for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.IssueEvent.id | Number | Event ID. | 
| GitHub.IssueEvent.node_id | String | Event node ID. | 
| GitHub.IssueEvent.url | String | Event URL. | 
| GitHub.IssueEvent.actor.login | String | Event actor login username. | 
| GitHub.IssueEvent.actor.id | Number | Event actor ID. | 
| GitHub.IssueEvent.actor.node_id | String | Event actor node ID. | 
| GitHub.IssueEvent.actor.avatar_url | String | Event actor avatar URL. | 
| GitHub.IssueEvent.actor.gravatar_id | String | Event actor gravatar ID. | 
| GitHub.IssueEvent.actor.url | String | Event actor URL. | 
| GitHub.IssueEvent.actor.html_url | String | Event actor HTML URL. | 
| GitHub.IssueEvent.actor.followers_url | String | Event actor followers URL. | 
| GitHub.IssueEvent.actor.following_url | String | Event actor following URL. | 
| GitHub.IssueEvent.actor.gists_url | String | Event actor gists URL. | 
| GitHub.IssueEvent.actor.starred_url | String | Event actor starred URL. | 
| GitHub.IssueEvent.actor.subscriptions_url | String | Event actor subscriptions URL. | 
| GitHub.IssueEvent.actor.organizations_url | String | Event actor organizations URL. | 
| GitHub.IssueEvent.actor.repos_url | String | Event actor repos URL. | 
| GitHub.IssueEvent.actor.events_url | String | Event actor events URL. | 
| GitHub.IssueEvent.actor.received_events_url | String | Event actor received events URL. | 
| GitHub.IssueEvent.actor.type | String | Event actor type. | 
| GitHub.IssueEvent.actor.site_admin | Boolean | Indicates whether the event actor is the site admin. | 
| GitHub.IssueEvent.event | String | Issue event type, for example labeled, closed. | 
| GitHub.IssueEvent.commit_id | Unknown | Event commit ID. | 
| GitHub.IssueEvent.commit_url | Unknown | Event commit URL. | 
| GitHub.IssueEvent.created_at | Date | Event created time. | 
| GitHub.IssueEvent.label.name | String | Event label name. | 
| GitHub.IssueEvent.label.color | String | Event label color. | 
| GitHub.IssueEvent.performed_via_github_app | Unknown | Indicates whether event was performed via a GitHub application. | 
| GitHub.IssueEvent.assignee.login | String | Assignee login username. | 
| GitHub.IssueEvent.assignee.id | Number | Assignee ID. | 
| GitHub.IssueEvent.assignee.node_id | String | Assignee node ID. | 
| GitHub.IssueEvent.assignee.avatar_url | String | Assignee avatar URL. | 
| GitHub.IssueEvent.assignee.gravatar_id | String | Assignee gravatar ID. | 
| GitHub.IssueEvent.assignee.url | String | Assignee URL. | 
| GitHub.IssueEvent.assignee.html_url | String | Assignee HTML URL. | 
| GitHub.IssueEvent.assignee.followers_url | String | Assignee followers URL. | 
| GitHub.IssueEvent.assignee.following_url | String | Assignee following URL. | 
| GitHub.IssueEvent.assignee.gists_url | String | Assignee gists URL. | 
| GitHub.IssueEvent.assignee.starred_url | String | Assignee starred URL. | 
| GitHub.IssueEvent.assignee.subscriptions_url | String | Assignee subscriptions URL. | 
| GitHub.IssueEvent.assignee.organizations_url | String | Assignee organizations URL. | 
| GitHub.IssueEvent.assignee.repos_url | String | Assignee repos URL. | 
| GitHub.IssueEvent.assignee.events_url | String | Assignee events URL. | 
| GitHub.IssueEvent.assignee.received_events_url | String | Assignee received events URL. | 
| GitHub.IssueEvent.assignee.type | String | Assignee type. | 
| GitHub.IssueEvent.assignee.site_admin | Boolean | Indicates whether the assignee is a site admin. | 
| GitHub.IssueEvent.assigner.login | String | Assigner login username. | 
| GitHub.IssueEvent.assigner.id | Number | Assigner ID. | 
| GitHub.IssueEvent.assigner.node_id | String | Assigner node ID. | 
| GitHub.IssueEvent.assigner.avatar_url | String | Assigner avatar URL. | 
| GitHub.IssueEvent.assigner.gravatar_id | String | Assigner gravatar ID. | 
| GitHub.IssueEvent.assigner.url | String | Assigner URL. | 
| GitHub.IssueEvent.assigner.html_url | String | Assigner HTML URL. | 
| GitHub.IssueEvent.assigner.followers_url | String | Assigner followers URL. | 
| GitHub.IssueEvent.assigner.following_url | String | Assigner following URL. | 
| GitHub.IssueEvent.assigner.gists_url | String | Assigner gists URL. | 
| GitHub.IssueEvent.assigner.starred_url | String | Assigner starred URL. | 
| GitHub.IssueEvent.assigner.subscriptions_url | String | Assigner subscriptions URL. | 
| GitHub.IssueEvent.assigner.organizations_url | String | Assigner organizations URL. | 
| GitHub.IssueEvent.assigner.repos_url | String | Assigner repos URL. | 
| GitHub.IssueEvent.assigner.events_url | String | Assigner events URL. | 
| GitHub.IssueEvent.assigner.received_events_url | String | Assigner received events URL. | 
| GitHub.IssueEvent.assigner.type | String | Assigner type. | 
| GitHub.IssueEvent.assigner.site_admin | Boolean | Indicates whether the assignee is a site admin. | 


#### Command Example
```!Github-list-issue-events issue_number=1079```

#### Context Example
```json
{
    "GitHub": {
        "IssueEvent": [
            {
                "actor": {
                    "avatar_url": "https://avatars.githubusercontent.com/u/70005542?v=4",
                    "events_url": "https://api.github.com/users/tomneeman151293/events{/privacy}",
                    "followers_url": "https://api.github.com/users/tomneeman151293/followers",
                    "following_url": "https://api.github.com/users/tomneeman151293/following{/other_user}",
                    "gists_url": "https://api.github.com/users/tomneeman151293/gists{/gist_id}",
                    "gravatar_id": "",
                    "html_url": "https://github.com/tomneeman151293",
                    "id": 70005542,
                    "login": "tomneeman151293",
                    "node_id": "MDQ6VXNlcjcwMDA1NTQy",
                    "organizations_url": "https://api.github.com/users/tomneeman151293/orgs",
                    "received_events_url": "https://api.github.com/users/tomneeman151293/received_events",
                    "repos_url": "https://api.github.com/users/tomneeman151293/repos",
                    "site_admin": false,
                    "starred_url": "https://api.github.com/users/tomneeman151293/starred{/owner}{/repo}",
                    "subscriptions_url": "https://api.github.com/users/tomneeman151293/subscriptions",
                    "type": "User",
                    "url": "https://api.github.com/users/tomneeman151293"
                },
                "commit_id": null,
                "commit_url": null,
                "created_at": "2021-01-28T13:00:26Z",
                "event": "labeled",
                "id": 4260960414,
                "label": {
                    "color": "d73a4a",
                    "name": "bug"
                },
                "node_id": "MDEyOkxhYmVsZWRFdmVudDQyNjA5NjA0MTQ=",
                "performed_via_github_app": null,
                "url": "https://api.github.com/repos/demisto/demisto-sdk/issues/events/4260960414"
            },
            {
                "actor": {
                    "avatar_url": "https://avatars.githubusercontent.com/u/70005542?v=4",
                    "events_url": "https://api.github.com/users/tomneeman151293/events{/privacy}",
                    "followers_url": "https://api.github.com/users/tomneeman151293/followers",
                    "following_url": "https://api.github.com/users/tomneeman151293/following{/other_user}",
                    "gists_url": "https://api.github.com/users/tomneeman151293/gists{/gist_id}",
                    "gravatar_id": "",
                    "html_url": "https://github.com/tomneeman151293",
                    "id": 70005542,
                    "login": "tomneeman151293",
                    "node_id": "MDQ6VXNlcjcwMDA1NTQy",
                    "organizations_url": "https://api.github.com/users/tomneeman151293/orgs",
                    "received_events_url": "https://api.github.com/users/tomneeman151293/received_events",
                    "repos_url": "https://api.github.com/users/tomneeman151293/repos",
                    "site_admin": false,
                    "starred_url": "https://api.github.com/users/tomneeman151293/starred{/owner}{/repo}",
                    "subscriptions_url": "https://api.github.com/users/tomneeman151293/subscriptions",
                    "type": "User",
                    "url": "https://api.github.com/users/tomneeman151293"
                },
                "commit_id": null,
                "commit_url": null,
                "created_at": "2021-01-28T15:20:27Z",
                "event": "closed",
                "id": 4261648354,
                "node_id": "MDExOkNsb3NlZEV2ZW50NDI2MTY0ODM1NA==",
                "performed_via_github_app": null,
                "url": "https://api.github.com/repos/demisto/demisto-sdk/issues/events/4261648354"
            }
        ]
    }
}
```

#### Human Readable Output

>### GitHub Issue Events For Issue 1079
>|actor|commit_id|commit_url|created_at|event|id|label|node_id|performed_via_github_app|url|
>|---|---|---|---|---|---|---|---|---|---|
>| login: tomneeman151293<br/>id: 70005542<br/>node_id: MDQ6VXNlcjcwMDA1NTQy<br/>avatar_url: https://avatars.githubusercontent.com/u/70005542?v=4<br/>gravatar_id: <br/>url: https://api.github.com/users/tomneeman151293<br/>html_url: https://github.com/tomneeman151293<br/>followers_url: https://api.github.com/users/tomneeman151293/followers<br/>following_url: https://api.github.com/users/tomneeman151293/following{/other_user}<br/>gists_url: https://api.github.com/users/tomneeman151293/gists{/gist_id}<br/>starred_url: https://api.github.com/users/tomneeman151293/starred{/owner}{/repo}<br/>subscriptions_url: https://api.github.com/users/tomneeman151293/subscriptions<br/>organizations_url: https://api.github.com/users/tomneeman151293/orgs<br/>repos_url: https://api.github.com/users/tomneeman151293/repos<br/>events_url: https://api.github.com/users/tomneeman151293/events{/privacy}<br/>received_events_url: https://api.github.com/users/tomneeman151293/received_events<br/>type: User<br/>site_admin: false |  |  | 2021-01-28T13:00:26Z | labeled | 4260960414 | name: bug<br/>color: d73a4a | MDEyOkxhYmVsZWRFdmVudDQyNjA5NjA0MTQ= |  | https://api.github.com/repos/demisto/demisto-sdk/issues/events/4260960414 |
>| login: tomneeman151293<br/>id: 70005542<br/>node_id: MDQ6VXNlcjcwMDA1NTQy<br/>avatar_url: https://avatars.githubusercontent.com/u/70005542?v=4<br/>gravatar_id: <br/>url: https://api.github.com/users/tomneeman151293<br/>html_url: https://github.com/tomneeman151293<br/>followers_url: https://api.github.com/users/tomneeman151293/followers<br/>following_url: https://api.github.com/users/tomneeman151293/following{/other_user}<br/>gists_url: https://api.github.com/users/tomneeman151293/gists{/gist_id}<br/>starred_url: https://api.github.com/users/tomneeman151293/starred{/owner}{/repo}<br/>subscriptions_url: https://api.github.com/users/tomneeman151293/subscriptions<br/>organizations_url: https://api.github.com/users/tomneeman151293/orgs<br/>repos_url: https://api.github.com/users/tomneeman151293/repos<br/>events_url: https://api.github.com/users/tomneeman151293/events{/privacy}<br/>received_events_url: https://api.github.com/users/tomneeman151293/received_events<br/>type: User<br/>site_admin: false |  |  | 2021-01-28T15:20:27Z | closed | 4261648354 |  | MDExOkNsb3NlZEV2ZW50NDI2MTY0ODM1NA== |  | https://api.github.com/repos/demisto/demisto-sdk/issues/events/4261648354 |

### GitHub-list-all-projects

***
Lists all project boards a user can see.

#### Base Command

`GitHub-list-all-projects`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_filter | Only list projects with the specified numbers (IDs). | Optional | 
| limit | The number of projects to return. Default is 20. Maximum is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Project.Name | String | The name of the project board. | 
| GitHub.Project.ID | Number | The ID of the  project board. | 
| GitHub.Project.Number | Number | The project board number. | 
| GitHub.Project.Columns.Name | String | The column Name. | 
| GitHub.Project.Columns.ColumnID | Number | The ID of the column. | 
| GitHub.Project.Columns.Cards.CardID | Number | The ID of the card. | 
| GitHub.Project.Columns.Cards.ContentNumber | Number | The content number of this card, usually this is the issue number. | 
| GitHub.Project.Issues | List | List of all issue numbers that are in this project board. | 
            
#### Command Example

```!GitHub-list-all-projects project_filter="1,2"```

#### Context Example
```json
{
  "GitHub": {
    "Project": {
       "XSOAR Data": {
        "Number": 23,
        "ID": 2,
        "Columns": {
          "In progress": {
            "Cards": [
              {
                "CardID": 55555,
                "ContentNumber": 33883
              },
              {
                "CardID": 66666,
                "ContentNumber": 34852
              },
            ],
            "Name": "In progress",
            "ColumnID": 13241511
          },
          "Done": {
            "Cards": [
              {
                "CardID": 61858005,
                "ContentNumber": 37480
              },
              {
                "CardID": 60428728,
                "ContentNumber": 36608
              },
            ],
            "Name": "Done",
            "ColumnID": 13437971
          }
        },
        "Issues": [
          33883,
          34852,
          37480,
          36608
        ],
        "Name": "XSOAR Data"
      }
  }
}
```


### GitHub-move-issue-to-project-board

***
Moves an issue in the project board to a different column.

#### Base Command

`GitHub-move-issue-to-project-board`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| column_id | The destination column ID. | Required | 
| card_id | The card ID to move. | Required | 
| position | The position of the card in the new column. | Optional | 

           
#### Command Example

```!GitHub-move-issue-to-project-board card_id=1111 column_id=1234 position="top"```

### GitHub-get-path-data
***
Gets the data of the a given path.


#### Base Command

`GitHub-get-path-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| relative_path | Relative path to retrieve its data. | Required | 
| branch_name | The branch name from which to get the file data. Default is master. | Optional | 
| organization | The name of the organization containing the file. | Optional | 
| repository | The repository of the file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.PathData.name | String | Path name. | 
| GitHub.PathData.path | String | Relative path for the given repository. | 
| GitHub.PathData.sha | String | Path SHA. | 
| GitHub.PathData.size | Number | Path size in bytes. Will be 0 if path to a dir was given. | 
| GitHub.PathData.url | String | Path URL. | 
| GitHub.PathData.html_url | String | Path HTML URL. | 
| GitHub.PathData.git_url | String | Path Git URL. | 
| GitHub.PathData.download_url | String | Path download URL. If a directory path was given will be empty. | 
| GitHub.PathData.type | String | Path data, for example file, dir. | 
| GitHub.PathData.content | String | Content of the path if a file path was given. | 
| GitHub.PathData.encoding | String | Encoding method if path to a file was given. | 
| GitHub.PathData.entries.name | String | If a dir was given in file_path, name of the dir entry. | 
| GitHub.PathData.entries.path | String | If a dir was given in file_path, path of the dir entry. | 
| GitHub.PathData.entries.sha | String | If a dir was given in file_path, SHA of the dir entry. | 
| GitHub.PathData.entries.size | Number | If a dir was given in file_path, size of the dir entry. Will be 0 if entry is also a dir. | 
| GitHub.PathData.entries.url | String | If a dir was given in file_path, URL of the dir entry. | 
| GitHub.PathData.entries.html_url | String | If a dir was given in file_path, HTML URL of the dir entry. | 
| GitHub.PathData.entries.git_url | String | If a dir was given in file_path, Git URL of the dir entry. | 
| GitHub.PathData.entries.download_url | String | If a dir was given in file_path, download URL of the dir entry. Will be empty if entry is also a dir. | 
| GitHub.PathData.entries.type | String | If a dir was given in file_path, type of the dir entry. | 


#### Command Example
```!GitHub-get-path-data organization=demisto repository=content relative_path=Packs/BitcoinAbuse/Integrations/BitcoinAbuse```

#### Context Example
```json
{
    "GitHub": {
        "PathData": {
            "download_url": null,
            "entries": [
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/23b55cb33aadaa6753e3df1e1d90d3cdc951c745",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py",
                    "name": "BitcoinAbuse.py",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py",
                    "sha": "23b55cb33aadaa6753e3df1e1d90d3cdc951c745",
                    "size": 14395,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/17bbcfd9270570727c2e0f48591fcb9a98a0711e",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml",
                    "name": "BitcoinAbuse.yml",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml",
                    "sha": "17bbcfd9270570727c2e0f48591fcb9a98a0711e",
                    "size": 3929,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/7d969d68833e2424ba8411c93fb8110face60414",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md",
                    "name": "BitcoinAbuse_description.md",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md",
                    "sha": "7d969d68833e2424ba8411c93fb8110face60414",
                    "size": 1305,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/52bef504f8dc4b58ddc6f200cdd135bcdfe9719a",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png",
                    "name": "BitcoinAbuse_image.png",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png",
                    "sha": "52bef504f8dc4b58ddc6f200cdd135bcdfe9719a",
                    "size": 3212,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/dc2c4106cc3589461c7470a5c26e6e8927192d7f",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py",
                    "name": "BitcoinAbuse_test.py",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py",
                    "sha": "dc2c4106cc3589461c7470a5c26e6e8927192d7f",
                    "size": 7150,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/3523d3b6b93bd611859c23e1f63a774d78a0363a",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile",
                    "name": "Pipfile",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile",
                    "sha": "3523d3b6b93bd611859c23e1f63a774d78a0363a",
                    "size": 257,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/6bdb9313414e337e128df3715f17d372f5691608",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock",
                    "name": "Pipfile.lock",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock",
                    "sha": "6bdb9313414e337e128df3715f17d372f5691608",
                    "size": 15993,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock?ref=master"
                },
                {
                    "download_url": "https://raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md",
                    "git_url": "https://api.github.com/repos/demisto/content/git/blobs/fba823cddcc3637b2989598b7ae08731002f8feb",
                    "html_url": "https://github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md",
                    "name": "README.md",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md",
                    "sha": "fba823cddcc3637b2989598b7ae08731002f8feb",
                    "size": 7188,
                    "type": "file",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md?ref=master"
                },
                {
                    "download_url": null,
                    "git_url": "https://api.github.com/repos/demisto/content/git/trees/ed2025b734667dfde3b405f8a131b785e9d8fc9d",
                    "html_url": "https://github.com/demisto/content/tree/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/test_data",
                    "name": "test_data",
                    "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse/test_data",
                    "sha": "ed2025b734667dfde3b405f8a131b785e9d8fc9d",
                    "size": 0,
                    "type": "dir",
                    "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/test_data?ref=master"
                }
            ],
            "git_url": "https://api.github.com/repos/demisto/content/git/trees/1a0c49c84e7bcd02af5587082b6ed48634a20402",
            "html_url": "https://github.com/demisto/content/tree/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse",
            "name": "BitcoinAbuse",
            "path": "Packs/BitcoinAbuse/Integrations/BitcoinAbuse",
            "sha": "1a0c49c84e7bcd02af5587082b6ed48634a20402",
            "size": 0,
            "type": "dir",
            "url": "https://api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse?ref=master"
        }
    }
}
```

#### Human Readable Output

>### File Data For File Packs/BitcoinAbuse/Integrations/BitcoinAbuse
>|entries|git_url|html_url|name|path|sha|size|type|url|
>|---|---|---|---|---|---|---|---|---|
>| {'name': 'BitcoinAbuse.py', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py', 'sha': '23b55cb33aadaa6753e3df1e1d90d3cdc951c745', 'size': 14395, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/23b55cb33aadaa6753e3df1e1d90d3cdc951c745', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.py', 'type': 'file'},<br/>{'name': 'BitcoinAbuse.yml', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml', 'sha': '17bbcfd9270570727c2e0f48591fcb9a98a0711e', 'size': 3929, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/17bbcfd9270570727c2e0f48591fcb9a98a0711e', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse.yml', 'type': 'file'},<br/>{'name': 'BitcoinAbuse_description.md', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md', 'sha': '7d969d68833e2424ba8411c93fb8110face60414', 'size': 1305, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/7d969d68833e2424ba8411c93fb8110face60414', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_description.md', 'type': 'file'},<br/>{'name': 'BitcoinAbuse_image.png', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png', 'sha': '52bef504f8dc4b58ddc6f200cdd135bcdfe9719a', 'size': 3212, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/52bef504f8dc4b58ddc6f200cdd135bcdfe9719a', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_image.png', 'type': 'file'},<br/>{'name': 'BitcoinAbuse_test.py', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py', 'sha': 'dc2c4106cc3589461c7470a5c26e6e8927192d7f', 'size': 7150, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/dc2c4106cc3589461c7470a5c26e6e8927192d7f', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/BitcoinAbuse_test.py', 'type': 'file'},<br/>{'name': 'Pipfile', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile', 'sha': '3523d3b6b93bd611859c23e1f63a774d78a0363a', 'size': 257, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/3523d3b6b93bd611859c23e1f63a774d78a0363a', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile', 'type': 'file'},<br/>{'name': 'Pipfile.lock', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock', 'sha': '6bdb9313414e337e128df3715f17d372f5691608', 'size': 15993, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/6bdb9313414e337e128df3715f17d372f5691608', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/Pipfile.lock', 'type': 'file'},<br/>{'name': 'README.md', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md', 'sha': 'fba823cddcc3637b2989598b7ae08731002f8feb', 'size': 7188, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/blob/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/blobs/fba823cddcc3637b2989598b7ae08731002f8feb', 'download_url': 'https:<span>//</span>raw.githubusercontent.com/demisto/content/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/README.md', 'type': 'file'},<br/>{'name': 'test_data', 'path': 'Packs/BitcoinAbuse/Integrations/BitcoinAbuse/test_data', 'sha': 'ed2025b734667dfde3b405f8a131b785e9d8fc9d', 'size': 0, 'url': 'https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/test_data?ref=master', 'html_url': 'https:<span>//</span>github.com/demisto/content/tree/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse/test_data', 'git_url': 'https:<span>//</span>api.github.com/repos/demisto/content/git/trees/ed2025b734667dfde3b405f8a131b785e9d8fc9d', 'download_url': None, 'type': 'dir'} | https:<span>//</span>api.github.com/repos/demisto/content/git/trees/1a0c49c84e7bcd02af5587082b6ed48634a20402 | https:<span>//</span>github.com/demisto/content/tree/master/Packs/BitcoinAbuse/Integrations/BitcoinAbuse | BitcoinAbuse | Packs/BitcoinAbuse/Integrations/BitcoinAbuse | 1a0c49c84e7bcd02af5587082b6ed48634a20402 | 0 | dir | https:<span>//</span>api.github.com/repos/demisto/content/contents/Packs/BitcoinAbuse/Integrations/BitcoinAbuse?ref=master |

### GitHub-releases-list
***
Gets release data from a given repository and organization.


#### Base Command

`GitHub-releases-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number to retrieve releases from. If limit argument is not given, defaults to 1. | Optional | 
| page_size | The size of the page. If the limit argument is not specified, defaults to 50. | Optional |
| limit | The maximum number of releases to retrieve data for. Will get results of the first pages. Cannot be given with page_size or page arguments. | Optional |
| organization | The name of the organization containing the repository. Defaults to the organization instance parameter if not given. | Optional | 
| repository | The repository containing the releases. Defaults to repository instance parameter if not given. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.Release.url | String | The release URL. | 
| GitHub.Release.assets_url | String | The release assets URL. | 
| GitHub.Release.upload_url | String | The upload URL. | 
| GitHub.Release.html_url | String | The HTML URL. | 
| GitHub.Release.id | Number | The release ID. | 
| GitHub.Release.author.login | String | The release author login username. | 
| GitHub.Release.author.id | Number | The release author user ID. | 
| GitHub.Release.author.node_id | String | The release author node ID. | 
| GitHub.Release.author.avatar_url | String | The release author avatar URL. | 
| GitHub.Release.author.gravatar_id | String | The release author gravatar ID. | 
| GitHub.Release.author.url | String | The release author URL. | 
| GitHub.Release.author.html_url | String | The release author HTML URL. | 
| GitHub.Release.author.followers_url | String | The release author followers URL. | 
| GitHub.Release.author.following_url | String | The release author following URL. | 
| GitHub.Release.author.gists_url | String | The release author gists URL. | 
| GitHub.Release.author.starred_url | String | The release author starred URL. | 
| GitHub.Release.author.subscriptions_url | String | The release author subscriptions URL. | 
| GitHub.Release.author.organizations_url | String | The release author organizations URL. | 
| GitHub.Release.author.repos_url | String | The release author repos URL. | 
| GitHub.Release.author.events_url | String | The release author events URL. | 
| GitHub.Release.author.received_events_url | String | The release author received events URL. | 
| GitHub.Release.author.type | String | The release author type, for example "User". | 
| GitHub.Release.author.site_admin | Boolean | Whether the release author is the site admin. | 
| GitHub.Release.node_id | String | The release Node ID. | 
| GitHub.Release.tag_name | String | The release tag name. | 
| GitHub.Release.target_commitish | String | The release target commit. | 
| GitHub.Release.name | String | The release name. | 
| GitHub.Release.draft | Boolean | Whether the release is a draft. | 
| GitHub.Release.prerelease | Boolean | Whether the release is a pre release. | 
| GitHub.Release.created_at | Date | The date the release was created. | 
| GitHub.Release.published_at | Date | The date the release was published. | 
| GitHub.Release.tarball_url | String | The release tar URL download. | 
| GitHub.Release.zipball_url | String | The release zip URL download. | 
| GitHub.Release.body | String | The release body. | 


#### Command Example
```!GitHub-releases-list limit=1```

#### Context Example
```json
{
    "GitHub": {
        "Release": {
            "assets": [],
            "assets_url": "https://api.github.com/repos/content-bot/hello-world/releases/48262112/assets",
            "author": {
                "avatar_url": "https://avatars.githubusercontent.com/u/55035720?v=4",
                "events_url": "https://api.github.com/users/content-bot/events{/privacy}",
                "followers_url": "https://api.github.com/users/content-bot/followers",
                "following_url": "https://api.github.com/users/content-bot/following{/other_user}",
                "gists_url": "https://api.github.com/users/content-bot/gists{/gist_id}",
                "gravatar_id": "",
                "html_url": "https://github.com/content-bot",
                "id": 55035720,
                "login": "content-bot",
                "node_id": "MDQ6VXNlcjU1MDM1NzIw",
                "organizations_url": "https://api.github.com/users/content-bot/orgs",
                "received_events_url": "https://api.github.com/users/content-bot/received_events",
                "repos_url": "https://api.github.com/users/content-bot/repos",
                "site_admin": false,
                "starred_url": "https://api.github.com/users/content-bot/starred{/owner}{/repo}",
                "subscriptions_url": "https://api.github.com/users/content-bot/subscriptions",
                "type": "User",
                "url": "https://api.github.com/users/content-bot"
            },
            "body": "test",
            "created_at": "2021-08-23T07:54:37Z",
            "draft": true,
            "html_url": "https://github.com/content-bot/hello-world/releases/tag/untagged-e106615f0216817665d8",
            "id": 48262112,
            "name": "1.0.0",
            "node_id": "MDc6UmVsZWFzZTQ4MjYyMTEy",
            "prerelease": false,
            "published_at": null,
            "tag_name": "1.0.0",
            "tarball_url": null,
            "target_commitish": "master",
            "upload_url": "https://uploads.github.com/repos/content-bot/hello-world/releases/48262112/assets{?name,label}",
            "url": "https://api.github.com/repos/content-bot/hello-world/releases/48262112",
            "zipball_url": null
        }
    }
}
```

#### Human Readable Output

>### Releases Data Of hello-world
>|assets_url|author|body|created_at|draft|html_url|id|name|node_id|prerelease|tag_name|target_commitish|upload_url|url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| https:<span>//</span>api.github.com/repos/content-bot/hello-world/releases/48262112/assets | login: content-bot<br/>id: 55035720<br/>node_id: MDQ6VXNlcjU1MDM1NzIw<br/>avatar_url: https:<span>//</span>avatars.githubusercontent.com/u/55035720?v=4<br/>gravatar_id: <br/>url: https:<span>//</span>api.github.com/users/content-bot<br/>html_url: https:<span>//</span>github.com/content-bot<br/>followers_url: https:<span>//</span>api.github.com/users/content-bot/followers<br/>following_url: https:<span>//</span>api.github.com/users/content-bot/following{/other_user}<br/>gists_url: https:<span>//</span>api.github.com/users/content-bot/gists{/gist_id}<br/>starred_url: https:<span>//</span>api.github.com/users/content-bot/starred{/owner}{/repo}<br/>subscriptions_url: https:<span>//</span>api.github.com/users/content-bot/subscriptions<br/>organizations_url: https:<span>//</span>api.github.com/users/content-bot/orgs<br/>repos_url: https:<span>//</span>api.github.com/users/content-bot/repos<br/>events_url: https:<span>//</span>api.github.com/users/content-bot/events{/privacy}<br/>received_events_url: https:<span>//</span>api.github.com/users/content-bot/received_events<br/>type: User<br/>site_admin: false | test | 2021-08-23T07:54:37Z | true | https:<span>//</span>github.com/content-bot/hello-world/releases/tag/untagged-e106615f0216817665d8 | 48262112 | 1.0.0 | MDc6UmVsZWFzZTQ4MjYyMTEy | false | 1.0.0 | master | https:<span>//</span>uploads.github.com/repos/content-bot/hello-world/releases/48262112/assets{?name,label} | https:<span>//</span>api.github.com/repos/content-bot/hello-world/releases/48262112 |
