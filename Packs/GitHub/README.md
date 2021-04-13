Integration to GitHub API
This integration was integrated and tested with version xx of GitHub
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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| GitHub.Issue.Owner | String | The repository owner. | 


#### Command Example
``` ```

#### Human Readable Output



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
| GitHub.Issue.Owner | String | The repository owner. | 


#### Command Example
``` ```

#### Human Readable Output



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
| GitHub.Issue.Owner | String | The repository owner. | 


#### Command Example
``` ```

#### Human Readable Output



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
| GitHub.Issue.Owner | String | The repository owner. | 


#### Command Example
``` ```

#### Human Readable Output



### GitHub-search-issues
***
Searches for and returns issues that match a given query.


#### Base Command

`GitHub-search-issues`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query line for the search. For more information see the GitHub documentation at https://help.github.com/en/articles/searching-issues-and-pull-requests. | Required | 
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
| GitHub.Issue.Owner | String | The repository owner. | 


#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
| repository | The repository of the pull request. | Required | 


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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



### GitHub-is-pr-merged
***
Returns a merged pull request. If the pull request has been merged, the API returns 'Status: 204 No Content'. If the pull request has not been merged the API returns 'Status: 404 Not Found'


#### Base Command

`GitHub-is-pr-merged`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pull_number | The issue number of the pull request to check. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



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
| create_file_from_content | Whether to create a file entry in the War Room with the file contents. Possible values are: "true" and "false". Default value is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitHub.FileContent.Path | String | The path of the file. | 
| GitHub.FileContent.Content | Number | The content of the file. | 
| GitHub.FileContent.MediaType | String | The media type in which the file was fetched. | 
| GitHub.FileContent.Branch | Unknown | The branch from which the file was fetched. | 


#### Command Example
``` ```

#### Human Readable Output



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
| GitHub.File.Type | String | The type of the file. | 
| GitHub.File.Size | Number | The size of the file in bytes. | 
| GitHub.File.Path | String | The file path inside the repository. | 
| GitHub.File.DownloadUrl | String | Link to download the file content. | 


#### Command Example
``` ```

#### Human Readable Output


