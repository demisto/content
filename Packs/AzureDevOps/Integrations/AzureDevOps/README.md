# Azure DevOps
Create and manage Git repositories in Azure DevOps Services.
This integration was integrated and tested with version 6.1 of AzureDevOps

## Configure AzureDevOps on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureDevOps.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Client ID | App Registration Client ID | True |
    | Organization | Organizaion name | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Maximum incidents for one fetch. | Default is 50. Maximum is 200. | False |
    | Pull-request project name | The name of the project which the pull requests belongs to. This argument is mandatory for Fetch functionality. | False |
    | Pull-request repository name | The name of the repository pull request's target branch. This argument is mandatory for Fetch functionality. | False |
    | First pull-request ID | Indicated the first pull-request ID to fetch. If this argument will not be provided, the first pull-request to fetch will be the oldest pull-request ID. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-devops-auth-test
***
Tests the connectivity to Azure.


#### Base Command

`azure-devops-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-devops-auth-test```

#### Human Readable Output

>Success!

### azure-devops-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.


#### Base Command

`azure-devops-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-devops-auth-start```

#### Human Readable Output

>### Authorization instructions
>1. To sign in, use a web browser to open the page [https:<span>//</span>microsoft.com/devicelogin](https:<span>//</span>microsoft.com/devicelogin)
>and enter the code *XXXX** to authenticate.
>2. Run the **!azure-devops-auth-complete** command in the War Room.

### azure-devops-auth-complete
***
Run this command to complete the authorization process. Should be used after running the azure-devops-auth-start command.


#### Base Command

`azure-devops-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-devops-auth-complete```

#### Human Readable Output

>Authorization completed successfully.

### azure-devops-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-devops-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-devops-auth-reset```

#### Human Readable Output

>Authorization was reset successfully. Run **!azure-devops-auth-start** to start the authentication process.

### azure-devops-pipeline-run
***
Run a pipeline.


#### Base Command

`azure-devops-pipeline-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| pipeline_id | The ID of the pipeline. | Required | 
| branch_name | The name of the repository branch which runs the pipeline. | Required | 
| polling | Use XSOAR built-in polling to retrieve the result when it's ready. Possible values are: True, False. Default is False. | Optional | 
| interval | Indicates how long to wait between commands execution (in seconds) when 'polling' argument is true. Default is 10 seconds,  minimum is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 60 seconds. Default is 60. | Optional | 
| run_id | The ID of the pipeline run to retrieve when polling argument is 'True'. Intended for use by the Polling process and does not need to be provided by the user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.Project.Pipeline.revision | Number | Pipeline revision number | 
| AzureDevOps.Project.Pipeline.name | String | Pipeline repository name | 
| AzureDevOps.Project.Pipeline.folder | String | Pipeline folder | 
| AzureDevOps.Project.Pipeline.Run.state | String | The run state. | 
| AzureDevOps.Project.Pipeline.Run.createdDate | Date | Run-pipeline creation date. | 
| AzureDevOps.Project.Pipeline.Run.url | String | The URL of the run. | 
| AzureDevOps.Project.Pipeline.Run.id | Number | The ID of the run. | 
| AzureDevOps.Project.Pipeline.Run.name | String | The name of the run. | 
| AzureDevOps.Project.Pipeline.Run.name | String | The result of the pipeline running. If the run is in progress, the default value is 'unknown'. | 


#### Command Example
```!azure-devops-pipeline-run project="xsoar" pipeline_id="1" branch_name="main"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Pipeline": {
                "Run": {
                    "createdDate": "2021-11-03T09:25:20",
                    "id": 113,
                    "name": "20211103.1",
                    "result": "unknown",
                    "state": "inProgress",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/113"
                },
                "folder": "\\",
                "id": 1,
                "name": "xsoar",
                "revision": 1
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pipeline Run Information:
>|Pipeline Id|Run State|Creation Date|Run Id|Result|
>|---|---|---|---|---|
>| 1 | inProgress | 2021-11-03T09:25:20 | 113 | unknown |


### azure-devops-user-add
***
Add a user, assign license and extensions and make them a member of a project group in an account.


#### Base Command

`azure-devops-user-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_email | The Email of the user to add to the organization. | Required | 
| account_license_type | The type of account license (e.g. Express, Stakeholder etc.). More information can be found here: https://docs.microsoft.com/en-us/rest/api/azure/devops/memberentitlementmanagement/user-entitlements/add?view=azure-devops-rest-6.1#accountlicensetype . Possible values are: express, stakeholder, advanced, earlyAdopter, professional. | Required | 
| group_type | Project Group type (e.g. Contributor, Reader etc.). More information can be found here: https://docs.microsoft.com/en-us/rest/api/azure/devops/memberentitlementmanagement/user-entitlements/add?view=azure-devops-rest-6.1#grouptype . Possible values are: projectReader, projectContributor, projectAdministrator, projectStakeholder. | Required | 
| project_id | The ID of the project. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.User.id | String | The ID of the user. | 
| AzureDevOps.User.accountLicenseType | String | The type of account license. | 
| AzureDevOps.User.lastAccessedDate | Date | Date the user last accessed the collection. | 


#### Command Example
```!azure-devops-user-add user_email="user1@xsoar.com" account_license_type="express" group_type="projectContributor" project_id="xsoar-project"```

#### Context Example
```json
{
    "AzureDevOps": {
        "User": {
            "accountLicenseType": "express",
            "id": "XXXX",
            "lastAccessedDate": "0001-01-01T00:00:00Z"
        }
    }
}
```

#### Human Readable Output

>### User Information:
>|Id|Account License Type|Last Accessed Date|
>|---|---|---|
>| XXXX | express | 0001-01-01T00:00:00Z |


### azure-devops-user-remove
***
Remove the user from all project memberships.


#### Base Command

`azure-devops-user-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user to remove from the organization. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-devops-user-remove user_id="XXXX"```

#### Human Readable Output

>The User successfully removed from the organization.

### azure-devops-pull-request-create
***
Create a new pull request.


#### Base Command

`azure-devops-pull-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| repository_id | The repository ID of the pull request's target branch. | Required | 
| source_branch | The name of the source branch of the pull request. | Required | 
| target_branch | The name of the target branch of the pull request. | Required | 
| title | The title of the pull request. | Required | 
| description | The description of the pull request. | Required | 
| reviewers_ids | Comma-separated list of the pull request reviewers IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Repository.id | String | The ID of the repository. | 
| AzureDevOps.Project.Repository.name | String | The name of the repository. | 
| AzureDevOps.Project.Repository.url | String | The URL of the repository. | 
| AzureDevOps.Project.Repository.size | Number | The size of the repository. | 
| AzureDevOps.Project.Repository.PullRequest.Id | Number | The ID of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.creationDate | Date | The creation date of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.Project.Repository.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.isDraft | Boolean | Draft / WIP pull request. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.commitId | String | The ID of the commit at the head of the source branch at the time of the last pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeTargetCommit.commitId | String | The ID of the commit at the head of the target branch at the time of the last pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeTargetCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.reviewerUrl | String | URL to retrieve information about the reviewer identity. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.vote | Number | Vote on a pull request: 10 - approved 5 - approved with suggestions 0 - no vote -5 - waiting for author -10 - rejected | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.hasDeclined | Boolean | Indicates if this reviewer has declined to review this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.isFlagged | Boolean | Indicates if this reviewer is flagged for attention on this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.displayName | String | The display name of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.id | String | The ID of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.uniqueName | String | The unique name of the pull request reviewer. | 


#### Command Example
```!azure-devops-pull-request-create project="xsoar" repository_id="XXXX" source_branch="qm1" target_branch="main" title="Test xsoar" description="Demo pr" reviewers_ids="XXXX"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Repository": {
                "PullRequest": {
                    "CreatedBy": {
                        "displayName": "XSOAR User",
                        "id": "XXXX",
                        "uniqueName": "user2@xsoar.com"
                    },
                    "Id": 48,
                    "LastMergeSourceCommit": {
                        "commitId": "e44039f67d30924c24615bb334350dd72e41cf44",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/e44039f67d30924c24615bb334350dd72e41cf44"
                    },
                    "LastMergeTargetCommit": {
                        "commitId": "cb63a958fbaed6d416c68330ac8f8a9e5544603c",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/cb63a958fbaed6d416c68330ac8f8a9e5544603c"
                    },
                    "Reviewers": [
                        {
                            "displayName": "XSOAR User",
                            "hasDeclined": false,
                            "id": "XXXX",
                            "isFlagged": false,
                            "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/48/reviewers/XXXX",
                            "uniqueName": "user2@xsoar.com",
                            "vote": 0
                        }
                    ],
                    "creationDate": "2021-11-03T09:24:48",
                    "description": "Demo pr",
                    "isDraft": false,
                    "mergeStatus": "queued",
                    "sourceRefName": "refs/heads/qm1",
                    "status": "active",
                    "targetRefName": "refs/heads/main",
                    "title": "Test xsoar"
                },
                "id": "XXXX",
                "name": "xsoar",
                "size": 9439,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pull Request Information:
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| Test xsoar | Demo pr | XSOAR User | 48 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-03T09:24:48 |


### azure-devops-pull-request-update
***
Update a pull request. At least one of the arguments: title, description, or status must be provided.


#### Base Command

`azure-devops-pull-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| repository_id | The repository ID of the pull request's target branch. | Required | 
| pull_request_id | The ID of the pull request to update. | Required | 
| title | The updated pull-request title. | Optional | 
| description | The updated pull-request description. | Optional | 
| status | The updated pull-request status. Possible values are: abandoned, completed, active. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Repository.id | String | The ID of the repository. | 
| AzureDevOps.Project.Repository.name | String | The name of the repository. | 
| AzureDevOps.Project.Repository.url | String | The URL of the repository. | 
| AzureDevOps.Project.Repository.size | Number | The size of the repository. | 
| AzureDevOps.Project.Repository.PullRequest.Id | Number | The ID of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.creationDate | Date | The creation date of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.Project.Repository.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.isDraft | Boolean | Draft / WIP pull request. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.commitId | String | The ID of the commit. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeTargetCommit.commitId | String | The ID of the commit. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.reviewerUrl | String | URL to retrieve information about the reviewer identity. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.vote | Number | Vote on a pull request: 10 - approved 5 - approved with suggestions 0 - no vote -5 - waiting for author -10 - rejected | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.hasDeclined | Boolean | Indicates if this reviewer has declined to review this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.isFlagged | Boolean | Indicates if this reviewer is flagged for attention on this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.displayName | String | The display name of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.id | String | The ID of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.uniqueName | String | The unique name of the pull request reviewer. | 


#### Command Example
```!azure-devops-pull-request-update project="xsoar" repository_id="XXXX" pull_request_id="48" title="New title"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Repository": {
                "PullRequest": {
                    "CreatedBy": {
                        "displayName": "XSOAR User",
                        "id": "XXXX",
                        "uniqueName": "user2@xsoar.com"
                    },
                    "Id": 48,
                    "LastMergeSourceCommit": {
                        "commitId": "e44039f67d30924c24615bb334350dd72e41cf44",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/e44039f67d30924c24615bb334350dd72e41cf44"
                    },
                    "LastMergeTargetCommit": {
                        "commitId": "cb63a958fbaed6d416c68330ac8f8a9e5544603c",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/cb63a958fbaed6d416c68330ac8f8a9e5544603c"
                    },
                    "Reviewers": [
                        {
                            "displayName": "XSOAR User",
                            "hasDeclined": false,
                            "id": "XXXX",
                            "isFlagged": false,
                            "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/48/reviewers/XXXX",
                            "uniqueName": "user2@xsoar.com",
                            "vote": 0
                        }
                    ],
                    "creationDate": "2021-11-03T09:24:48",
                    "description": "Demo pr",
                    "isDraft": false,
                    "mergeStatus": "succeeded",
                    "sourceRefName": "refs/heads/qm1",
                    "status": "active",
                    "targetRefName": "refs/heads/main",
                    "title": "New title"
                },
                "id": "XXXX",
                "name": "xsoar",
                "size": 9439,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pull Request Information:
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| New title | Demo pr | XSOAR User | 48 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-03T09:24:48 |


### azure-devops-pull-request-list
***
Retrieve pull requests in repository.


#### Base Command

`azure-devops-pull-request-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project which the pull requests belongs to. | Required | 
| repository | The name of the repository pull request's target branch. | Required | 
| page | The page number of the results to retrieve. Default is 1, minimum is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Default is 50, minimum is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Repository.id | String | The ID of the repository. | 
| AzureDevOps.Project.Repository.name | String | The name of the repository. | 
| AzureDevOps.Project.Repository.url | String | The URL of the repository. | 
| AzureDevOps.Project.Repository.PullRequest.Id | Number | The ID of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.creationDate | Date | The creation date of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.Project.Repository.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.isDraft | Boolean | Draft / WIP pull request. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.commitId | String | The ID of the commit. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeTargetCommit.commitId | String | The ID of the commit. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.reviewerUrl | String | URL to retrieve information about the reviewer identity. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.vote | Number | Vote on a pull request: 10 - approved 5 - approved with suggestions 0 - no vote -5 - waiting for author -10 - rejected | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.hasDeclined | Boolean | Indicates if this reviewer has declined to review this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.isFlagged | Boolean | Indicates if this reviewer is flagged for attention on this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.displayName | String | The display name of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.id | String | The ID of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.uniqueName | String | The unique name of the pull request reviewer. | 


#### Command Example
```!azure-devops-pull-request-list project="xsoar" repository="xsoar" page="1" limit="2"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Repository": {
                "PullRequest": [
                    {
                        "CreatedBy": {
                            "displayName": "XSOAR User",
                            "id": "XXXX",
                            "uniqueName": "user2@xsoar.com"
                        },
                        "Id": 48,
                        "LastMergeSourceCommit": {
                            "commitId": "e44039f67d30924c24615bb334350dd72e41cf44",
                            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/e44039f67d30924c24615bb334350dd72e41cf44"
                        },
                        "LastMergeTargetCommit": {
                            "commitId": "cb63a958fbaed6d416c68330ac8f8a9e5544603c",
                            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/cb63a958fbaed6d416c68330ac8f8a9e5544603c"
                        },
                        "Reviewers": [
                            {
                                "displayName": "XSOAR User",
                                "hasDeclined": false,
                                "id": "XXXX",
                                "isFlagged": false,
                                "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/48/reviewers/XXXX",
                                "uniqueName": "user2@xsoar.com",
                                "vote": 0
                            }
                        ],
                        "creationDate": "2021-11-03T09:24:48",
                        "description": "Demo pr",
                        "isDraft": false,
                        "mergeStatus": "succeeded",
                        "sourceRefName": "refs/heads/qm1",
                        "status": "active",
                        "targetRefName": "refs/heads/main",
                        "title": "Test xsoar"
                    },
                    {
                        "CreatedBy": {
                            "displayName": "XSOAR User",
                            "id": "XXXX",
                            "uniqueName": "user2@xsoar.com"
                        },
                        "Id": 31,
                        "LastMergeSourceCommit": {
                            "commitId": "b9dc78e5897c9640e3be3a8a70c8ec688ab5204b",
                            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b9dc78e5897c9640e3be3a8a70c8ec688ab5204b"
                        },
                        "LastMergeTargetCommit": {
                            "commitId": "d44cbcddda038454199a78d4a757341caf2de7f7",
                            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/d44cbcddda038454199a78d4a757341caf2de7f7"
                        },
                        "Reviewers": [
                            {
                                "displayName": "XSOAR User",
                                "hasDeclined": false,
                                "id": "XXXX",
                                "isFlagged": false,
                                "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/31/reviewers/XXXX",
                                "uniqueName": "user2@xsoar.com",
                                "vote": 0
                            }
                        ],
                        "creationDate": "2021-10-26T08:45:27",
                        "description": "Demo pr - mirroring description 2",
                        "isDraft": false,
                        "mergeStatus": "succeeded",
                        "sourceRefName": "refs/heads/xsoar-test",
                        "status": "active",
                        "targetRefName": "refs/heads/main",
                        "title": "test mirroring - Test demo"
                    }
                ],
                "id": "XXXX",
                "name": "xsoar",
                "size": null,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pull Request List:
> Current page size: 2
> Showing page 1 out others that may exist.
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| Test xsoar | Demo pr | XSOAR User | 48 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-03T09:24:48 |
>| test mirroring - Test demo | Demo pr - mirroring description 2 | XSOAR User | 31 | xsoar | XXXX | xsoar | xsoar-project | 2021-10-26T08:45:27 |


### azure-devops-project-list
***
Retrieve all projects in the organization that the authenticated user has access to.


#### Base Command

`azure-devops-project-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. Default is 1, minimum is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Default is 50, minimum is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.state | String | The state of the project. | 
| AzureDevOps.Project.revision | Number | The revision number of the project. | 
| AzureDevOps.Project.visibility | String | Indicates whom the project is visible to. | 
| AzureDevOps.Project.lastUpdateTime | Date | Project last update time. | 
| AzureDevOps.Project.id | String | The ID of the Project | 


#### Command Example
```!azure-devops-project-list page="1" limit="50"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": [
            {
                "id": "041923ed-7784-4f3a-83fe-4c3e2f381864",
                "lastUpdateTime": "2021-10-27T08:38:28",
                "name": "test",
                "revision": 39,
                "state": "wellFormed",
                "visibility": "private"
            },
            {
                "id": "xsoar-project",
                "lastUpdateTime": "2021-10-13T15:46:18",
                "name": "xsoar",
                "revision": 11,
                "state": "wellFormed",
                "visibility": "private"
            }
        ]
    }
}
```

#### Human Readable Output

>### Project List:
> Current page size: 50
> Showing page 1 out others that may exist.
>|Name|Id|State|Revision|Visibility|Last Update Time|
>|---|---|---|---|---|---|
>| test | 041923ed-7784-4f3a-83fe-4c3e2f381864 | wellFormed | 39 | private | 2021-10-27T08:38:28 |
>| xsoar | xsoar-project | wellFormed | 11 | private | 2021-10-13T15:46:18 |


### azure-devops-repository-list
***
Retrieve git repositories in the organization project.


#### Base Command

`azure-devops-repository-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project to which the repositories belong to. | Required | 
| limit | The number of results to retrieve. Default is 50, minimum is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Default is 1, minimum is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Repository.id | String | The ID of the repository. | 
| AzureDevOps.Project.Repository.name | String | The name of the repository. | 
| AzureDevOps.Project.Repository.url | String | The URL of the repository. | 
| AzureDevOps.Project.Repository.size | Number | The size of the repository. | 


#### Command Example
```!azure-devops-repository-list project="xsoar" limit="1" page="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Repository": [
                {
                    "id": "XXXX",
                    "name": "yehuda123",
                    "size": 1183,
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
                }
            ],
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Repositories List:
> Current page size: 1
> Showing page 1 out others that may exist.
>|Id|Name|Size ( Bytes )|
>|---|---|---|
>| XXXX | yehuda123 | 1183 |


### azure-devops-user-list
***
Query users  in the organization.


#### Base Command

`azure-devops-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Users or organization query prefix. For example, If we want to retrieve information about the user 'Tom' we can enter the value of this argument as 'Tom' . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.User.entityType | String | The type of the entity. | 
| AzureDevOps.User.id | String | The ID of the identity. | 
| AzureDevOps.User.email | String | The email address of the user. | 


#### Command Example
```!azure-devops-user-list query="ofek"```

#### Context Example
```json
{
    "AzureDevOps": {
        "User": [
            {
                "email": "user1@xsoar.com",
                "entityType": "User",
                "id": "XXXX"
            },
            {
                "email": "user2@xsoar.com",
                "entityType": "User",
                "id": "XXXX"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users list:
>|Email|Entity Type|Id|
>|---|---|---|
>| user1@xsoar.com | User | XXXX |
>| user2@xsoar.com | User | XXXX |


### azure-devops-pull-request-get
***
Retrieve pull-request.


#### Base Command

`azure-devops-pull-request-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| repository_id | The repository ID of the pull request's target branch. | Required | 
| pull_request_id | The ID of the pull request to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Repository.id | String | The ID of the repository. | 
| AzureDevOps.Project.Repository.name | String | The name of the repository. | 
| AzureDevOps.Project.Repository.url | String | The URL of the repository. | 
| AzureDevOps.Project.Repository.size | Number | The size of the repository. | 
| AzureDevOps.Project.Repository.PullRequest.Id | Number | The ID of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.CreatedBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.Project.Repository.PullRequest.creationDate | Date | The creation date of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.Project.Repository.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.Project.Repository.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.isDraft | Boolean | Draft / WIP pull request. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.commitId | String | The ID of the commit at the head of the source branch at the time of the last pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeTargetCommit.commitId | String | The ID of the commit at the head of the target branch at the time of the last pull request merge. | 
| AzureDevOps.Project.Repository.PullRequest.LastMergeTargetCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.reviewerUrl | String | URL to retrieve information about the reviewer identity. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.vote | Number | Vote on a pull request: 10 - approved 5 - approved with suggestions 0 - no vote -5 - waiting for author -10 - rejected | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.hasDeclined | Boolean | Indicates if this reviewer has declined to review this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.isFlagged | Boolean | Indicates if this reviewer is flagged for attention on this pull request. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.displayName | String | The display name of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.id | String | The ID of the pull request reviewer. | 
| AzureDevOps.Project.Repository.PullRequest.Reviewers.uniqueName | String | The unique name of the pull request reviewer. | 


#### Command Example
```!azure-devops-pull-request-get project="xsoar" repository_id="XXXX" pull_request_id="48"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Repository": {
                "PullRequest": {
                    "CreatedBy": {
                        "displayName": "XSOAR User",
                        "id": "XXXX",
                        "uniqueName": "user2@xsoar.com"
                    },
                    "Id": 48,
                    "LastMergeSourceCommit": {
                        "commitId": "e44039f67d30924c24615bb334350dd72e41cf44",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/e44039f67d30924c24615bb334350dd72e41cf44"
                    },
                    "LastMergeTargetCommit": {
                        "commitId": "cb63a958fbaed6d416c68330ac8f8a9e5544603c",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/cb63a958fbaed6d416c68330ac8f8a9e5544603c"
                    },
                    "Reviewers": [
                        {
                            "displayName": "XSOAR User",
                            "hasDeclined": false,
                            "id": "XXXX",
                            "isFlagged": false,
                            "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/48/reviewers/XXXX",
                            "uniqueName": "user2@xsoar.com",
                            "vote": 0
                        }
                    ],
                    "creationDate": "2021-11-03T09:24:48",
                    "description": "Demo pr",
                    "isDraft": false,
                    "mergeStatus": "succeeded",
                    "sourceRefName": "refs/heads/qm1",
                    "status": "active",
                    "targetRefName": "refs/heads/main",
                    "title": "Test xsoar"
                },
                "id": "XXXX",
                "name": "xsoar",
                "size": 9439,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pull Request Information:
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| Test xsoar | Demo pr | XSOAR User | 48 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-03T09:24:48 |


### azure-devops-pipeline-run-get
***
Retrieve pipeline run information.


#### Base Command

`azure-devops-pipeline-run-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| pipeline_id | The ID of the pipeline to retrieve. | Required | 
| run_id | The ID of the pipeline run to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.Project.Pipeline.revision | Number | Pipeline revision number | 
| AzureDevOps.Project.Pipeline.name | String | Pipeline repository name | 
| AzureDevOps.Project.Pipeline.folder | String | Pipeline folder | 
| AzureDevOps.Project.Pipeline.Run.state | String | The run state. | 
| AzureDevOps.Project.Pipeline.Run.createdDate | Date | Run-pipeline creation date. | 
| AzureDevOps.Project.Pipeline.Run.url | String | The URL of the run. | 
| AzureDevOps.Project.Pipeline.Run.id | Number | The ID of the run. | 
| AzureDevOps.Project.Pipeline.Run.name | String | The name of the run. | 
| AzureDevOps.Project.Pipeline.Run.name | String | The result of the pipeline running. If the run is in progress, the default value is 'unknown'. | 


#### Command Example
```!azure-devops-pipeline-run-get project="xsoar" pipeline_id="1" run_id="13"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Pipeline": {
                "Run": {
                    "createdDate": "2021-10-25T06:34:31",
                    "id": 13,
                    "name": "20211025.1",
                    "result": "failed",
                    "state": "completed",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/13"
                },
                "folder": "\\",
                "id": 1,
                "name": "xsoar",
                "revision": 1
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pipeline Run Information:
>|Pipeline Id|Run State|Creation Date|Run Id|Result|
>|---|---|---|---|---|
>| 1 | completed | 2021-10-25T06:34:31 | 13 | failed |


### azure-devops-pipeline-run-list
***
Retrieve pipeline runs list. The command retrieves up to the top 10000 runs for a particular pipeline.


#### Base Command

`azure-devops-pipeline-run-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the organizaion project. | Required | 
| page | The page number of the results to retrieve. Default is 1, minimum is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Default is 50, minimum is 1. Default is 50. | Optional | 
| pipeline_id | The ID of the pipeline which the runs belongs to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.Project.Pipeline.revision | Number | Pipeline revision number | 
| AzureDevOps.Project.Pipeline.name | String | Pipeline repository name | 
| AzureDevOps.Project.Pipeline.folder | String | Pipeline folder | 
| AzureDevOps.Project.Pipeline.Run.state | String | The run state. | 
| AzureDevOps.Project.Pipeline.Run.createdDate | Date | Run-pipeline creation date. | 
| AzureDevOps.Project.Pipeline.Run.url | String | The URL of the run. | 
| AzureDevOps.Project.Pipeline.Run.id | Number | The ID of the run. | 
| AzureDevOps.Project.Pipeline.Run.name | String | The name of the run. | 
| AzureDevOps.Project.Pipeline.Run.name | String | The result of the pipeline running. If the run is in progress, the default value is 'unknown'. | 


#### Command Example
```!azure-devops-pipeline-run-list project="xsoar" page="1" limit="1" pipeline_id="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Pipeline": [
                {
                    "Run": {
                        "createdDate": "2021-11-03T09:25:20",
                        "id": 113,
                        "name": "20211103.1",
                        "result": "failed",
                        "state": "completed",
                        "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/113"
                    },
                    "folder": "\\",
                    "id": 1,
                    "name": "xsoar",
                    "revision": 1
                }
            ],
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pipeline runs List:
> Current page size: 1
> Showing page 1 out others that may exist.
>|Pipeline Id|Run State|Creation Date|Run Id|Result|
>|---|---|---|---|---|
>| 1 | completed | 2021-11-03T09:25:20 | 113 | failed |


### azure-devops-pipeline-list
***
Retrieve project pipelines list.


#### Base Command

`azure-devops-pipeline-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the organizaion project. | Required | 
| page | The page number of the results to retrieve. Default is 1, minimum is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Default is 50, minimum is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.Project.Pipeline.revision | Number | Pipeline revision number | 
| AzureDevOps.Project.Pipeline.name | String | Pipeline repository name | 
| AzureDevOps.Project.Pipeline.folder | String | Pipeline folder | 


#### Command Example
```!azure-devops-pipeline-list project="xsoar" page="1" limit="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Pipeline": [
                {
                    "folder": "\\",
                    "id": 2,
                    "name": "xsoar (1)",
                    "revision": 1
                }
            ],
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Pipelines List:
> Current page size: 1
> Showing page 1 out others that may exist.
>|Id|Name|Revision|Folder|
>|---|---|---|---|
>| 2 | xsoar (1) | 1 | \ |


### azure-devops-branch-list
***
Retrieve repository branches list.


#### Base Command

`azure-devops-branch-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the organizaion project. | Required | 
| repository | The name of the project repository. | Required | 
| page | The page number of the results to retrieve. Default is 1, minimum is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Default is 50, minimum is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.Repository.name | String | The name of the repository. | 
| AzureDevOps.Project.Repository.Branch.name | String | The name of the branch | 
| AzureDevOps.Project.Repository.Branch.creator | String | Thr creator of the branch. | 


#### Command Example
```!azure-devops-branch-list project="xsoar" repository="xsoar" page="1" limit="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": {
            "Repository": {
                "Branch": [
                    {
                        "creator": "XSOAR User",
                        "name": "main"
                    }
                ],
                "name": "xsoar"
            },
            "name": "xsoar"
        }
    }
}
```

#### Human Readable Output

>### Branches List:
> Current page size: 1
> Showing page 1 out others that may exist.
>|Name|Creator|
>|---|---|
>| main | XSOAR User |

