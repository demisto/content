# Azure DevOps
Manage Git repositories in Azure DevOps Services. Integration capabilities include retrieving, creating, and updating pull requests. Run pipelines and retrieve git information.
** Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
This integration was integrated and tested with version 6.1 of AzureDevOps

## Configure AzureDevOps (Beta) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureDevOps (Beta).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Client ID | App Registration Client ID | True |
    | Organization | Organizaion name | True |
    | Maximum incidents for one fetch. | Default is 50. Maximum is 200. | False |
    | Pull-request project name | The name of the project which the pull requests belongs to. This argument is mandatory for Fetch functionality. | False |
    | Pull-request repository name | The name of the repository pull request's target branch. This argument is mandatory for Fetch functionality. | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Outgoing mirroring |  | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |

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
>1. To sign in, use a web browser to open the page [https:<span>//</span>microsoft.com/devicelogin](https://microsoft.com/devicelogin)
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
Run this command if you need to rerun the authentication process for some reason.


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

### get-mapping-fields
***
Get mapping fields from remote incident. Please note that this method will not update the current incident. It's here for debugging purposes.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### azure-devops-pipeline-run
***
Run a pipeline. A DevOps pipeline is a set of automated processes and tools that allows both developers and operations professionals to work cohesively to build and deploy code to a production environment.


#### Base Command

`azure-devops-pipeline-run`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| pipeline_id | The ID of the pipeline. | Required | 
| branch_name | The name of the repository branch which runs the pipeline. | Required | 
| polling | Use Cortex XSOAR built-in polling to retrieve the result when it's ready. Possible values are: True, False. Default is False. | Optional | 
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 60. | Optional | 
| run_id | The ID of the pipeline run to retrieve when polling argument is 'True'. Intended for use by the Polling process and does not need to be provided by the user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PipelineRun.project | String | The name of the project. | 
| AzureDevOps.PipelineRun.pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.PipelineRun.pipeline.name | String | The pipeline repository name. | 
| AzureDevOps.PipelineRun.state | String | The run state. | 
| AzureDevOps.PipelineRun.createdDate | Date | The run creation date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PipelineRun.run_id | Number | The ID of the run. | 
| AzureDevOps.PipelineRun.name | String | The name of the run. | 
| AzureDevOps.PipelineRun.result | String | The result of the pipeline running. If the run is in progress, the default value is 'unknown'. | 


#### Command Example
```!azure-devops-pipeline-run project="xsoar" pipeline_id="1" branch_name="main"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PipelineRun": {
            "_links": {
                "pipeline": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1?revision=1"
                },
                "pipeline.web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/definition?definitionId=1"
                },
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/1154"
                },
                "web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/results?buildId=1154"
                }
            },
            "createdDate": "2021-11-30T08:57:03.110121+00:00",
            "name": "20211130.1",
            "pipeline": {
                "folder": "\\",
                "id": 1,
                "name": "xsoar",
                "revision": 1,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1?revision=1"
            },
            "project": "xsoar",
            "resources": {
                "repositories": {
                    "self": {
                        "refName": "refs/heads/main",
                        "repository": {
                            "id": "XXXX",
                            "type": "azureReposGit"
                        },
                        "version": "2eca089fab76f1f32051d188653ea7d279b90a4b"
                    }
                }
            },
            "result": "unknown",
            "run_id": 1154,
            "state": "inProgress",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/1154"
        }
    }
}
```

#### Human Readable Output

>### Pipeline Run Information:
>|Pipeline Id|Run State|Creation Date|Run Id|Result|
>|---|---|---|---|---|
>| 1 | inProgress | 2021-11-30T08:57:03.110121+00:00 | 1154 | unknown |


### azure-devops-user-add
***
Add a user, assign the user a license and extensions, and make the user a member of a project group in an account.


#### Base Command

`azure-devops-user-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_email | The email address of the user to add to the organization. | Required | 
| account_license_type | The type of account license. Possible values: "express", "stakeholder", "advanced", "earlyAdopter", and "professional". More information can be found here: https://docs.microsoft.com/en-us/rest/api/azure/devops/memberentitlementmanagement/user-entitlements/add?view=azure-devops-rest-6.1#accountlicensetype. | Required | 
| group_type | The project group type. Possible values: "projectReader", "projectContributor", "projectAdministrator", and "projectStakeholder". More information can be found here: https://docs.microsoft.com/en-us/rest/api/azure/devops/memberentitlementmanagement/user-entitlements/add?view=azure-devops-rest-6.1#grouptype. | Required | 
| project_id | The ID of the project. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.User.id | String | The ID of the user. | 


#### Command Example
```!azure-devops-user-add user_email="user1@xsoar.com" account_license_type="express" group_type="projectContributor" project_id="xsoar-project"```

#### Context Example
```json
{
    "AzureDevOps": {
        "User": {
            "accessLevel": {
                "accountLicenseType": "express",
                "assignmentSource": "unknown",
                "licenseDisplayName": "Basic",
                "licensingSource": "account",
                "msdnLicenseType": "none",
                "status": "pending",
                "statusMessage": ""
            },
            "dateCreated": "2021-11-29T09:05:26.9223894Z",
            "extensions": [],
            "groupAssignments": [],
            "id": "XXXX",
            "lastAccessedDate": "0001-01-01T00:00:00Z",
            "projectEntitlements": [],
            "user": {
                "_links": {
                    "avatar": {
                        "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3"
                    },
                    "membershipState": {
                        "href": "https://vssps.dev.azure.com/xsoar-organization/_apis/Graph/MembershipStates/aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3"
                    },
                    "memberships": {
                        "href": "https://vssps.dev.azure.com/xsoar-organization/_apis/Graph/Memberships/aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3"
                    },
                    "self": {
                        "href": "https://vssps.dev.azure.com/xsoar-organization/_apis/Graph/Users/aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3"
                    },
                    "storageKey": {
                        "href": "https://vssps.dev.azure.com/xsoar-organization/_apis/Graph/StorageKeys/aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3"
                    }
                },
                "descriptor": "aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3",
                "directoryAlias": "User 1",
                "displayName": "XSOAR User 2",
                "domain": "XXXX",
                "mailAddress": "user1@xsoar.com",
                "metaType": "member",
                "origin": "aad",
                "originId": "2c7514ff-41d0-4eb0-ac82-35b8671de094",
                "principalName": "user1@xsoar.com",
                "subjectKind": "user",
                "url": "https://vssps.dev.azure.com/xsoar-organization/_apis/Graph/Users/aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3"
            }
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
| user_id | The ID of the user to be removed from the organization. A user ID can be obtained by running the 'azure-devops-user-list' command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-devops-user-remove user_id="XXXX"```

#### Human Readable Output

>User XXXX was successfully removed from the organization.

### azure-devops-pull-request-create
***
Create a new pull request.


#### Base Command

`azure-devops-pull-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name or ID of the project. | Required | 
| repository_id | The repository ID of the pull request's target branch. A repository ID can be obtained by running the 'azure-devops-repository-list' command. | Required | 
| source_branch | The name of the source branch of the pull request. | Required | 
| target_branch | The name of the target branch of the pull request. | Required | 
| title | The title of the pull request. | Required | 
| description | The description of the pull request. | Required | 
| reviewers_ids | Comma-separated list of the pull request reviewers IDs. A reviewer ID can be obtained by running the 'azure-devops-user-list' command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequest.repository.project.name | String | The name of the project. | 
| AzureDevOps.PullRequest.repository.id | String | The ID of the repository. | 
| AzureDevOps.PullRequest.repository.name | String | The name of the repository. | 
| AzureDevOps.PullRequest.repository.url | String | The URL of the repository. | 
| AzureDevOps.PullRequest.repository.size | Number | The size of the repository. | 
| AzureDevOps.PullRequest.pullRequestId | Number | The ID of the pull request. | 
| AzureDevOps.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.PullRequest.createdBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.PullRequest.creationDate | Date | The creation date of the pull request, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.PullRequest.isDraft | Boolean | Whether the pull request is a draft / WIP. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.commitId | String | The ID of the commit at the head of the source branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.commitId | String | The ID of the commit at the head of the target branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.url | String | The REST URL for this resource. | 


#### Command Example
```!azure-devops-pull-request-create project="xsoar" repository_id="XXXX" source_branch="test-test" target_branch="main" title="Test xsoar" description="Demo pr" reviewers_ids="XXXX"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PullRequest": {
            "_links": {
                "createdBy": {
                    "href": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
                },
                "iterations": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/iterations"
                },
                "repository": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
                },
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
                },
                "sourceBranch": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs/heads/test-test"
                },
                "sourceCommit": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
                },
                "statuses": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/statuses"
                },
                "targetBranch": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs/heads/main"
                },
                "targetCommit": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
                },
                "workItems": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/workitems"
                }
            },
            "artifactId": "vstfs:///Git/PullRequestId/xsoar-project%2fXXXX%2f70",
            "codeReviewId": 70,
            "createdBy": {
                "_links": {
                    "avatar": {
                        "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                    }
                },
                "descriptor": "aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5",
                "displayName": "XSOAR User 1",
                "id": "XXXX",
                "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                "uniqueName": "user2@xsoar.com",
                "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
            },
            "creationDate": "2021-11-30T08:56:55.531709+00:00",
            "description": "Demo pr",
            "isDraft": false,
            "labels": [],
            "lastMergeSourceCommit": {
                "commitId": "b21e2330a6ae2f920b8f5ae9b74e069230b27087",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
            },
            "lastMergeTargetCommit": {
                "commitId": "2eca089fab76f1f32051d188653ea7d279b90a4b",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
            },
            "mergeId": "a950a614-1a14-4412-90ad-e6f7417e26c6",
            "mergeStatus": "queued",
            "pullRequestId": 70,
            "repository": {
                "id": "XXXX",
                "isDisabled": false,
                "name": "xsoar",
                "project": {
                    "id": "xsoar-project",
                    "lastUpdateTime": "2021-10-13T15:46:18.017Z",
                    "name": "xsoar",
                    "revision": 11,
                    "state": "wellFormed",
                    "url": "https://dev.azure.com/xsoar-organization/_apis/projects/xsoar-project",
                    "visibility": "private"
                },
                "remoteUrl": "https://xsoar-organization@dev.azure.com/xsoar-organization/xsoar/_git/xsoar",
                "size": 12366,
                "sshUrl": "git@ssh.dev.azure.com:v3/xsoar-organization/xsoar/xsoar",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX",
                "webUrl": "https://dev.azure.com/xsoar-organization/xsoar/_git/xsoar"
            },
            "reviewers": [
                {
                    "_links": {
                        "avatar": {
                            "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                        }
                    },
                    "displayName": "XSOAR User 1",
                    "hasDeclined": false,
                    "id": "XXXX",
                    "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                    "isFlagged": false,
                    "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/reviewers/XXXX",
                    "uniqueName": "user2@xsoar.com",
                    "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX",
                    "vote": 0
                }
            ],
            "sourceRefName": "refs/heads/test-test",
            "status": "active",
            "supportsIterations": true,
            "targetRefName": "refs/heads/main",
            "title": "Test xsoar",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
        }
    }
}
```

#### Human Readable Output

>### Pull Request Information:
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| Test xsoar | Demo pr | XSOAR User 1 | 70 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-30T08:56:55 |


### azure-devops-pull-request-update
***
Update a pull request. At least one of the following arguments must be provided: title, description, or status.


#### Base Command

`azure-devops-pull-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name or ID of the project. | Required | 
| repository_id | The repository ID of the pull request's target branch. A repository ID can be obtained by running the 'azure-devops-repository-list' command. | Required | 
| pull_request_id | The ID of the pull request to update. | Required | 
| title | The updated pull-request title. | Optional | 
| description | The updated pull-request description. | Optional | 
| status | The updated pull-request status. Possible values: "abandoned", "completed", and "active". Possible values are: abandoned, completed, active. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequest.repository.project.name | String | The name of the project. | 
| AzureDevOps.PullRequest.repository.id | String | The ID of the repository. | 
| AzureDevOps.PullRequest.repository.name | String | The name of the repository. | 
| AzureDevOps.PullRequest.repository.url | String | The URL of the repository. | 
| AzureDevOps.PullRequest.repository.size | Number | The size of the repository. | 
| AzureDevOps.PullRequest.pullRequestId | Number | The ID of the pull request. | 
| AzureDevOps.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.PullRequest.createdBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.PullRequest.creationDate | Date | The creation date of the pull request, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.PullRequest.isDraft | Boolean | Whether the pull request is a draft / WIP. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.commitId | String | The ID of the commit at the head of the source branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.commitId | String | The ID of the commit at the head of the target branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.url | String | The REST URL for this resource. | 


#### Command Example
```!azure-devops-pull-request-update project="xsoar" repository_id="XXXX" pull_request_id="70" title="New title"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PullRequest": {
            "_links": {
                "createdBy": {
                    "href": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
                },
                "iterations": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/iterations"
                },
                "repository": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
                },
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
                },
                "sourceBranch": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs/heads/test-test"
                },
                "sourceCommit": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
                },
                "statuses": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/statuses"
                },
                "targetBranch": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs/heads/main"
                },
                "targetCommit": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
                },
                "workItems": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/workitems"
                }
            },
            "artifactId": "vstfs:///Git/PullRequestId/xsoar-project%2fXXXX%2f70",
            "codeReviewId": 70,
            "createdBy": {
                "_links": {
                    "avatar": {
                        "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                    }
                },
                "descriptor": "aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5",
                "displayName": "XSOAR User 1",
                "id": "XXXX",
                "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                "uniqueName": "user2@xsoar.com",
                "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
            },
            "creationDate": "2021-11-30T08:56:55.531709+00:00",
            "description": "Demo pr",
            "isDraft": false,
            "lastMergeCommit": {
                "author": {
                    "date": "2021-11-30T08:56:55Z",
                    "email": "user2@xsoar.com",
                    "name": "XSOAR User 1"
                },
                "comment": "Merge pull request 70 from test-test into main",
                "commitId": "333b2ec34ca6b330901af84a2483c87effb49c23",
                "committer": {
                    "date": "2021-11-30T08:56:55Z",
                    "email": "user2@xsoar.com",
                    "name": "XSOAR User 1"
                },
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/333b2ec34ca6b330901af84a2483c87effb49c23"
            },
            "lastMergeSourceCommit": {
                "commitId": "b21e2330a6ae2f920b8f5ae9b74e069230b27087",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
            },
            "lastMergeTargetCommit": {
                "commitId": "2eca089fab76f1f32051d188653ea7d279b90a4b",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
            },
            "mergeId": "a950a614-1a14-4412-90ad-e6f7417e26c6",
            "mergeStatus": "succeeded",
            "pullRequestId": 70,
            "repository": {
                "id": "XXXX",
                "isDisabled": false,
                "name": "xsoar",
                "project": {
                    "id": "xsoar-project",
                    "lastUpdateTime": "2021-10-13T15:46:18.017Z",
                    "name": "xsoar",
                    "revision": 11,
                    "state": "wellFormed",
                    "url": "https://dev.azure.com/xsoar-organization/_apis/projects/xsoar-project",
                    "visibility": "private"
                },
                "remoteUrl": "https://xsoar-organization@dev.azure.com/xsoar-organization/xsoar/_git/xsoar",
                "size": 12366,
                "sshUrl": "git@ssh.dev.azure.com:v3/xsoar-organization/xsoar/xsoar",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX",
                "webUrl": "https://dev.azure.com/xsoar-organization/xsoar/_git/xsoar"
            },
            "reviewers": [
                {
                    "_links": {
                        "avatar": {
                            "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                        }
                    },
                    "displayName": "XSOAR User 1",
                    "hasDeclined": false,
                    "id": "XXXX",
                    "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                    "isFlagged": false,
                    "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/reviewers/XXXX",
                    "uniqueName": "user2@xsoar.com",
                    "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX",
                    "vote": 0
                }
            ],
            "sourceRefName": "refs/heads/test-test",
            "status": "active",
            "supportsIterations": true,
            "targetRefName": "refs/heads/main",
            "title": "New title",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
        }
    }
}
```

#### Human Readable Output

>### Pull Request Information:
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| New title | Demo pr | XSOAR User 1 | 70 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-30T08:56:55 |


### azure-devops-pull-request-list
***
Retrieve pull requests in repository.


#### Base Command

`azure-devops-pull-request-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name or ID of the project which the pull requests belongs to. | Required | 
| repository | The name of the repository pull request's target branch. | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum  value is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequest.repository.project.name | String | The name of the project. | 
| AzureDevOps.PullRequest.repository.id | String | The ID of the repository. | 
| AzureDevOps.PullRequest.repository.name | String | The name of the repository. | 
| AzureDevOps.PullRequest.repository.url | String | The URL of the repository. | 
| AzureDevOps.PullRequest.pullRequestId | Number | The ID of the pull request. | 
| AzureDevOps.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.PullRequest.createdBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.PullRequest.creationDate | Date | The creation date of the pull request, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.PullRequest.isDraft | Boolean | Whether the pull request is a draft / WIP. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.commitId | String | The ID of the commit at the head of the source branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.url | String | The REST URL for this resource. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.commitId | String | The ID of the commit at the head of the target branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.url | String | The REST URL for this resource. | 


#### Command Example
```!azure-devops-pull-request-list project="xsoar" repository="xsoar" page="1" limit="2"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PullRequest": [
            {
                "codeReviewId": 70,
                "createdBy": {
                    "_links": {
                        "avatar": {
                            "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                        }
                    },
                    "descriptor": "aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5",
                    "displayName": "XSOAR User 1",
                    "id": "XXXX",
                    "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                    "uniqueName": "user2@xsoar.com",
                    "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
                },
                "creationDate": "2021-11-30T08:56:55.531709+00:00",
                "description": "Demo pr",
                "isDraft": false,
                "lastMergeCommit": {
                    "commitId": "333b2ec34ca6b330901af84a2483c87effb49c23",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/333b2ec34ca6b330901af84a2483c87effb49c23"
                },
                "lastMergeSourceCommit": {
                    "commitId": "b21e2330a6ae2f920b8f5ae9b74e069230b27087",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
                },
                "lastMergeTargetCommit": {
                    "commitId": "2eca089fab76f1f32051d188653ea7d279b90a4b",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
                },
                "mergeId": "a950a614-1a14-4412-90ad-e6f7417e26c6",
                "mergeStatus": "succeeded",
                "pullRequestId": 70,
                "repository": {
                    "id": "XXXX",
                    "name": "xsoar",
                    "project": {
                        "id": "xsoar-project",
                        "lastUpdateTime": "0001-01-01T00:00:00",
                        "name": "xsoar",
                        "state": "unchanged",
                        "visibility": "unchanged"
                    },
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
                },
                "reviewers": [
                    {
                        "_links": {
                            "avatar": {
                                "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                            }
                        },
                        "displayName": "XSOAR User 1",
                        "hasDeclined": false,
                        "id": "XXXX",
                        "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                        "isFlagged": false,
                        "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/reviewers/XXXX",
                        "uniqueName": "user2@xsoar.com",
                        "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX",
                        "vote": 0
                    }
                ],
                "sourceRefName": "refs/heads/test-test",
                "status": "active",
                "supportsIterations": true,
                "targetRefName": "refs/heads/main",
                "title": "Test xsoar",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
            },
            {
                "codeReviewId": 65,
                "createdBy": {
                    "_links": {
                        "avatar": {
                            "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                        }
                    },
                    "descriptor": "aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5",
                    "displayName": "XSOAR User 1",
                    "id": "XXXX",
                    "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                    "uniqueName": "user2@xsoar.com",
                    "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
                },
                "creationDate": "2021-11-28T16:08:09.172985+00:00",
                "description": "Demo pr",
                "isDraft": false,
                "lastMergeCommit": {
                    "commitId": "62d2b76a5479406cdfba377f041fed7bb621ccf7",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/62d2b76a5479406cdfba377f041fed7bb621ccf7"
                },
                "lastMergeSourceCommit": {
                    "commitId": "738ab51bc619423969314de9bb93373bfb6ae101",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/738ab51bc619423969314de9bb93373bfb6ae101"
                },
                "lastMergeTargetCommit": {
                    "commitId": "2eca089fab76f1f32051d188653ea7d279b90a4b",
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
                },
                "mergeId": "46bd552a-8a93-45bb-82ae-4c108020ca15",
                "mergeStatus": "succeeded",
                "pullRequestId": 65,
                "repository": {
                    "id": "XXXX",
                    "name": "xsoar",
                    "project": {
                        "id": "xsoar-project",
                        "lastUpdateTime": "0001-01-01T00:00:00",
                        "name": "xsoar",
                        "state": "unchanged",
                        "visibility": "unchanged"
                    },
                    "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
                },
                "reviewers": [
                    {
                        "_links": {
                            "avatar": {
                                "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                            }
                        },
                        "displayName": "XSOAR User 1",
                        "hasDeclined": false,
                        "id": "XXXX",
                        "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                        "isFlagged": false,
                        "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/65/reviewers/XXXX",
                        "uniqueName": "user2@xsoar.com",
                        "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX",
                        "vote": 0
                    }
                ],
                "sourceRefName": "refs/heads/xsoar-test",
                "status": "active",
                "supportsIterations": true,
                "targetRefName": "refs/heads/main",
                "title": "Test xsoar",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/65"
            }
        ]
    }
}
```

#### Human Readable Output

>### Pull Request List:
> Current page size: 2
> Showing page 1 out others that may exist.
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| Test xsoar | Demo pr | XSOAR User 1 | 70 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-30T08:56:55 |
>| Test xsoar | Demo pr | XSOAR User 1 | 65 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-28T16:08:09 |


### azure-devops-project-list
***
Retrieve all projects in the organization that the authenticated user has access to.


#### Base Command

`azure-devops-project-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Project.state | String | The state of the project. | 
| AzureDevOps.Project.revision | Number | The revision number of the project. | 
| AzureDevOps.Project.visibility | String | Indicates whom the project is visible to. | 
| AzureDevOps.Project.lastUpdateTime | Date | The project last update time, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.Project.id | String | The ID of the Project. | 


#### Command Example
```!azure-devops-project-list page="1" limit="50"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Project": [
            {
                "id": "xsoar-project",
                "lastUpdateTime": "2021-10-13T15:46:18.017000+00:00",
                "name": "xsoar",
                "revision": 11,
                "state": "wellFormed",
                "url": "https://dev.azure.com/xsoar-organization/_apis/projects/xsoar-project",
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
>| xsoar | xsoar-project | wellFormed | 11 | private | 2021-10-13T15:46:18.017000+00:00 |


### azure-devops-repository-list
***
Retrieve git repositories in the organization project.


#### Base Command

`azure-devops-repository-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name or ID of the project to which the repositories belong to. | Required | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Project.name | String | The name of the project. | 
| AzureDevOps.Repository.id | String | The ID of the repository. | 
| AzureDevOps.Repository.name | String | The name of the repository. | 
| AzureDevOps.Repository.webUrl | String | The web URL of the repository. | 
| AzureDevOps.Repository.size | Number | The size of the repository \(in bytes\). | 


#### Command Example
```!azure-devops-repository-list project="xsoar" limit="1" page="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Repository": {
            "id": "xsoar-repository",
            "isDisabled": false,
            "name": "test2803",
            "project": {
                "id": "xsoar-project",
                "lastUpdateTime": "2021-10-13T15:46:18.017Z",
                "name": "xsoar",
                "revision": 11,
                "state": "wellFormed",
                "url": "https://dev.azure.com/xsoar-organization/_apis/projects/xsoar-project",
                "visibility": "private"
            },
            "remoteUrl": "https://xsoar-organization@dev.azure.com/xsoar-organization/xsoar/_git/test2803",
            "size": 0,
            "sshUrl": "git@ssh.dev.azure.com:v3/xsoar-organization/xsoar/test2803",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/xsoar-repository",
            "webUrl": "https://dev.azure.com/xsoar-organization/xsoar/_git/test2803"
        }
    }
}
```

#### Human Readable Output

>### Repositories List:
> Current page size: 1
> Showing page 1 out others that may exist.
>|Id|Name|Web Url|Size ( Bytes )|
>|---|---|---|---|
>| xsoar-repository | test2803 | https:<span>//</span>dev.azure.com/xsoar-organization/xsoar/_git/test2803 | 0 |


### azure-devops-user-list
***
Query users that were added to organization projects.


#### Base Command

`azure-devops-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Users or organization query prefix. For example, if you want to retrieve information about the user 'Tom', you can enter the value of this argument as 'Tom'. | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.User.entityType | String | The type of the entity. | 
| AzureDevOps.User.localId | String | The ID of the identity. | 
| AzureDevOps.User.signInAddress | String | The email address of the user. | 


#### Command Example
```!azure-devops-user-list query="ofek"```

#### Context Example
```json
{
    "AzureDevOps": {
        "User": [
            {
                "active": true,
                "department": null,
                "description": null,
                "displayName": "XSOAR User 2",
                "entityId": "vss.ds.v1.aad.user.2c7514ff41d04eb0ac8235b8671de094",
                "entityType": "User",
                "guest": false,
                "isMru": false,
                "jobTitle": null,
                "localDirectory": "vsd",
                "localId": "XXXX",
                "mail": "user1@xsoar.com",
                "mailNickname": "User 1",
                "originDirectory": "aad",
                "originId": "2c7514ff-41d0-4eb0-ac82-35b8671de094",
                "physicalDeliveryOfficeName": null,
                "samAccountName": "user1@xsoar.com",
                "scopeName": "Palo Alto Networks",
                "signInAddress": "user1@xsoar.com",
                "subjectDescriptor": "aad.NWYyZWMzNTctMjgzMS03M2I4LTk1NWYtMmRkZGM2OWVmMzg3",
                "surname": "User 1",
                "telephoneNumber": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Users List:
> Current page size: 50
> Showing page 1 out others that may exist.
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
| project | The name or ID of the project. | Required | 
| repository_id | The repository ID of the pull request's target branch. A repository ID can be obtained by running the 'azure-devops-repository-list' command. | Required | 
| pull_request_id | The ID of the pull request to retrieve. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequest.repository.project.name | String | The name of the project. | 
| AzureDevOps.PullRequest.repository.id | String | The ID of the repository. | 
| AzureDevOps.PullRequest.repository.name | String | The name of the repository. | 
| AzureDevOps.PullRequest.repository.url | String | The URL of the repository. | 
| AzureDevOps.PullRequest.repository.size | Number | The size of the repository. | 
| AzureDevOps.PullRequest.pullRequestId | Number | The ID of the pull request. | 
| AzureDevOps.PullRequest.status | String | The status of the pull request. | 
| AzureDevOps.PullRequest.createdBy.displayName | String | The display name of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.id | String | The ID of the pull request creator. | 
| AzureDevOps.PullRequest.createdBy.uniqueName | String | The unique name of the pull request creator. | 
| AzureDevOps.PullRequest.creationDate | Date | The creation date of the pull request, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PullRequest.title | String | The title of the pull request | 
| AzureDevOps.PullRequest.description | String | The description of the pull request. | 
| AzureDevOps.PullRequest.sourceRefName | String | The source branch of the pull request. | 
| AzureDevOps.PullRequest.targetRefName | String | The target branch of the pull request. | 
| AzureDevOps.PullRequest.mergeStatus | String | The current status of the pull request merge. | 
| AzureDevOps.PullRequest.isDraft | Boolean | Whether the pull request is a draft / WIP. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.commitId | String | The ID of the commit at the head of the source branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeSourceCommit.url | String | The REST URL for the merge source commit. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.commitId | String | The ID of the commit at the head of the target branch at the time of the last pull request merge. | 
| AzureDevOps.PullRequest.lastMergeTargetCommit.url | String | The REST URL for the merge target commit. | 


#### Command Example
```!azure-devops-pull-request-get project="xsoar" repository_id="XXXX" pull_request_id="70"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PullRequest": {
            "_links": {
                "createdBy": {
                    "href": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
                },
                "iterations": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/iterations"
                },
                "repository": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX"
                },
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
                },
                "sourceBranch": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs/heads/test-test"
                },
                "sourceCommit": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
                },
                "statuses": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/statuses"
                },
                "targetBranch": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs/heads/main"
                },
                "targetCommit": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
                },
                "workItems": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/workitems"
                }
            },
            "artifactId": "vstfs:///Git/PullRequestId/xsoar-project%2fXXXX%2f70",
            "codeReviewId": 70,
            "createdBy": {
                "_links": {
                    "avatar": {
                        "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                    }
                },
                "descriptor": "aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5",
                "displayName": "XSOAR User 1",
                "id": "XXXX",
                "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                "uniqueName": "user2@xsoar.com",
                "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
            },
            "creationDate": "2021-11-30T08:56:55.531709+00:00",
            "description": "Demo pr",
            "isDraft": false,
            "lastMergeCommit": {
                "author": {
                    "date": "2021-11-30T08:56:55Z",
                    "email": "user2@xsoar.com",
                    "name": "XSOAR User 1"
                },
                "comment": "Merge pull request 70 from test-test into main",
                "commitId": "333b2ec34ca6b330901af84a2483c87effb49c23",
                "committer": {
                    "date": "2021-11-30T08:56:55Z",
                    "email": "user2@xsoar.com",
                    "name": "XSOAR User 1"
                },
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/333b2ec34ca6b330901af84a2483c87effb49c23"
            },
            "lastMergeSourceCommit": {
                "commitId": "b21e2330a6ae2f920b8f5ae9b74e069230b27087",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/b21e2330a6ae2f920b8f5ae9b74e069230b27087"
            },
            "lastMergeTargetCommit": {
                "commitId": "2eca089fab76f1f32051d188653ea7d279b90a4b",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/commits/2eca089fab76f1f32051d188653ea7d279b90a4b"
            },
            "mergeId": "a950a614-1a14-4412-90ad-e6f7417e26c6",
            "mergeStatus": "succeeded",
            "pullRequestId": 70,
            "repository": {
                "id": "XXXX",
                "isDisabled": false,
                "name": "xsoar",
                "project": {
                    "id": "xsoar-project",
                    "lastUpdateTime": "2021-10-13T15:46:18.017Z",
                    "name": "xsoar",
                    "revision": 11,
                    "state": "wellFormed",
                    "url": "https://dev.azure.com/xsoar-organization/_apis/projects/xsoar-project",
                    "visibility": "private"
                },
                "remoteUrl": "https://xsoar-organization@dev.azure.com/xsoar-organization/xsoar/_git/xsoar",
                "size": 12366,
                "sshUrl": "git@ssh.dev.azure.com:v3/xsoar-organization/xsoar/xsoar",
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX",
                "webUrl": "https://dev.azure.com/xsoar-organization/xsoar/_git/xsoar"
            },
            "reviewers": [
                {
                    "_links": {
                        "avatar": {
                            "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                        }
                    },
                    "displayName": "XSOAR User 1",
                    "hasDeclined": false,
                    "id": "XXXX",
                    "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                    "isFlagged": false,
                    "reviewerUrl": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70/reviewers/XXXX",
                    "uniqueName": "user2@xsoar.com",
                    "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX",
                    "vote": 0
                }
            ],
            "sourceRefName": "refs/heads/test-test",
            "status": "active",
            "supportsIterations": true,
            "targetRefName": "refs/heads/main",
            "title": "Test xsoar",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/pullRequests/70"
        }
    }
}
```

#### Human Readable Output

>### Pull Request Information:
>|Title|Description|Created By|Pull Request Id|Repository Name|Repository Id|Project Name|Project Id|Creation Date|
>|---|---|---|---|---|---|---|---|---|
>| Test xsoar | Demo pr | XSOAR User 1 | 70 | xsoar | XXXX | xsoar | xsoar-project | 2021-11-30T08:56:55 |


### azure-devops-pipeline-run-get
***
Retrieve information for a pipeline run.


#### Base Command

`azure-devops-pipeline-run-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the project. | Required | 
| pipeline_id | The ID of the pipeline to retrieve. | Required | 
| run_id | The ID of the pipeline run to retrieve. | Required | 
| scheduled | Indicates if the command was scheduled. Possible values are: True, False. Default is False. | Optional | 
| interval | Indicates how long to wait between command execution (in seconds) when 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence timeouts. Default is 60. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PipelineRun.project | String | The name of the project. | 
| AzureDevOps.PipelineRun.pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.PipelineRun.pipeline.name | String | Pipeline repository name. | 
| AzureDevOps.PipelineRun.state | String | The run state. | 
| AzureDevOps.PipelineRun.createdDate | Date | The run creation date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PipelineRun.run_id | Number | The ID of the run. | 
| AzureDevOps.PipelineRun.name | String | The name of the run. | 
| AzureDevOps.PipelineRun.result | String | The result of the pipeline running. If the run is in progress, the default value is 'unknown'. | 


#### Command Example
```!azure-devops-pipeline-run-get project="xsoar" pipeline_id="1" run_id="114"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PipelineRun": {
            "_links": {
                "pipeline": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1?revision=1"
                },
                "pipeline.web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/definition?definitionId=1"
                },
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/114"
                },
                "web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/results?buildId=114"
                }
            },
            "createdDate": "2021-11-07T08:09:03.592213+00:00",
            "finishedDate": "2021-11-07T08:09:28.3447367Z",
            "name": "20211107.1",
            "pipeline": {
                "folder": "\\",
                "id": 1,
                "name": "xsoar",
                "revision": 1,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1?revision=1"
            },
            "project": "xsoar",
            "resources": {
                "repositories": {
                    "self": {
                        "refName": "refs/heads/main",
                        "repository": {
                            "id": "XXXX",
                            "type": "azureReposGit"
                        },
                        "version": "2eca089fab76f1f32051d188653ea7d279b90a4b"
                    }
                }
            },
            "result": "failed",
            "run_id": 114,
            "state": "completed",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/114"
        }
    }
}
```

#### Human Readable Output

>### Pipeline Run Information:
>|Pipeline Id|Run State|Creation Date|Run Id|Result|
>|---|---|---|---|---|
>| 1 | completed | 2021-11-07T08:09:03.592213+00:00 | 114 | failed |


### azure-devops-pipeline-run-list
***
Retrieve pipeline runs list. The command retrieves up to the top 10000 runs for a particular pipeline.


#### Base Command

`azure-devops-pipeline-run-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the organization project. | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| pipeline_id | The ID of the pipeline which the runs belongs to. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PipelineRun.project | String | The name of the project. | 
| AzureDevOps.PipelineRun.pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.PipelineRun.pipeline.name | String | Pipeline repository name | 
| AzureDevOps.PipelineRun.state | String | The run state. | 
| AzureDevOps.PipelineRun.createdDate | Date | The run creation date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.PipelineRun.run_id | Number | The ID of the run. | 
| AzureDevOps.PipelineRun.name | String | The name of the run. | 
| AzureDevOps.PipelineRun.result | String | The result of the pipeline running. If the run is in progress, the default value is 'unknown'. | 


#### Command Example
```!azure-devops-pipeline-run-list project="xsoar" page="1" limit="1" pipeline_id="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "PipelineRun": {
            "_links": {
                "pipeline": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1?revision=1"
                },
                "pipeline.web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/definition?definitionId=1"
                },
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/1154"
                },
                "web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/results?buildId=1154"
                }
            },
            "createdDate": "2021-11-30T08:57:03.110121+00:00",
            "name": "20211130.1",
            "pipeline": {
                "folder": "\\",
                "id": 1,
                "name": "xsoar",
                "revision": 1,
                "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1?revision=1"
            },
            "project": "xsoar",
            "result": "unknown",
            "run_id": 1154,
            "state": "inProgress",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/1/runs/1154"
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
>| 1 | inProgress | 2021-11-30T08:57:03.110121+00:00 | 1154 | unknown |


### azure-devops-pipeline-list
***
Retrieve project pipelines list.


#### Base Command

`azure-devops-pipeline-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The name of the organization project. | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Pipeline.project | String | The name of the project. | 
| AzureDevOps.Pipeline.id | Number | The ID of the pipeline. | 
| AzureDevOps.Pipeline.revision | Number | Pipeline revision number. | 
| AzureDevOps.Pipeline.name | String | Pipeline name. | 
| AzureDevOps.Pipeline.folder | String | Pipeline folder. | 


#### Command Example
```!azure-devops-pipeline-list project="xsoar" page="1" limit="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Pipeline": {
            "_links": {
                "self": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/2?revision=1"
                },
                "web": {
                    "href": "https://dev.azure.com/xsoar-organization/xsoar-project/_build/definition?definitionId=2"
                }
            },
            "folder": "\\",
            "id": 2,
            "name": "xsoar (1)",
            "project": "xsoar",
            "revision": 1,
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/pipelines/2?revision=1"
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
| project | The name of the organization project. | Required | 
| repository | The name of the project repository. | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Branch.project | String | The name of the project. | 
| AzureDevOps.Branch.repository | String | The name of the repository. | 
| AzureDevOps.Branch.name | String | The name of the branch. | 


#### Command Example
```!azure-devops-branch-list project="xsoar" repository="xsoar" page="1" limit="1"```

#### Context Example
```json
{
    "AzureDevOps": {
        "Branch": {
            "creator": {
                "_links": {
                    "avatar": {
                        "href": "https://dev.azure.com/xsoar-organization/_apis/GraphProfile/MemberAvatars/aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5"
                    }
                },
                "descriptor": "aad.ZWFlMjk2ZGYtMzYwOS03YWY3LWFkNzMtYzNlYmRhZDM3ZmQ5",
                "displayName": "XSOAR User 1",
                "id": "XXXX",
                "imageUrl": "https://dev.azure.com/xsoar-organization/_api/_common/identityImage?id=XXXX",
                "uniqueName": "user2@xsoar.com",
                "url": "https://vssps.visualstudio.com/XXXX/_apis/Identities/XXXX"
            },
            "name": "refs/heads/main",
            "objectId": "2eca089fab76f1f32051d188653ea7d279b90a4b",
            "project": "xsoar",
            "repository": "xsoar",
            "url": "https://dev.azure.com/xsoar-organization/xsoar-project/_apis/git/repositories/XXXX/refs?filter=heads%2Fmain"
        }
    }
}
```

#### Human Readable Output

>### Branches List:
> Current page size: 1
> Showing page 1 out others that may exist.
>|Name|
>|---|
>| refs/heads/main |

