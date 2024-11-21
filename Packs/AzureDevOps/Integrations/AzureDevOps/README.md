# Azure DevOps
Manage Git repositories in Azure DevOps Services. Integration capabilities include retrieving, creating, and updating pull requests. Run pipelines and retrieve git information.

## Configure AzureDevOps in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Client ID | App Registration Client ID | True |
| Organization | Organization name | True |
| Maximum incidents for one fetch. | Default is 50. Maximum is 200. | False |
| Pull-request project name | The name of the project which the pull requests belongs to. A project name can be obtained by running the 'azure-devops-project-list' command. This argument is mandatory for Fetch functionality. | False |
| Pull-request repository name | The name of the repository pull request's target branch. A repository name can be obtained by running the 'azure-devops-repository-list' command. This argument is mandatory for Fetch functionality. | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Outgoing mirroring |  | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Authentication Type | Type of authentication - could be Authorization Code Flow \(recommended\), Device Code Flow or Client Credentials Flow. | False |
| Tenant ID | For user-auth mode or client credentials.| False |
| Client Secret | For user-auth mode or client credentials. | False |
| Application redirect URI | For user-auth mode or client credentials. | False |
| Authorization code | for user-auth mode - received from the authorization step. see Detailed Instructions \(?\) section | False |


In order to connect to the Azure DevOps using the Self-Deployed Azure App, use one of the following methods:

- *Authorization Code Flow* (Recommended).
- *Device Code Flow*.
- *Client Credentials Flow*.

## Self-Deployed Azure App

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.
To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.
1. Add the following permissions to your registered app:
   - `Azure DevOps/user_impersonation`
   - `Microsoft Graph/User.Read`
  To add a permission:
   a. Navigate to **Azure Portal > **Home** > **App registrations**.
   b. Search for your app under 'all applications'.
   c. Click **API permissions** > **Add permission**.
   d. Search for the specific Microsoft API and select the specific permission of type Delegated.
   e. Click **Grant admin consent**.
1. In your registered app - Get the Application (client) ID. 
   a. In the Azure Portal, navigate to **App registrations** > your registered application > **Overview**.
   b. Copy and save the Application (client) ID.
2. In the *Client ID* parameter, enter your registered app Application (client) ID.
3. In the *Organization* parameter, enter the Azure DevOps organization name.
   More information about creating an organization or project can be found here:
   
    [Create an organization](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/create-organization?view=azure-devops)

    [Create a project](https://docs.microsoft.com/en-us/azure/devops/organizations/projects/create-project?view=azure-devops&tabs=preview-page)

To the Azure DevOps Account, use one of the following flows-

## Authorization Code Flow(Recommended).

For a Authorization Code configuration:

   1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
   2. In the *Authentication Type* field, select the **Authorization Code** option.
   3. In the **Application ID** field, enter your Client/Application ID. 
   4. In the **Client Secret** field, enter your Client Secret.
   5. In the **Tenant ID** field, enter your Tenant ID .
   6. In the **Application redirect URI** field, enter your Application redirect URI.
   7. Save the instance.
   8. Run the `!azure-devops-generate-login-url` command in the War Room and follow the instruction.
   9. Run the ***!azure-devops-auth-test*** command - a 'Success' message should be printed to the War Room.


## Device Code Flow

To use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

   1. In the **Application ID** field, enter your Client/Application ID.
   2. Run the ***!azure-devops-auth-start*** command.
   3. Follow the instructions that appear.
   4. Run the ***!azure-devops-auth-complete*** command.
   

## Client Credentials Flow

Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)
*Note:* In the *Select members* section, assign the application you created earlier.
To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   1. In the **Authentication Type** field, select the **Client Credentials** option.
   2. In the **Application ID** field, enter your Client/Application ID.
   3. In the **Tenant ID** field, enter your Tenant ID .
   4. In the **Client Secret** field, enter your Client Secret.
   5. Click **Test** to validate the URLs, token, and connection
   6. Save the instance.
    
### Testing authentication and connectivity
If you are using Device Code Flow or Authorization Code Flow, for testing your authentication and connectivity to the Azure DevOps service run the ***!azure-devops-auth-test*** command. 

If you are using Client Credentials Flow, click **Test** when you are configuring the instance.

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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

### azure-devops-generate-login-url
***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-devops-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```azure-devops-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
>```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `“code=”` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.



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
>1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
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
| account_license_type | The type of account license. More information can be found here: https://docs.microsoft.com/en-us/rest/api/azure/devops/memberentitlementmanagement/user-entitlements/add?view=azure-devops-rest-6.1#accountlicensetype. Possible values are: express, stakeholder, advanced, earlyAdopter, professional. | Required | 
| group_type | The project group type. More information can be found here: https://docs.microsoft.com/en-us/rest/api/azure/devops/memberentitlementmanagement/user-entitlements/add?view=azure-devops-rest-6.1#grouptype. Possible values are: projectReader, projectContributor, projectAdministrator, projectStakeholder. | Required | 
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
| status | The updated pull-request status. Possible values are: abandoned, completed, active. | Optional | 


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


### azure-devops-pull-request-reviewer-list

***
Retrieve the reviewers for a pull request.

#### Base Command

`azure-devops-pull-request-reviewer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| pull_request_id | ID of the pull request. By using the azure-devops-pull-request-list command, you can obtain the ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequestReviewer.reviewerUrl | String | URL to retrieve information about this identity. | 
| AzureDevOps.PullRequestReviewer.vote | Number | Vote on a pull request, 10 - approved, 5 - approved with suggestions, 0 - no vote, -5 - waiting for author, -10 - rejected. | 
| AzureDevOps.PullRequestReviewer.hasDeclined | Boolean | Whether the pull request has been declined. | 
| AzureDevOps.PullRequestReviewer.isRequired | Boolean | Indicates if this is a required reviewer for this pull request. Branches can have policies that require particular reviewers are required for pull requests. | 
| AzureDevOps.PullRequestReviewer.isFlagged | Boolean | A way to mark some special Pull Requests we are dealing with to distinguish them from other Pull Requests. | 
| AzureDevOps.PullRequestReviewer.displayName | String | This is the non-unique display name of the graph subject. To change this field, you must alter its value in the source provider. | 
| AzureDevOps.PullRequestReviewer.url | String | REST URL for this resource. | 
| AzureDevOps.PullRequestReviewer._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.PullRequestReviewer.id | String | Pull-request reviewers IDs. | 
| AzureDevOps.PullRequestReviewer.uniqueName | String | The reviewers user name. | 
| AzureDevOps.PullRequestReviewer.imageUrl | String | Link to the reviewers user image. | 

### azure-devops-pull-request-reviewer-add

***
Add a reviewer to a pull request.

#### Base Command

`azure-devops-pull-request-reviewer-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| reviewer_user_id | ID of the reviewer. By using the azure-devops-user-list command, you can obtain the user ID. | Required | 
| is_required | Indicates if this is a required reviewer for this pull request. Branches can have policies that require particular reviewers are required for pull requests. Possible values are: True, False. | Optional | 
| pull_request_id | ID of the pull request. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequestReviewer.reviewerUrl | String | URL to retrieve information about this identity. | 
| AzureDevOps.PullRequestReviewer.vote | Number | Vote on a pull request, 10 - approved, 5 - approved with suggestions, 0 - no vote, -5 - waiting for author, -10 - rejected. | 
| AzureDevOps.PullRequestReviewer.hasDeclined | Boolean | Whether the pull request has been declined. | 
| AzureDevOps.PullRequestReviewer.isFlagged | Boolean | A way to mark some special Pull Requests we are dealing with to distinguish them from other Pull Requests. | 
| AzureDevOps.PullRequestReviewer._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.PullRequestReviewer.id | String | Pull-request reviewers IDs. | 
| AzureDevOps.PullRequestReviewer.displayName | String | This is the non-unique display name of the graph subject. To change this field, you must alter its value in the source provider. | 
| AzureDevOps.PullRequestReviewer.uniqueName | String | The reviewers user name. | 
| AzureDevOps.PullRequestReviewer.url | String | REST URL for this resource. | 
| AzureDevOps.PullRequestReviewer.imageUrl | String | Link to the reviewers user image. | 

### azure-devops-pull-request-commit-list

***
Get the commits for the specified pull request.

#### Base Command

`azure-devops-pull-request-commit-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| pull_request_id | ID of the pull request. By using the azure-devops-pull-request-list command, you can obtain the ID. | Required | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Commit.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.Commit.author.name | String | Name of the commit author. | 
| AzureDevOps.Commit.author.email | String | Email address of the commit author. | 
| AzureDevOps.Commit.author.date | Date | Date of the commit operation. | 
| AzureDevOps.Commit.committer.name | String | Name of the commit committer. | 
| AzureDevOps.Commit.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.Commit.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.Commit.comment | String | Comment or message of the commit. | 
| AzureDevOps.Commit.url | String | REST URL for this resource. | 

### azure-devops-commit-list

***
Retrieve git commits for a project.

#### Base Command

`azure-devops-commit-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| limit | The number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Commit.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.Commit.author.name | String | Name of the commit author. | 
| AzureDevOps.Commit.author.email | String | Email address of the commit author. | 
| AzureDevOps.Commit.author.date | Date | Date of the commit operation. | 
| AzureDevOps.Commit.committer.name | String | Name of the commit committer. | 
| AzureDevOps.Commit.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.Commit.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.Commit.comment | String | Comment or message of the commit. | 
| AzureDevOps.Commit.changeCounts | Number | Counts of the types of changes \(edits, deletes, etc.\) included with the commit. | 
| AzureDevOps.Commit.url | String | REST URL for this resource. | 
| AzureDevOps.Commit.remoteUrl | String | Remote URL path to the commit. | 

### azure-devops-commit-get

***
Retrieve a particular commit.

#### Base Command

`azure-devops-commit-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| commit_id | The id of the commit. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Commit.treeId | String | Tree ID of the commit. | 
| AzureDevOps.Commit.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.Commit.author.name | String | Name of the commit author. | 
| AzureDevOps.Commit.author.email | String | Email address of the commit author. | 
| AzureDevOps.Commit.author.date | Date | Date of the commit operation. | 
| AzureDevOps.Commit.author.imageUrl | String | Link to the author user image. | 
| AzureDevOps.Commit.committer.name | String | Name of the commit committer. | 
| AzureDevOps.Commit.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.Commit.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.Commit.committer.imageUrl | String | Link to the committer user image. | 
| AzureDevOps.Commit.comment | String | Comment or message of the commit. | 
| AzureDevOps.Commit.parents | String | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.Commit.url | String | REST URL for this resource. | 
| AzureDevOps.Commit.remoteUrl | String | Remote URL path to the commit. | 
| AzureDevOps.Commit._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.Commit._links.repository.href | String | Link to the repository where the commit is. | 
| AzureDevOps.Commit._links.web.href | String | Link to the commit. | 
| AzureDevOps.Commit._links.changes.href | String | Link to the commit changes. | 
| AzureDevOps.Commit.push.pushedBy.displayName | String | Display name of the user who pushed the commit. | 
| AzureDevOps.Commit.push.pushedBy.url | String | Identity Reference. | 
| AzureDevOps.Commit.push.pushedBy._links.avatar.href | String | Url for the user's avatar. | 
| AzureDevOps.Commit.push.pushedBy.id | String | ID of the user who pushed the commit. | 
| AzureDevOps.Commit.push.pushedBy.uniqueName | String | Domain and principal name. | 
| AzureDevOps.Commit.push.pushedBy.imageUrl | String | Identity Image. | 
| AzureDevOps.Commit.push.pushedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.Commit.push.pushId | Number | Unique ID of the push operation. | 
| AzureDevOps.Commit.push.date | Date | Date of the push operation. | 

### azure-devops-work-item-get

***
Returns a single work item.

#### Base Command

`azure-devops-work-item-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| item_id | The work item id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.WorkItem.id | Number | The work item ID. | 
| AzureDevOps.WorkItem.rev | Number | Revision number of the work item. | 
| AzureDevOps.WorkItem.fields.System.AreaPath | String | The work item AreaPath. Area paths allow you to group work items by team, product, or feature area. | 
| AzureDevOps.WorkItem.fields.System.TeamProject | String | The work item TeamProject. A group of project members focused on specific products, services, or feature areas. | 
| AzureDevOps.WorkItem.fields.System.IterationPath | String | The work item IterationPath. Iteration paths allow you to group work into sprints, milestones, or other event-specific or time-related period. | 
| AzureDevOps.WorkItem.fields.System.WorkItemType | String | The work item type. Epic, Feature, User Story and Task/Bug. | 
| AzureDevOps.WorkItem.fields.System.State | String | Workflow states define how a work item progresses from its creation to closure. The four main states that are defined for the User Story describe a user story's progression. The workflow states are New, Active, Resolved, and Closed. | 
| AzureDevOps.WorkItem.fields.System.Reason | String | This field requires a state to determine what values are allowed. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.displayName | String | Display name of user assigned to the work item. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.id | String | ID of user assigned to the work item. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.uniqueName | String | The unique name of user assigned to the work item. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.imageUrl | String | Link to the user \(assigned to the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.CreatedDate | Date | The run creation date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.displayName | String | Display name of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.id | String | ID of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.uniqueName | String | The unique name of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.imageUrl | String | Link to the user \(created the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.ChangedDate | Date | The run changing date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.displayName | String | Display name of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.id | String | ID of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.uniqueName | String | The unique name of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.imageUrl | String | Link to the user \(changed the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.CommentCount | Number | Count of the work item comments. | 
| AzureDevOps.WorkItem.fields.System.Title | String | The work item title. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.StateChangeDate | Date | The state changing date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedDate | Date | The activated date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.displayName | String | Display name of user activated the work item. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.id | String | ID of user activated the work item. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.uniqueName | String | The unique name of user activated the work item. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.imageUrl | String | Link to the user \(activated the work item\) image. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.Priority | Number | This field specifies which work the team should do first. | 
| AzureDevOps.WorkItem.fields.System.Description | String | The work item description. | 
| AzureDevOps.WorkItem.fields.System.Tags | String | Tags related to the work item. | 
| AzureDevOps.WorkItem._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.WorkItem._links.workItemUpdates.href | String | Link to the work item updates. | 
| AzureDevOps.WorkItem._links.workItemRevisions.href | String | Link to the work item revisions. | 
| AzureDevOps.WorkItem._links.workItemComments.href | String | Link to the work item comments. | 
| AzureDevOps.WorkItem._links.html.href | String | Link to the work item html. | 
| AzureDevOps.WorkItem._links.workItemType.href | String | Link to the work item type. | 
| AzureDevOps.WorkItem._links.fields.href | String | Link to the work item fields. | 
| AzureDevOps.WorkItem.url | String | Link to the work item. | 

### azure-devops-work-item-create

***
Creates a single work item.

#### Base Command

`azure-devops-work-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| type | The work item type of the work item to create. Possible values are: Task, Epic, Issue. | Required | 
| title | The work item title of the work item to create. | Required | 
| iteration_path | The path for the operation. | Optional | 
| description | Describes the work item. | Optional | 
| priority | Specifies which work the team should do first. Possible values are: 1, 2, 3, 4. | Optional | 
| tag | Tag related to the work item. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.WorkItem.id | Number | The work item ID. | 
| AzureDevOps.WorkItem.rev | Number | Revision number of the work item. | 
| AzureDevOps.WorkItem.fields.System.AreaPath | String | The work item AreaPath. Area paths allow you to group work items by team, product, or feature area. | 
| AzureDevOps.WorkItem.fields.System.TeamProject | String | The work item TeamProject. A group of project members focused on specific products, services, or feature areas. | 
| AzureDevOps.WorkItem.fields.System.IterationPath | String | The work item IterationPath. Iteration paths allow you to group work into sprints, milestones, or other event-specific or time-related period. | 
| AzureDevOps.WorkItem.fields.System.WorkItemType | String | The work item type. Epic, Feature, User Story and Task/Bug. | 
| AzureDevOps.WorkItem.fields.System.State | String | Workflow states define how a work item progresses from its creation to closure. The four main states that are defined for the User Story describe a user story's progression. The workflow states are New, Active, Resolved, and Closed. | 
| AzureDevOps.WorkItem.fields.System.Reason | String | This field requires a state to determine what values are allowed. | 
| AzureDevOps.WorkItem.fields.System.CreatedDate | Date | The run creation date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.displayName | String | Display name of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.id | String | ID of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.uniqueName | String | The unique name of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.imageUrl | String | Link to the user \(created the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.ChangedDate | Date | The run changing date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.displayName | String | Display name of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.id | String | ID of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.uniqueName | String | The unique name of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.imageUrl | String | Link to the user \(changed the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.CommentCount | Number | Count of the work item comments. | 
| AzureDevOps.WorkItem.fields.System.Title | String | The work item title. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.StateChangeDate | Date | The state changing date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.Priority | Number | This field specifies which work the team should do first. | 
| AzureDevOps.WorkItem.fields.System.Description | String | The work item description. | 
| AzureDevOps.WorkItem.fields.System.Tags | String | Tags related to the work item. | 
| AzureDevOps.WorkItem._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.WorkItem._links.workItemUpdates.href | String | Link to the work item updates. | 
| AzureDevOps.WorkItem._links.workItemRevisions.href | String | Link to the work item revisions. | 
| AzureDevOps.WorkItem._links.workItemComments.href | String | Link to the work item comments. | 
| AzureDevOps.WorkItem._links.html.href | String | Link to the work item html. | 
| AzureDevOps.WorkItem._links.workItemType.href | String | Link to the work item type. | 
| AzureDevOps.WorkItem._links.fields.href | String | Link to the work item fields. | 
| AzureDevOps.WorkItem.url | String | Link to the work item. | 

### azure-devops-work-item-update

***
Updates a single work item.

#### Base Command

`azure-devops-work-item-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| item_id | The work item id to update. | Required | 
| title | A new title for the work item. | Optional | 
| assignee_display_name | Display name of user assigned to the work item. This argument can be obtained by running the 'azure-devops-user-list' command. | Optional | 
| state | A new state for the work item. Possible values are: To Do, Doing, Done. | Optional | 
| iteration_path | a new path for the operation. | Optional | 
| description | A new description for the work item. | Optional | 
| priority | A new priority for the work item. Possible values are: 1, 2, 3, 4. | Optional | 
| tag | A new priority for the work item. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.WorkItem.id | Number | The work item ID. | 
| AzureDevOps.WorkItem.rev | Number | Revision number of the work item. | 
| AzureDevOps.WorkItem.fields.System.AreaPath | String | The work item AreaPath. Area paths allow you to group work items by team, product, or feature area. | 
| AzureDevOps.WorkItem.fields.System.TeamProject | String | The work item TeamProject. A group of project members focused on specific products, services, or feature areas. | 
| AzureDevOps.WorkItem.fields.System.IterationPath | String | The work item IterationPath. Iteration paths allow you to group work into sprints, milestones, or other event-specific or time-related period. | 
| AzureDevOps.WorkItem.fields.System.WorkItemType | String | The work item type. Epic, Feature, User Story and Task/Bug. | 
| AzureDevOps.WorkItem.fields.System.State | String | Workflow states define how a work item progresses from its creation to closure. The four main states that are defined for the User Story describe a user story's progression. The workflow states are New, Active, Resolved, and Closed. | 
| AzureDevOps.WorkItem.fields.System.Reason | String | This field requires a state to determine what values are allowed. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.displayName | String | Display name of user assigned to the work item. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.id | String | ID of user assigned to the work item. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.uniqueName | String | The unique name of user assigned to the work item. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.imageUrl | String | Link to the user \(assigned to the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.AssignedTo.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.CreatedDate | Date | The run creation date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.displayName | String | Display name of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.id | String | ID of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.uniqueName | String | The unique name of user created the work item. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.imageUrl | String | Link to the user \(created the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.CreatedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.ChangedDate | Date | The run changing date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.displayName | String | Display name of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.id | String | ID of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.uniqueName | String | The unique name of user changed the work item. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.imageUrl | String | Link to the user \(changed the work item\) image. | 
| AzureDevOps.WorkItem.fields.System.ChangedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.System.CommentCount | Number | Count of the work item comments. | 
| AzureDevOps.WorkItem.fields.System.Title | String | The work item title. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.StateChangeDate | Date | The state changing date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedDate | Date | The activated date, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.displayName | String | Display name of user activated the work item. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.url | String | The work item url. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.id | String | ID of user activated the work item. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.uniqueName | String | The unique name of user activated the work item. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.imageUrl | String | Link to the user \(activated the work item\) image. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.ActivatedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.WorkItem.fields.Microsoft.VSTS.Common.Priority | Number | This field specifies which work the team should do first. | 
| AzureDevOps.WorkItem.fields.System.Description | String | The work item description. | 
| AzureDevOps.WorkItem.fields.System.Tags | String | Tags related to the work item. | 
| AzureDevOps.WorkItem._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.WorkItem._links.workItemUpdates.href | String | Link to the work item updates. | 
| AzureDevOps.WorkItem._links.workItemRevisions.href | String | Link to the work item revisions. | 
| AzureDevOps.WorkItem._links.workItemComments.href | String | Link to the work item comments. | 
| AzureDevOps.WorkItem._links.html.href | String | Link to the work item html. | 
| AzureDevOps.WorkItem._links.workItemType.href | String | Link to the work item type. | 
| AzureDevOps.WorkItem._links.fields.href | String | Link to the work item fields. | 
| AzureDevOps.WorkItem.url | String | Link to the work item. | 

### azure-devops-file-create

***
Add a file to the repository.

#### Base Command

`azure-devops-file-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| branch_name | The branch name. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| branch_id | The branch ID. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| commit_comment | Comment or message of the commit. | Required | 
| file_path | The file path. | Optional | 
| file_content | The file content. | Optional | 
| entry_id | There is an option to the user to provide an entry_id. In that case we will take the file_content and the file_path from the given id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.File.commits.treeId | String | Tree ID of the commit. | 
| AzureDevOps.File.commits.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.File.commits.author.name | String | Name of the commit author. | 
| AzureDevOps.File.commits.author.email | String | Email address of the commit author. | 
| AzureDevOps.File.commits.author.date | Date | Date of the commit operation. | 
| AzureDevOps.File.commits.committer.name | String | Name of the commit committer. | 
| AzureDevOps.File.commits.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.File.commits.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.File.commits.comment | String | Comment or message of the commit. | 
| AzureDevOps.File.commits.parents | String | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.File.commits.url | String | REST URL for this resource. | 
| AzureDevOps.File.refUpdates.repositoryId | String | The ID of the repository. | 
| AzureDevOps.File.refUpdates.name | String | The branch name. | 
| AzureDevOps.File.refUpdates.oldObjectId | String | The last commit ID. | 
| AzureDevOps.File.refUpdates.newObjectId | String | The new commit ID. | 
| AzureDevOps.File.repository.id | String | The ID of the repository. | 
| AzureDevOps.File.repository.name | String | The name of the repository. | 
| AzureDevOps.File.repository.url | String | The URL of the repository. | 
| AzureDevOps.File.repository.project.id | String | The ID of the Project. | 
| AzureDevOps.File.repository.project.name | String | The name of the project. | 
| AzureDevOps.File.repository.project.description | String | The description of the project. | 
| AzureDevOps.File.repository.project.url | String | The URL of the project. | 
| AzureDevOps.File.repository.project.state | String | The state of the project. | 
| AzureDevOps.File.repository.project.revision | Number | The revision number of the project. | 
| AzureDevOps.File.repository.project.visibility | String | Indicates whom the project is visible to. | 
| AzureDevOps.File.repository.project.lastUpdateTime | Date | The project last update time, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.File.repository.size | Number | The size of the repository \(in bytes\). | 
| AzureDevOps.File.repository.remoteUrl | String | Remote URL path to the repository. | 
| AzureDevOps.File.repository.sshUrl | String | The ssh URL of the repository. | 
| AzureDevOps.File.repository.webUrl | String | The web URL of the repository. | 
| AzureDevOps.File.repository.isDisabled | Boolean | If the repository is disabled or not. | 
| AzureDevOps.File.repository.isInMaintenance | Boolean | If the repository is in maintenance or not. | 
| AzureDevOps.File.pushedBy.displayName | String | Display name of the user who pushed the commit / file. | 
| AzureDevOps.File.pushedBy.url | String | Identity Reference. | 
| AzureDevOps.File.pushedBy._links.avatar.href | String | Url for the user's avatar. | 
| AzureDevOps.File.pushedBy.id | String | ID of the user who pushed the commit / file. | 
| AzureDevOps.File.pushedBy.uniqueName | String | Domain and principal name. | 
| AzureDevOps.File.pushedBy.imageUrl | String | Identity Image. | 
| AzureDevOps.File.pushedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.File.pushId | Number | Unique ID of the push operation. | 
| AzureDevOps.File.date | Date | Date of the operation. | 
| AzureDevOps.File.url | String | Link to the commit. | 
| AzureDevOps.File._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.File._links.repository.href | String | Link to the repository where the commit is. | 
| AzureDevOps.File._links.commits.href | String | Link to the commits. | 
| AzureDevOps.File._links.pusher.href | String | Link to the commit pusher. | 
| AzureDevOps.File._links.refs.href | String | Link to the branch. | 

### azure-devops-file-update

***
Update a file in the repository.

#### Base Command

`azure-devops-file-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| branch_name | The branch name. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| branch_id | The branch ID. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| commit_comment | Comment or message of the commit. | Required | 
| file_path | The file path. | Optional | 
| file_content | The file content. | Optional | 
| entry_id | There is an option to the user to provide an entry_id. In that case we will take the file_content and the file_path from the given id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.File.commits.treeId | String | Tree ID of the commit. | 
| AzureDevOps.File.commits.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.File.commits.author.name | String | Name of the commit author. | 
| AzureDevOps.File.commits.author.email | String | Email address of the commit author. | 
| AzureDevOps.File.commits.author.date | Date | Date of the commit operation. | 
| AzureDevOps.File.commits.committer.name | String | Name of the commit committer. | 
| AzureDevOps.File.commits.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.File.commits.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.File.commits.comment | String | Comment or message of the commit. | 
| AzureDevOps.File.commits.parents | String | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.File.commits.url | String | REST URL for this resource. | 
| AzureDevOps.File.refUpdates.repositoryId | String | The ID of the repository. | 
| AzureDevOps.File.refUpdates.name | String | The branch name. | 
| AzureDevOps.File.refUpdates.oldObjectId | String | The last commit ID. | 
| AzureDevOps.File.refUpdates.newObjectId | String | The new commit ID. | 
| AzureDevOps.File.repository.id | String | The ID of the repository. | 
| AzureDevOps.File.repository.name | String | The name of the repository. | 
| AzureDevOps.File.repository.url | String | The URL of the repository. | 
| AzureDevOps.File.repository.project.id | String | The ID of the Project. | 
| AzureDevOps.File.repository.project.name | String | The name of the project. | 
| AzureDevOps.File.repository.project.description | String | The description of the project. | 
| AzureDevOps.File.repository.project.url | String | The URL of the project. | 
| AzureDevOps.File.repository.project.state | String | The state of the project. | 
| AzureDevOps.File.repository.project.revision | Number | The revision number of the project. | 
| AzureDevOps.File.repository.project.visibility | String | Indicates whom the project is visible to. | 
| AzureDevOps.File.repository.project.lastUpdateTime | Date | The project last update time, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.File.repository.size | Number | The size of the repository \(in bytes\). | 
| AzureDevOps.File.repository.remoteUrl | String | Remote URL path to the repository. | 
| AzureDevOps.File.repository.sshUrl | String | The ssh URL of the repository. | 
| AzureDevOps.File.repository.webUrl | String | The web URL of the repository. | 
| AzureDevOps.File.repository.isDisabled | Boolean | If the repository is disabled or not. | 
| AzureDevOps.File.repository.isInMaintenance | Boolean | If the repository is in maintenance or not. | 
| AzureDevOps.File.pushedBy.displayName | String | Display name of the user who pushed the commit / file. | 
| AzureDevOps.File.pushedBy.url | String | Identity Reference. | 
| AzureDevOps.File.pushedBy._links.avatar.href | String | Url for the user's avatar. | 
| AzureDevOps.File.pushedBy.id | String | ID of the user who pushed the commit / file. | 
| AzureDevOps.File.pushedBy.uniqueName | String | Domain and principal name. | 
| AzureDevOps.File.pushedBy.imageUrl | String | Identity Image. | 
| AzureDevOps.File.pushedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.File.pushId | Number | Unique ID of the push operation. | 
| AzureDevOps.File.date | Date | Date of the operation. | 
| AzureDevOps.File.url | String | Link to the commit. | 
| AzureDevOps.File._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.File._links.repository.href | String | Link to the repository where the commit is. | 
| AzureDevOps.File._links.commits.href | String | Link to the commits. | 
| AzureDevOps.File._links.pusher.href | String | Link to the commit pusher. | 
| AzureDevOps.File._links.refs.href | String | Link to the branch. | 

### azure-devops-file-delete

***
Update a file in the repository.

#### Base Command

`azure-devops-file-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| branch_name | The branch name. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| branch_id | The branch ID. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| commit_comment | Comment or message of the commit. | Required | 
| file_path | The file path. | Optional | 
| entry_id | There is an option to the user to provide an entry_id. In that case we will take the file_content and the file_path from the given id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.File.commits.treeId | String | Tree ID of the commit. | 
| AzureDevOps.File.commits.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.File.commits.author.name | String | Name of the commit author. | 
| AzureDevOps.File.commits.author.email | String | Email address of the commit author. | 
| AzureDevOps.File.commits.author.date | Date | Date of the commit operation. | 
| AzureDevOps.File.commits.committer.name | String | Name of the commit committer. | 
| AzureDevOps.File.commits.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.File.commits.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.File.commits.comment | String | Comment or message of the commit. | 
| AzureDevOps.File.commits.parents | String | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.File.commits.url | String | REST URL for this resource. | 
| AzureDevOps.File.refUpdates.repositoryId | String | The ID of the repository. | 
| AzureDevOps.File.refUpdates.name | String | The branch name. | 
| AzureDevOps.File.refUpdates.oldObjectId | String | The last commit ID. | 
| AzureDevOps.File.refUpdates.newObjectId | String | The new commit ID. | 
| AzureDevOps.File.repository.id | String | The ID of the repository. | 
| AzureDevOps.File.repository.name | String | The name of the repository. | 
| AzureDevOps.File.repository.url | String | The URL of the repository. | 
| AzureDevOps.File.repository.project.id | String | The ID of the Project. | 
| AzureDevOps.File.repository.project.name | String | The name of the project. | 
| AzureDevOps.File.repository.project.description | String | The description of the project. | 
| AzureDevOps.File.repository.project.url | String | The URL of the project. | 
| AzureDevOps.File.repository.project.state | String | The state of the project. | 
| AzureDevOps.File.repository.project.revision | Number | The revision number of the project. | 
| AzureDevOps.File.repository.project.visibility | String | Indicates whom the project is visible to. | 
| AzureDevOps.File.repository.project.lastUpdateTime | Date | The project last update time, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.File.repository.size | Number | The size of the repository \(in bytes\). | 
| AzureDevOps.File.repository.remoteUrl | String | Remote URL path to the repository. | 
| AzureDevOps.File.repository.sshUrl | String | The ssh URL of the repository. | 
| AzureDevOps.File.repository.webUrl | String | The web URL of the repository. | 
| AzureDevOps.File.repository.isDisabled | Boolean | If the repository is disabled or not. | 
| AzureDevOps.File.repository.isInMaintenance | Boolean | If the repository is in maintenance or not. | 
| AzureDevOps.File.pushedBy.displayName | String | Display name of the user who pushed the commit / file. | 
| AzureDevOps.File.pushedBy.url | String | Identity Reference. | 
| AzureDevOps.File.pushedBy._links.avatar.href | String | Url for the user's avatar. | 
| AzureDevOps.File.pushedBy.id | String | ID of the user who pushed the commit / file. | 
| AzureDevOps.File.pushedBy.uniqueName | String | Domain and principal name. | 
| AzureDevOps.File.pushedBy.imageUrl | String | Identity Image. | 
| AzureDevOps.File.pushedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.File.pushId | Number | Unique ID of the push operation. | 
| AzureDevOps.File.date | Date | Date of the operation. | 
| AzureDevOps.File.url | String | Link to the commit. | 
| AzureDevOps.File._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.File._links.repository.href | String | Link to the repository where the commit is. | 
| AzureDevOps.File._links.commits.href | String | Link to the commits. | 
| AzureDevOps.File._links.pusher.href | String | Link to the commit pusher. | 
| AzureDevOps.File._links.refs.href | String | Link to the branch. | 

### azure-devops-file-list

***
Retrieve repository files (items) list.

#### Base Command

`azure-devops-file-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| branch_name | The branch name. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| recursion_level | The recursion level of this request. The default is None, no recursion. Possible values are: None, OneLevel, Full. Default is None. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.File.objectId | String | The file object ID. | 
| AzureDevOps.File.gitObjectType | String | The file git object type. | 
| AzureDevOps.File.commitId | String | ID \(SHA-1\) of the file commit. | 
| AzureDevOps.File.path | String | The file's path. | 
| AzureDevOps.File.isFolder | Boolean | If the item is folder or not. | 
| AzureDevOps.File.contentMetadata.fileName | String | The file name. | 
| AzureDevOps.File.url | String | URL link to the item. | 

### azure-devops-file-get

***
Getting the content file.

#### Base Command

`azure-devops-file-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| branch_name | The branch name. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| file_name | The file name. | Required |
| format | The file format (json or zip). Default is json. Possible values are: json, zip. Default is json. | Optional | 
| include_content | Include item content. Default is True. Possible values are: True, False. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.File.objectId | String | The file object ID. | 
| AzureDevOps.File.gitObjectType | String | The file git object type. | 
| AzureDevOps.File.commitId | String | ID \(SHA-1\) of the file commit. | 
| AzureDevOps.File.path | String | The file's path. | 
| AzureDevOps.File.content | String | The file content. | 

### azure-devops-branch-create

***
Create a branch.

#### Base Command

`azure-devops-branch-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| branch_name | The branch name. This argument can be obtained by running the 'azure-devops-branch-list' command. | Required | 
| commit_comment | Comment or message of the commit. | Required | 
| file_path | The file path. | Optional | 
| file_content | The file content. | Optional | 
| entry_id | There is an option to the user to provide an entry_id. In that case we will take the file_content and the file_path from the given id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Branch.commits.treeId | String | Tree ID of the commit. | 
| AzureDevOps.Branch.commits.commitId | String | ID \(SHA-1\) of the commit. | 
| AzureDevOps.Branch.commits.author.name | String | Name of the commit author. | 
| AzureDevOps.Branch.commits.author.email | String | Email address of the commit author. | 
| AzureDevOps.Branch.commits.author.date | Date | Date of the commit operation. | 
| AzureDevOps.Branch.commits.committer.name | String | Name of the commit committer. | 
| AzureDevOps.Branch.commits.committer.email | String | Email address of the commit committer. | 
| AzureDevOps.Branch.commits.committer.date | Date | Date of the commit operation. | 
| AzureDevOps.Branch.commits.comment | String | Comment or message of the commit. | 
| AzureDevOps.Branch.commits.parents | Unknown | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.Branch.commits.url | String | REST URL for this resource. | 
| AzureDevOps.Branch.refUpdates.repositoryId | String | The ID of the repository. | 
| AzureDevOps.Branch.refUpdates.name | String | The branch name. | 
| AzureDevOps.Branch.refUpdates.oldObjectId | String | The last commit ID. | 
| AzureDevOps.Branch.refUpdates.newObjectId | String | The new commit ID. | 
| AzureDevOps.Branch.repository.id | String | The ID of the repository. | 
| AzureDevOps.Branch.repository.name | String | The name of the repository. | 
| AzureDevOps.Branch.repository.url | String | The URL of the repository. | 
| AzureDevOps.Branch.repository.project.id | String | The ID of the Project. | 
| AzureDevOps.Branch.repository.project.name | String | The name of the project. | 
| AzureDevOps.Branch.repository.project.description | String | The description of the project. | 
| AzureDevOps.Branch.repository.project.url | String | The URL of the project. | 
| AzureDevOps.Branch.repository.project.state | String | The state of the project. | 
| AzureDevOps.Branch.repository.project.revision | Number | The revision number of the project. | 
| AzureDevOps.Branch.repository.project.visibility | String | Indicates whom the project is visible to. | 
| AzureDevOps.Branch.repository.project.lastUpdateTime | Date | The project last update time, using ISO 8601 format in UTC time. For example, midnight UTC on Jan 1, 2022 would be: "2022-01-01T00:00:00Z". | 
| AzureDevOps.Branch.repository.size | Number | The size of the repository \(in bytes\). | 
| AzureDevOps.Branch.repository.remoteUrl | String | Remote URL path to the repository. | 
| AzureDevOps.Branch.repository.sshUrl | String | The ssh URL of the repository. | 
| AzureDevOps.Branch.repository.webUrl | String | The web URL of the repository. | 
| AzureDevOps.Branch.repository.isDisabled | Boolean | If the repository is disabled or not. | 
| AzureDevOps.Branch.repository.isInMaintenance | Boolean | If the repository is in maintenance or not. | 
| AzureDevOps.Branch.pushedBy.displayName | String | Display name of the user who pushed the commit / file. | 
| AzureDevOps.Branch.pushedBy.url | String | Identity Reference. | 
| AzureDevOps.Branch.pushedBy._links.avatar.href | String | Url for the user's avatar. | 
| AzureDevOps.Branch.pushedBy.id | String | ID of the user who pushed the commit / file. | 
| AzureDevOps.Branch.pushedBy.uniqueName | String | Domain and principal name. | 
| AzureDevOps.Branch.pushedBy.imageUrl | String | Identity Image. | 
| AzureDevOps.Branch.pushedBy.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.Branch.pushId | Number | Unique ID of the push operation. | 
| AzureDevOps.Branch.date | Date | Date of the operation. | 
| AzureDevOps.Branch.url | String | Link to the commit. | 
| AzureDevOps.Branch._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.Branch._links.repository.href | String | Link to the repository where the commit is. | 
| AzureDevOps.Branch._links.commits.href | String | Link to the commits. | 
| AzureDevOps.Branch._links.pusher.href | String | Link to the commit pusher. | 
| AzureDevOps.Branch._links.refs.href | String | Link to the branch. | 

### azure-devops-pull-request-thread-create

***
Create a thread in a pull request.

#### Base Command

`azure-devops-pull-request-thread-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| pull_request_id | The ID of the pull request to update. | Required | 
| comment_text | The comment content. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequestThread.pullRequestThreadContext | Unknown | Extended context information unique to pull requests. |
| AzureDevOps.PullRequestThread.id | Number | The ID of the pull request. | 
| AzureDevOps.PullRequestThread.publishedDate | Date | The date the thread was published. | 
| AzureDevOps.PullRequestThread.lastUpdatedDate | Date | Last update date. | 
| AzureDevOps.PullRequestThread.comments.id | Number | The ID of the comments. | 
| AzureDevOps.PullRequestThread.comments.parentCommentId | Number | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.PullRequestThread.comments.author.displayName | String | The display name of the comments creator. | 
| AzureDevOps.PullRequestThread.comments.author.url | String | URL to retrieve information about this identity. | 
| AzureDevOps.PullRequestThread.comments.author._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.PullRequestThread.comments.author.id | String | The ID of the thread author. | 
| AzureDevOps.PullRequestThread.comments.author.uniqueName | String | The unique name of the thread author. | 
| AzureDevOps.PullRequestThread.comments.author.imageUrl | String | Link to the thread author user image. | 
| AzureDevOps.PullRequestThread.comments.author.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.PullRequestThread.comments.content | String | The comments content. | 
| AzureDevOps.PullRequestThread.comments.publishedDate | Date | The date the comments were published. | 
| AzureDevOps.PullRequestThread.comments.lastUpdatedDate | Date | Last update date. | 
| AzureDevOps.PullRequestThread.comments.lastContentUpdatedDate | Date | The date the comment's content was last updated. | 
| AzureDevOps.PullRequestThread.comments.commentType | String | The comment type at the time of creation. | 
| AzureDevOps.PullRequestThread.comments._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.PullRequestThread.comments._links.repository.href | String | Link to the repository where the comments are. | 
| AzureDevOps.PullRequestThread.comments._links.threads.href | String | Link to the threads. | 
| AzureDevOps.PullRequestThread.comments._links.pullRequests.href | String | Link to the pull request. | 
| AzureDevOps.PullRequestThread.status | String | The status of the pull request thread. | 
| AzureDevOps.PullRequestThread.threadContext | Unknown | Extended context information unique to pull requests. | 
| AzureDevOps.PullRequestThread.properties | Unknown | Properties associated with the thread as a collection of key-value pairs. | 
| AzureDevOps.PullRequestThread.identities | Unknown | Set of identities related to this thread. | 
| AzureDevOps.PullRequestThread.isDeleted | Boolean | Specify if the thread is deleted which happens when all comments are deleted. | 
| AzureDevOps.PullRequestThread._links.self.href | String | Link to the thread. | 
| AzureDevOps.PullRequestThread._links.repository.href | String | Link to the repository. | 

### azure-devops-pull-request-thread-update

***
Update a thread in a pull request.

#### Base Command

`azure-devops-pull-request-thread-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| pull_request_id | The ID of the pull request to update. | Required | 
| thread_id | The ID of the thread to update. | Required | 
| comment_text | The comment content. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequestThread.pullRequestThreadContext | Unknown | Extended context information unique to pull requests. |
| AzureDevOps.PullRequestThread.id | Number | The ID of the pull request. | 
| AzureDevOps.PullRequestThread.publishedDate | Date | The date the thread was published. | 
| AzureDevOps.PullRequestThread.lastUpdatedDate | Date | Last update date. | 
| AzureDevOps.PullRequestThread.comments.id | Number | The ID of the comments. | 
| AzureDevOps.PullRequestThread.comments.parentCommentId | Number | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.PullRequestThread.comments.author.displayName | String | The display name of the comments creator. | 
| AzureDevOps.PullRequestThread.comments.author.url | String | URL to retrieve information about this identity. | 
| AzureDevOps.PullRequestThread.comments.author._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.PullRequestThread.comments.author.id | String | The ID of the thread author. | 
| AzureDevOps.PullRequestThread.comments.author.uniqueName | String | The unique name of the thread author. | 
| AzureDevOps.PullRequestThread.comments.author.imageUrl | String | Link to the thread author user image. | 
| AzureDevOps.PullRequestThread.comments.author.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.PullRequestThread.comments.content | String | The comments content. | 
| AzureDevOps.PullRequestThread.comments.publishedDate | Date | The date the comments were published. | 
| AzureDevOps.PullRequestThread.comments.lastUpdatedDate | Date | Last update date. | 
| AzureDevOps.PullRequestThread.comments.lastContentUpdatedDate | Date | The date the comment's content was last updated. | 
| AzureDevOps.PullRequestThread.comments.commentType | String | The comment type at the time of creation. | 
| AzureDevOps.PullRequestThread.comments._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.PullRequestThread.comments._links.repository.href | String | Link to the repository where the comments are. | 
| AzureDevOps.PullRequestThread.comments._links.threads.href | String | Link to the threads. | 
| AzureDevOps.PullRequestThread.comments._links.pullRequests.href | String | Link to the pull request. | 
| AzureDevOps.PullRequestThread.status | String | The status of the pull request thread. | 
| AzureDevOps.PullRequestThread.threadContext | Unknown | Extended context information unique to pull requests. | 
| AzureDevOps.PullRequestThread.properties | Unknown | Properties associated with the thread as a collection of key-value pairs. | 
| AzureDevOps.PullRequestThread.identities | Unknown | Set of identities related to this thread. | 
| AzureDevOps.PullRequestThread.isDeleted | Boolean | Specify if the thread is deleted which happens when all comments are deleted. | 
| AzureDevOps.PullRequestThread._links.self.href | String | Link to the thread. | 
| AzureDevOps.PullRequestThread._links.repository.href | String | Link to the repository. | 

### azure-devops-pull-request-thread-list

***
Retrieve all threads in a pull request.

#### Base Command

`azure-devops-pull-request-thread-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| pull_request_id | The ID of the pull request to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.PullRequestThread.pullRequestThreadContext | Unknown | Extended context information unique to pull requests. | 
| AzureDevOps.PullRequestThread.id | Number | The ID of the pull request. | 
| AzureDevOps.PullRequestThread.publishedDate | Date | The date the thread was published. | 
| AzureDevOps.PullRequestThread.lastUpdatedDate | Date | Last update date. | 
| AzureDevOps.PullRequestThread.comments.id | Number | The ID of the comments. | 
| AzureDevOps.PullRequestThread.comments.parentCommentId | Number | An enumeration of the parent commit IDs for this commit. | 
| AzureDevOps.PullRequestThread.comments.author.displayName | String | The display name of the comments creator. | 
| AzureDevOps.PullRequestThread.comments.author.url | String | URL to retrieve information about this identity. | 
| AzureDevOps.PullRequestThread.comments.author._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.PullRequestThread.comments.author.id | String | The ID of the thread author. | 
| AzureDevOps.PullRequestThread.comments.author.uniqueName | String | The unique name of the thread author. | 
| AzureDevOps.PullRequestThread.comments.author.imageUrl | String | Link to the thread author user image. | 
| AzureDevOps.PullRequestThread.comments.author.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.PullRequestThread.comments.content | String | The comments content. | 
| AzureDevOps.PullRequestThread.comments.publishedDate | Date | The date the comments were published. | 
| AzureDevOps.PullRequestThread.comments.lastUpdatedDate | Date | Last update date. | 
| AzureDevOps.PullRequestThread.comments.lastContentUpdatedDate | Date | The date the comment's content was last updated. | 
| AzureDevOps.PullRequestThread.comments.commentType | String | The comment type at the time of creation. | 
| AzureDevOps.PullRequestThread.comments.usersLiked | Unknown | A list of the users who have liked this comment. | 
| AzureDevOps.PullRequestThread.comments._links.self.href | String | A collection of related REST reference links. | 
| AzureDevOps.PullRequestThread.comments._links.repository.href | String | Link to the repository where the comments are. | 
| AzureDevOps.PullRequestThread.comments._links.threads.href | String | Link to the threads. | 
| AzureDevOps.PullRequestThread.comments._links.pullRequests.href | String | Link to the pull request. | 
| AzureDevOps.PullRequestThread.threadContext | Unknown | Extended context information unique to pull requests. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewThreadType.$type | String | The type of the code review thread. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewThreadType.$value | String | The content in the code review thread. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumAdded.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumAdded.$value | Number | Number of code reviewers updated the pull request. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumChanged.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumChanged.$value | Number | Number of code reviewers changed the pull request. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumDeclined.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumDeclined.$value | Number | Number of code reviewers declined the pull request. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumRemoved.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedNumRemoved.$value | Number | Number of code reviewers are removed. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedAddedIdentity.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedAddedIdentity.$value | String | Number of code reviewers added identity. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedByIdentity.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedByIdentity.$value | String | Number of code reviewers updated by identity. | 
| AzureDevOps.PullRequestThread.identities.1.displayName | String | The display name of the pull request thread creator. | 
| AzureDevOps.PullRequestThread.identities.1.url | String | Link to the the pull request thread creator. | 
| AzureDevOps.PullRequestThread.identities.1._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.PullRequestThread.identities.1.id | String | The ID of the pull request thread creator. | 
| AzureDevOps.PullRequestThread.identities.1.uniqueName | String | The user name of the pull request thread creator. | 
| AzureDevOps.PullRequestThread.identities.1.imageUrl | String | Link to the pull request thread creator user image. | 
| AzureDevOps.PullRequestThread.identities.1.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 
| AzureDevOps.PullRequestThread.isDeleted | Boolean | Specify if the thread is deleted which happens when all comments are deleted. | 
| AzureDevOps.PullRequestThread._links.self.href | String | Link to the thread. | 
| AzureDevOps.PullRequestThread._links.repository.href | String | Link to the repository. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedChangedToRequired.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedChangedToRequired.$value | String | Number of code reviewers were changed to required. | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedChangedIdentity.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.CodeReviewReviewersUpdatedChangedIdentity.$value | String | Number of code reviewers changed the identity. | 
| AzureDevOps.PullRequestThread.status | String | The status of the comment thread. | 
| AzureDevOps.PullRequestThread.properties | Unknown | Properties associated with the thread as a collection of key-value pairs. | 
| AzureDevOps.PullRequestThread.identities | Unknown | Set of identities related to this thread. | 
| AzureDevOps.PullRequestThread.properties.Microsoft.TeamFoundation.Discussion.SupportsMarkdown.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.Microsoft.TeamFoundation.Discussion.SupportsMarkdown.$value | Number | Supports markdown number. | 
| AzureDevOps.PullRequestThread.properties.Microsoft.TeamFoundation.Discussion.UniqueID.$type | String | A number \(Int32\). | 
| AzureDevOps.PullRequestThread.properties.Microsoft.TeamFoundation.Discussion.UniqueID.$value | String | The unique ID of the Team Foundation. | 

### azure-devops-project-team-list

***
Get a list of teams.

#### Base Command

`azure-devops-project-team-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.Team.id | String | Team \(Identity\) Guid. A Team Foundation ID. | 
| AzureDevOps.Team.name | String | Team name. | 
| AzureDevOps.Team.url | String | Team REST API Url. | 
| AzureDevOps.Team.description | String | Team description. | 
| AzureDevOps.Team.identityUrl | String | Identity REST API Url to this team. | 
| AzureDevOps.Team.projectName | String | The project name. | 
| AzureDevOps.Team.projectId | String | The project ID. | 

### azure-devops-team-member-list

***
Get a list of members for a specific team.

#### Base Command

`azure-devops-team-member-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| team_id | The name or ID (GUID) of the team . | Required | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| limit | The number of results to retrieve. Minimum  value is 1. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureDevOps.TeamMember.isTeamAdmin | Boolean | if the member is the team admin. | 
| AzureDevOps.TeamMember.identity.displayName | String | The display name of the team member. | 
| AzureDevOps.TeamMember.identity.url | String | URL to retrieve information about this member. | 
| AzureDevOps.TeamMember.identity._links.avatar.href | String | This field contains zero or more interesting links about the graph subject. These links may be invoked to obtain additional relationships or more detailed information about this graph subject. | 
| AzureDevOps.TeamMember.identity.id | String | ID of the team member. | 
| AzureDevOps.TeamMember.identity.uniqueName | String | The unique name of team member. | 
| AzureDevOps.TeamMember.identity.imageUrl | String | Link to the team member image. | 
| AzureDevOps.TeamMember.identity.descriptor | String | The descriptor is the primary way to reference the graph subject while the system is running. This field will uniquely identify the same graph subject across both Accounts and Organizations. | 

### azure-devops-blob-zip-get

***
Get a single blob.

#### Base Command

`azure-devops-blob-zip-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the Azure DevOps organization. Default value will be config param, user can supply a different value. | Optional | 
| project_name | Project ID or project name. Default value will be config param, user can supply a different value. | Optional | 
| repository_id | The repository ID. Default value will be config param, user can supply a different value. | Optional | 
| file_object_id | The ID of the blob object. This ID can be obtained by running the 'azure-devops-file-list' command. | Required | 

#### Context Output

There is no context output for this command.


## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and AzureDevOps corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and AzureDevOps.