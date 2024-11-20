## GCP-IAM 
Manage identity and access control for Google Cloud Platform resources.
This integration was integrated and tested with the following version of GCP-IAM API:
- Identity and Access Management API - v1 version.
- Cloud Resource Manager API - v3 version.
- Cloud Identity API - v1 version.

## Configure GCP-IAM in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Service Account Private Key file content (JSON). | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gcp-iam-projects-get
***
Lists project under the specified parent, or retrieves a specific project''s information. One of the arguments: ''parent'' or ''project_name''  must be provided.


#### Base Command

`gcp-iam-projects-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | A comma-separated list of project names to retrieve. For example, projects/415104041262. Leave empty to retrieve a list of projects under a specified parent resource. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Maximum value is 100. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| parent | The name of the parent resource to list projects under. For example, setting this field to 'folders/1234' would list all projects directly under that folder. | Optional | 
| show_deleted | If true, projects that have been marked for deletion will also be retrieved. Possible values are: False, True. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Project.createTime | Date | Project creation time. | 
| GCPIAM.Project.displayName | String | Project display name. | 
| GCPIAM.Project.name | String | The unique resource name of the project. | 
| GCPIAM.Project.parent | String | The project parent resource. | 
| GCPIAM.Project.projectId | String | The unique, user-assigned ID of the project. | 
| GCPIAM.Project.state | String | The project lifecycle state. | 
| GCPIAM.Project.updateTime | Date | The most recent time the project was modified. | 

#### Command example
```!gcp-iam-projects-get project_name="projects/project-name-1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Project": {
                "createTime": "2021-11-01T10:43:50.858000+00:00",
                "displayName": "My First Project",
                "etag": "SIVTMlYY9sE1j3K0iNDLcw==",
                "name": "projects/project-name-1",
                "parent": "organizations/xsoar-organization",
                "projectId": "project-id-1",
                "state": "ACTIVE",
                "updateTime": "2021-11-01T10:43:53.026000+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Project projects/project-name-1 information:
>|Name|Parent|Project Id|Display Name|Create Time|Update Time|
>|---|---|---|---|---|---|
>| projects/project-name-1 | organizations/xsoar-organization | project-id-1 | My First Project | 2021-11-01T10:43:50.858000+00:00 | 2021-11-01T10:43:53.026000+00:00 |

### gcp-iam-project-iam-policy-get
***
Retrieves the IAM access control policy for the specified project.


#### Base Command

`gcp-iam-project-iam-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The project name for which the policy is being requested. For example, projects/415104041262. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Policy.bindings.members | String | The members who associate to the role. | 
| GCPIAM.Policy.bindings.role | String | The role that is assigned to the list of members. | 
| GCPIAM.Policy.name | String | The unique resource name of the project. Note that this output was added manually. | 


#### Command Example
```!gcp-iam-project-iam-policy-get project_name="projects/project-name-1" limit=2```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Policy": {
                "bindings": [
                    {
                        "members": [
                            "serviceAccount:service-account-1@project-id-1.iam.gserviceaccount.com"
                        ],
                        "role": "roles/anthosidentityservice.serviceAgent"
                    },
                    {
                        "members": [
                            "group:poctest@xsoar.com",
                            "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"
                        ],
                        "role": "roles/browser"
                    }
                ],
                "etag": "BwXRnN60xqw=",
                "name": "projects/project-name-1",
                "version": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Project projects/project-name-1 IAM Policy List:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Role|Members|
>|---|---|
>| roles/anthosidentityservice.serviceAgent | serviceAccount:service-account-1@project-id-1.iam.gserviceaccount.com |
>| roles/browser | group:poctest@xsoar.com,<br/>serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com |

### gcp-iam-project-iam-permission-test
***
Returns permissions that a caller has on the specified project. The permission list can be obtained by running the 'gcp-iam-testable-permission-list' command.


#### Base Command

`gcp-iam-project-iam-permission-test`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The project name for which the permissions is being tested. For example, projects/415104041262. | Required | 
| permissions | A comma-separated list of permissions names to validate for the resource. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Permission | String | The caller allowed permissions. | 


#### Command Example
```!gcp-iam-project-iam-permission-test project_name="projects/project-name-1" permissions="compute.instances.create,aiplatform.dataItems.create"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Permission": [
                {
                    "name": "aiplatform.dataItems.create"
                },
                {
                    "name": "compute.instances.create"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Project projects/project-name-1 permissions:
>|Name|
>|---|
>| aiplatform.dataItems.create |
>| compute.instances.create |

### gcp-iam-project-iam-member-add
***
Adds members to the project policy.


#### Base Command

`gcp-iam-project-iam-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The resource for which the policy is being specified. For example, projects/415104041262. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members to add to the policy. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-project-iam-member-add project_name="projects/project-name-3" role="roles/browser" members="serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"```
#### Human Readable Output
>Role roles/browser updated successfully.
### gcp-iam-project-iam-member-remove
***
Removes members from the project policy.
#### Base Command
`gcp-iam-project-iam-member-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project for which the policy is being specified. For example, projects/415104041262. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members to remove from the policy. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-project-iam-member-remove project_name="projects/project-name-3" role="roles/browser" members="serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"```
#### Human Readable Output
>Role roles/browser updated successfully.
### gcp-iam-project-iam-policy-set
***
Sets the IAM access control policy for the specified project. This operation will overwrite any existing policy.
#### Base Command
`gcp-iam-project-iam-policy-set`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project for which the policy is being specified. For example, projects/415104041262. | Required | 
| policy | A comma-separated list of JSON policies objects. Every policy item consists of 'role' and 'members'. For example: [<br/>  {<br/>    "role": "roles/resourcemanager.organizationViewer",<br/>    "members": [<br/>      "user:eve@example.com"<br/>    ]<br/>  }<br/>]. | Required | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Policy.bindings.members | String | The members who associate to the role. | 
| GCPIAM.Policy.bindings.role | String | The role that is assigned to the list of members. | 
| GCPIAM.Policy.name | String | The unique resource name of the project. Note that this output was added manually. | 
#### Command Example
```!gcp-iam-project-iam-policy-set project_name="projects/project-name-3" policy=`{"role": "roles/owner", "members": ["group:poctest@xsoar.com", "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"]}, { "role": "roles/browser", "members": [ "group:poctest@xsoar.com" ] }````
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Policy": {
                "bindings": [
                    {
                        "members": [
                            "group:poctest@xsoar.com"
                        ],
                        "role": "roles/browser"
                    },
                    {
                        "members": [
                            "group:poctest@xsoar.com",
                            "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"
                        ],
                        "role": "roles/owner"
                    }
                ],
                "etag": "BwXUDeggkiM=",
                "name": "projects/project-name-3",
                "version": 1
            }
        }
    }
}
```

#### Human Readable Output

>### projects/project-name-3 IAM policy updated successfully.
>|Role|Members|
>|---|---|
>| roles/browser | group:poctest@xsoar.com |
>| roles/owner | group:poctest@xsoar.com,<br/>serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com |

### gcp-iam-project-iam-policy-create
***
Adds a new project IAM policy.


#### Base Command

`gcp-iam-project-iam-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project for which the policy is being specified. For example, projects/415104041262. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members associated with the role. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-project-iam-policy-create project_name="projects/project-name-3" role="roles/anthosidentityservice.serviceAgent" members="serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"```
#### Human Readable Output
>Role roles/anthosidentityservice.serviceAgent updated successfully.
### gcp-iam-folders-get
***
Lists folders under the specified parent, or retrieves a specific folder information. One of the arguments: ''parent'' or ''folder_name''  must be provided.
#### Base Command
`gcp-iam-folders-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | A comma-separated list of folder names to retrieve. For example, folders/12342. Leave empty to retrieve a list of folders under a specified parent resource. | Optional | 
| parent | The name of the parent resource to list folders under. For example, setting this field to 'folders/1234' would list all folder directly under that folder. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 100. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| show_deleted | If true, folders that have been marked for deletion will also be retrieved. Possible values are: False, True. Default is False. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Folder.createTime | Date | Folder creation time. | 
| GCPIAM.Folder.displayName | String | Folder display name. | 
| GCPIAM.Folder.name | String | The unique resource name of the folder. | 
| GCPIAM.Folder.parent | String | The folder parent resource. | 
| GCPIAM.Folder.state | String | The folder lifecycle state. | 
| GCPIAM.Folder.updateTime | Date | The most recent time the folder was modified. | 
#### Command example
```!gcp-iam-folders-get folder_name="folders/folder-name-1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Folder": {
                "createTime": "2021-12-20T09:16:57.801000+00:00",
                "displayName": "integration folder",
                "etag": "DNurvk2qbYsaHclxISf8AQ==",
                "name": "folders/folder-name-1",
                "parent": "organizations/xsoar-organization",
                "state": "ACTIVE",
                "updateTime": "2021-12-20T09:16:57.801000+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Folder folders/folder-name-1 information:
>|Name|Parent|Display Name|Create Time|Update Time|
>|---|---|---|---|---|
>| folders/folder-name-1 | organizations/xsoar-organization | integration folder | 2021-12-20T09:16:57.801000+00:00 | 2021-12-20T09:16:57.801000+00:00 |

### gcp-iam-folder-iam-policy-get
***
Retrieves the IAM access control policy for the specified folder.


#### Base Command

`gcp-iam-folder-iam-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The folder name for which the policy is being requested. For example, folders/12342. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional |
| roles | A comma-separated list of roles. (Ex: "roles/bigquery.admin, roles/editor, roles/owner"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Policy.bindings.members | String | The members who associate to the role. | 
| GCPIAM.Policy.bindings.role | String | The role that is assigned to the list of members. | 
| GCPIAM.Policy.name | String | The unique resource name of the folder. Note that this output was added manually. | 


#### Command Example
```!gcp-iam-folder-iam-policy-get folder_name="folders/folder-name-3" limit=2```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Policy": {
                "bindings": [
                    {
                        "members": [
                            "group:poctest@xsoar.com",
                            "serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"
                        ],
                        "role": "organizations/xsoar-organization/roles/xsoar_demo_99"
                    },
                    {
                        "members": [
                            "user:user-1@xsoar.com"
                        ],
                        "role": "roles/resourcemanager.folderAdmin"
                    }
                ],
                "etag": "BwXUDa+Bs4c=",
                "name": "folders/folder-name-3",
                "version": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Folder folders/folder-name-3 IAM Policy List:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Role|Members|
>|---|---|
>| organizations/xsoar-organization/roles/xsoar_demo_99 | group:poctest@xsoar.com,<br/>serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com |
>| roles/resourcemanager.folderAdmin | user:user-1@xsoar.com |

### gcp-iam-folder-iam-permission-test
***
Returns permissions that a caller has on the specified folder. The permission list can be obtained by running the 'gcp-iam-testable-permission-list' command.


#### Base Command

`gcp-iam-folder-iam-permission-test`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The folder name for which the permissions is being tested. For example, folders/12342. | Required | 
| permissions | A comma-separated list of permission names to validate for the resource. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Permission | String | The caller allowed permissions. | 


#### Command Example
```!gcp-iam-folder-iam-permission-test folder_name="folders/folder-name-3" permissions="compute.instances.create,aiplatform.dataItems.create"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Permission": [
                {
                    "name": "aiplatform.dataItems.create"
                },
                {
                    "name": "compute.instances.create"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Folder folders/folder-name-3 permissions:
>|Name|
>|---|
>| aiplatform.dataItems.create |
>| compute.instances.create |

### gcp-iam-folder-iam-member-add
***
Adds members to the folder policy.


#### Base Command

`gcp-iam-folder-iam-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The resource for which the policy is being specified. For example, folders/12342. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members to add to the policy. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-folder-iam-member-add folder_name=folders/folder-name-3 role=roles/resourcemanager.folderEditor members=serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com,group:poctest@xsoar.com```
#### Human Readable Output
>Role roles/resourcemanager.folderEditor updated successfully.
### gcp-iam-folder-iam-member-remove
***
Removes members from the folder policy.
#### Base Command
`gcp-iam-folder-iam-member-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The name of the folder for which the policy is being specified. For example, folders/12342. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members to remove from the policy. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-folder-iam-member-remove folder_name="folders/folder-name-3" role="roles/resourcemanager.folderEditor" members="serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com"```
#### Human Readable Output
>Role roles/resourcemanager.folderEditor updated successfully.
### gcp-iam-folder-iam-policy-set
***
Sets the IAM access control policy for the specified folder. This operation will overwrite any existing policy.
#### Base Command
`gcp-iam-folder-iam-policy-set`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The name of the folder for which the policy is being specified. For example, folders/12342. | Required | 
| policy | A comma-separated list of JSON policies objects. Every policy item consists of 'role' and 'members'. For example: [<br/>  {<br/>    "role": "roles/resourcemanager.organizationViewer",<br/>    "members": [<br/>      "user:eve@example.com"<br/>    ]<br/>  }<br/>]. | Required | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Policy.bindings.members | String | The members who associate to the role. | 
| GCPIAM.Policy.bindings.role | String | The role that is assigned to the list of members. | 
| GCPIAM.Policy.name | String | The unique resource name of the folder. Note that this output was added manually. | 
#### Command Example
```!gcp-iam-folder-iam-policy-set folder_name="folders/folder-name-3" policy=`{"role": "roles/resourcemanager.folderAdmin","members": ["user:user-1@xsoar.com"]},{"role": "roles/resourcemanager.folderEditor","members": ["user:user-1@xsoar.com"]}````
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Policy": {
                "bindings": [
                    {
                        "members": [
                            "user:user-1@xsoar.com"
                        ],
                        "role": "roles/resourcemanager.folderAdmin"
                    },
                    {
                        "members": [
                            "user:user-1@xsoar.com"
                        ],
                        "role": "roles/resourcemanager.folderEditor"
                    }
                ],
                "etag": "BwXUDa8IhW0=",
                "name": "folders/folder-name-3",
                "version": 1
            }
        }
    }
}
```

#### Human Readable Output

>### folders/folder-name-3 IAM policy updated successfully.
>|Role|Members|
>|---|---|
>| roles/resourcemanager.folderAdmin | user:user-1@xsoar.com |
>| roles/resourcemanager.folderEditor | user:user-1@xsoar.com |

### gcp-iam-folder-iam-policy-create
***
Adds a new folder IAM policy.


#### Base Command

`gcp-iam-folder-iam-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The name of the folder for which the policy is being specified. For example, folders/12342. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members associated with the role. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-folder-iam-policy-create folder_name="folders/folder-name-3" role="organizations/xsoar-organization/roles/xsoar_demo_99" members="serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com,group:poctest@xsoar.com"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_99 updated successfully.
### gcp-iam-organizations-get
***
Lists organization resources that are visible to the caller, or retrieves an organization's information.
#### Base Command
`gcp-iam-organizations-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| organization_name | A comma-separated list of organization names to retrieve. For example, organizations/3456. Leave empty to retrieve a list of organizations that are visible to the caller. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Organization.createTime | Date | Organization creation time. | 
| GCPIAM.Organization.directoryCustomerId | String | The G Suite / Workspace customer ID used in the Directory API. | 
| GCPIAM.Organization.displayName | String | Organization display name. | 
| GCPIAM.Organization.name | String | The unique resource name of the organization. | 
| GCPIAM.Organization.state | String | The organization lifecycle state. | 
| GCPIAM.Organization.updateTime | Date | The most recent time the organization was modified. | 
#### Command example
```!gcp-iam-organizations-get limit="50" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Organization": {
                "createTime": "2021-11-01T10:32:53.855000+00:00",
                "directoryCustomerId": "xsoar-customer-id",
                "displayName": "xsoar.com",
                "etag": "TdmlNua+ZCbmiXGBNzldeg==",
                "name": "organizations/xsoar-organization",
                "state": "ACTIVE",
                "updateTime": "2021-11-01T10:32:53.855000+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Organizations List:
> Current page size: 50
> Showing page 1 out of others that may exist.
>|Name|Display Name|Directory Customer Id|Create Time|Update Time|
>|---|---|---|---|---|
>| organizations/xsoar-organization | xsoar.com | xsoar-customer-id | 2021-11-01T10:32:53.855000+00:00 | 2021-11-01T10:32:53.855000+00:00 |

### gcp-iam-organization-iam-policy-get
***
Retrieves the IAM access control policy for the specified organization.


#### Base Command

`gcp-iam-organization-iam-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The organization name for which the policy is being requested. For example, organizations/3456. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Policy.bindings.members | String | The members who associate to the role. | 
| GCPIAM.Policy.bindings.role | String | The role that is assigned to the list of members. | 
| GCPIAM.Policy.name | String | The unique resource name of the organization. Note that this output was added manually. | 


#### Command Example
```!gcp-iam-organization-iam-policy-get organization_name="organizations/xsoar-organization" limit=2```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Policy": {
                "bindings": [
                    {
                        "members": [
                            "user:user-1@xsoar.com"
                        ],
                        "role": "roles/bigquery.admin"
                    },
                    {
                        "members": [
                            "user:user-1@xsoar.com"
                        ],
                        "role": "roles/bigquery.user"
                    }
                ],
                "etag": "BwXUxBjIO70=",
                "name": "organizations/xsoar-organization",
                "version": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Organization organizations/xsoar-organization IAM Policy List:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Role|Members|
>|---|---|
>| roles/bigquery.admin | user:user-1@xsoar.com |
>| roles/bigquery.user | user:user-1@xsoar.com |

### gcp-iam-organization-iam-permission-test
***
Returns permissions that a caller has on the specified organization. The permission list can be obtained by running the 'gcp-iam-testable-permission-list' command.


#### Base Command

`gcp-iam-organization-iam-permission-test`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The organization name for which the permissions is being tested. For example, organizations/3456. | Required | 
| permissions | A comma-separated list of permissions names to validate for the resource. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Permission | String | The caller allowed permissions. | 


#### Command Example
```!gcp-iam-organization-iam-permission-test organization_name="organizations/xsoar-organization" permissions="compute.instances.create,aiplatform.dataItems.create"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Permission": [
                {
                    "name": "compute.instances.create"
                },
                {
                    "name": "aiplatform.dataItems.create"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Organization organizations/xsoar-organization permissions:
>|Name|
>|---|
>| compute.instances.create |
>| aiplatform.dataItems.create |

### gcp-iam-organization-iam-member-add
***
Adds members to the organization policy.


#### Base Command

`gcp-iam-organization-iam-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The resource for which the policy is being specified. For example, organizations/3456. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members ato add to the policy. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-organization-iam-member-add organization_name="organizations/xsoar-organization" role="organizations/xsoar-organization/roles/xsoar_demo_70" members="user:user-1@xsoar.com"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_70 updated successfully.
### gcp-iam-organization-iam-member-remove
***
Removes members from the organization policy.
#### Base Command
`gcp-iam-organization-iam-member-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization for which the policy is being specified. For example, organizations/3456. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members to remove from the policy. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-organization-iam-member-remove organization_name="organizations/xsoar-organization" role="organizations/xsoar-organization/roles/xsoar_demo_70" members="user:user-1@xsoar.com"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_70 updated successfully.
### gcp-iam-organization-iam-policy-set
***
Sets the IAM access control policy for the specified organization. This operation will overwrite any existing policy.
#### Base Command
`gcp-iam-organization-iam-policy-set`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization for which the policy is being specified. For example, organizations/3456. | Required | 
| policy | A comma-separated list of JSON policies objects. Every policy item consists of 'role' and 'members'. For example: [<br/>  {<br/>    "role": "roles/resourcemanager.organizationViewer",<br/>    "members": [<br/>      "user:eve@example.com"<br/>    ]<br/>  }<br/>]. | Required | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Policy.bindings.members | String | The members who associate to the role. | 
| GCPIAM.Policy.bindings.role | String | The role that is assigned to the list of members. | 
| GCPIAM.Policy.name | String | The unique resource name of the organization. Note that this output was added manually. | 
#### Command Example
```!gcp-iam-organization-iam-policy-set organization_name="organizations/xsoar-organization" policy=` { "members": [ "user:user-1@xsoar.com" ], "role": "roles/bigquery.admin" }````
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Policy": {
                "bindings": [
                    {
                        "members": [
                            "user:user-1@xsoar.com"
                        ],
                        "role": "roles/bigquery.admin"
                    }
                ],
                "etag": "BwXUxBs/sN0=",
                "name": "organizations/xsoar-organization",
                "version": 1
            }
        }
    }
}
```

#### Human Readable Output

>### organizations/xsoar-organization IAM policy updated successfully.
>|Role|Members|
>|---|---|
>| roles/bigquery.admin | user:user-1@xsoar.com |

### gcp-iam-organization-iam-policy-create
***
Adds a new organization IAM policy.


#### Base Command

`gcp-iam-organization-iam-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization for which the policy is being specified. For example, organizations/3456. | Required | 
| role | The name of the policy role. | Required | 
| members | A comma-separated list of members associated with the role. For example: user:mike@example.com, group:admins@example.com, domain:google.com, serviceAccount:my-project-id@xsoar.gserviceaccount.com. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-organization-iam-policy-create organization_name="organizations/xsoar-organization" role="organizations/xsoar-organization/roles/xsoar_demo_70" members="serviceAccount:service-account-2@project-id-1.iam.gserviceaccount.com,group:poctest@xsoar.com"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_70 updated successfully.
### gcp-iam-group-create
***
Creates a new group. The end user making the request will be added as the initial owner of the group.
#### Base Command
`gcp-iam-group-create`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent | The parent resource of the groups to create. Must be of the form identitysources/{identity_source_id} for external- identity-mapped groups or customers/{customer_id} for Google Groups. The customer_id must begin with "C" (for example, 'C046psxkn'). Customer ID can be obtained by running the 'gcp-iam-organizations-get' command. The customer ID can be found in the 'directoryCustomerId' field. | Required | 
| description | The description of the group. | Optional | 
| display_name | The display name of the group. | Required | 
| group_email_address | The group unique email address. There is no need to set up the email in the organization, the command will do this independently. | Required | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Group.createTime | Date | Group creation time. | 
| GCPIAM.Group.displayName | String | The display name of the group | 
| GCPIAM.Group.groupKey.id | String | The ID of the group. | 
| GCPIAM.Group.name | String | The resource name of the group. | 
| GCPIAM.Group.parent | String | The resource name of the entity under which this group resides in the Cloud Identity resource hierarchy. | 
| GCPIAM.Group.updateTime | Date | The most recent time the group was modified. | 
#### Command Example
```!gcp-iam-group-create parent="customers/xsoar-customer-id" display_name="integration-test" group_email_address="xsoar-test-10@xsoar.com"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Group": {
                "@type": "type.googleapis.com/google.apps.cloudidentity.groups.v1.Group",
                "createTime": "2022-01-04T15:25:46.218759+00:00",
                "displayName": "integration-test",
                "groupKey": {
                    "id": "xsoar-test-10@xsoar.com"
                },
                "labels": {
                    "cloudidentity.googleapis.com/groups.discussion_forum": ""
                },
                "name": "group-4-name",
                "parent": "customers/xsoar-customer-id",
                "updateTime": "2022-01-04T15:25:46.218759+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Successfully Created Group "group-4-name"
>|Name|Group Key|Parent|Display Name|Create Time|Update Time|
>|---|---|---|---|---|---|
>| group-4-name | id: xsoar-test-10@xsoar.com | customers/xsoar-customer-id | integration-test | 2022-01-04T15:25:46.218759+00:00 | 2022-01-04T15:25:46.218759+00:00 |

### gcp-iam-group-list
***
Lists groups that are visible to the caller.


#### Base Command

`gcp-iam-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent | The parent resource of the groups to retrieve. This parameter is usually equal to the organization customer ID. For example customers/C01234. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 500. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Group.displayName | String | The display name of the group. | 
| GCPIAM.Group.groupKey.id | String | The ID of the group. | 
| GCPIAM.Group.name | String | The resource name of the group. | 


#### Command Example
```!gcp-iam-group-list parent="customers/xsoar-customer-id" limit="2" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Group": [
                {
                    "displayName": "integration-test",
                    "groupKey": {
                        "id": "xsoar-service-account-245@xsoar.com"
                    },
                    "name": "groups/group-5-name"
                },
                {
                    "displayName": "xsoar-api-test-2",
                    "groupKey": {
                        "id": "poctest1s2@xsoar.com"
                    },
                    "name": "groups/group-4-name"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Groups List:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Group Key|Display Name|
>|---|---|---|
>| groups/group-5-name | id: xsoar-service-account-245@xsoar.com | integration-test |
>| groups/group-4-name | id: poctest1s2@xsoar.com | xsoar-api-test-2 |

### gcp-iam-group-get
***
Retrieves a group information.


#### Base Command

`gcp-iam-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the group to retrieve. Must be of the form groups/{group_id}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Group.createTime | Date | Group creation time. | 
| GCPIAM.Group.displayName | String | The display name of the group | 
| GCPIAM.Group.groupKey.id | String | The ID of the group. | 
| GCPIAM.Group.name | String | The resource name of the group. | 
| GCPIAM.Group.parent | String | The resource name of the entity under which this group resides in the Cloud Identity resource hierarchy. | 
| GCPIAM.Group.updateTime | Date | The most recent time the group was modified. | 


#### Command Example
```!gcp-iam-group-get group_name="groups/group-5-name"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Group": {
                "createTime": "2021-12-14T12:33:04.648409+00:00",
                "displayName": "integration-test",
                "groupKey": {
                    "id": "xsoar-service-account-245@xsoar.com"
                },
                "labels": {
                    "cloudidentity.googleapis.com/groups.discussion_forum": ""
                },
                "name": "groups/group-5-name",
                "parent": "customers/xsoar-customer-id",
                "updateTime": "2021-12-14T12:33:04.648409+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Group information:
>|Name|Group Key|Parent|Display Name|Create Time|Update Time|
>|---|---|---|---|---|---|
>| groups/group-5-name | id: xsoar-service-account-245@xsoar.com | customers/xsoar-customer-id | integration-test | 2021-12-14T12:33:04.648409+00:00 | 2021-12-14T12:33:04.648409+00:00 |

### gcp-iam-group-delete
***
Deletes a group.


#### Base Command

`gcp-iam-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the group to delete. Must be of the form groups/{group_id}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-group-delete group_name="group-4-name"```
#### Human Readable Output
>Group group-4-name was successfully deleted.
### gcp-iam-group-membership-create
***
Creates a group membership.
#### Base Command
`gcp-iam-group-membership-create`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| groups_name | A comma-separated list of group names that will contain the membership. Every group name must be of the form groups/{group_id}. | Required | 
| member_email | The email address of the member to add to the group. | Required | 
| role | A comma-separated list of membership roles that apply to the membership. The 'MEMBER' role must be provided. Possible values are: OWNER, MANAGER, MEMBER. Default is MEMBER. | Required | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Membership.name | String | The resource name of the membership. | 
| GCPIAM.Membership.preferredMemberKey.id | String | The member key ID. | 
| GCPIAM.Membership.roles.name | String | The membership roles that apply to the membership. | 
#### Command Example
```!gcp-iam-group-membership-create groups_name="groups/group-5-name" member_email="user-1@xsoar.com" role="MEMBER"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Membership": {
                "@type": "type.googleapis.com/google.apps.cloudidentity.groups.v1.Membership",
                "name": "groups/group-5-name/memberships/membership-3",
                "preferredMemberKey": {
                    "id": "user-1@xsoar.com"
                },
                "roles": [
                    {
                        "name": "MEMBER"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Membership information:
>|Name|Roles|Preferred Member Key|
>|---|---|---|
>| groups/group-5-name/memberships/membership-3 | MEMBER | user-1@xsoar.com |

### gcp-iam-group-membership-list
***
Lists the group memberships.


#### Base Command

`gcp-iam-group-membership-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the group that contains the membership. Must be of the form groups/{group_id}. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 500. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Membership.name | String | The resource name of the membership. | 
| GCPIAM.Membership.preferredMemberKey.id | String | The member key ID. | 
| GCPIAM.Membership.roles.name | String | The membership roles that apply to the membership. | 


#### Command Example
```!gcp-iam-group-membership-list group_name="groups/group-5-name" limit="2" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Membership": [
                {
                    "name": "groups/group-5-name/memberships/membership-3",
                    "preferredMemberKey": {
                        "id": "user-1@xsoar.com"
                    },
                    "roles": [
                        {
                            "name": "MEMBER"
                        }
                    ]
                },
                {
                    "name": "groups/group-5-name/memberships/membership-1",
                    "preferredMemberKey": {
                        "id": "user-2@xsoar.com"
                    },
                    "roles": [
                        {
                            "name": "MEMBER"
                        },
                        {
                            "name": "MANAGER"
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Membership List:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Roles|Preferred Member Key|
>|---|---|---|
>| groups/group-5-name/memberships/membership-3 | MEMBER | user-1@xsoar.com |
>| groups/group-5-name/memberships/membership-1 | MEMBER,<br/>MANAGER | user-2@xsoar.com |

### gcp-iam-group-membership-get
***
Retrieves group membership information.


#### Base Command

`gcp-iam-group-membership-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership_name | The name of the group membership to retrieve. Must be of the form: groups/{group_id}/memberships/{membership_id}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Membership.createTime | Date | The membership creation time. | 
| GCPIAM.Membership.name | String | The resource name of the membership. | 
| GCPIAM.Membership.preferredMemberKey.id | String | The member key ID. | 
| GCPIAM.Membership.roles.name | String | The membership roles that apply to the membership. | 
| GCPIAM.Membership.updateTime | Date | The most recent time the membership was modified. | 


#### Command Example
```!gcp-iam-group-membership-get membership_name="groups/group-5-name/memberships/membership-1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Membership": {
                "createTime": "2021-12-14T13:12:46.091080+00:00",
                "name": "groups/group-5-name/memberships/membership-1",
                "preferredMemberKey": {
                    "id": "user-2@xsoar.com"
                },
                "roles": [
                    {
                        "name": "MEMBER"
                    },
                    {
                        "name": "MANAGER"
                    }
                ],
                "type": "USER",
                "updateTime": "2021-12-14T13:12:46.091080+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Membership information:
>|Name|Roles|Preferred Member Key|
>|---|---|---|
>| groups/group-5-name/memberships/membership-1 | MEMBER,<br/>MANAGER | user-2@xsoar.com |

### gcp-iam-group-membership-role-add
***
Adds a group membership role.


#### Base Command

`gcp-iam-group-membership-role-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership_name | The name of the group membership to update. Must be of the form: groups/{group_id}/memberships/{membership_id}. | Required | 
| role | A comma-separated list of membership roles to add to the membership. Possible values are: MANAGER, OWNER. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-group-membership-role-add membership_name="groups/group-5-name/memberships/membership-3" role="OWNER"```
#### Human Readable Output
>Membership groups/group-5-name/memberships/membership-3 updated successfully.
### gcp-iam-group-membership-role-remove
***
Removes a group membership role.
#### Base Command
`gcp-iam-group-membership-role-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership_name | The resource name of the membership. Must be of the form: groups/{group_id}/memberships/{membership_id}. | Required | 
| role | A comma-separated list of membership roles to remove from the membership. Possible values are: OWNER, MANAGER. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-group-membership-role-remove membership_name="groups/group-5-name/memberships/membership-3" role="OWNER"```
#### Human Readable Output
>Membership groups/group-5-name/memberships/membership-3 updated successfully.
### gcp-iam-group-membership-delete
***
Deletes a group membership.
#### Base Command
`gcp-iam-group-membership-delete`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership_names | A comma-separated list of resource names of the memberships to delete. Must be of the form: groups/{group_id}/memberships/{membership_id}. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-group-membership-delete membership_names=groups/group-5-name/memberships/membership-1```
#### Human Readable Output
>Membership groups/group-5-name/memberships/membership-1 deleted successfully.
### gcp-iam-service-account-create
***
Creates a service account in project.
#### Base Command
`gcp-iam-service-account-create`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project associated with the service account. Must be of the form projects/{project_id}. | Required | 
| service_account_id | The account ID that is used to generate the service account email address and a stable unique ID. It is unique within a project, must be 6-30 characters long, and match the regular expression `[a-z]([-a-z0-9]*[a-z0-9])`. | Required | 
| display_name | Human readable name for the created service account. | Optional | 
| description | Human readable description for the created service account. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.ServiceAccount.email | String | The email address of the service account. | 
| GCPIAM.ServiceAccount.name | String | The resource name of the service account. | 
| GCPIAM.ServiceAccount.oauth2ClientId | String | The OAuth 2.0 client ID for the service account. | 
| GCPIAM.ServiceAccount.projectId | String | The ID of the project that owns the service account. | 
| GCPIAM.ServiceAccount.uniqueId | String | The unique, stable numeric ID for the service account. | 
| GCPIAM.ServiceAccount.disabled | Boolean | Indicates whether the service account is disabled. | 
#### Command Example
```!gcp-iam-service-account-create project_name="projects/project-name-3" service_account_id="integration-test-15" display_name="xsoar-service-account" description="XSOAR integration service-account"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "ServiceAccount": {
                "description": "XSOAR integration service-account",
                "disabled": false,
                "displayName": "xsoar-service-account",
                "email": "integration-test-15@project-name-3.iam.gserviceaccount.com",
                "etag": "MDEwMjE5MjA=",
                "name": "projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com",
                "oauth2ClientId": "unique-id-5",
                "projectId": "project-id-1",
                "uniqueId": "unique-id-5"
            }
        }
    }
}
```

#### Human Readable Output

>### Service account information:
>|Name|Display Name|Description|Project Id|
>|---|---|---|---|
>| projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com | xsoar-service-account | XSOAR integration service-account | project-id-1 |

### gcp-iam-service-account-update
***
Updates a service account.


#### Base Command

`gcp-iam-service-account-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_name | The name of the service account to update. Must be of the form projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. | Required | 
| display_name | Human readable name for the updated service account. | Optional | 
| description | Human readable description for the updated service account. | Optional | 
| fields_to_update | A comma-separated list of names list of the fields to update. Possible values are: displayName, description. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-service-account-update service_account_name="projects/project-id-1/serviceAccounts/integration-test-3@project-name-3.iam.gserviceaccount.com" display_name="xsoar-service-account" fields_to_update="displayName"```
#### Human Readable Output
>Service account projects/project-id-1/serviceAccounts/integration-test-3@project-name-3.iam.gserviceaccount.com updated successfully.
### gcp-iam-service-accounts-get
***
Lists service accounts in project, or retrieves a specific service accounts information. One of the arguments: ''service_account_name'' or ''project_name''  must be provided.
#### Base Command
`gcp-iam-service-accounts-get`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_name | A comma-separated list of service accounts names to retrieve in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. Leave empty to retrieve a list of service accounts under a specified project resource. | Optional | 
| project_name | The name of the project associated with the service accounts to retrieve, for example: projects/my-project-123. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 100. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.ServiceAccount.email | String | The email address of the service account. | 
| GCPIAM.ServiceAccount.name | String | The resource name of the service account. | 
| GCPIAM.ServiceAccount.oauth2ClientId | String | The OAuth 2.0 client ID for the service account. | 
| GCPIAM.ServiceAccount.projectId | String | The ID of the project that owns the service account. | 
| GCPIAM.ServiceAccount.uniqueId | String | The unique, stable numeric ID for the service account. | 
| GCPIAM.ServiceAccount.disabled | Boolean | Indicates whether the service account is disabled. | 
#### Command Example
```!gcp-iam-service-accounts-get service_account_name="projects/project-id-1/serviceAccounts/integration-test-2@project-name-3.iam.gserviceaccount.com"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "ServiceAccount": {
                "description": "user-1-description",
                "disabled": false,
                "displayName": "user-1-display-name",
                "email": "integration-test-2@project-name-3.iam.gserviceaccount.com",
                "etag": "MDEwMjE5MjA=",
                "name": "projects/project-id-1/serviceAccounts/integration-test-2@project-name-3.iam.gserviceaccount.com",
                "oauth2ClientId": "unique-id-3",
                "projectId": "project-id-1",
                "uniqueId": "unique-id-3"
            }
        }
    }
}
```

#### Human Readable Output

>### Service account information:
>|Name|Display Name|Description|Project Id|
>|---|---|---|---|
>| projects/project-id-1/serviceAccounts/integration-test-2@project-name-3.iam.gserviceaccount.com | user-1-display-name | user-1-description | project-id-1 |

### gcp-iam-service-account-enable
***
Enables a project service account.


#### Base Command

`gcp-iam-service-account-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_name | A comma-separated list of names of service accounts to enable. Every resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-service-account-enable service_account_name="projects/xsoar-project-5/serviceAccounts/my-service-account@xsoar-project-5.iam.gserviceaccount.com"```
#### Human Readable Output
>Service account projects/xsoar-project-5/serviceAccounts/my-service-account@xsoar-project-5.iam.gserviceaccount.com updated successfully.
### gcp-iam-service-account-disable
***
Disables a project service account.
#### Base Command
`gcp-iam-service-account-disable`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_name | A comma-separated list of names of service accounts to disable. Every resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-service-account-disable service_account_name="projects/xsoar-project-5/serviceAccounts/my-service-account@xsoar-project-5.iam.gserviceaccount.com"```
#### Human Readable Output
>Service account projects/xsoar-project-5/serviceAccounts/my-service-account@xsoar-project-5.iam.gserviceaccount.com updated successfully.
### gcp-iam-service-account-key-create
***
Creates a service account key. A service account can have up to 10 keys. Service account keys that you create don't have an expiry date and stay valid until you delete them.
#### Base Command
`gcp-iam-service-account-key-create`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_name | The name of the service account associated with the key. Must be of the form projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. | Required | 
| key_algorithm | The RSA key algorithm. Possible values are: KEY_ALG_RSA_1024, KEY_ALG_RSA_2048. Default is KEY_ALG_RSA_2048. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.ServiceAccountKey.keyAlgorithm | String | Specifies the algorithm for the key. | 
| GCPIAM.ServiceAccountKey.keyOrigin | String | Service account key origin provider. | 
| GCPIAM.ServiceAccountKey.keyType | String | Indicates the resource managed type. | 
| GCPIAM.ServiceAccountKey.name | String | The resource name of the service account key. | 
| GCPIAM.ServiceAccountKey.privateKeyData | String | The encrypted private key data. | 
| GCPIAM.ServiceAccountKey.privateKeyType | String | The output format for the private key. | 
| GCPIAM.ServiceAccountKey.validAfterTime | Date | Indicates the time the key can be used after this timestamp. | 
| GCPIAM.ServiceAccountKey.validBeforeTime | Date | Indicates the time the key can be used before this timestamp. | 
| GCPIAM.ServiceAccountKey.disabled | Boolean | Indicates whether the service account key is disabled. | 
#### Command Example
```!gcp-iam-service-account-key-create service_account_name="projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com" key_algorithm="KEY_ALG_RSA_1024"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "ServiceAccountKey": {
                "disabled": false,
                "keyAlgorithm": "KEY_ALG_RSA_1024",
                "keyOrigin": "GOOGLE_PROVIDED",
                "keyType": "USER_MANAGED",
                "name": "projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com/keys/key-3",
                "privateKeyData": "my-private-key-data",
                "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
                "validAfterTime": "2022-01-04T15:37:22+00:00",
                "validBeforeTime": "9999-12-31T23:59:59+00:00"
            }
        }
    }
}
```

#### Human Readable Output

>### Service account key information:
>|Name|Valid After Time|Valid Before Time|Disabled|Key Type|
>|---|---|---|---|---|
>| projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com/keys/key-3 | 2022-01-04T15:37:22+00:00 | 9999-12-31T23:59:59+00:00 | false | USER_MANAGED |

### gcp-iam-service-account-keys-get
***
Lists service account keys, or retrieves a specific service account key information. One of the arguments: ''service_account_name'' or ''key_name'' must be provided.


#### Base Command

`gcp-iam-service-account-keys-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_name | The resource name of the service account key to retrieve. The resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}/keys/{key}. Leave empty to retrieve a list of service account keys that are associated with the service account resource. | Optional | 
| service_account_name | The name of the service account associated with the keys. Must be of the form projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.ServiceAccountKey.keyAlgorithm | String | Specifies the algorithm for the key. | 
| GCPIAM.ServiceAccountKey.keyOrigin | String | Service account key origin provider. | 
| GCPIAM.ServiceAccountKey.keyType | String | Indicates the resource managed type. | 
| GCPIAM.ServiceAccountKey.name | String | The resource name of the service account key. | 
| GCPIAM.ServiceAccountKey.validAfterTime | Date | Indicates the time the key can be used after this timestamp. | 
| GCPIAM.ServiceAccountKey.validBeforeTime | Date | Indicates the time the key can be used before this timestamp. | 
| GCPIAM.ServiceAccountKey.disabled | Boolean | Indicates whether the service account key is disabled. | 


#### Command Example
```!gcp-iam-service-account-keys-get service_account_name="projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com" limit="2" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "ServiceAccountKey": [
                {
                    "disabled": false,
                    "keyAlgorithm": "KEY_ALG_RSA_2048",
                    "keyOrigin": "GOOGLE_PROVIDED",
                    "keyType": "SYSTEM_MANAGED",
                    "name": "projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-1",
                    "validAfterTime": "2021-12-15T13:10:43+00:00",
                    "validBeforeTime": "2022-01-01T13:10:43+00:00"
                },
                {
                    "disabled": false,
                    "keyAlgorithm": "KEY_ALG_RSA_2048",
                    "keyOrigin": "GOOGLE_PROVIDED",
                    "keyType": "SYSTEM_MANAGED",
                    "name": "projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-2",
                    "validAfterTime": "2021-12-24T13:10:43+00:00",
                    "validBeforeTime": "2022-01-09T13:10:43+00:00"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Service Account Keys List:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Valid After Time|Valid Before Time|Disabled|Key Type|
>|---|---|---|---|---|
>| projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-1 | 2021-12-15T13:10:43+00:00 | 2022-01-01T13:10:43+00:00 | false | SYSTEM_MANAGED |
>| projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-2 | 2021-12-24T13:10:43+00:00 | 2022-01-09T13:10:43+00:00 | false | SYSTEM_MANAGED |

### gcp-iam-service-account-key-enable
***
Enables a service account key.


#### Base Command

`gcp-iam-service-account-key-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_name | A comma-separated list of names of resource name of the service account key to enable. Every resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}/keys/{key}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-service-account-key-enable key_name="projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-3"```
#### Human Readable Output
>Service account key projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-3 updated successfully.
### gcp-iam-service-account-key-disable
***
Disables a service account key.
#### Base Command
`gcp-iam-service-account-key-disable`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_name | A comma-separated list of names of resource name of the service account key to disable. Every resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}/keys/{key}. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-service-account-key-disable key_name="projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-3"```
#### Human Readable Output
>Service account key projects/project-id-1/serviceAccounts/service-account-1@project-name-3.iam.gserviceaccount.com/keys/key-3 updated successfully.
### gcp-iam-service-account-key-delete
***
Deletes a service account key.
#### Base Command
`gcp-iam-service-account-key-delete`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key_name | A comma-separated list of names of resource name of the service account key to delete. Every resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}/keys/{key}. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-service-account-key-delete key_name="projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com/keys/key-3"```
#### Human Readable Output
>Service account key projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com/keys/key-3 deleted successfully.
### gcp-iam-organization-role-create
***
Creates a custom organization role.
#### Base Command
`gcp-iam-organization-role-create`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization that contains the custom role. For example organizations/1234567. | Required | 
| role_id | The unique ID of the role to create. A role ID may contain alphanumeric characters, underscores (_), and periods (.). It must contain a minimum of 3 characters and a maximum of 64 characters. | Required | 
| description | The description of the role to create. | Optional | 
| title | The title of the role to create. | Optional | 
| permissions | A comma-separated list of names of the permissions the role grants when bound in an IAM policy. | Optional | 
| stage | The launch stage of the role. More information can be found here: https://cloud.google.com/iam/docs/reference/rest/v1/organizations.roles#rolelaunchstage. Possible values are: ALPHA, BETA, GA, DEPRECATED, DISABLED, EAP. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The name of the role. | 
#### Command Example
```!gcp-iam-organization-role-create organization_name="organizations/xsoar-organization" role_id="xsoar_demo_60" stage=ALPHA description="Demo role" permissions=accessapproval.requests.approve,aiplatform.artifacts.get title="XSOAR Role"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": {
                "deleted": false,
                "description": "Demo role",
                "etag": "BwXUw4jsavE=",
                "includedPermissions": [
                    "accessapproval.requests.approve",
                    "aiplatform.artifacts.get"
                ],
                "name": "organizations/xsoar-organization/roles/xsoar_demo_60",
                "stage": "ALPHA",
                "title": "XSOAR Role"
            }
        }
    }
}
```

#### Human Readable Output

>### Role organizations/xsoar-organization/roles/xsoar_demo_60 information:
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| organizations/xsoar-organization/roles/xsoar_demo_60 | accessapproval.requests.approve,<br/>aiplatform.artifacts.get | XSOAR Role | Demo role |

### gcp-iam-organization-role-update
***
Updates a custom organization role.


#### Base Command

`gcp-iam-organization-role-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The name of the role to update. Must be in the format of organizations/{ORGANIZATION_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 
| description | The updated description of the role. | Optional | 
| title | The updated title of the role. | Optional | 
| permissions | A comma-separated list of names of the permissions the role grants when bound in an IAM policy. Note that this command argument will replace the existing permissions. | Optional | 
| fields_to_update | A comma-separated list of names of the fields to update. Possible values are: description, title, includedPermissions, stage. | Required | 
| stage | The launch stage of the role. More information can be found here: https://cloud.google.com/iam/docs/reference/rest/v1/organizations.roles#rolelaunchstage. Possible values are: ALPHA, BETA, GA, DEPRECATED, DISABLED, EAP. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-organization-role-update role_name="organizations/xsoar-organization/roles/xsoar_demo_70" title="xsoar role 70" fields_to_update="title"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_70 updated successfully.
### gcp-iam-organization-role-permission-add
***
Adds permissions to a custom organization role.
#### Base Command
`gcp-iam-organization-role-permission-add`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The resource name of the role. Must be in the format of organizations/{ORGANIZATION_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 
| permissions | A comma-separated list of names of the permissions to add to the role. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-organization-role-permission-add role_name="organizations/xsoar-organization/roles/xsoar_demo_70" permissions="aiplatform.artifacts.get"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_70 updated successfully.
### gcp-iam-organization-role-permission-remove
***
Removes permissions from a custom organization role.
#### Base Command
`gcp-iam-organization-role-permission-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The resource name of the role. Must be in the format of organizations/{ORGANIZATION_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 
| permissions | A comma-separated list of names of the permissions to remove from the role. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-organization-role-permission-remove role_name="organizations/xsoar-organization/roles/xsoar_demo_70" permissions="aiplatform.artifacts.get"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_70 updated successfully.
### gcp-iam-organization-role-list
***
Lists the organization custom roles.
#### Base Command
`gcp-iam-organization-role-list`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization that contains the custom role. For example organizations/12345. | Required | 
| include_permissions | Indicates whether to include permissions in the response. Possible values are: True, False. Default is True. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 1,000. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1, maximum value is 1000. Default is 1. | Optional | 
| show_deleted | If true, roles that have been deleted will also be retrieved. Possible values are: False, True. Default is False. | Optional | 
| title_filter | Used to filter the retrieved roles by the rule title. The command will retrieve the rules that include the provided argument in their title. | Optional | 
| permission_filter | A comma-separated list of role permissions. Used to filter the retrieved roles by their permissions. The command will retrieve the rules that include all the provided permissions in their permissions list. If the argument is provided, the command will include the role permissions in the output. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The resource name of the role. | 
#### Command Example
```!gcp-iam-organization-role-list organization_name="organizations/xsoar-organization" include_permissions="True" limit="2" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": [
                {
                    "deleted": false,
                    "description": "my first role",
                    "etag": "BwXUDfGzgu0=",
                    "includedPermissions": [
                        "accessapproval.requests.approve",
                        "aiplatform.artifacts.get"
                    ],
                    "name": "organizations/xsoar-organization/roles/xsoar_demo_70",
                    "stage": "ALPHA",
                    "title": "xsoar role 70"
                },
                {
                    "deleted": false,
                    "etag": "BwXTfraB2FU=",
                    "includedPermissions": [],
                    "name": "organizations/xsoar-organization/roles/xsoar_demo_9",
                    "stage": "BETA"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Custom Organization Roles list:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| organizations/xsoar-organization/roles/xsoar_demo_70 | accessapproval.requests.approve,<br/>aiplatform.artifacts.get | xsoar role 70 | my first role |
>| organizations/xsoar-organization/roles/xsoar_demo_9 |  |  |  |

### gcp-iam-organization-role-get
***
Retrieves an organization role information.


#### Base Command

`gcp-iam-organization-role-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | A comma-separated list of organization roles to retrieve. Every role name should be in the following format: organizations/{ORGANIZATION_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The resource name of the role. | 


#### Command Example
```!gcp-iam-organization-role-get role_name="organizations/xsoar-organization/roles/xsoar_demo_70"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": {
                "deleted": false,
                "description": "my first role",
                "etag": "BwXUC+Mfa9M=",
                "includedPermissions": [
                    "accessapproval.requests.approve",
                    "aiplatform.artifacts.get"
                ],
                "name": "organizations/xsoar-organization/roles/xsoar_demo_70",
                "stage": "ALPHA",
                "title": "my demo role"
            }
        }
    }
}
```

#### Human Readable Output

>### Role organizations/xsoar-organization/roles/xsoar_demo_70 information:
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| organizations/xsoar-organization/roles/xsoar_demo_70 | accessapproval.requests.approve,<br/>aiplatform.artifacts.get | my demo role | my first role |

### gcp-iam-organization-role-delete
***
Deletes a custom organization role.


#### Base Command

`gcp-iam-organization-role-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | A comma-separated list of organization roles to delete. Every role name should be in the following format: organizations/{ORGANIZATION_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-organization-role-delete role_name="organizations/xsoar-organization/roles/xsoar_demo_60"```
#### Human Readable Output
>Role organizations/xsoar-organization/roles/xsoar_demo_60 deleted successfully.
### gcp-iam-project-role-create
***
Creates a custom project role.
#### Base Command
`gcp-iam-project-role-create`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project that contains the custom role. | Required | 
| role_id | The unique ID of the role to create. A role ID may contain alphanumeric characters, underscores (_), and periods (.). It must contain a minimum of 3 characters and a maximum of 64 characters. | Required | 
| description | The description of the role to create. | Optional | 
| title | The title of the role to create. | Optional | 
| permissions | A comma-separated list of names of the permissions the role grants when bound in an IAM policy. | Optional | 
| stage | The launch stage of the role. More information can be found here: https://cloud.google.com/iam/docs/reference/rest/v1/organizations.roles#rolelaunchstage. Possible values are: ALPHA, BETA, GA, DEPRECATED, DISABLED, EAP. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The name of the role. | 
#### Command Example
```!gcp-iam-project-role-create project_id="xsoar-project-5" role_id="xsoar_demo_role_1" description="My demo role" title="test xsoar platform" permissions="accessapproval.requests.approve,aiplatform.artifacts.get" stage="ALPHA"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": {
                "deleted": false,
                "description": "My demo role",
                "etag": "BwXUw5Zrxew=",
                "includedPermissions": [
                    "accessapproval.requests.approve",
                    "aiplatform.artifacts.get"
                ],
                "name": "projects/xsoar-project-5/roles/xsoar_demo_role_1",
                "stage": "ALPHA",
                "title": "test xsoar platform"
            }
        }
    }
}
```

#### Human Readable Output

>### Role projects/xsoar-project-5/roles/xsoar_demo_role_1 information:
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| projects/xsoar-project-5/roles/xsoar_demo_role_1 | accessapproval.requests.approve,<br/>aiplatform.artifacts.get | test xsoar platform | My demo role |

### gcp-iam-project-role-update
***
Updates a custom project role.


#### Base Command

`gcp-iam-project-role-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The name of the role to update. Must be in the format of projects/{PROJECT_ID}/roles/{CUSTOM_ROLE_ID}. . | Required | 
| description | The updated description of the role. | Optional | 
| title | The updated title of the role. | Optional | 
| permissions | A comma-separated list of names of the permissions the role grants when bound in an IAM policy. Note that this command argument will replace the existing permissions. | Optional | 
| stage | The launch stage of the role. More information can be found here: https://cloud.google.com/iam/docs/reference/rest/v1/organizations.roles#rolelaunchstage. Possible values are: ALPHA, BETA, GA, DEPRECATED, DISABLED, EAP. | Optional | 
| fields_to_update | A comma-separated list of names of the fields to update. Possible values are: description, title, includedPermissions, stage. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-project-role-update role_name="projects/xsoar-project-5/roles/test_xsoar_101" title="xsoar role update" permissions="accessapproval.requests.approve,aiplatform.artifacts.get" stage="BETA" fields_to_update="includedPermissions,title,stage"```
#### Human Readable Output
>Role projects/xsoar-project-5/roles/test_xsoar_101 updated successfully.
### gcp-iam-project-role-permission-add
***
Adds permissions to a custom project role.
#### Base Command
`gcp-iam-project-role-permission-add`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The resource name of the role. Must be in the format of projects/{PROJECT_ID}/roles/{CUSTOM_ROLE_ID}. . | Required | 
| permissions | A comma-separated list of names of the permissions to add to the role. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-project-role-permission-add role_name="projects/xsoar-project-5/roles/test_xsoar_101" permissions="accessapproval.requests.approve,aiplatform.artifacts.get"```
#### Human Readable Output
>Role projects/xsoar-project-5/roles/test_xsoar_101 updated successfully.
### gcp-iam-project-role-permission-remove
***
Removes permissions from the custom project role.
#### Base Command
`gcp-iam-project-role-permission-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The resource name of the role. Must be in the format of projects/{PROJECT_ID}/roles/{CUSTOM_ROLE_ID}. . | Required | 
| permissions | A comma-separated list of names of the permissions to remove from the role. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-project-role-permission-remove role_name="projects/xsoar-project-5/roles/test_xsoar_101" permissions="aiplatform.artifacts.get"```
#### Human Readable Output
>Role projects/xsoar-project-5/roles/test_xsoar_101 updated successfully.
### gcp-iam-project-role-list
***
Lists the project custom roles.
#### Base Command
`gcp-iam-project-role-list`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project that contains the custom role. | Required | 
| include_permissions | Indicates whether to include permissions in the response. Possible values are: True, False. Default is True. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 1,000. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| show_deleted | If true, roles that have been deleted will also be retrieved. Possible values are: False, True. Default is False. | Optional | 
| title_filter | Used to filter the retrieved roles by the rule title. The command will retrieve the rules that include the provided argument in their title. | Optional | 
| permission_filter | A comma-separated list of role permissions. Used to filter the retrieved roles by their permissions. The command will retrieve the rules that include all the provided permissions in their permissions list. If the argument is provided, the command will include the role permissions in the output. | Optional |
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The resource name of the role. | 
#### Command Example
```!gcp-iam-project-role-list project_id="xsoar-project-5" include_permissions="True" limit="2" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": [
                {
                    "deleted": false,
                    "description": "my-description-1",
                    "etag": "BwXTknaCMm0=",
                    "includedPermissions": [
                        "accessapproval.requests.approve",
                        "aiplatform.artifacts.get"
                    ],
                    "name": "projects/xsoar-project-5/roles/testRolePoc12112573",
                    "stage": "BETA",
                    "title": "xsoar role update"
                },
                {
                    "deleted": false,
                    "description": "my first role",
                    "etag": "BwXUDgTKKN0=",
                    "includedPermissions": [
                        "accessapproval.requests.approve"
                    ],
                    "name": "projects/xsoar-project-5/roles/test_xsoar_101",
                    "stage": "BETA",
                    "title": "xsoar role update"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Custom Project Roles list:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| projects/xsoar-project-5/roles/testRolePoc12112573 | accessapproval.requests.approve,<br/>aiplatform.artifacts.get | xsoar role update | my-description-1 |
>| projects/xsoar-project-5/roles/test_xsoar_101 | accessapproval.requests.approve | xsoar role update | my first role |

### gcp-iam-project-role-get
***
Retrieves a custom project role.


#### Base Command

`gcp-iam-project-role-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | A comma-separated list of project roles to retrieve. Every role name should be in the following format: projects/{PROJECT_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String |  | 


#### Command Example
```!gcp-iam-project-role-get role_name="projects/xsoar-project-5/roles/test_xsoar_101"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": {
                "deleted": false,
                "description": "my first role",
                "etag": "BwXUDfNUGpM=",
                "includedPermissions": [
                    "accessapproval.requests.approve",
                    "aiplatform.artifacts.get"
                ],
                "name": "projects/xsoar-project-5/roles/test_xsoar_101",
                "stage": "BETA",
                "title": "xsoar role update"
            }
        }
    }
}
```

#### Human Readable Output

>### Role projects/xsoar-project-5/roles/test_xsoar_101 information:
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| projects/xsoar-project-5/roles/test_xsoar_101 | accessapproval.requests.approve,<br/>aiplatform.artifacts.get | xsoar role update | my first role |

### gcp-iam-project-role-delete
***
Deletes a custom project role.


#### Base Command

`gcp-iam-project-role-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | A comma-separated list of project role to delete. Every role name should be in the following format: projects/{PROJECT_ID}/roles/{CUSTOM_ROLE_ID}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-project-role-delete role_name="projects/xsoar-project-5/roles/xsoar_demo_role_1"```
#### Human Readable Output
>Role projects/xsoar-project-5/roles/xsoar_demo_role_1 deleted successfully.
### gcp-iam-testable-permission-list
***
Lists every permission can be tested on a resource.
#### Base Command
`gcp-iam-testable-permission-list`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | The name of the resource to query from the list of testable permissions. For a project's resource, provide "projects/project-ID", and for organizations, provide "organizations/organization-ID". | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 1,000. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Permission.name | String | The name of the permissions. | 
| GCPIAM.Permission.stage | String | The current launch stage of the permission | 
#### Command Example
```!gcp-iam-testable-permission-list resource_name="organizations/xsoar-organization" limit="2"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Permission": [
                {
                    "name": "accessapproval.requests.approve",
                    "stage": "BETA"
                },
                {
                    "name": "accessapproval.requests.dismiss",
                    "stage": "BETA"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### organizations/xsoar-organization testable permissions list:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Stage|
>|---|---|
>| accessapproval.requests.approve | BETA |
>| accessapproval.requests.dismiss | BETA |

### gcp-iam-service-account-delete
***
Deletes a service account.


#### Base Command

`gcp-iam-service-account-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_name | A comma-separated list of names of service accounts to delete. Every resource name should be in the following format: projects/{PROJECT_ID}/serviceAccounts/{ACCOUNT}. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-service-account-delete service_account_name="projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com"```
#### Human Readable Output
>Service account projects/project-id-1/serviceAccounts/integration-test-15@project-name-3.iam.gserviceaccount.com deleted successfully.
### gcp-iam-grantable-role-list
***
Lists roles that can be granted on a Google Cloud resource. A role is grantable if the IAM policy for the resource can contain bindings to the role.
#### Base Command
`gcp-iam-grantable-role-list`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_name | The resource name to query from the list of grantable roles. For a project's resource, provide "projects/project-ID", and for organizations, provide "organizations/organization-ID". | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 1,000. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
#### Context Output
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The name of the role. | 
#### Command Example
```!gcp-iam-grantable-role-list resource_name="organizations/xsoar-organization" limit="2"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Roles": {
                "description": "my first role",
                "etag": "BwXUDfL1OlM=",
                "name": "organizations/xsoar-organization/roles/xsoar_demo_70",
                "title": "xsoar role 70"
            }
        }
    }
}
```

#### Human Readable Output

>### organizations/xsoar-organization grantable roles list:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Title|Description|
>|---|---|---|
>| organizations/xsoar-organization/roles/xsoar_demo_70 | xsoar role 70 | my first role |

### gcp-iam-role-get
***
Retrieves the GCP IAM predefined role information.


#### Base Command

`gcp-iam-role-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | A comma-separated list of GCP IAM predefined roles to retrieve. Every role name should be in the following format: roles/{ROLE_NAME}. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The resource name of the role. | 


#### Command Example
```!gcp-iam-role-get role_name="roles/accessapproval.viewer"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": {
                "deleted": false,
                "description": "Ability to view access approval requests and configuration",
                "etag": "AA==",
                "includedPermissions": [
                    "accessapproval.requests.get",
                    "accessapproval.requests.list",
                    "accessapproval.settings.get",
                    "resourcemanager.projects.get",
                    "resourcemanager.projects.list"
                ],
                "name": "roles/accessapproval.viewer",
                "stage": "BETA",
                "title": "Access Approval Viewer"
            }
        }
    }
}
```

#### Human Readable Output

>### Role roles/accessapproval.viewer information:
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| roles/accessapproval.viewer | accessapproval.requests.get,<br/>accessapproval.requests.list,<br/>accessapproval.settings.get,<br/>resourcemanager.projects.get,<br/>resourcemanager.projects.list | Access Approval Viewer | Ability to view access approval requests and configuration |

### gcp-iam-role-list
***
Lists the GCP IAM predefined roles.


#### Base Command

`gcp-iam-role-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_permissions | Indicates whether to include permissions in the response. Possible values are: True, False. Default is True. | Optional | 
| limit | The maximum number of results to retrieve. Minimum value is 1, maximum value is 1,000. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| show_deleted | If true, roles that have been deleted will also be retrieved. Possible values are: False, True. Default is False. | Optional | 
| title_filter | Used to filter the retrieved roles by the rule title. The command will retrieve the rules that include the provided argument in their title. | Optional | 
| permission_filter | A comma-separated list of role permissions. Used to filter the retrieved roles by their permissions. The command will retrieve the rules that include all the provided permissions in their permissions list. If the argument is provided, the command will include the role permissions in the output. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.Role.name | String | The resource name of the role. | 


#### Command Example
```!gcp-iam-role-list include_permissions="True" limit="2" page="1"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "Role": [
                {
                    "deleted": false,
                    "description": "Ability to view or act on access approval requests and view configuration",
                    "etag": "AA==",
                    "includedPermissions": [
                        "accessapproval.requests.approve",
                        "accessapproval.requests.dismiss",
                        "accessapproval.requests.get",
                        "accessapproval.requests.list",
                        "accessapproval.settings.get",
                        "resourcemanager.projects.get",
                        "resourcemanager.projects.list"
                    ],
                    "name": "roles/accessapproval.approver",
                    "stage": "BETA",
                    "title": "Access Approval Approver"
                },
                {
                    "deleted": false,
                    "description": "Ability update the Access Approval configuration",
                    "etag": "AA==",
                    "includedPermissions": [
                        "accessapproval.settings.delete",
                        "accessapproval.settings.get",
                        "accessapproval.settings.update",
                        "resourcemanager.projects.get",
                        "resourcemanager.projects.list"
                    ],
                    "name": "roles/accessapproval.configEditor",
                    "stage": "BETA",
                    "title": "Access Approval Config Editor"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### GCP IAM Predefined Roles list:
> Current page size: 2
> Showing page 1 out of others that may exist.
>|Name|Included Permissions|Title|Description|
>|---|---|---|---|
>| roles/accessapproval.approver | accessapproval.requests.approve,<br/>accessapproval.requests.dismiss,<br/>accessapproval.requests.get,<br/>accessapproval.requests.list,<br/>accessapproval.settings.get,<br/>resourcemanager.projects.get,<br/>resourcemanager.projects.list | Access Approval Approver | Ability to view or act on access approval requests and view configuration |
>| roles/accessapproval.configEditor | accessapproval.settings.delete,<br/>accessapproval.settings.get,<br/>accessapproval.settings.update,<br/>resourcemanager.projects.get,<br/>resourcemanager.projects.list | Access Approval Config Editor | Ability update the Access Approval configuration |
### gcp-iam-organization-iam-policy-remove
***
Removes a policy from the organization IAM policies.


#### Base Command

`gcp-iam-organization-iam-policy-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization for which the policy is being specified. For example, organizations/3456. | Required | 
| role | A comma-separated list of policy role names to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gcp-iam-organization-iam-policy-remove organization_name="organizations/xsoar-organization" role="organizations/xsoar-organization/roles/xsoar_demo_99"```
#### Human Readable Output
>Organization organizations/xsoar-organization IAM policies updated successfully.
### gcp-iam-folder-iam-policy-remove
***
Removes a policy from the folder IAM policies .
#### Base Command
`gcp-iam-folder-iam-policy-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folder_name | The name of the folder for which the policy is being specified. For example, folders/12342. | Required | 
| role | A comma-separated list of policy role names to remove. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-folder-iam-policy-remove folder_name="folders/folder-name-3" role="organizations/xsoar-organization/roles/xsoar_demo_99"```
#### Human Readable Output
>Folder folders/folder-name-3 IAM policies updated successfully.
### gcp-iam-project-iam-policy-remove
***
Removes a policy from the project IAM policies.
#### Base Command
`gcp-iam-project-iam-policy-remove`
#### Input
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_name | The name of the project for which the policy is being specified. For example, projects/415104041262. | Required | 
| role | A comma-separated list of policy role names to remove. | Required | 
#### Context Output
There is no context output for this command.
#### Command Example
```!gcp-iam-project-iam-policy-remove project_name="projects/project-name-3" role="roles/anthosidentityservice.serviceAgent"```
#### Human Readable Output
>Project projects/project-name-3 IAM policies updated successfully.

### gcp-iam-tagbindings-list
***
List tag bindings (key value pair) applied to a project/folder/organization object.


#### Base Command

`gcp-iam-tagbindings-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent |  The name of the resource to list tag bindings under. For example, setting this field to 'folders/1234' would list all tags directly applied to that folder. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GCPIAM.TagBindings.key | String | Tag bindings key. | 
| GCPIAM.TagBindings.value | String | Tag bindings value. | 

#### Command example
```!gcp-iam-tagbindings-list parent="//cloudresourcemanager.googleapis.com/folders/111111111111"```
#### Context Example
```json
{
    "GCP": {
        "IAM": {
            "TagBindings": {
                "key": "environment",
                "value": "non-production"
            }
        }
    }
}
```

#### Human Readable Output

>### Project projects/project-name-1 information:
>|key|value|
>|---|---|
>| environment | non-production |

### gcp-iam-service-account-generate-access-token

***
Create a short-lived access token for a service account. The generated token will be exposed to the context menu and War Room, and can potentially be logged.

#### Base Command

`gcp-iam-service-account-generate-access-token`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_account_email | The email address of the privilege-bearing service account for which the short-lived token is created. | Required | 
| lifetime | Lifetime of the Access Token in seconds. Default is 3600. | Required | 