An Integration with GitLab
This integration was integrated and tested with version v4.0 of GitLab API
## Configure GitLab Integration on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for GitLab Integration.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://gitlab.com/api/v4\) | True |
| api_key | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### gitlab-get-projects
***
Get a list of all visible projects across GitLab for the authenticated user. When accessed without authentication, only public projects with “simple” fields are returned.


#### Base Command

`gitlab-get-projects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repository_storage | Limit results to projects stored on repository_storage. Available for admins only. | Optional | 
| last_activity_before | Limit results to projects with last_activity before specified time. | Optional | 
| min_access_level | Limit by current user minimal access level. | Optional | 
| simple | Return only limited fields for each project. This is a no-op without authentication as then only simple fields are returned. | Optional | 
| sort | Return projects sorted in asc or desc order. | Optional | 
| membership | Limit by projects that the current user is a member of. | Optional | 
| search_namespaces | Include ancestor namespaces when matching search criteria. | Optional | 
| archived | Limit by archived status . | Optional | 
| search | Return list of projects matching the search criteria . | Optional | 
| id_before | Limit results to projects with IDs less than the specified ID . | Optional | 
| last_activity_after | Limit results to projects with last_activity after specified time | Optional | 
| starred | Limit by projects starred by the current user . | Optional | 
| id_after | Limit results to projects with IDs greater than the specified ID. | Optional | 
| owned | Limit by projects explicitly owned by the current user. | Optional | 
| order_by | Return projects ordered by id, name, path, created_at, updated_at, or last_activity_at fields. repository_size, storage_size, or wiki_size fields are only allowed for admins. Default is created_at. | Optional | 
| statistics | Include project statistics . | Optional | 
| visibility | Limit by visibility public, internal, or private . | Optional | 
| with_custom_attributes | Include custom attributes in response (admins only). | Optional | 
| with_issues_enabled | Limit by enabled issues feature . | Optional | 
| with_merge_requests_enabled | Limit by enabled merge requests feature. | Optional | 
| with_programming_language | Limit by projects which use the given programming language. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Projects.web_url | Unknown | Project Web URL | 
| GitLab.Projects.name | Unknown | Project Name | 
| GitLab.Projects.path | Unknown | Project Path | 
| GitLab.Projects.created_at | Unknown | Project Created At | 
| GitLab.Projects.visibility | Unknown | Project Visiblity | 
| GitLab.Projects.id | Unknown | Project ID | 


#### Command Example
```!gitlab-get-projects owned=true using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "Projects": [
            {
                "_links": {
                    "events": "https://gitlab.com/api/v4/projects/21898188/events",
                    "issues": "https://gitlab.com/api/v4/projects/21898188/issues",
                    "labels": "https://gitlab.com/api/v4/projects/21898188/labels",
                    "members": "https://gitlab.com/api/v4/projects/21898188/members",
                    "merge_requests": "https://gitlab.com/api/v4/projects/21898188/merge_requests",
                    "repo_branches": "https://gitlab.com/api/v4/projects/21898188/repository/branches",
                    "self": "https://gitlab.com/api/v4/projects/21898188"
                },
                "allow_merge_on_skipped_pipeline": null,
                "approvals_before_merge": 0,
                "archived": false,
                "auto_cancel_pending_pipelines": "enabled",
                "auto_devops_deploy_strategy": "continuous",
                "auto_devops_enabled": false,
                "autoclose_referenced_issues": true,
                "avatar_url": null,
                "build_coverage_regex": null,
                "build_timeout": 3600,
                "builds_access_level": "enabled",
                "can_create_merge_request_in": true,
                "ci_config_path": "",
                "ci_default_git_depth": 50,
                "ci_forward_deployment_enabled": true,
                "compliance_frameworks": [],
                "container_expiration_policy": {
                    "cadence": "1d",
                    "enabled": true,
                    "keep_n": 10,
                    "name_regex": null,
                    "name_regex_keep": null,
                    "next_run_at": "2020-10-21T10:49:15.236Z",
                    "older_than": "90d"
                },
                "container_registry_enabled": true,
                "created_at": "2020-10-20T10:49:15.219Z",
                "creator_id": 5773551,
                "default_branch": "master",
                "description": null,
                "emails_disabled": null,
                "empty_repo": false,
                "external_authorization_classification_label": "",
                "forking_access_level": "enabled",
                "forks_count": 0,
                "http_url_to_repo": "https://gitlab.com/test-user/moon.git",
                "id": 21898188,
                "import_status": "finished",
                "issues_access_level": "enabled",
                "issues_enabled": true,
                "jobs_enabled": true,
                "last_activity_at": "2020-10-25T11:50:47.126Z",
                "lfs_enabled": true,
                "marked_for_deletion_at": null,
                "marked_for_deletion_on": null,
                "merge_method": "merge",
                "merge_requests_access_level": "enabled",
                "merge_requests_enabled": true,
                "mirror": false,
                "name": "moon",
                "name_with_namespace": "test user / moon",
                "namespace": {
                    "avatar_url": "/uploads/-/system/user/avatar/5773551/avatar.png",
                    "full_path": "test-user",
                    "id": 7637905,
                    "kind": "user",
                    "name": "test user",
                    "parent_id": null,
                    "path": "test-user",
                    "web_url": "https://gitlab.com/test-user"
                },
                "only_allow_merge_if_all_discussions_are_resolved": false,
                "only_allow_merge_if_pipeline_succeeds": false,
                "open_issues_count": 16,
                "owner": {
                    "avatar_url": "https://assets.gitlab-static.net/uploads/-/system/user/avatar/5773551/avatar.png",
                    "id": 5773551,
                    "name": "test user",
                    "state": "active",
                    "username": "test-user",
                    "web_url": "https://gitlab.com/test-user"
                },
                "packages_enabled": true,
                "pages_access_level": "enabled",
                "path": "moon",
                "path_with_namespace": "test-user/moon",
                "permissions": {
                    "group_access": null,
                    "project_access": {
                        "access_level": 40,
                        "notification_level": 3
                    }
                },
                "printing_merge_request_link_enabled": true,
                "public_jobs": true,
                "readme_url": "https://gitlab.com/test-user/moon/-/blob/master/README.md",
                "remove_source_branch_after_merge": true,
                "repository_access_level": "enabled",
                "request_access_enabled": true,
                "resolve_outdated_diff_discussions": false,
                "service_desk_address": "incoming+test-user-moon-21898188-issue-@incoming.gitlab.com",
                "service_desk_enabled": true,
                "shared_runners_enabled": true,
                "shared_with_groups": [],
                "snippets_access_level": "enabled",
                "snippets_enabled": true,
                "ssh_url_to_repo": "git@gitlab.com:test-user/moon.git",
                "star_count": 0,
                "suggestion_commit_message": null,
                "tag_list": [],
                "visibility": "public",
                "web_url": "https://gitlab.com/test-user/moon",
                "wiki_access_level": "enabled",
                "wiki_enabled": true
            },
            {
                "_links": {
                    "events": "https://gitlab.com/api/v4/projects/18044686/events",
                    "issues": "https://gitlab.com/api/v4/projects/18044686/issues",
                    "labels": "https://gitlab.com/api/v4/projects/18044686/labels",
                    "members": "https://gitlab.com/api/v4/projects/18044686/members",
                    "merge_requests": "https://gitlab.com/api/v4/projects/18044686/merge_requests",
                    "repo_branches": "https://gitlab.com/api/v4/projects/18044686/repository/branches",
                    "self": "https://gitlab.com/api/v4/projects/18044686"
                },
                "allow_merge_on_skipped_pipeline": null,
                "approvals_before_merge": 0,
                "archived": false,
                "auto_cancel_pending_pipelines": "enabled",
                "auto_devops_deploy_strategy": "continuous",
                "auto_devops_enabled": false,
                "autoclose_referenced_issues": true,
                "avatar_url": null,
                "build_coverage_regex": null,
                "build_timeout": 3600,
                "builds_access_level": "enabled",
                "can_create_merge_request_in": true,
                "ci_config_path": null,
                "ci_default_git_depth": 0,
                "ci_forward_deployment_enabled": true,
                "compliance_frameworks": [],
                "container_expiration_policy": {
                    "cadence": "7d",
                    "enabled": true,
                    "keep_n": null,
                    "name_regex": null,
                    "name_regex_keep": null,
                    "next_run_at": "2020-10-24T01:50:06.530Z",
                    "older_than": null
                },
                "container_registry_enabled": true,
                "created_at": "2020-04-10T04:25:23.777Z",
                "creator_id": 5773551,
                "default_branch": "master",
                "description": "Python wrapper for OTRS (REST) API",
                "emails_disabled": null,
                "empty_repo": false,
                "external_authorization_classification_label": "",
                "forked_from_project": {
                    "avatar_url": null,
                    "created_at": "2016-04-25T10:01:22.538Z",
                    "default_branch": "master",
                    "description": "Python wrapper for OTRS (REST) API",
                    "forks_count": 9,
                    "http_url_to_repo": "https://gitlab.com/rhab/PyOTRS.git",
                    "id": 1112166,
                    "last_activity_at": "2020-10-20T18:46:30.547Z",
                    "name": "PyOTRS",
                    "name_with_namespace": "Robert Habermann / PyOTRS",
                    "namespace": {
                        "avatar_url": "https://secure.gravatar.com/avatar/fd996be0107aa697f0ca5753aa7b5d1f?s=80&d=identicon",
                        "full_path": "rhab",
                        "id": 599974,
                        "kind": "user",
                        "name": "Robert Habermann",
                        "parent_id": null,
                        "path": "rhab",
                        "web_url": "https://gitlab.com/rhab"
                    },
                    "path": "PyOTRS",
                    "path_with_namespace": "rhab/PyOTRS",
                    "readme_url": "https://gitlab.com/rhab/PyOTRS/-/blob/master/README.rst",
                    "ssh_url_to_repo": "git@gitlab.com:rhab/PyOTRS.git",
                    "star_count": 12,
                    "tag_list": [],
                    "web_url": "https://gitlab.com/rhab/PyOTRS"
                },
                "forking_access_level": "enabled",
                "forks_count": 0,
                "http_url_to_repo": "https://gitlab.com/test-user/PyOTRS.git",
                "id": 18044686,
                "import_status": "finished",
                "issues_access_level": "enabled",
                "issues_enabled": true,
                "jobs_enabled": true,
                "last_activity_at": "2020-04-10T04:25:23.777Z",
                "lfs_enabled": true,
                "marked_for_deletion_at": null,
                "marked_for_deletion_on": null,
                "merge_method": "merge",
                "merge_requests_access_level": "enabled",
                "merge_requests_enabled": true,
                "mirror": false,
                "name": "PyOTRS",
                "name_with_namespace": "test user / PyOTRS",
                "namespace": {
                    "avatar_url": "/uploads/-/system/user/avatar/5773551/avatar.png",
                    "full_path": "test-user",
                    "id": 7637905,
                    "kind": "user",
                    "name": "test user",
                    "parent_id": null,
                    "path": "test-user",
                    "web_url": "https://gitlab.com/test-user"
                },
                "only_allow_merge_if_all_discussions_are_resolved": false,
                "only_allow_merge_if_pipeline_succeeds": false,
                "open_issues_count": 0,
                "owner": {
                    "avatar_url": "https://assets.gitlab-static.net/uploads/-/system/user/avatar/5773551/avatar.png",
                    "id": 5773551,
                    "name": "test user",
                    "state": "active",
                    "username": "test-user",
                    "web_url": "https://gitlab.com/test-user"
                },
                "packages_enabled": true,
                "pages_access_level": "enabled",
                "path": "PyOTRS",
                "path_with_namespace": "test-user/PyOTRS",
                "permissions": {
                    "group_access": null,
                    "project_access": {
                        "access_level": 40,
                        "notification_level": 3
                    }
                },
                "printing_merge_request_link_enabled": true,
                "public_jobs": true,
                "readme_url": "https://gitlab.com/test-user/PyOTRS/-/blob/master/README.rst",
                "remove_source_branch_after_merge": true,
                "repository_access_level": "enabled",
                "request_access_enabled": true,
                "resolve_outdated_diff_discussions": false,
                "service_desk_address": "incoming+test-user-pyotrs-18044686-issue-@incoming.gitlab.com",
                "service_desk_enabled": true,
                "shared_runners_enabled": true,
                "shared_with_groups": [],
                "snippets_access_level": "enabled",
                "snippets_enabled": true,
                "ssh_url_to_repo": "git@gitlab.com:test-user/PyOTRS.git",
                "star_count": 0,
                "suggestion_commit_message": null,
                "tag_list": [],
                "visibility": "public",
                "web_url": "https://gitlab.com/test-user/PyOTRS",
                "wiki_access_level": "enabled",
                "wiki_enabled": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|_links|allow_merge_on_skipped_pipeline|approvals_before_merge|archived|auto_cancel_pending_pipelines|auto_devops_deploy_strategy|auto_devops_enabled|autoclose_referenced_issues|avatar_url|build_coverage_regex|build_timeout|builds_access_level|can_create_merge_request_in|ci_config_path|ci_default_git_depth|ci_forward_deployment_enabled|compliance_frameworks|container_expiration_policy|container_registry_enabled|created_at|creator_id|default_branch|description|emails_disabled|empty_repo|external_authorization_classification_label|forking_access_level|forks_count|http_url_to_repo|id|import_status|issues_access_level|issues_enabled|jobs_enabled|last_activity_at|lfs_enabled|marked_for_deletion_at|marked_for_deletion_on|merge_method|merge_requests_access_level|merge_requests_enabled|mirror|name|name_with_namespace|namespace|only_allow_merge_if_all_discussions_are_resolved|only_allow_merge_if_pipeline_succeeds|open_issues_count|owner|packages_enabled|pages_access_level|path|path_with_namespace|permissions|printing_merge_request_link_enabled|public_jobs|readme_url|remove_source_branch_after_merge|repository_access_level|request_access_enabled|resolve_outdated_diff_discussions|service_desk_address|service_desk_enabled|shared_runners_enabled|shared_with_groups|snippets_access_level|snippets_enabled|ssh_url_to_repo|star_count|suggestion_commit_message|tag_list|visibility|web_url|wiki_access_level|wiki_enabled|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| self: https://gitlab.com/api/v4/projects/21898188<br/>issues: https://gitlab.com/api/v4/projects/21898188/issues<br/>merge_requests: https://gitlab.com/api/v4/projects/21898188/merge_requests<br/>repo_branches: https://gitlab.com/api/v4/projects/21898188/repository/branches<br/>labels: https://gitlab.com/api/v4/projects/21898188/labels<br/>events: https://gitlab.com/api/v4/projects/21898188/events<br/>members: https://gitlab.com/api/v4/projects/21898188/members |  | 0 | false | enabled | continuous | false | true |  |  | 3600 | enabled | true |  | 50 | true |  | cadence: 1d<br/>enabled: true<br/>keep_n: 10<br/>older_than: 90d<br/>name_regex: null<br/>name_regex_keep: null<br/>next_run_at: 2020-10-21T10:49:15.236Z | true | 2020-10-20T10:49:15.219Z | 5773551 | master |  |  | false |  | enabled | 0 | https://gitlab.com/test-user/moon.git | 21898188 | finished | enabled | true | true | 2020-10-25T11:50:47.126Z | true |  |  | merge | enabled | true | false | moon | test user / moon | id: 7637905<br/>name: test user<br/>path: test-user<br/>kind: user<br/>full_path: test-user<br/>parent_id: null<br/>avatar_url: /uploads/-/system/user/avatar/5773551/avatar.png<br/>web_url: https://gitlab.com/test-user | false | false | 16 | id: 5773551<br/>name: test user<br/>username: test-user<br/>state: active<br/>avatar_url: https://assets.gitlab-static.net/uploads/-/system/user/avatar/5773551/avatar.png<br/>web_url: https://gitlab.com/test-user | true | enabled | moon | test-user/moon | project_access: {"access_level": 40, "notification_level": 3}<br/>group_access: null | true | true | https://gitlab.com/test-user/moon/-/blob/master/README.md | true | enabled | true | false | incoming+test-user-moon-21898188-issue-@incoming.gitlab.com | true | true |  | enabled | true | git@gitlab.com:test-user/moon.git | 0 |  |  | public | https://gitlab.com/test-user/moon | enabled | true |
>| self: https://gitlab.com/api/v4/projects/18044686<br/>issues: https://gitlab.com/api/v4/projects/18044686/issues<br/>merge_requests: https://gitlab.com/api/v4/projects/18044686/merge_requests<br/>repo_branches: https://gitlab.com/api/v4/projects/18044686/repository/branches<br/>labels: https://gitlab.com/api/v4/projects/18044686/labels<br/>events: https://gitlab.com/api/v4/projects/18044686/events<br/>members: https://gitlab.com/api/v4/projects/18044686/members |  | 0 | false | enabled | continuous | false | true |  |  | 3600 | enabled | true |  | 0 | true |  | cadence: 7d<br/>enabled: true<br/>keep_n: null<br/>older_than: null<br/>name_regex: null<br/>name_regex_keep: null<br/>next_run_at: 2020-10-24T01:50:06.530Z | true | 2020-04-10T04:25:23.777Z | 5773551 | master | Python wrapper for OTRS (REST) API |  | false |  | enabled | 0 | https://gitlab.com/test-user/PyOTRS.git | 18044686 | finished | enabled | true | true | 2020-04-10T04:25:23.777Z | true |  |  | merge | enabled | true | false | PyOTRS | test user / PyOTRS | id: 7637905<br/>name: test user<br/>path: test-user<br/>kind: user<br/>full_path: test-user<br/>parent_id: null<br/>avatar_url: /uploads/-/system/user/avatar/5773551/avatar.png<br/>web_url: https://gitlab.com/test-user | false | false | 0 | id: 5773551<br/>name: test user<br/>username: test-user<br/>state: active<br/>avatar_url: https://assets.gitlab-static.net/uploads/-/system/user/avatar/5773551/avatar.png<br/>web_url: https://gitlab.com/test-user | true | enabled | PyOTRS | test-user/PyOTRS | project_access: {"access_level": 40, "notification_level": 3}<br/>group_access: null | true | true | https://gitlab.com/test-user/PyOTRS/-/blob/master/README.rst | true | enabled | true | false | incoming+test-user-pyotrs-18044686-issue-@incoming.gitlab.com | true | true |  | enabled | true | git@gitlab.com:test-user/PyOTRS.git | 0 |  |  | public | https://gitlab.com/test-user/PyOTRS | enabled | true |


### gitlab-projects-get-access-requests
***
Gets a list of access requests viewable by the authenticated user.


#### Base Command

`gitlab-projects-get-access-requests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.AccessRequests.id | Unknown | Access Request ID | 
| GitLab.AccessRequests.username | Unknown | Access Request User | 
| GitLab.AccessRequests.requested_at | Unknown | Access Request Create Time | 
| GitLab.AccessRequests.state | Unknown | Access Request State | 


#### Command Example
```!gitlab-projects-get-access-requests id=21898188 using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "AccessRequests": {
            "avatar_url": "https://secure.gravatar.com/avatar/bcecfc2b23ff4a3962520685ccf046cc?s=80&d=identicon",
            "id": 7475865,
            "name": "test user",
            "requested_at": "2020-10-25T12:50:05.865Z",
            "state": "active",
            "username": "testuser",
            "web_url": "https://gitlab.com/testuser"
        }
    }
}
```

#### Human Readable Output

>### Results
>|avatar_url|id|name|requested_at|state|username|web_url|
>|---|---|---|---|---|---|---|
>| https://secure.gravatar.com/avatar/bcecfc2b23ff4a3962520685ccf046cc?s=80&d=identicon | 7475865 | test user | 2020-10-25T12:50:05.865Z | active | testuser | https://gitlab.com/testuser |


### gitlab-projects-request-access
***
Requests access for the authenticated user to a group or project.


#### Base Command

`gitlab-projects-request-access`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.AccessRequests.id | Unknown | Access Request ID | 
| GitLab.AccessRequests.username | Unknown | Access Request User | 
| GitLab.AccessRequests.requested_at | Unknown | Access Request Create Time | 
| GitLab.AccessRequests.state | Unknown | Access Request State | 


#### Command Example
```!gitlab-projects-request-access id=21898188 using=Asteroid```

#### Context Example
```json
{
    "GitLab": {
        "AccessRequests": {
            "avatar_url": "https://secure.gravatar.com/avatar/bcecfc2b23ff4a3962520685ccf046cc?s=80&d=identicon",
            "id": 7475865,
            "name": "test user",
            "requested_at": "2020-10-25T12:50:05.865Z",
            "state": "active",
            "username": "testuser",
            "web_url": "https://gitlab.com/testuser"
        }
    }
}
```

#### Human Readable Output

>### Results
>|avatar_url|id|name|requested_at|state|username|web_url|
>|---|---|---|---|---|---|---|
>| https://secure.gravatar.com/avatar/bcecfc2b23ff4a3962520685ccf046cc?s=80&d=identicon | 7475865 | test user | 2020-10-25T12:50:05.865Z | active | testuser | https://gitlab.com/testuser |


### gitlab-projects-approve-access
***
Approves an access request for the given user.


#### Base Command

`gitlab-projects-approve-access`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 
| user_id | The user ID of the access requester . | Required | 
| access_level | A valid access level (defaults: 30, developer access level)  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.AccessRequests.id | Unknown | Access Request ID | 
| GitLab.AccessRequests.username | Unknown | Access Request User | 
| GitLab.AccessRequests.requested_at | Unknown | Access Request Create Time | 
| GitLab.AccessRequests.state | Unknown | Access Request State | 


#### Command Example
``` ```

#### Human Readable Output



### gitlab-projects-deny-access
***
Denies an access request for the given user.


#### Base Command

`gitlab-projects-deny-access`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 
| user_id | The user ID of the access requester . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.AccessRequests.id | Unknown | Access Request ID | 
| GitLab.AccessRequests.state | Unknown | Access Request State | 


#### Command Example
```!gitlab-projects-deny-access id=21898188 user_id=7475865 using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "AccessRequests": {
            "id": "7475865",
            "state": "denied"
        }
    }
}
```

#### Human Readable Output

>### Results
>|id|state|
>|---|---|
>| 7475865 | denied |


### gitlab-projects-get-repository-branches
***
Get a list of repository  branches from a project, sorted by name alphabetically.


#### Base Command

`gitlab-projects-get-repository-branches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 
| search | Return list of  anches containing the search string. You can use ^term and term$ to find  anches that begin and end with term respectively. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Branches.name | Unknown | Branch Name | 
| GitLab.Branches.web_url | Unknown | Branch Web URL | 
| GitLab.Branches.commit.id | Unknown | Branch Head Commit ID | 


#### Command Example
```!gitlab-projects-get-repository-branches id=21898188 using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "Branches": [
            {
                "can_push": true,
                "commit": {
                    "author_email": "57979775+test-user@users.noreply.github.com",
                    "author_name": "test user",
                    "authored_date": "2020-09-09T05:39:00.000+00:00",
                    "committed_date": "2020-09-09T05:39:00.000+00:00",
                    "committer_email": "noreply@github.com",
                    "committer_name": "GitHub",
                    "created_at": "2020-09-09T05:39:00.000+00:00",
                    "id": "3ccb453019594b9a56ae8090663af76dcac4cc0c",
                    "message": "Create atom.py",
                    "parent_ids": null,
                    "short_id": "3ccb4530",
                    "title": "Create atom.py",
                    "web_url": "https://gitlab.com/test-user/moon/-/commit/3ccb453019594b9a56ae8090663af76dcac4cc0c"
                },
                "default": false,
                "developers_can_merge": false,
                "developers_can_push": false,
                "merged": false,
                "name": "codeql",
                "protected": false,
                "web_url": "https://gitlab.com/test-user/moon/-/tree/codeql"
            },
            {
                "can_push": true,
                "commit": {
                    "author_email": "amahmoud@paloaltonetworks.com",
                    "author_name": "test user",
                    "authored_date": "2020-09-09T14:53:17.000+00:00",
                    "committed_date": "2020-09-09T14:53:17.000+00:00",
                    "committer_email": "amahmoud@paloaltonetworks.com",
                    "committer_name": "test user",
                    "created_at": "2020-09-09T14:53:17.000+00:00",
                    "id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                    "message": "Update ReadME",
                    "parent_ids": null,
                    "short_id": "39eb3dc0",
                    "title": "Update ReadME",
                    "web_url": "https://gitlab.com/test-user/moon/-/commit/39eb3dc0c7e86d0b943df1be922b173068010bf5"
                },
                "default": true,
                "developers_can_merge": false,
                "developers_can_push": false,
                "merged": false,
                "name": "master",
                "protected": true,
                "web_url": "https://gitlab.com/test-user/moon/-/tree/master"
            },
            {
                "can_push": true,
                "commit": {
                    "author_email": "57979775+test-user@users.noreply.github.com",
                    "author_name": "test user",
                    "authored_date": "2020-09-09T05:40:27.000+00:00",
                    "committed_date": "2020-09-09T05:40:27.000+00:00",
                    "committer_email": "noreply@github.com",
                    "committer_name": "GitHub",
                    "created_at": "2020-09-09T05:40:27.000+00:00",
                    "id": "24ddc466d4736222407585a5d947b48b30265fe4",
                    "message": "Create template.yaml",
                    "parent_ids": null,
                    "short_id": "24ddc466",
                    "title": "Create template.yaml",
                    "web_url": "https://gitlab.com/test-user/moon/-/commit/24ddc466d4736222407585a5d947b48b30265fe4"
                },
                "default": false,
                "developers_can_merge": false,
                "developers_can_push": false,
                "merged": false,
                "name": "prisma",
                "protected": false,
                "web_url": "https://gitlab.com/test-user/moon/-/tree/prisma"
            },
            {
                "can_push": true,
                "commit": {
                    "author_email": "57979775+test-user@users.noreply.github.com",
                    "author_name": "test user",
                    "authored_date": "2020-09-09T05:49:46.000+00:00",
                    "committed_date": "2020-09-09T05:49:46.000+00:00",
                    "committer_email": "noreply@github.com",
                    "committer_name": "GitHub",
                    "created_at": "2020-09-09T05:49:46.000+00:00",
                    "id": "fb3f67b779ead6bff43c8a5002de516a2e8ca99b",
                    "message": "Create template.yaml",
                    "parent_ids": null,
                    "short_id": "fb3f67b7",
                    "title": "Create template.yaml",
                    "web_url": "https://gitlab.com/test-user/moon/-/commit/fb3f67b779ead6bff43c8a5002de516a2e8ca99b"
                },
                "default": false,
                "developers_can_merge": false,
                "developers_can_push": false,
                "merged": false,
                "name": "prisma-cloud",
                "protected": false,
                "web_url": "https://gitlab.com/test-user/moon/-/tree/prisma-cloud"
            },
            {
                "can_push": true,
                "commit": {
                    "author_email": "amahmoud@paloaltonetworks.com",
                    "author_name": "test user",
                    "authored_date": "2020-09-09T14:56:09.000+00:00",
                    "committed_date": "2020-09-09T14:56:09.000+00:00",
                    "committer_email": "amahmoud@paloaltonetworks.com",
                    "committer_name": "test user",
                    "created_at": "2020-09-09T14:56:09.000+00:00",
                    "id": "405fc6ea44910177f48db9b2eb6839efb4211743",
                    "message": "Test PR",
                    "parent_ids": null,
                    "short_id": "405fc6ea",
                    "title": "Test PR",
                    "web_url": "https://gitlab.com/test-user/moon/-/commit/405fc6ea44910177f48db9b2eb6839efb4211743"
                },
                "default": false,
                "developers_can_merge": false,
                "developers_can_push": false,
                "merged": false,
                "name": "vulnerable",
                "protected": false,
                "web_url": "https://gitlab.com/test-user/moon/-/tree/vulnerable"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|can_push|commit|default|developers_can_merge|developers_can_push|merged|name|protected|web_url|
>|---|---|---|---|---|---|---|---|---|
>| true | id: 3ccb453019594b9a56ae8090663af76dcac4cc0c<br/>short_id: 3ccb4530<br/>created_at: 2020-09-09T05:39:00.000+00:00<br/>parent_ids: null<br/>title: Create atom.py<br/>message: Create atom.py<br/>author_name: test user<br/>author_email: 57979775+test-user@users.noreply.github.com<br/>authored_date: 2020-09-09T05:39:00.000+00:00<br/>committer_name: GitHub<br/>committer_email: noreply@github.com<br/>committed_date: 2020-09-09T05:39:00.000+00:00<br/>web_url: https://gitlab.com/test-user/moon/-/commit/3ccb453019594b9a56ae8090663af76dcac4cc0c | false | false | false | false | codeql | false | https://gitlab.com/test-user/moon/-/tree/codeql |
>| true | id: 39eb3dc0c7e86d0b943df1be922b173068010bf5<br/>short_id: 39eb3dc0<br/>created_at: 2020-09-09T14:53:17.000+00:00<br/>parent_ids: null<br/>title: Update ReadME<br/>message: Update ReadME<br/>author_name: test user<br/>author_email: amahmoud@paloaltonetworks.com<br/>authored_date: 2020-09-09T14:53:17.000+00:00<br/>committer_name: test user<br/>committer_email: amahmoud@paloaltonetworks.com<br/>committed_date: 2020-09-09T14:53:17.000+00:00<br/>web_url: https://gitlab.com/test-user/moon/-/commit/39eb3dc0c7e86d0b943df1be922b173068010bf5 | true | false | false | false | master | true | https://gitlab.com/test-user/moon/-/tree/master |
>| true | id: 24ddc466d4736222407585a5d947b48b30265fe4<br/>short_id: 24ddc466<br/>created_at: 2020-09-09T05:40:27.000+00:00<br/>parent_ids: null<br/>title: Create template.yaml<br/>message: Create template.yaml<br/>author_name: test user<br/>author_email: 57979775+test-user@users.noreply.github.com<br/>authored_date: 2020-09-09T05:40:27.000+00:00<br/>committer_name: GitHub<br/>committer_email: noreply@github.com<br/>committed_date: 2020-09-09T05:40:27.000+00:00<br/>web_url: https://gitlab.com/test-user/moon/-/commit/24ddc466d4736222407585a5d947b48b30265fe4 | false | false | false | false | prisma | false | https://gitlab.com/test-user/moon/-/tree/prisma |
>| true | id: fb3f67b779ead6bff43c8a5002de516a2e8ca99b<br/>short_id: fb3f67b7<br/>created_at: 2020-09-09T05:49:46.000+00:00<br/>parent_ids: null<br/>title: Create template.yaml<br/>message: Create template.yaml<br/>author_name: test user<br/>author_email: 57979775+test-user@users.noreply.github.com<br/>authored_date: 2020-09-09T05:49:46.000+00:00<br/>committer_name: GitHub<br/>committer_email: noreply@github.com<br/>committed_date: 2020-09-09T05:49:46.000+00:00<br/>web_url: https://gitlab.com/test-user/moon/-/commit/fb3f67b779ead6bff43c8a5002de516a2e8ca99b | false | false | false | false | prisma-cloud | false | https://gitlab.com/test-user/moon/-/tree/prisma-cloud |
>| true | id: 405fc6ea44910177f48db9b2eb6839efb4211743<br/>short_id: 405fc6ea<br/>created_at: 2020-09-09T14:56:09.000+00:00<br/>parent_ids: null<br/>title: Test PR<br/>message: Test PR<br/>author_name: test user<br/>author_email: amahmoud@paloaltonetworks.com<br/>authored_date: 2020-09-09T14:56:09.000+00:00<br/>committer_name: test user<br/>committer_email: amahmoud@paloaltonetworks.com<br/>committed_date: 2020-09-09T14:56:09.000+00:00<br/>web_url: https://gitlab.com/test-user/moon/-/commit/405fc6ea44910177f48db9b2eb6839efb4211743 | false | false | false | false | vulnerable | false | https://gitlab.com/test-user/moon/-/tree/vulnerable |


### gitlab-projects-create-repository-branch
***
Create a new Branch in the repository.


#### Base Command

`gitlab-projects-create-repository-branch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 
| branch | Name of the  anch.  | Required | 
| ref | Branch name or commit SHA to create  anch from.  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.Branches.name | Unknown | Branch Name | 
| GitLab.Branches.web_url | Unknown | Branch Web URL | 
| GitLab.Branches.commit.id | Unknown | Branch Head Commit ID | 


#### Command Example
```!gitlab-projects-create-repository-branch branch=feature1 id=21898188 ref=master using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "Branches": {
            "can_push": true,
            "commit": {
                "author_email": "amahmoud@paloaltonetworks.com",
                "author_name": "test user",
                "authored_date": "2020-09-09T18:53:17.000+04:00",
                "committed_date": "2020-09-09T18:53:17.000+04:00",
                "committer_email": "amahmoud@paloaltonetworks.com",
                "committer_name": "test user",
                "created_at": "2020-09-09T18:53:17.000+04:00",
                "id": "39eb3dc0c7e86d0b943df1be922b173068010bf5",
                "message": "Update ReadME\n",
                "parent_ids": [
                    "b736f064314a254c5c847f042938290167598454"
                ],
                "short_id": "39eb3dc0",
                "title": "Update ReadME",
                "web_url": "https://gitlab.com/test-user/moon/-/commit/39eb3dc0c7e86d0b943df1be922b173068010bf5"
            },
            "default": false,
            "developers_can_merge": false,
            "developers_can_push": false,
            "merged": false,
            "name": "feature1",
            "protected": false,
            "web_url": "https://gitlab.com/test-user/moon/-/tree/feature1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|can_push|commit|default|developers_can_merge|developers_can_push|merged|name|protected|web_url|
>|---|---|---|---|---|---|---|---|---|
>| true | id: 39eb3dc0c7e86d0b943df1be922b173068010bf5<br/>short_id: 39eb3dc0<br/>created_at: 2020-09-09T18:53:17.000+04:00<br/>parent_ids: b736f064314a254c5c847f042938290167598454<br/>title: Update ReadME<br/>message: Update ReadME<br/><br/>author_name: test user<br/>author_email: amahmoud@paloaltonetworks.com<br/>authored_date: 2020-09-09T18:53:17.000+04:00<br/>committer_name: test user<br/>committer_email: amahmoud@paloaltonetworks.com<br/>committed_date: 2020-09-09T18:53:17.000+04:00<br/>web_url: https://gitlab.com/test-user/moon/-/commit/39eb3dc0c7e86d0b943df1be922b173068010bf5 | false | false | false | false | feature1 | false | https://gitlab.com/test-user/moon/-/tree/feature1 |


### gitlab-projects-delete-repository-branch
***
Delete a Branch from the repository.


#### Base Command

`gitlab-projects-delete-repository-branch`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 
| branch | Name of the  anch.  | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gitlab-projects-delete-repository-branch branch=feature1 id=21898188 using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "Branches": {
            "message": "Branch 'feature1' is deleted."
        }
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| Branch 'feature1' is deleted. |


### gitlab-projects-delete-repository-merged-branches
***
Will delete all branches that are merged into the project’s default  anch.


#### Base Command

`gitlab-projects-delete-repository-merged-branches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or URL-encoded path of the project owned by the authenticated user. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!gitlab-projects-delete-repository-merged-branches id=21898188 using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "message": "202 Accepted"
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| 202 Accepted |


### gitlab-get-version
***
Retrieve version information for this GitLab instance. Responds 200 OK for authenticated users.


#### Base Command

`gitlab-get-version`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GitLab.version | String | GitLab Verion | 
| GitLab.revision | String | GitLab Revision | 


#### Command Example
```!gitlab-get-version using="Moon-Integration"```

#### Context Example
```json
{
    "GitLab": {
        "revision": "18e3d7de8d5",
        "version": "13.6.0-pre"
    }
}
```

#### Human Readable Output

>### Results
>|revision|version|
>|---|---|
>| 18e3d7de8d5 | 13.6.0-pre |

