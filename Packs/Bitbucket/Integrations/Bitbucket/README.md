Bitbucket Cloud is a Git-based code and CI/CD tool optimized for teams using Jira.
This integration was integrated and tested with version 7.21.0 of Bitbucket

## Configure Bitbucket on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Bitbucket.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Workspace | True |
    | Server URL | True |
    | User Name | True |
    | App Password | True |
    | Repository | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

* Note: The test button uses the 'bitbucket-project-list' command. In order to perform it, add to the **app password**, **Read** permissions to **Projects**.  

### bitbucket-project-list
***
If a project_key is given, returns the requested project. Else, returns a list of the projects in the workspace.


#### Base Command

`bitbucket-project-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| project_key | The "id" of the project. Must be uppercase.                                                                              | Optional | 
| limit | The maximum number of projects to return. The default value is 50.                                                       | Optional | 
| page | The specific result page to display.                                                                                     | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Project.type | String | The type of the object. | 
| Bitbucket.Project.owner.display_name | String | The project owner name. | 
| Bitbucket.Project.owner.links | String | Links with information about the project owner. | 
| Bitbucket.Project.owner.type | String | The type of the project owner. | 
| Bitbucket.Project.owner.uuid | String | The project owner universal unique ID. | 
| Bitbucket.Project.owner.account_id | String | The project owner account ID. | 
| Bitbucket.Project.owner.nickname | String | The project owner nickname. | 
| Bitbucket.Project.workspace.type | String | The type of the workspace. | 
| Bitbucket.Project.workspace.uuid | String | The project workspace universal unique ID. | 
| Bitbucket.Project.workspace.name | String | The name of the project workspace. | 
| Bitbucket.Project.workspace.slug | String | The slug of the project workspace. | 
| Bitbucket.Project.workspace.links | String | Links to information about the workspace. | 
| Bitbucket.Project.key | String | The project key. | 
| Bitbucket.Project.uuid | String | The project universal unique ID. | 
| Bitbucket.Project.is_private | Boolean | Whether the project is private. | 
| Bitbucket.Project.name | String | The project name. | 
| Bitbucket.Project.description | String | The project description. | 
| Bitbucket.Project.links | String | Links to information about the project. | 
| Bitbucket.Project.created_on | String | The date the project was created. | 
| Bitbucket.Project.updated_on | String | The date the project was updated. | 
| Bitbucket.Project.has_publicly_visible_repos | Boolean | Whether the project has publicly visible repositories. | 

#### Command example
```!bitbucket-project-list```
#### Context Example
```json
{
    "Bitbucket": {
        "Project": [
            {
                "created_on": "2022-08-24T09:25:07.11111111+00:00",
                "description": "description",
                "has_publicly_visible_repos": false,
                "is_private": true,
                "key": "AP",
                "links": {
                    "avatar": {
                        "href": "https://bitbucket.org/account/user/workspace/projects/AP/avatar/11?ts=111111111"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/workspace/projects/AP"
                    },
                    "repositories": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace?q=project.key=\"AP\""
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/workspace/projects/AP"
                    }
                },
                "name": "Another Project",
                "owner": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Display Name",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/avatar-management--avatars.us-west-2.prod.public.atl-paas.net1111.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users"
                        }
                    },
                    "nickname": "Nickname",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "type": "project",
                "updated_on": "2022-08-24T09:25:07.11111111+00:00",
                "uuid": "{11111111-1111-1111-1111-111111111111}",
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/workspace/avatar/?ts=11111111"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/workspace"
                        }
                    },
                    "name": "Name",
                    "slug": "name",
                    "type": "workspace",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            {
                "created_on": "2022-08-21T13:19:18.1111111+00:00",
                "description": null,
                "has_publicly_visible_repos": false,
                "is_private": false,
                "key": "TES",
                "links": {
                    "avatar": {
                        "href": "https://bitbucket.org/account/user/workspace/projects/TES/avatar/11?ts=11111111"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/workspace/projects/TES"
                    },
                    "repositories": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace?q=project.key=\"TES\""
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/workspace/projects/TES"
                    }
                },
                "name": "testId",
                "owner": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Display Name",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/1111111111111?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net1111.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%11111111-1111-1111-1111-11111111111%11"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/"
                        }
                    },
                    "nickname": "nickname",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "type": "project",
                "updated_on": "2022-08-21T13:19:18.111111+00:00",
                "uuid": "{11111111-1111-1111-1111-111111111111}",
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/workspace/avatar/?ts=11111111"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/workspace"
                        }
                    },
                    "name": "Name",
                    "slug": "name",
                    "type": "workspace",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List of projects in workspace
>|Key|Name|Description|IsPrivate|
>|---|---|---|---|
>| AP | Another Project | description | true |
>| TES | testId |  | false |


### bitbucket-open-branch-list
***
Returns a list of the open branches.


#### Base Command

`bitbucket-open-branch-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| limit | The maximum number of items in the list. The default value is 50.                                                        | Optional | 
| page | The specific result page to display.                                                                                     | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Branch.name | String | The branch name. | 
| Bitbucket.Branch.target.type | String | The type of the last action in the branch. | 
| Bitbucket.Branch.target.hash | String | The hash of the last action in the branch. | 
| Bitbucket.Branch.target.date | Date | The creation date of the last action in the branch. | 
| Bitbucket.Branch.target.author.type | String | The type of the author of the last action. | 
| Bitbucket.Branch.target.author.raw | String | The raw information about the author of the last action. | 
| Bitbucket.Branch.target.author.user.display_name | String | The display name of the author of the last action. | 
| Bitbucket.Branch.target.author.user.links | String | Links to information about the user. | 
| Bitbucket.Branch.target.author.user.type | String | The user type of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.author.user.uuid | String | The unique user ID of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.author.user.account_id | String | The account ID of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.author.user.nickname | String | The nickname of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.message | String | The message assigned to the last action in the branch. | 
| Bitbucket.Branch.target.links | String | The links associated with this command. | 
| Bitbucket.Branch.target.parents.type | String | The type of the parent who created the branch. | 
| Bitbucket.Branch.target.parents.hash | String | The hash of the parent who created the branch. | 
| Bitbucket.Branch.target.parents.links | String | The links associated with the parents of the command. | 
| Bitbucket.Branch.target.repository.type | String | The repository type. | 
| Bitbucket.Branch.target.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Branch.target.repository.links | String | Links with information about the relevant repository. | 
| Bitbucket.Branch.target.repository.name | String | The name of the repository | 
| Bitbucket.Branch.target.repository.uuid | String | The repository unique ID. | 
| Bitbucket.Branch.links | String | Links with information about the branch. | 
| Bitbucket.Branch.type | String | The type of the branch. | 
| Bitbucket.Branch.merge_strategies | String | The merge strategy of the branch. | 
| Bitbucket.Branch.default_merge_strategy | String | The default merge strategy in the branch. | 

#### Command example
```!bitbucket-open-branch-list```
#### Context Example
```json
{
    "Bitbucket": {
        "Branch": [
            {
                "default_merge_strategy": "merge_commit",
                "links": {
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspae/start_repo/commits/master"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/branch/master"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/refs/branches/master"
                    }
                },
                "merge_strategies": [
                    "merge_commit",
                    "squash",
                    "fast_forward"
                ],
                "name": "master",
                "target": {
                    "author": {
                        "raw": "Some User <someuser@gmail.com>",
                        "type": "author",
                        "user": {
                            "account_id": "11111111111111111",
                            "display_name": "Some User",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%1111%.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/111111111/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/11111111111"
                                }
                            },
                            "nickname": "nickname",
                            "type": "user",
                            "uuid": "{11111111-1111-1111-1111-111111111111}"
                        }
                    },
                    "date": "2022-09-18T08:00:00+00:00",
                    "hash": "1111111111111111111111111111111111111111",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/1111111111111111111111111111111111111111"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                        },
                        "patch": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/patch/1111111111111111111111111111111111111111"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/statuses"
                        }
                    },
                    "message": "delete the new file",
                    "parents": [
                        {
                            "hash": "1111111111111111111111111111111111111111",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%11111111-1111-1111-1111-11111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    },
                    "type": "commit"
                },
                "type": "branch"
            },
            {
                "default_merge_strategy": "merge_commit",
                "links": {
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commits/branch"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/branch/branch"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/refs/branches/branch"
                    }
                },
                "merge_strategies": [
                    "merge_commit",
                    "squash",
                    "fast_forward"
                ],
                "name": "branch",
                "target": {
                    "author": {
                        "raw": "Some User <someuser@gmail.com>",
                        "type": "author",
                        "user": {
                            "account_id": "1111111111111111111111",
                            "display_name": "Display Name",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/avatar-management--avatars.us-west-2.prod.public.atl-paas.net%1Finitials%1111-1.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/%11111111111%11/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/%11111111-1111-1111-1111-111111111%11"
                                }
                            },
                            "nickname": "nickname",
                            "type": "user",
                            "uuid": "{11111111-1111-1111-1111-111111111111}"
                        }
                    },
                    "date": "2022-09-08T00:00:00+00:00",
                    "hash": "1111111111111111111111111111111111111111",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/1111111111111111111111111111111111111111"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                        },
                        "patch": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/patch/1111111111111111111111111111111111111111"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/statuses"
                        }
                    },
                    "message": "something",
                    "parents": [
                        {
                            "hash": "1111111111111111111111111111111111111111",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%111111111-1111-1111-1111-1111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    },
                    "type": "commit"
                },
                "type": "branch"
            }
        ]
    }
}
```

#### Human Readable Output

>### Open Branches
>|Name|LastCommitCreatedBy|LastCommitCreatedAt|LastCommitHash|
>|---|---|---|---|
>| master | Some User | 2022-09-18T08:00:00+00:00 | 1111111111111111111111111111111111111111 |
>| branch | Some User | 2022-09-08T14:00:00+00:00 | 1111111111111111111111111111111111111111 |


### bitbucket-branch-get
***
Returns the information of the requested branch.


#### Base Command

`bitbucket-branch-get`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name. Should be given here or in the instance arguments.                                                  | Optional | 
| branch_name | The name of the branch for which to retrieve the information.                                                            | Required |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Branch.name | String | The name of the branch. | 
| Bitbucket.Branch.target.type | String | The last action type. | 
| Bitbucket.Branch.target.hash | String | The hash of the last action in the branch. | 
| Bitbucket.Branch.target.date | Date | The date of the last action in the branch. | 
| Bitbucket.Branch.target.author.type | String | The type of the author. | 
| Bitbucket.Branch.target.author.raw | String | The raw information about the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.display_name | String | The display name of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.links | String | Links about the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.type | String | The user type of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.uuid | String | The unique universal ID of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.account_id | String | The account ID of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.nickname | String | The nickname of the author of the last action in the branch. | 
| Bitbucket.Branch.target.message | String | The message associated with the last action in the branch. | 
| Bitbucket.Branch.target.links | String | The links of the last action in the branch. | 
| Bitbucket.Branch.target.parents.type | String | The type of the parents of the last action in the branch. | 
| Bitbucket.Branch.target.parents.hash | String | The hash of the parents of the last action in the branch. | 
| Bitbucket.Branch.target.parents.links | String | The link associated with the parents of the last action in the branch. | 
| Bitbucket.Branch.target.repository.type | String | The type of the branch repository. | 
| Bitbucket.Branch.target.repository.full_name | String | The name of the branch repository. | 
| Bitbucket.Branch.target.repository.links | String | Links with information about the branch repository. | 
| Bitbucket.Branch.target.repository.name | String | The name of the repository. | 
| Bitbucket.Branch.target.repository.uuid | String | The unique ID of the repository. | 
| Bitbucket.Branch.links | String | Links with information about the branch. | 
| Bitbucket.Branch.type | String | The type of the branch. | 
| Bitbucket.Branch.merge_strategies | String | The merge strategy of the branch. | 
| Bitbucket.Branch.default_merge_strategy | String | The default merge strategy. | 

#### Command example
```!bitbucket-branch-get branch_name=master```
#### Context Example
```json
{
    "Bitbucket": {
        "Branch": {
            "default_merge_strategy": "merge_commit",
            "links": {
                "commits": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commits/master"
                },
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/branch/master"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/refs/branches/master"
                }
            },
            "merge_strategies": [
                "merge_commit",
                "squash",
                "fast_forward"
            ],
            "name": "master",
            "target": {
                "author": {
                    "raw": "Some user <someuser@gmail.com>",
                    "type": "author",
                    "user": {
                        "account_id": "1111111111111111111111",
                        "display_name": "Display Name",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%11initials%1111-1.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%11111111-1111-1111-1111-11111111111%11/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%11111111-1111-1111-1111-11111111111%11"
                            }
                        },
                        "nickname": "nickname",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "date": "2022-09-18T00:00:00+00:00",
                "hash": "1111111111111111111111111111111111111111",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/1111111111111111111111111111111111111111"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/patch/1111111111111111111111111111111111111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/statuses"
                    }
                },
                "message": "delete the new file",
                "parents": [
                    {
                        "hash": "1111111111111111111111111111111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%11111111-1111-1111-1111-11111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "type": "commit"
            },
            "type": "branch"
        }
    }
}
```

#### Human Readable Output

>### Information about the branch: master
>|Name|LastCommitCreatedAt|LastCommitHash|
>|---|---|---|
>| master | Some User | 2022-09-18T08:07:00+00:00 | 1111111111111111111111111111111111111111 |


### bitbucket-branch-create
***
Creates a new branch in Bitbucket.


#### Base Command

`bitbucket-branch-create`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| name | The name of the new branch.                                                                                              | Required | 
| target_branch | The name of the branch from which the new branch will be created.                                                        | Required |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Branch.name | String | The name of the new branch. | 
| Bitbucket.Branch.target.type | String | The type of the last action in the target branch. | 
| Bitbucket.Branch.target.hash | String | The hash of the last action in the target branch. | 
| Bitbucket.Branch.target.date | Date | The date of the last action in the target branch. | 
| Bitbucket.Branch.target.author.type | String | The type of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.raw | String | The raw information about the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.display_name | String | The display name of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.links | String | The links with the information about the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.type | String | The user type of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.uuid | String | The unique ID of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.account_id | String | The account ID of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.nickname | String | The nickname of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.message | String | The message in the last action in the target branch. | 
| Bitbucket.Branch.target.links | String | The links with the information about the target branch. | 
| Bitbucket.Branch.target.parents.type | String | The type of the parent action of the last action in the target branch. | 
| Bitbucket.Branch.target.parents.hash | String | The hash of the parent action of the last action in the target branch. | 
| Bitbucket.Branch.target.parents.links | String | The links associated with the parents of the command. | 
| Bitbucket.Branch.target.repository.type | String | The type of the repository of the target branch. | 
| Bitbucket.Branch.target.repository.full_name | String | The full name of the repository of the target branch. | 
| Bitbucket.Branch.target.repository.links | String | The links with the information about the repository of the target branch. | 
| Bitbucket.Branch.target.repository.name | String | The name of the repository of the target branch. | 
| Bitbucket.Branch.target.repository.uuid | String | The unique ID of the repository of the target branch. | 
| Bitbucket.Branch.links | String | The links with the information about the new branch. | 
| Bitbucket.Branch.type | String | The type of the new branch. | 
| Bitbucket.Branch.merge_strategies | String | The merge strategies of the new branch. | 
| Bitbucket.Branch.default_merge_strategy | String | The default merge strategy in the new branch. | 

#### Command example
```!bitbucket-branch-create name=testing target_branch=master```
#### Context Example
```json
{
    "Bitbucket": {
        "Branch": {
            "default_merge_strategy": "merge_commit",
            "links": {
                "commits": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commits/testing"
                },
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/branch/testing"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/refs/branches/testing"
                }
            },
            "merge_strategies": [
                "merge_commit",
                "squash",
                "fast_forward"
            ],
            "name": "testing",
            "target": {
                "author": {
                    "raw": "Some User <someuser@gmail.com>",
                    "type": "author",
                    "user": {
                        "account_id": "1111111111111111111111",
                        "display_name": "Some user",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/?d=https1avatar-management--avatars.us-west-2.prod.public.atl-paas.net%initials%1111-1.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%11111111-1111-1111-1111-111111111111%11/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%11111111-1111-1111-1111-1111111111%11"
                            }
                        },
                        "nickname": "Some User",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "date": "2022-09-18T08:00:00+00:00",
                "hash": "1111111111111111111111111111111111111111",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/1111111111111111111111111111111111111111"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/patch/1111111111111111111111111111111111111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/statuses"
                    }
                },
                "message": "delete the new file",
                "parents": [
                    {
                        "hash": "1111111111111111111111111111111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "type": "commit"
            },
            "type": "branch"
        }
    }
}
```

#### Human Readable Output

>The branch "testing" was created successfully.

### bitbucket-branch-delete
***
Deletes the given branch from Bitbucket.


#### Base Command

`bitbucket-branch-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| branch_name | The name of the branch to delete. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!bitbucket-branch-delete branch_name=testing```
#### Human Readable Output

>The branch testing was deleted successfully.

### bitbucket-commit-create
***
Creates a new commit in Bitbucket.


#### Base Command

`bitbucket-commit-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| message | Commit a message with the file. | Required | 
| branch | This branch will be associated with the committed file. | Required | 
| file_name | The name of the file to commit. | Optional | 
| file_content | The content of the file to commit. | Optional | 
| entry_id | The entry_id of the file to commit. This is the EntryId from uploading a file to the War Room. | Optional | 
| author_name | The name of the author of the file. | Optional | 
| author_email | The email of the author of the file. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!bitbucket-commit-create branch=master message="checking master" file_name="new_file.txt" file_content="some new content"```
#### Human Readable Output

>The commit was created successfully.

### bitbucket-commit-list
***
Returns a list of the commit in accordance with the included and excluded branches.


#### Base Command

`bitbucket-commit-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| file_path | Will limit the results to commits that affect that path.                                                                 | Optional | 
| excluded_branches | A comma-separated list of branches to exclude from the commits that are returned.                                        | Optional | 
| included_branches | A comma-separated list of branches to include in the commits that are returned.                                          | Optional | 
| limit | The maximum number of items in the list. The default value is 50.                                                        | Optional | 
| page | The specific result page to display.                                                                                     | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Commit.type | String | The type of the commit. | 
| Bitbucket.Commit.hash | String | The commit hash. | 
| Bitbucket.Commit.date | Date | The creation date of the commit. | 
| Bitbucket.Commit.author.type | String | The type of the author. | 
| Bitbucket.Commit.author.raw | String | The raw information about the author, including the display name and user email. | 
| Bitbucket.Commit.author.user.display_name | String | The display name of the author. | 
| Bitbucket.Commit.author.user.links | String | Links with information about the author. | 
| Bitbucket.Commit.author.user.type | String | The user type of the author. | 
| Bitbucket.Commit.author.user.uuid | String | The user unique key of the author. | 
| Bitbucket.Commit.author.user.account_id | String | The user account ID of the author. | 
| Bitbucket.Commit.author.user.nickname | String | The user nickname of the author. | 
| Bitbucket.Commit.message | String | The commit message. | 
| Bitbucket.Commit.summary.type | String | The type of the summary. | 
| Bitbucket.Commit.summary.raw | String | The raw summary of the commit. | 
| Bitbucket.Commit.summary.markup | String | The text styling type, such as markdown. | 
| Bitbucket.Commit.summary.html | String | The summary in HTML format. | 
| Bitbucket.Commit.links | String | Links with information about the commit. | 
| Bitbucket.Commit.parents.type | String | The type of the commit parents. | 
| Bitbucket.Commit.parents.hash | String | The hash of the commit parents. | 
| Bitbucket.Commit.parents.links | String | Links with information about the parents. | 
| Bitbucket.Commit.repository.type | String | The type of the repository. | 
| Bitbucket.Commit.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Commit.repository.links.self.href | String | Links with information about the repository. | 
| Bitbucket.Commit.repository.name | String | The name of the repository. | 
| Bitbucket.Commit.repository.uuid | String | The unique ID of the repository. | 

#### Command example
```!bitbucket-commit-list limit=2```
#### Context Example
```json
{
    "Bitbucket": {
        "Commit": [
            {
                "author": {
                    "raw": "Some User <someuser@gmail.com>",
                    "type": "author",
                    "user": {
                        "account_id": "111111111111",
                        "display_name": "Display Name",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/111111111111111111111111111?d=httpsFavatar-management--avatars.us-west-2.prod.public.atl-paas.net%initials%1111-1.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%11111111-1111-1111-1111-111111111111%11/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%11111111-1111-1111-1111-111111111111%11"
                            }
                        },
                        "nickname": "nickname",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "date": "2022-09-18T08:00:00+00:00",
                "hash": "1111111111111111111111111111111111111111",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/1111111111111111111111111111111111111111"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/patch/1111111111111111111111111111111111111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/statuses"
                    }
                },
                "message": "checking master",
                "parents": [
                    {
                        "hash": "1111111111111111111111111111111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>checking master</p>",
                        "markup": "markdown",
                        "raw": "checking master",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-1111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "summary": {
                    "html": "<p>checking master</p>",
                    "markup": "markdown",
                    "raw": "checking master",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Some User <someuser@gmail.com>",
                    "type": "author",
                    "user": {
                        "account_id": "111111111111111111111111",
                        "display_name": "Some User",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/?d=httpsFavatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%1111-1.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%%11/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%%11"
                            }
                        },
                        "nickname": "Some User",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "date": "2022-09-18T08:07:38+00:00",
                "hash": "1111111111111111111111111111111111111111",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/1111111111111111111111111111111111111111"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/patch/1111111111111111111111111111111111111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111/statuses"
                    }
                },
                "message": "delete the new file",
                "parents": [
                    {
                        "hash": "1111111111111111111111111111111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/1111111111111111111111111111111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/1111111111111111111111111111111111111111"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete the new file</p>",
                        "markup": "markdown",
                        "raw": "delete the new file",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "summary": {
                    "html": "<p>delete the new file</p>",
                    "markup": "markdown",
                    "raw": "delete the new file",
                    "type": "rendered"
                },
                "type": "commit"
            }
        ]
    }
}
```

#### Human Readable Output

>### The list of commits
>|Author|Commit|Message|CreatedAt|
>|---|---|---|---|
>| Some User <someuser@gmail.com> | 1111111111111111111111111111111111111111 | checking master | 2022-09-18T08:56:51+00:00 |
>| Some User <someuser@gmail.com> | 1111111111111111111111111111111111111111 | delete the new file | 2022-09-18T08:07:38+00:00 |


### bitbucket-file-delete
***
Deletes the given file from Bitbucket.


#### Base Command

`bitbucket-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| message | Commit a message with the file. | Required | 
| branch | The branch of the file to delete. | Required | 
| file_name | The name of the file to delete. | Required | 
| author_name | The name of the author of the file. | Optional | 
| author_email | The email of the author of the file. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!bitbucket-file-delete branch=master file_name=new_file.txt message="delete the new file"```
#### Human Readable Output

>The file was deleted successfully.

### bitbucket-raw-file-get
***
Returns the content of the given file, along with the option to download it.


#### Base Command

`bitbucket-raw-file-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| file_path | The path of the needed file. | Required | 
| branch | The branch of the file. If a branch isn't given, by default the command will return the content of the last edited file with the same file_path. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.RawFile.file_path | String | The path of the file. | 
| Bitbucket.RawFile.file_content | String | The content of the file. | 
| InfoFile.Size | Number | The size of the file. |
| InfoFile.Name | String | The name of the file. | 
| InfoFile.EntryID | String | The entry ID of the file. | 
| InfoFile.Info | String | File information. | 
| InfoFile.Type | String | The file type. |

#### Command example
```!bitbucket-raw-file-get file_path=new.txt branch=branch```
#### Context Example
```json
{
    "Bitbucket": {
        "RawFile": {
            "file_content":"Hi I am a new file.",
            "file_path": "new.txt"
        }
    },
    "File": {
        "EntryID": "111111111111-1111-1111-1111-111111111111",
        "Extension": "txt",
        "Info": "txt",
        "MD5": "11111111111111111111111111111111",
        "Name": "new.txt",
        "SHA1": "1111111111111111111111111111111111111111",
        "SHA256": "111111111111111111111111111111111111111111111111111111111111111111",
        "SHA512": "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "SSDeep": "11:1111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        "Size": 19,
        "Type": "text/plain; charset=utf-8"
    }
}
```

#### Human Readable Output

>The content of the file "new.txt" is: Hi I am a new file.

### bitbucket-issue-create
***
Creates an issue in Bitbucket.

##### Required Permissions
In order to perform this command, please create an issue tracker by clicking on the relevant repo -> Repository settings -> Issue tracker

#### Base Command

`bitbucket-issue-create`
#### Input

| **Argument Name** | **Description**                                                                                                                                       | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                                                          | Optional | 
| title | The title of the new issue.                                                                                                                           | Required | 
| state | The state of the issues to create. Possible values are: new, open, resolved, on hold, invalid, duplicate, wontfix, closed. Default is new.            | Optional | 
| type | The type of the issues to create. Possible values are: bug, enhancement, proposal, task. Default is bug.                                              | Optional | 
| priority | The priority of the issues to create. Possible values are: trivial, minor, major, critical, blocker. Default is major.                                | Optional | 
| content | The content of the issue to create.                                                                                                                   | Optional | 
| assignee_id | The ID of the assignee of the issue to create. To get the assignee_id, use the !bitbucket-workspace-member-list command, and use the field AccountId. | Optional | 
| assignee_user_name | The user name of the assignee of the issue to create.                                                                                                 | Optional |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true.                              | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Issue.type | String | The action type. | 
| Bitbucket.Issue.id | Number | The ID of the issue. | 
| Bitbucket.Issue.repository.type | String | The type of the repository. | 
| Bitbucket.Issue.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Issue.repository.links | String | Links with information about the repository related to the issue. | 
| Bitbucket.Issue.repository.name | String | The name of the repository. | 
| Bitbucket.Issue.repository.uuid | String | The unique ID of the repository. | 
| Bitbucket.Issue.links.self.href | String | An API link to the issue. | 
| Bitbucket.Issue.title | String | The title of the issue | 
| Bitbucket.Issue.content.type | String | The type of the content. | 
| Bitbucket.Issue.content.raw | String | The content of the issue. | 
| Bitbucket.Issue.content.markup | String | The type of markup \(like markdown\). | 
| Bitbucket.Issue.content.html | String | The content of the issue in HTML format. | 
| Bitbucket.Issue.reporter.display_name | String | The display name of the reporter of the issue. | 
| Bitbucket.Issue.reporter.links | String | Links with information about the reporter. | 
| Bitbucket.Issue.reporter.type | String | The type of the reporter. | 
| Bitbucket.Issue.reporter.uuid | String | The unique ID of the reporter | 
| Bitbucket.Issue.reporter.account_id | String | The account ID of the reporter. | 
| Bitbucket.Issue.reporter.nickname | String | The nickname of the reporter. | 
| Bitbucket.Issue.assignee.display_name | String | The display name of the assignee to the issue. | 
| Bitbucket.Issue.assignee.links | String | Links with information about the assignee. | 
| Bitbucket.Issue.assignee.type | String | The type of the assignee. | 
| Bitbucket.Issue.assignee.uuid | String | The unique ID of the assignee. | 
| Bitbucket.Issue.assignee.account_id | String | The account ID of the assignee. | 
| Bitbucket.Issue.assignee.nickname | String | The nickname of the assignee. | 
| Bitbucket.Issue.created_on | String | The creation date of the issue. | 
| Bitbucket.Issue.edited_on | Unknown | The edit date of the issue. | 
| Bitbucket.Issue.updated_on | String | The update date of the issue. | 
| Bitbucket.Issue.state | String | The state of the issue. | 
| Bitbucket.Issue.kind | String | The kind of the issue. | 
| Bitbucket.Issue.milestone | Unknown | The milestones in the issue. | 
| Bitbucket.Issue.component | Unknown | The different components of the issue. | 
| Bitbucket.Issue.priority | String | The priority of the issue. | 
| Bitbucket.Issue.version | Unknown | The version of the issue. | 
| Bitbucket.Issue.votes | Number | The votes of approval of the issue. | 
| Bitbucket.Issue.watches | Unknown | The watchers of the issue. | 

#### Command example
```!bitbucket-issue-create title="a new issue"```
#### Context Example
```json
{
    "Bitbucket": {
        "Issue": {
            "assignee": null,
            "component": null,
            "content": {
                "html": "",
                "markup": "markdown",
                "raw": "",
                "type": "rendered"
            },
            "created_on": "2022-09-18T08:00:00.000000+00:00",
            "edited_on": null,
            "id": 92,
            "kind": "bug",
            "links": {
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/92"
                }
            },
            "milestone": null,
            "priority": "major",
            "reporter": {
                "account_id": "111111111111111111111111",
                "display_name": "Some User",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%1111-1.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                    }
                },
                "nickname": "Some User",
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            },
            "repository": {
                "full_name": "workspace/start_repo",
                "links": {
                    "avatar": {
                        "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                    }
                },
                "name": "start_repo",
                "type": "repository",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            },
            "state": "new",
            "title": "a new issue",
            "type": "issue",
            "updated_on": "2022-09-18T08:00:00.000000+00:00",
            "version": null,
            "votes": 0,
            "watches": null
        }
    }
}
```

#### Human Readable Output

>The issue "a new issue" was created successfully

### bitbucket-issue-list
***
If an issue_id is given, returns the information about it. Otherwise, returns a list of all the issues, according to the limit parameter.


#### Base Command

`bitbucket-issue-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| issue_id | The ID of the requested issue. To get the issue_id, use the !bitbucket-issue-list command.                               | Optional | 
| limit | The maximum number of items in the list. The default value is 50.                                                        | Optional | 
| page | The specific result page to display.                                                                                     | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Issue.type | String | The action type. | 
| Bitbucket.Issue.id | Number | The ID of the issue. | 
| Bitbucket.Issue.repository.type | String | The type of the repository. | 
| Bitbucket.Issue.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Issue.repository.links | String | Links with information about the repository related to the issue. | 
| Bitbucket.Issue.repository.name | String | The name of the repository. | 
| Bitbucket.Issue.repository.uuid | String | The unique ID of the repository. | 
| Bitbucket.Issue.links | String | Links with information about the issue. | 
| Bitbucket.Issue.title | String | The title of the issue. | 
| Bitbucket.Issue.content.type | String | The type of the content. | 
| Bitbucket.Issue.content.raw | String | The content of the issue. | 
| Bitbucket.Issue.content.markup | String | The type of markup \(like markdown\). | 
| Bitbucket.Issue.content.html | String | The content of the issue in HTML format. | 
| Bitbucket.Issue.reporter.display_name | String | The display name of the reporter of the issue. | 
| Bitbucket.Issue.reporter.links | String | Links with information about the reporter. | 
| Bitbucket.Issue.reporter.type | String | The type of the reporter. | 
| Bitbucket.Issue.reporter.uuid | String | The unique ID of the reporter | 
| Bitbucket.Issue.reporter.account_id | String | The account ID of the reporter. | 
| Bitbucket.Issue.reporter.nickname | String | The nickname of the reporter. | 
| Bitbucket.Issue.assignee.display_name | String | The display name of the assignee to the issue. | 
| Bitbucket.Issue.assignee.links | String | Links with information about the assignee. | 
| Bitbucket.Issue.assignee.type | String | The type of the assignee. | 
| Bitbucket.Issue.assignee.uuid | String | The unique ID of the assignee. | 
| Bitbucket.Issue.assignee.account_id | String | The account ID of the assignee. | 
| Bitbucket.Issue.assignee.nickname | String | The nickname of the assignee. | 
| Bitbucket.Issue.created_on | String | The creation date of the issue. | 
| Bitbucket.Issue.edited_on | Unknown | The edit date of the issue. | 
| Bitbucket.Issue.updated_on | String | The update date of the issue. | 
| Bitbucket.Issue.state | String | The state ID of the issue. | 
| Bitbucket.Issue.kind | String | The kind of the issue. | 
| Bitbucket.Issue.milestone | Unknown | The milestones in the issue. | 
| Bitbucket.Issue.component | Unknown | The different components of the issue. | 
| Bitbucket.Issue.priority | String | The priority of the issue. | 
| Bitbucket.Issue.version | Unknown | The version of the issue. | 
| Bitbucket.Issue.votes | Number | The votes of approval of the issue. | 
| Bitbucket.Issue.watches | Number | The watchers of the issue. | 

#### Command example
```!bitbucket-issue-list limit=2```
#### Context Example
```json
{
    "Bitbucket": {
        "Issue": [
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "",
                    "markup": "markdown",
                    "raw": "",
                    "type": "rendered"
                },
                "created_on": "2022-09-18T08:00:00.000000+00:00",
                "edited_on": null,
                "id": 92,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/92/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/92/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/issues/92/a-new-issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/92"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/92/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/92/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%1Finitials%1111-1.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "state": "new",
                "title": "a new issue",
                "type": "issue",
                "updated_on": "2022-09-18T08:57:05.560996+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "",
                    "markup": "markdown",
                    "raw": "",
                    "type": "rendered"
                },
                "created_on": "2022-09-18T08:00:00.000000+00:00",
                "edited_on": null,
                "id": 91,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/issues/91/a-new-issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%initials%1111-1.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "state": "resolved",
                "title": "a new issue",
                "type": "issue",
                "updated_on": "2022-09-18T08:00:00.000000+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Issues List
>|Id|Title|Type|Priority|Status|Votes|CreatedAt|UpdatedAt|
>|---|---|---|---|---|---|---|---|
>| 92 | a new issue | bug | major | new | 0 | 2022-09-18T08:00:00.000000+00:00 | 2022-09-18T08:00:00.000000+00:00 |
>| 91 | a new issue | bug | major | resolved | 0 | 2022-09-18T08:00:00.000000+00:00 | 2022-09-18T08:00:00.000000+00:00 |


### bitbucket-issue-update
***
Updates an issue in Bitbucket.

##### Required Permissions
In order to perform this command, please create an issue tracker by clicking on the relevant repo -> Repository settings -> Issue tracker.

#### Base Command

`bitbucket-issue-update`
#### Input

| **Argument Name** | **Description**                                                                                                                                       | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                                                          | Optional | 
| title | The title of the new issue.                                                                                                                           | Required | 
| issue_id | The ID of the issue to update. To get the issue_id, use the !bitbucket-issue-list command.                                                            | Required | 
| state | The state of the issues to create. Possible values are: new, open, resolved, on hold, invalid, duplicate, wontfix, closed.                            | Optional | 
| type | The type of the issues to create. Possible values are: bug, enhancement, proposal, task.                                                              | Optional | 
| priority | The priority of the issues to create. Possible values are: trivial, minor, major, critical, blocker.                                                  | Optional | 
| content | The content of the issue to create.                                                                                                                   | Optional | 
| assignee_id | The ID of the assignee of the issue to create. To get the assignee_id, use the !bitbucket-workspace-member-list command, and use the field AccountId. | Optional | 
| assignee_user_name | The user name of the assignee of the issue to create.                                                                                                 | Optional |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true.                              | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Issue.type | String | The action type. | 
| Bitbucket.Issue.id | Number | The ID of the issue. | 
| Bitbucket.Issue.repository.type | String | The type of the repository. | 
| Bitbucket.Issue.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Issue.repository.links | String | Links with information about the repository related to the issue. | 
| Bitbucket.Issue.repository.name | String | The name of the repository. | 
| Bitbucket.Issue.repository.uuid | String | The unique ID of the repository. | 
| Bitbucket.Issue.links | String | Links with information about the issue. | 
| Bitbucket.Issue.title | String | The title of the issue. | 
| Bitbucket.Issue.content.type | String | The type of the content. | 
| Bitbucket.Issue.content.raw | String | The content of the issue. | 
| Bitbucket.Issue.content.markup | String | The type of markup \(like markdown\). | 
| Bitbucket.Issue.content.html | String | The content of the issue in HTML format. | 
| Bitbucket.Issue.reporter.display_name | String | The display name of the reporter of the issue. | 
| Bitbucket.Issue.reporter.links | String | Links with information about the reporter. | 
| Bitbucket.Issue.reporter.type | String | The type of the reporter. | 
| Bitbucket.Issue.reporter.uuid | String | The unique ID of the reporter. | 
| Bitbucket.Issue.reporter.account_id | String | The account ID of the reporter. | 
| Bitbucket.Issue.reporter.nickname | String | The nickname of the reporter. | 
| Bitbucket.Issue.assignee.display_name | String | The display name of the assignee to the issue. | 
| Bitbucket.Issue.assignee.links | String | Links with information about the assignee. | 
| Bitbucket.Issue.assignee.type | String | The type of the assignee. | 
| Bitbucket.Issue.assignee.uuid | String | The unique ID of the assignee. | 
| Bitbucket.Issue.assignee.account_id | String | The account ID of the assignee. | 
| Bitbucket.Issue.assignee.nickname | String | The nickname of the assignee. | 
| Bitbucket.Issue.created_on | String | The creation date of the issue. | 
| Bitbucket.Issue.edited_on | Unknown | The edit date of the issue. | 
| Bitbucket.Issue.updated_on | String | The update date of the issue. | 
| Bitbucket.Issue.state | String | The state ID of the issue. | 
| Bitbucket.Issue.kind | String | The kind of the issue. | 
| Bitbucket.Issue.milestone | Unknown | The milestones in the issue. | 
| Bitbucket.Issue.component | Unknown | The different components of the issue. | 
| Bitbucket.Issue.priority | String | The priority of the issue. | 
| Bitbucket.Issue.version | Unknown | The version of the issue. | 
| Bitbucket.Issue.votes | Number | The votes of approval of the issue. | 
| Bitbucket.Issue.watches | Number | The watchers of the issue. | 

#### Command example
```!bitbucket-issue-update issue_id=91 title="a new issue" state=resolved```
#### Context Example
```json
{
    "Bitbucket": {
        "Issue": {
            "assignee": null,
            "component": null,
            "content": {
                "html": "",
                "markup": "markdown",
                "raw": "",
                "type": "rendered"
            },
            "created_on": "2022-09-18T08:00:00.000000+00:00",
            "edited_on": null,
            "id": 91,
            "kind": "bug",
            "links": {
                "attachments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/attachments"
                },
                "comments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/comments"
                },
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/issues/91/a-new-issue"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91"
                },
                "vote": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/vote"
                },
                "watch": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/91/watch"
                }
            },
            "milestone": null,
            "priority": "major",
            "reporter": {
                "account_id": "111111111111111111111111",
                "display_name": "Some User",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%Finitials%1111-1.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                    }
                },
                "nickname": "Some User",
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            },
            "repository": {
                "full_name": "workspace/start_repo",
                "links": {
                    "avatar": {
                        "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                    }
                },
                "name": "start_repo",
                "type": "repository",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            },
            "state": "resolved",
            "title": "a new issue",
            "type": "issue",
            "updated_on": "2022-09-18T08:00:00.000000+00:00",
            "version": null,
            "votes": 0,
            "watches": 1
        }
    }
}
```

#### Human Readable Output

>The issue with id "91" was updated successfully

### bitbucket-pull-request-create
***
Creates a pull request in Bitbucket.


#### Base Command

`bitbucket-pull-request-create`
#### Input

| **Argument Name** | **Description**                                                                                                                                                                        | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                                                                                           | Optional | 
| title | The title of the new pull request.                                                                                                                                                     | Required | 
| source_branch | The branch that contains the proposed changes.                                                                                                                                         | Required | 
| destination_branch | The branch that will contain the changes after the merge process.                                                                                                                      | Optional | 
| reviewer_id | A comma-separated list of account_ids of the person to review the pull request. To get the reviewer_id, use the !bitbucket-workspace-member-list command, and use the field AccountId. | Optional | 
| description | A description of the pull request.                                                                                                                                                     | Optional | 
| close_source_branch | Whether the source branch should be closed after the pull request. Possible values are: yes, no.                                                                                       | Optional |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true.                                                               | Optional |


#### Context Output

| **Path** | **Type** | **Description**                                                                         |
| --- |----------|-----------------------------------------------------------------------------------------|
| Bitbucket.PullRequest.comment_count | Number   | The number of comments there are in the pull request.                                   | 
| Bitbucket.PullRequest.task_count | Number   | The number of tasks there are in the pull request.                                      | 
| Bitbucket.PullRequest.type | String   | The type of the request.                                                                | 
| Bitbucket.PullRequest.id | Number   | The pull request ID.                                                                    | 
| Bitbucket.PullRequest.title | String   | The title of the pull request.                                                          | 
| Bitbucket.PullRequest.description | String   | The description of the pull request.                                                    | 
| Bitbucket.PullRequest.rendered.title.type | String   | The type of the title of the request.                                                   | 
| Bitbucket.PullRequest.rendered.title.raw | String   | The content of the rendered title.                                                      | 
| Bitbucket.PullRequest.rendered.title.markup | String   | The text styling type, such as markdown.                                                | 
| Bitbucket.PullRequest.rendered.title.html | String   | The HTML format of the pull request title.                                              | 
| Bitbucket.PullRequest.rendered.description.type | String   | The type of the pull request description                                                | 
| Bitbucket.PullRequest.rendered.description.raw | String   | The content of the description of the pull request.                                     | 
| Bitbucket.PullRequest.rendered.description.markup | String   | The text styling type, such as markdown.                                                | 
| Bitbucket.PullRequest.rendered.description.html | String   | HTML format of the description content.                                                 | 
| Bitbucket.PullRequest.state | String   | The status of the pull request.                                                         | 
| Bitbucket.PullRequest.merge_commit | Unknown  | Whether it is a merge commit.                                                           | 
| Bitbucket.PullRequest.close_source_branch | Boolean  | Whether the branch should be closed after the merge.                                    | 
| Bitbucket.PullRequest.closed_by | Unknown  | The user who closed the pull request.                                                   | 
| Bitbucket.PullRequest.author.display_name | String   | The display name of the author of the pull request.                                     | 
| Bitbucket.PullRequest.author.links | String   | Links with information about the author of the pull request.                            | 
| Bitbucket.PullRequest.author.type | String   | The type of the author                                                                  | 
| Bitbucket.PullRequest.author.uuid | String   | The unique universal ID of the author.                                                  | 
| Bitbucket.PullRequest.author.account_id | String   | The account ID of the author of the pull request.                                       | 
| Bitbucket.PullRequest.author.nickname | String   | The nickname of the author.                                                             | 
| Bitbucket.PullRequest.reason | String   | The reason to create the request.                                                       | 
| Bitbucket.PullRequest.created_on | String   | The creation date of the request.                                                       | 
| Bitbucket.PullRequest.updated_on | String   | The date of the last update of the pull request.                                        | 
| Bitbucket.PullRequest.destination.branch.name | String   | The name of the destination branch. This is the branch to merge to.                     | 
| Bitbucket.PullRequest.destination.commit.type | String   | The type of the commit.                                                                 | 
| Bitbucket.PullRequest.destination.commit.hash | String   | The hash of the commit.                                                                 | 
| Bitbucket.PullRequest.destination.commit.links | String   | Links with information about the commit.                                                | 
| Bitbucket.PullRequest.destination.repository.type | String   | The type of the repository.                                                             | 
| Bitbucket.PullRequest.destination.repository.full_name | String   | The full name of the repository of the destination branch.                              | 
| Bitbucket.PullRequest.destination.repository.links | String   | Links with information about the repository of the destination branch.                  | 
| Bitbucket.PullRequest.destination.repository.name | String   | The name of the repository.                                                             | 
| Bitbucket.PullRequest.destination.repository.uuid | String   | The unique ID of the repository.                                                        | 
| Bitbucket.PullRequest.source.branch.name | String   | The name of the source branch. This is the branch with the changes that will be merged. | 
| Bitbucket.PullRequest.source.commit.type | String   | The type of the commit in the source branch.                                            | 
| Bitbucket.PullRequest.source.commit.hash | String   | The hash of the commit in the source branch                                             | 
| Bitbucket.PullRequest.source.commit.links | String   | Links with information about the commit in the source branch.                           | 
| Bitbucket.PullRequest.source.repository.type | String   | The type of the repository of the source branch.                                        | 
| Bitbucket.PullRequest.source.repository.full_name | String   | The full name of the repository of the source branch.                                   | 
| Bitbucket.PullRequest.source.repository.links.self.href | String   | Links with information about the repository of the source branch.                       | 
| Bitbucket.PullRequest.source.repository.links | String   | Links with information about the repository of the source branch.                       | 
| Bitbucket.PullRequest.source.repository.name | String   | The name of the repository of the source branch.                                        | 
| Bitbucket.PullRequest.source.repository.uuid | String   | The unique ID of the repository of the source branch.                                   |
| Bitbucket.PullRequest.reviewers.display_name | String   | The display name of the reviewer.                                                       |
| Bitbucket.PullRequest.reviewers.links | String   | Links with information about the reviewer.                                              |
| Bitbucket.PullRequest.reviewers.type | String   | The type of the reviewer.                                                               |
| Bitbucket.PullRequest.reviewers.uuid | String   | The unique id of the reviewer.                                                          |
| Bitbucket.PullRequest.reviewers.account_id | String   | The account id of the reviewer.                                                         |
| Bitbucket.PullRequest.reviewers.nickname | String   | The nickname of the reviewer.                                                           |
| Bitbucket.PullRequest.participants.type | String   | The type of the participant.                                                            |
| Bitbucket.PullRequest.participants.user.display_name | String   | The display name of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.links | String   | Links with information about the user.                                                    |
| Bitbucket.PullRequest.participants.user.type | String   | The type of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.uuid | String   | The unique id of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.account_id | String   | The account id of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.nickname | String   | The nickname of the participant.                                                    |
| Bitbucket.PullRequest.participants.role | String   | The role of the participant.                                                    |
| Bitbucket.PullRequest.participants.approved | String   | The approval status of the pull request.                                                    |
| Bitbucket.PullRequest.participants.state | String   | The state of the participant.                                                    |
| Bitbucket.PullRequest.participants.participated_on | Unknown  | The date of participation.                                                    |
| Bitbucket.PullRequest.links | String   | Links to information about the pull request.                                            | 
| Bitbucket.PullRequest.summary.type | String   | The type of the pull request.                                                           | 
| Bitbucket.PullRequest.summary.raw | String   | The description of the pull request.                                                    | 
| Bitbucket.PullRequest.summary.markup | String   | The text styling type, such as markdown.                                                | 
| Bitbucket.PullRequest.summary.html | String   | The description of the pull request in HTML format.                                     | 

#### Command example
```!bitbucket-pull-request-create source_branch=test title="pull_request"```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequest": {
            "author": {
                "account_id": "111111111111111111111111",
                "display_name": "Some User",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%Finitials%1111-1.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                    }
                },
                "nickname": "Some User",
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            },
            "close_source_branch": false,
            "closed_by": null,
            "comment_count": 12,
            "created_on": "2022-09-12T09:00:00.000000+00:00",
            "description": "",
            "destination": {
                "branch": {
                    "name": "master"
                },
                "commit": {
                    "hash": "111111111111",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            "id": 8,
            "links": {
                "activity": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/activity"
                },
                "approve": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/approve"
                },
                "comments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/comments"
                },
                "commits": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/commits"
                },
                "decline": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/decline"
                },
                "diff": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/workspace/start_repo:0111111111111111111111111?from_pullrequest_id=8&topic=true"
                },
                "diffstat": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diffstat/workspace/start_repo:01111111111%0D111111111111?from_pullrequest_id=8&topic=true"
                },
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/pull-requests/8"
                },
                "merge": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/merge"
                },
                "request-changes": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/request-changes"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8"
                },
                "statuses": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/statuses"
                }
            },
            "merge_commit": null,
            "participants": [
                {
                    "approved": false,
                    "participated_on": "2022-09-15T12:00:00.000000+00:00",
                    "role": "PARTICIPANT",
                    "state": null,
                    "type": "participant",
                    "user": {
                        "account_id": "111111111111111111111111",
                        "display_name": "Some User",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%initials.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                            }
                        },
                        "nickname": "Some User",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                }
            ],
          "reviewers": [
              {
                "display_name": "Some User",
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/"
                    },
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/"
                    }
                },
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}",
                "account_id": "111111111111111111111111",
                "nickname": "Some User"
              }
            ],
            "reason": "",
            "rendered": {
                "description": {
                    "html": "",
                    "markup": "markdown",
                    "raw": "",
                    "type": "rendered"
                },
                "title": {
                    "html": "<p>pull_request</p>",
                    "markup": "markdown",
                    "raw": "pull_request",
                    "type": "rendered"
                }
            },
            "source": {
                "branch": {
                    "name": "test"
                },
                "commit": {
                    "hash": "111111111111",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            "state": "OPEN",
            "summary": {
                "html": "",
                "markup": "markdown",
                "raw": "",
                "type": "rendered"
            },
            "task_count": 0,
            "title": "pull_request",
            "type": "pullrequest",
            "updated_on": "2022-09-18T08:00:00.000000+00:00"
        }
    }
}
```

#### Human Readable Output

>The pull request was created successfully

### bitbucket-pull-request-update
***
Updates a pull request in Bitbucket.


#### Base Command

`bitbucket-pull-request-update`
#### Input

| **Argument Name** | **Description**                                                                                                                                                       | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                                                                          | Optional | 
| pull_request_id | The ID of the pull request to update. To get the pull_request_id, use the !bitbucket-pull-request-list command.                                                       | Required | 
| title | The title of the new pull request.                                                                                                                                    | Optional | 
| source_branch | The branch that contains the proposed changes.                                                                                                                        | Optional | 
| destination_branch | The branch that will contain the changes after the merge process.                                                                                                     | Optional | 
| reviewer_id | The ID of the account of the person to review the pull request. To get the reviewer_id, use the bitbucket-workspace-member-list command, and use the field AccountId. | Optional | 
| description | A description of the pull request.                                                                                                                                    | Optional | 
| close_source_branch | Whether the source branch should be closed after the pull request. Possible values are: yes, no.                                                                      | Optional |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true.                                              | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- |----------| --- |
| Bitbucket.PullRequest.comment_count | Number   | The number of comments in the pull request. | 
| Bitbucket.PullRequest.task_count | Number   | The number of tasks in the pull request. | 
| Bitbucket.PullRequest.type | String   | The type of the request. | 
| Bitbucket.PullRequest.id | Number   | The pull request ID. | 
| Bitbucket.PullRequest.title | String   | The title of the pull request. | 
| Bitbucket.PullRequest.description | String   | The description of the pull request. | 
| Bitbucket.PullRequest.rendered.title.type | String   | The type of the title of the request. | 
| Bitbucket.PullRequest.rendered.title.raw | String   | The content of the rendered title. | 
| Bitbucket.PullRequest.rendered.title.markup | String   | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.rendered.title.html | String   | The HTML format of the pull request title. | 
| Bitbucket.PullRequest.rendered.description.type | String   | The type of the pull request description. | 
| Bitbucket.PullRequest.rendered.description.raw | String   | The content of the description of the pull request. | 
| Bitbucket.PullRequest.rendered.description.markup | String   | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.rendered.description.html | String   | HTML format of the description content. | 
| Bitbucket.PullRequest.state | String   | The status of the pull request. | 
| Bitbucket.PullRequest.merge_commit | Unknown  | Whether it is a merge commit. | 
| Bitbucket.PullRequest.close_source_branch | Boolean  | Whether the branch should be closed after the merge. | 
| Bitbucket.PullRequest.closed_by | Unknown  | The user who closed the pull request. | 
| Bitbucket.PullRequest.author.display_name | String   | The display name of the author of the pull request. | 
| Bitbucket.PullRequest.author.links | String   | Links with information about the author of the pull request. | 
| Bitbucket.PullRequest.author.type | String   | The type of the author. | 
| Bitbucket.PullRequest.author.uuid | String   | The unique universal ID of the author. | 
| Bitbucket.PullRequest.author.account_id | String   | The account ID of the author of the pull request. | 
| Bitbucket.PullRequest.author.nickname | String   | The nickname of the author. | 
| Bitbucket.PullRequest.reason | String   | The reason to create the request. | 
| Bitbucket.PullRequest.created_on | String   | The creation date of the request. | 
| Bitbucket.PullRequest.updated_on | String   | The date of the last update of the pull request. | 
| Bitbucket.PullRequest.destination.branch.name | String   | The name of the destination branch. This is the branch to merge to. | 
| Bitbucket.PullRequest.destination.commit.type | String   | The type of the commit. | 
| Bitbucket.PullRequest.destination.commit.hash | String   | The hash of the commit. | 
| Bitbucket.PullRequest.destination.commit.links | String   | Links with information about the commit. | 
| Bitbucket.PullRequest.destination.repository.type | String   | The type of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.full_name | String   | The full name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.links | String   | Links with information about the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.name | String   | The name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.uuid | String   | The unique ID of the repository of the destination branch. | 
| Bitbucket.PullRequest.source.branch.name | String   | The name of the source branch. That is the branch with the changes that will be merged. | 
| Bitbucket.PullRequest.source.commit.type | String   | The type of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.hash | String   | The hash of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.links | String   | Links with information about the commit in the source branch. | 
| Bitbucket.PullRequest.source.repository.type | String   | The type of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.full_name | String   | The full name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.links | String   | Links with information about the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.name | String   | The name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.uuid | String   | The unique ID of the repository of the source branch. |
| Bitbucket.PullRequest.reviewers.display_name | String   | The display name of the reviewer.                                                       |
| Bitbucket.PullRequest.reviewers.links | String   | Links with information about the reviewer.                                              |
| Bitbucket.PullRequest.reviewers.type | String   | The type of the reviewer.                                                               |
| Bitbucket.PullRequest.reviewers.uuid | String   | The unique id of the reviewer.                                                          |
| Bitbucket.PullRequest.reviewers.account_id | String   | The account id of the reviewer.                                                         |
| Bitbucket.PullRequest.reviewers.nickname | String   | The nickname of the reviewer.                                                           |
| Bitbucket.PullRequest.participants.type | String   | The type of the participant.                                                            |
| Bitbucket.PullRequest.participants.user.display_name | String   | The display name of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.links | String   | Links with information about the user.                                                    |
| Bitbucket.PullRequest.participants.user.type | String   | The type of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.uuid | String   | The unique id of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.account_id | String   | The account id of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.nickname | String   | The nickname of the participant.                                                    |
| Bitbucket.PullRequest.participants.role | String   | The role of the participant.                                                    |
| Bitbucket.PullRequest.participants.approved | String   | The approval status of the pull request.                                                    |
| Bitbucket.PullRequest.participants.state | String   | The state of the participant.                                                    |
| Bitbucket.PullRequest.participants.participated_on | String   | The date of participation.                                                    |
| Bitbucket.PullRequest.links | String   | Links to information about the pull request. | 
| Bitbucket.PullRequest.summary.type | String   | The type of the pull request. | 
| Bitbucket.PullRequest.summary.raw | String   | The description of the pull request. | 
| Bitbucket.PullRequest.summary.markup | String   | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.summary.html | String   | The description of the pull request in HTML format. | 

#### Command example
```!bitbucket-pull-request-update pull_request_id=8 description="updating description"```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequest": {
            "author": {
                "account_id": "111111111111111111111111",
                "display_name": "Some User",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%Finitials%1111-1.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                    }
                },
                "nickname": "Some User",
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            },
            "close_source_branch": false,
            "closed_by": null,
            "comment_count": 12,
            "created_on": "2022-09-12T09:00:00.000000+00:00",
            "description": "updating description",
            "destination": {
                "branch": {
                    "name": "master"
                },
                "commit": {
                    "hash": "111111111111",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            "id": 8,
            "links": {
                "activity": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/activity"
                },
                "approve": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/approve"
                },
                "comments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/comments"
                },
                "commits": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/commits"
                },
                "decline": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/decline"
                },
                "diff": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/workspace/start_repo:0111111111111111111111111?from_pullrequest_id=8&topic=true"
                },
                "diffstat": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diffstat/workspace/start_repo:01111111111%0D111111111111?from_pullrequest_id=8&topic=true"
                },
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/pull-requests/8"
                },
                "merge": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/merge"
                },
                "request-changes": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/request-changes"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8"
                },
                "statuses": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/statuses"
                }
            },
            "merge_commit": null,
            "participants": [
                {
                    "approved": false,
                    "participated_on": "2022-09-15T12:00:00.000000+00:00",
                    "role": "PARTICIPANT",
                    "state": null,
                    "type": "participant",
                    "user": {
                        "account_id": "111111111111111111111111",
                        "display_name": "Some User",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%initials.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                            }
                        },
                        "nickname": "Some User",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                }
            ],
          "reviewers": [
              {
                "display_name": "Some User",
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/"
                    },
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/"
                    }
                },
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}",
                "account_id": "111111111111111111111111",
                "nickname": "Some User"
              }
            ],
            "reason": "",
            "rendered": {
                "description": {
                    "html": "<p>updating description</p>",
                    "markup": "markdown",
                    "raw": "updating description",
                    "type": "rendered"
                },
                "title": {
                    "html": "<p>pull_request</p>",
                    "markup": "markdown",
                    "raw": "pull_request",
                    "type": "rendered"
                }
            },
            "source": {
                "branch": {
                    "name": "test"
                },
                "commit": {
                    "hash": "111111111111",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            "state": "OPEN",
            "summary": {
                "html": "",
                "markup": "markdown",
                "raw": "",
                "type": "rendered"
            },
            "task_count": 0,
            "title": "pull_request",
            "type": "pullrequest",
            "updated_on": "2022-09-18T08:00:00.000000+00:00"
        }
    }
}
```

### bitbucket-pull-request-list
***
Returns a list of the pull requests. If a state is provided than the list will contain only PRs with the wanted status. If a state is not provided, by default a list of the open pull requests will return.


#### Base Command

`bitbucket-pull-request-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| pull_request_id | The ID of the pull request to update. To get the pull_request_id, use the !bitbucket-pull-request-list command.          | Optional | 
| state | The state of the pull requests to see. Possible values are: OPEN, MERGED, DECLINED, SUPERSEDED, ALL.                     | Optional | 
| limit | The maximum number of items in the list. The default value is 50.                                                        | Optional | 
| page | The specific result page to display.                                                                                     | Optional |
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- |----------| --- |
| Bitbucket.PullRequest.comment_count | Number   | The number of comments in the pull request. | 
| Bitbucket.PullRequest.task_count | Number   | The number of tasks in the pull request. | 
| Bitbucket.PullRequest.type | String   | The type of the request. | 
| Bitbucket.PullRequest.id | Number   | The pull request ID. | 
| Bitbucket.PullRequest.title | String   | The title of the pull request. | 
| Bitbucket.PullRequest.description | String   | The description of the pull request. | 
| Bitbucket.PullRequest.state | String   | The status of the pull request. | 
| Bitbucket.PullRequest.merge_commit.type | String   | The type of the merge commit. | 
| Bitbucket.PullRequest.merge_commit.hash | String   | The hash of the merged commit. | 
| Bitbucket.PullRequest.merge_commit.links | String   | Links with information about the merged commit. | 
| Bitbucket.PullRequest.close_source_branch | Boolean  | Whether the branch should be closed after the merge. | 
| Bitbucket.PullRequest.closed_by.display_name | String   | The display name of the user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.links | String   | Links with information about the user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.type | String   | The type of user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.uuid | String   | The unique ID of the user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.account_id | String   | The account ID of the user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.nickname | String   | The nickname of the user who closed the pull request. | 
| Bitbucket.PullRequest.author.display_name | String   | The display name of the author of the pull request. | 
| Bitbucket.PullRequest.author.links.self.href | String   | Links with information about the author of the pull request. | 
| Bitbucket.PullRequest.author.type | String   | The type of the author. | 
| Bitbucket.PullRequest.author.uuid | String   | The unique universal ID of the author. | 
| Bitbucket.PullRequest.author.account_id | String   | The account ID of the author of the pull request. | 
| Bitbucket.PullRequest.author.nickname | String   | The nickname of the author. | 
| Bitbucket.PullRequest.reason | String   | The reason to create the request. | 
| Bitbucket.PullRequest.created_on | String   | The creation date of the request. | 
| Bitbucket.PullRequest.updated_on | String   | The date of the last update of the pull request. | 
| Bitbucket.PullRequest.destination.branch.name | String   | The name of the destination branch. That is the branch to merge to. | 
| Bitbucket.PullRequest.destination.commit.type | String   | The type of the commit. | 
| Bitbucket.PullRequest.destination.commit.hash | String   | The hash of the commit. | 
| Bitbucket.PullRequest.destination.commit.links | String   | Links with information about the commit. | 
| Bitbucket.PullRequest.destination.repository.type | String   | The type of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.full_name | String   | The full name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.links | String   | Links with information about the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.name | String   | The name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.uuid | String   | The unique ID of the repository of the destination branch. | 
| Bitbucket.PullRequest.source.branch.name | String   | The name of the source branch. The branch with the changes that will be merged. | 
| Bitbucket.PullRequest.source.commit.type | String   | The type of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.hash | String   | The hash of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.links | String   | Links with information about the commit in the source branch. | 
| Bitbucket.PullRequest.source.repository.type | String   | The type of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.full_name | String   | The full name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.links | String   | Links with information about the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.name | String   | The name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.uuid | String   | The unique ID of the repository of the source branch. |
| Bitbucket.PullRequest.reviewers.display_name | String   | The display name of the reviewer.                                                       |
| Bitbucket.PullRequest.reviewers.links | String   | Links with information about the reviewer.                                              |
| Bitbucket.PullRequest.reviewers.type | String   | The type of the reviewer.                                                               |
| Bitbucket.PullRequest.reviewers.uuid | String   | The unique id of the reviewer.                                                          |
| Bitbucket.PullRequest.reviewers.account_id | String   | The account id of the reviewer.                                                         |
| Bitbucket.PullRequest.reviewers.nickname | String   | The nickname of the reviewer.                                                           |
| Bitbucket.PullRequest.participants.type | String   | The type of the participant.                                                            |
| Bitbucket.PullRequest.participants.user.display_name | String   | The display name of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.links | String   | Links with information about the user.                                                    |
| Bitbucket.PullRequest.participants.user.type | String   | The type of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.uuid | String   | The unique id of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.account_id | String   | The account id of the participant.                                                    |
| Bitbucket.PullRequest.participants.user.nickname | String   | The nickname of the participant.                                                    |
| Bitbucket.PullRequest.participants.role | String   | The role of the participant.                                                    |
| Bitbucket.PullRequest.participants.approved | String   | The approval status of the pull request.                                                    |
| Bitbucket.PullRequest.participants.state | String   | The state of the participant.                                                    |
| Bitbucket.PullRequest.participants.participated_on | Unknown  | The date of participation.                                                    |
| Bitbucket.PullRequest.links | String   | Links to information about the pull request. | 
| Bitbucket.PullRequest.summary.type | String   | The type of the pull request. | 
| Bitbucket.PullRequest.summary.raw | String   | The description of the pull request. | 
| Bitbucket.PullRequest.summary.markup | String   | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.summary.html | String   | The description of the pull request in HTML format. | 

#### Command example
```!bitbucket-pull-request-list```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequest": [
            {
                "author": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.ne.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "close_source_branch": false,
                "closed_by": null,
                "comment_count": 12,
                "created_on": "2022-09-12T09:00:00.000000+00:00",
                "description": "",
                "destination": {
                    "branch": {
                        "name": "master"
                    },
                    "commit": {
                        "hash": "111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "participants": [
                {
                    "approved": false,
                    "participated_on": "2022-09-15T12:00:00.000000+00:00",
                    "role": "PARTICIPANT",
                    "state": null,
                    "type": "participant",
                    "user": {
                        "account_id": "111111111111111111111111",
                        "display_name": "Some User",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net%initials.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                            }
                        },
                        "nickname": "Some User",
                        "type": "user",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                }
            ],
              "reviewers": [
                  {
                    "display_name": "Some User",
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/"
                        },
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/"
                        }
                    },
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}",
                    "account_id": "111111111111111111111111",
                    "nickname": "Some User"
                  }
                ],
                "id": 8,
                "links": {
                    "activity": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/activity"
                    },
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/comments"
                    },
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/commits"
                    },
                    "decline": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/decline"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/workspace/start_repo:111111111111%111111111111?from_pullrequest_id=8&topic=true"
                    },
                    "diffstat": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diffstat/workspace/start_repo:111111111111%111111111111?from_pullrequest_id=8&topic=true"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/pull-requests/8"
                    },
                    "merge": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/merge"
                    },
                    "request-changes": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/request-changes"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/8/statuses"
                    }
                },
                "merge_commit": null,
                "reason": "",
                "source": {
                    "branch": {
                        "name": "test"
                    },
                    "commit": {
                        "hash": "111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "state": "OPEN",
                "summary": {
                    "html": "",
                    "markup": "markdown",
                    "raw": "",
                    "type": "rendered"
                },
                "task_count": 0,
                "title": "pull_request",
                "type": "pullrequest",
                "updated_on": "2022-09-18T08:00:00.000000+00:00"
            },
            {
                "author": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "close_source_branch": true,
                "closed_by": null,
                "comment_count": 10,
                "created_on": "2022-09-08T12:00:00.000000+00:00",
                "description": "updates description",
                "destination": {
                    "branch": {
                        "name": "master"
                    },
                    "commit": {
                        "hash": "111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "id": 6,
                "links": {
                    "activity": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/activity"
                    },
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/comments"
                    },
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/commits"
                    },
                    "decline": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/decline"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diff/workspace/start_repo:1111111111%111111111111?from_pullrequest_id=6&topic=true"
                    },
                    "diffstat": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/diffstat/workspace/start_repo:1111111111%111111111111?from_pullrequest_id=6&topic=true"
                    },
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/pull-requests/6"
                    },
                    "merge": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/merge"
                    },
                    "request-changes": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/request-changes"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/6/statuses"
                    }
                },
                "merge_commit": null,
                "reason": "",
                "source": {
                    "branch": {
                        "name": "branch"
                    },
                    "commit": {
                        "hash": "111111111111",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo/commits/111111111111"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/commit/111111111111"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    }
                },
                "state": "OPEN",
                "summary": {
                    "html": "<p>updates description</p>",
                    "markup": "markdown",
                    "raw": "updates description",
                    "type": "rendered"
                },
                "task_count": 0,
                "title": "uuuupdate",
                "type": "pullrequest",
                "updated_on": "2022-09-15T12:00:00.000000+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the pull requests
>|Id|Title|Description|SourceBranch|DestinationBranch|State|CreatedBy|CreatedAt|UpdatedAt|
>|---|---|---|---|---|---|---|---|---|
>| 8 | pull_request |  | test | master | OPEN | Some User | 2022-09-12T09:51:55.458494+00:00 | 2022-09-18T08:57:20.815479+00:00 |
>| 6 | uuuupdate | updates description | branch | master | OPEN | Some User | 2022-09-08T12:23:04.303626+00:00 | 2022-09-15T12:44:45.785951+00:00 |


### bitbucket-issue-comment-create
***
Creates a comment on an issue in Bitbucket.


#### Base Command

`bitbucket-issue-comment-create`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| issue_id | The ID of the issue to comment on. To get the issue_id, use the !bitbucket-issue-list command.                           | Required | 
| content | The content of the comment.                                                                                              | Required | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.IssueComment.type | String | The action type. | 
| Bitbucket.IssueComment.id | Number | The ID of the comment on the issue. | 
| Bitbucket.IssueComment.created_on | String | The creation date of the comment. | 
| Bitbucket.IssueComment.updated_on | Unknown | When the comment was updated. | 
| Bitbucket.IssueComment.content.type | String | The type of the content. | 
| Bitbucket.IssueComment.content.raw | String | The content of the comment. | 
| Bitbucket.IssueComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.IssueComment.content.html | String | The content of the comment in HTML format. | 
| Bitbucket.IssueComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.IssueComment.user.links | String | Links with information about the user who created the comment. | 
| Bitbucket.IssueComment.user.type | String | The type of the user who created the comment. | 
| Bitbucket.IssueComment.user.uuid | String | The unique ID of the user who created the comment. | 
| Bitbucket.IssueComment.user.account_id | String | The account ID of the user who created the comment. | 
| Bitbucket.IssueComment.user.nickname | String | The nickname of the user who created the comment. | 
| Bitbucket.IssueComment.issue.type | String | The type of the issue. | 
| Bitbucket.IssueComment.issue.id | Number | The ID of the issue. | 
| Bitbucket.IssueComment.issue.repository.type | String | The type of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.full_name | String | The full name of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.links | String | Links to information about the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.name | String | The name of the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.uuid | String | The unique ID of the relevant repository. | 
| Bitbucket.IssueComment.issue.links | String | Links with information about the issue. | 
| Bitbucket.IssueComment.issue.title | String | The title of the issue. | 
| Bitbucket.IssueComment.links | String | Links to information about the comment. | 

#### Command example
```!bitbucket-issue-comment-create content="some comment" issue_id=1```
#### Context Example
```json
{
    "Bitbucket": {
        "IssueComment": {
            "content": {
                "html": "<p>some comment</p>",
                "markup": "markdown",
                "raw": "some comment",
                "type": "rendered"
            },
            "created_on": "2022-09-18T08:00:00.000000+00:00",
            "id": 11111111,
            "issue": {
                "id": 1,
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1"
                    }
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "title": "new issue",
                "type": "issue"
            },
            "links": {
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/issues/1#comment-11111111"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1/comments/11111111"
                }
            },
            "type": "issue_comment",
            "updated_on": null,
            "user": {
                "account_id": "111111111111111111111111",
                "display_name": "Some User",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                    }
                },
                "nickname": "Some User",
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            }
        }
    }
}
```

#### Human Readable Output

>The comment was created successfully

### bitbucket-issue-comment-delete
***
Deletes a comment on an issue in Bitbucket.


#### Base Command

`bitbucket-issue-comment-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| issue_id | The ID of the issue to comment on. To get the issue_id, use the !bitbucket-issue-list command. | Required | 
| comment_id | The ID of the comment to delete. To get the comment_id, use the !bitbucket-issue-comment-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Human Readable Output

>The comment was deleted successfully

### bitbucket-issue-comment-list
***
Returns a list of comments on a specific issue. If a comment_id is given it will return information only about the specific comment.


#### Base Command

`bitbucket-issue-comment-list`
#### Input

| **Argument Name** | **Description**                                                                                                               | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                                  | Optional | 
| issue_id | The ID of the issue to comment on. To get the issue_id, use the bitbucket-issue-list command.                                 | Required | 
| comment_id | The ID of the comment to delete. To get the comment_id, use the !bitbucket-issue-comment-list command without any parameters. | Optional | 
| limit | The maximum number of items in the list. The default value is 50.                                                             | Optional | 
| page | The specific result page to display.                                                                                          | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true.      | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.IssueComment.type | String | The action type. | 
| Bitbucket.IssueComment.id | Number | The ID of comment on the issue. | 
| Bitbucket.IssueComment.created_on | String | The creation date of the comment. | 
| Bitbucket.IssueComment.updated_on | Unknown | When the comment was updated. | 
| Bitbucket.IssueComment.content.type | String | The type of the content. | 
| Bitbucket.IssueComment.content.raw | String | The content of the comment. | 
| Bitbucket.IssueComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.IssueComment.content.html | String | The content of the comment in HTML format. | 
| Bitbucket.IssueComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.IssueComment.user.links | String | Links with information about the user who created the comment. | 
| Bitbucket.IssueComment.user.type | String | The type of the user who created the comment. | 
| Bitbucket.IssueComment.user.uuid | String | The unique ID of the user who created the comment. | 
| Bitbucket.IssueComment.user.account_id | String | The account ID of the user who created the comment. | 
| Bitbucket.IssueComment.user.nickname | String | The nickname of the user who created the comment. | 
| Bitbucket.IssueComment.issue.type | String | The type of the issue. | 
| Bitbucket.IssueComment.issue.id | Number | The ID of the issue. | 
| Bitbucket.IssueComment.issue.repository.type | String | The type of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.full_name | String | The full name of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.links | String | Links to information about the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.name | String | The name of the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.uuid | String | The unique ID of the relevant repository. | 
| Bitbucket.IssueComment.issue.links | String | Links with information about the issue. | 
| Bitbucket.IssueComment.issue.title | String | The title of the issue. | 
| Bitbucket.IssueComment.links | String | Links to information about the comment. | 

#### Command example
```!bitbucket-issue-comment-list issue_id=1```
#### Context Example
```json
{
    "Bitbucket": {
        "IssueComment": [
            {
                "content": {
                    "html": "<p>new bug</p>",
                    "markup": "markdown",
                    "raw": "new bug",
                    "type": "rendered"
                },
                "created_on": "2022-09-06T14:00:00.000000+00:00",
                "id": 11111111,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/issues/1#comment-11111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1/comments/11111111"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            {
                "content": {
                    "html": "<p>just a comment</p>",
                    "markup": "markdown",
                    "raw": "just a comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-11T10:00:00.000000+00:00",
                "id": 11111111,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "workspace/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/workspace/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{11111111-1111-1111-1111-111111111111}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/issues/1#comment-11111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1/comments/11111111"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the comments on issue "1"
>|Id|Content|CreatedBy|CreatedAt|UpdatedAt|IssueId|IssueTitle|
>|---|---|---|---|---|---|---|
>| 11111111 | new bug | Some User | 2022-09-06T14:23:03.776275+00:00 |  | 1 | new issue |
>| 11111111 | just a comment | Some User | 2022-09-11T10:54:14.356238+00:00 |  | 1 | new issue |


### bitbucket-issue-comment-update
***
Updates a specific comment on a given issue.


#### Base Command

`bitbucket-issue-comment-update`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| issue_id | The ID of the issue to comment on. To get the issue_id, use the !bitbucket-issue-list command.                           | Required | 
| comment_id | The ID of the comment to delete. To get the issue_id, use the !bitbucket-issue-comment-list command.                     | Required | 
| content | The new content of the comment.                                                                                          | Required | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.IssueComment.type | String | The action type. | 
| Bitbucket.IssueComment.id | Number | The ID of the comment on the issue. | 
| Bitbucket.IssueComment.created_on | String | The creation date of the comment. | 
| Bitbucket.IssueComment.updated_on | Unknown | When the comment was updated. | 
| Bitbucket.IssueComment.content.type | String | The type of the content. | 
| Bitbucket.IssueComment.content.raw | String | The content of the comment. | 
| Bitbucket.IssueComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.IssueComment.content.html | String | The content of the comment in HTML format. | 
| Bitbucket.IssueComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.IssueComment.user.links | String | Links with information about the user who created the comment. | 
| Bitbucket.IssueComment.user.type | String | The type of the user who created the comment. | 
| Bitbucket.IssueComment.user.uuid | String | The unique ID of the user who created the comment. | 
| Bitbucket.IssueComment.user.account_id | String | The account ID of the user who created the comment. | 
| Bitbucket.IssueComment.user.nickname | String | The nickname of the user who created the comment. | 
| Bitbucket.IssueComment.issue.type | String | The type of the issue. | 
| Bitbucket.IssueComment.issue.id | Number | The ID of the issue. | 
| Bitbucket.IssueComment.issue.repository.type | String | The type of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.full_name | String | The full name of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.links | String | Links to information about the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.name | String | The name of the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.uuid | String | The unique ID of the relevant repository. | 
| Bitbucket.IssueComment.issue.links | String | Links with information about the issue. | 
| Bitbucket.IssueComment.issue.title | String | The title of the issue. | 
| Bitbucket.IssueComment.links | String | Links to information about the comment. | 

#### Command example
```!bitbucket-issue-comment-update issue_id=1 comment_id=11111111 content="updating content info"```
#### Context Example
```json
{
    "Bitbucket": {
        "IssueComment": {
            "content": {
                "html": "<p>updating content info</p>",
                "markup": "markdown",
                "raw": "updating content info",
                "type": "rendered"
            },
            "created_on": "2022-09-14T15:00:00.000000+00:00",
            "id": 11111111,
            "issue": {
                "id": 1,
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1"
                    }
                },
                "repository": {
                    "full_name": "workspace/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%1111111111-1111-1111-1111-111111111111%11?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "title": "new issue",
                "type": "issue"
            },
            "links": {
                "html": {
                    "href": "https://bitbucket.org/workspace/start_repo/issues/1#comment-11111111"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/issues/1/comments/11111111"
                }
            },
            "type": "issue_comment",
            "updated_on": "2022-09-18T08:00:00.000000+00:00",
            "user": {
                "account_id": "111111111111111111111111",
                "display_name": "Some User",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                    }
                },
                "nickname": "Some User",
                "type": "user",
                "uuid": "{11111111-1111-1111-1111-111111111111}"
            }
        }
    }
}
```

#### Human Readable Output

>The comment "11111111" on issue "1" was updated successfully

### bitbucket-pull-request-comment-create
***
Creates a new comment on a pull request.


#### Base Command

`bitbucket-pull-request-comment-create`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| pull_request_id | The ID of the pull request to comment on. To get the pull request ID, use the  !bitbucket-pull-request-list command.     | Required | 
| content | The content of the comment.                                                                                              | Required | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequestComment.id | Number | The ID of the comment in the pull request. | 
| Bitbucket.PullRequestComment.created_on | String | The creation date of the pull request comment. | 
| Bitbucket.PullRequestComment.updated_on | String | The update date of the pull request comment. | 
| Bitbucket.PullRequestComment.content.type | String | The type of the content, such as rendered. | 
| Bitbucket.PullRequestComment.content.raw | String | The actual content of the comment. | 
| Bitbucket.PullRequestComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequestComment.content.html | String | The content of the comment in HTML format. | 
| Bitbucket.PullRequestComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.PullRequestComment.user.links | String | Links to information about the user | 
| Bitbucket.PullRequestComment.user.type | String | The type of the user. | 
| Bitbucket.PullRequestComment.user.uuid | String | The unique ID of the user. | 
| Bitbucket.PullRequestComment.user.account_id | String | The account ID of the user. | 
| Bitbucket.PullRequestComment.user.nickname | String | The nickname of the user. | 
| Bitbucket.PullRequestComment.deleted | Boolean | Whether the comment was deleted. | 
| Bitbucket.PullRequestComment.type | String | The type of the action. | 
| Bitbucket.PullRequestComment.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.type | String | The type of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.id | Number | The ID of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.links | String | Links to information about the pull request. | 

#### Command example
```!bitbucket-pull-request-comment-create content="new comment on a pull request" pull_request_id=1```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequestComment": [
            {
                "content": {
                    "html": "<p>new comment on a pull request</p>",
                    "markup": "markdown",
                    "raw": "new comment on a pull request",
                    "type": "rendered"
                },
                "created_on": "2022-09-18T08:00:00.000000+00:00",
                "deleted": false,
                "id": 11111111,
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/pull-requests/1/_/diff#comment-11111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/1/comments/11111111"
                    }
                },
                "pullrequest": {
                    "id": 1,
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/pull-requests/1"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/1"
                        }
                    },
                    "title": "change 2",
                    "type": "pullrequest"
                },
                "type": "pullrequest_comment",
                "updated_on": "2022-09-18T08:00:00.000000+00:00",
                "user": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>The comment was created successfully

### bitbucket-pull-request-comment-list
***
Returns a list of comments of a specific pull request.


#### Base Command

`bitbucket-pull-request-comment-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| pull_request_id | The ID of the pull request. To get the pull_request_id, use the !bitbucket-pull-request-list command.                    | Required | 
| comment_id | The ID of the comment. To get the comment_id, use the !bitbucket-pull-request-comment-list command.                      | Optional | 
| limit | The maximum number of items in the list. The default value is 50.                                                        | Optional | 
| page | The specific result page to display.                                                                                     | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequestComment.id | Number | The ID of the comment in the pull request. | 
| Bitbucket.PullRequestComment.created_on | String | The creation date of the pull request comment. | 
| Bitbucket.PullRequestComment.updated_on | String | The update date of the pull request comment. | 
| Bitbucket.PullRequestComment.content.type | String | The type of the content, such as rendered. | 
| Bitbucket.PullRequestComment.content.raw | String | The actual content of the comment. | 
| Bitbucket.PullRequestComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequestComment.content.html | String | The content of the comment in HTML format. | 
| Bitbucket.PullRequestComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.PullRequestComment.user.links | String | Links to information about the user. | 
| Bitbucket.PullRequestComment.user.type | String | The type of the user. | 
| Bitbucket.PullRequestComment.user.uuid | String | The unique ID of the user. | 
| Bitbucket.PullRequestComment.user.account_id | String | The account ID of the user. | 
| Bitbucket.PullRequestComment.user.nickname | String | The nickname of the user. | 
| Bitbucket.PullRequestComment.deleted | Boolean | Whether the comment was deleted. | 
| Bitbucket.PullRequestComment.type | String | The type of the action. | 
| Bitbucket.PullRequestComment.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.type | String | The type of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.id | Number | The ID of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.links | String | Links to information about the pull request. | 

#### Command example
```!bitbucket-pull-request-comment-list pull_request_id=1```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequestComment": [
            {
                "content": {
                    "html": "<p>new comment on a pull request</p>",
                    "markup": "markdown",
                    "raw": "new comment on a pull request",
                    "type": "rendered"
                },
                "created_on": "2022-09-18T08:00:00.000000+00:00",
                "deleted": false,
                "id": 11111111,
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/pull-requests/1/_/diff#comment-11111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/1/comments/11111111"
                    }
                },
                "pullrequest": {
                    "id": 1,
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/pull-requests/1"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/1"
                        }
                    },
                    "title": "change 2",
                    "type": "pullrequest"
                },
                "type": "pullrequest_comment",
                "updated_on": "2022-09-18T08:00:00.000000+00:00",
                "user": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the comments on pull request "1"
>|Id|Content|CreatedBy|CreatedAt|UpdatedAt|
>|---|---|---|---|---|
>| 11111111 | new comment on a pull request | Some User | 2022-09-18T08:57:13.848266+00:00 | 2022-09-18T08:57:13.848309+00:00 |


### bitbucket-pull-request-comment-update
***
Updates a specific comment in a specific pull request.


#### Base Command

`bitbucket-pull-request-comment-update`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| repo | The repository name or slug.                                                                                             | Optional | 
| pull_request_id | The ID of the pull request. To get the pull request_id use, the !bitbucket-pull-request-list command.                    | Required | 
| comment_id | The ID of the comment. To get the comment_id, use the !bitbucket-pull-request-comment-list command.                      | Required | 
| content | The ID of the comment.                                                                                                   | Required | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequestComment.id | Number | The ID of the comment in the pull request. | 
| Bitbucket.PullRequestComment.created_on | String | The creation date of the pull request comment. | 
| Bitbucket.PullRequestComment.updated_on | String | The update date of the pull request comment. | 
| Bitbucket.PullRequestComment.content.type | String | The type of the content, such as rendered. | 
| Bitbucket.PullRequestComment.content.raw | String | The actual content of the comment. | 
| Bitbucket.PullRequestComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequestComment.content.html | String | The content of the comment in HTML format. | 
| Bitbucket.PullRequestComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.PullRequestComment.user.links | String | Links to information about the user. | 
| Bitbucket.PullRequestComment.user.type | String | The type of the user. | 
| Bitbucket.PullRequestComment.user.uuid | String | The unique ID of the user. | 
| Bitbucket.PullRequestComment.user.account_id | String | The account ID of the user. | 
| Bitbucket.PullRequestComment.user.nickname | String | The nickname of the user. | 
| Bitbucket.PullRequestComment.deleted | Boolean | Whether the comment was deleted. | 
| Bitbucket.PullRequestComment.type | String | The type of the action. | 
| Bitbucket.PullRequestComment.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.type | String | The type of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.id | Number | The ID of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.links | String | Links to information about the pull request. | 

#### Command example
```!bitbucket-pull-request-comment-update comment_id=111111111 content="hi you" pull_request_id=1```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequestComment": [
            {
                "content": {
                    "html": "<p>new comment on a pull request</p>",
                    "markup": "markdown",
                    "raw": "new comment on a pull request",
                    "type": "rendered"
                },
                "created_on": "2022-09-18T08:00:00.000000+00:00",
                "deleted": false,
                "id": 11111111,
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/workspace/start_repo/pull-requests/1/_/diff#comment-11111111"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/1/comments/11111111"
                    }
                },
                "pullrequest": {
                    "id": 1,
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/workspace/start_repo/pull-requests/1"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/workspace/start_repo/pullrequests/1"
                        }
                    },
                    "title": "change 2",
                    "type": "pullrequest"
                },
                "type": "pullrequest_comment",
                "updated_on": "2022-09-18T08:00:00.000000+00:00",
                "user": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Some User",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B11111111-1111-1111-1111-111111111111%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "Some User",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### The comment was updated successfully

### bitbucket-pull-request-comment-delete
***
Deletes a specific comment in a specific pull request.


#### Base Command

`bitbucket-pull-request-comment-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The ID of the pull request. To get the pull_request_id, use the !bitbucket-pull-request-list command. | Required | 
| comment_id | The ID of the comment. To get the comment_id, use the !bitbucket-pull-request-comment-list command. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!bitbucket-pull-request-comment-delete comment_id=331372169 pull_request_id=1```
#### Human Readable Output

>The comment was deleted successfully.

### bitbucket-workspace-member-list
***
Returns a list of all the members in the workspace.


#### Base Command

`bitbucket-workspace-member-list`
#### Input

| **Argument Name** | **Description**                                                                                                          | **Required** |
| --- |--------------------------------------------------------------------------------------------------------------------------| --- |
| limit | The maximum number of items in the list. The default value is 50.                                                        | Optional | 
| page | The specific result page to display.                                                                                     | Optional | 
| partial_response | Return a partial response if true, else return the full API response. Possible values are: true, false. Default is true. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.WorkspaceMember.type | String | The action type. | 
| Bitbucket.WorkspaceMember.user.display_name | String | The display name of the user. | 
| Bitbucket.WorkspaceMember.user.links | String | Links with information about the user. | 
| Bitbucket.WorkspaceMember.user.type | String | The type of the user. | 
| Bitbucket.WorkspaceMember.user.uuid | String | The unique ID of the user. | 
| Bitbucket.WorkspaceMember.user.account_id | String | The account ID of the user. | 
| Bitbucket.WorkspaceMember.user.nickname | String | The nickname of the user. | 
| Bitbucket.WorkspaceMember.workspace.type | String | The type of the workspace. | 
| Bitbucket.WorkspaceMember.workspace.uuid | String | The unique ID of the workspace. | 
| Bitbucket.WorkspaceMember.workspace.name | String | The name of the workspace. | 
| Bitbucket.WorkspaceMember.workspace.slug | String | The slug of the workspace. | 
| Bitbucket.WorkspaceMember.workspace.links | String | Links to information about the workspace. | 

#### Command example
```!bitbucket-workspace-member-list```
#### Context Example
```json
{
    "Bitbucket": {
        "WorkspaceMember": [
            {
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/workspace/members/%111111111111-1111-1111-1111-111111111111%11"
                    }
                },
                "type": "workspace_membership",
                "user": {
                    "account_id": "111111111111111111111111",
                    "display_name": "Display Name",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%111111111111-1111-1111-1111-111111111111%11/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B11111111-1111-1111-1111-111111111111%7D"
                        }
                    },
                    "nickname": "nixkname",
                    "type": "user",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                },
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/workspace/avatar/?ts=1111111111"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/workspace"
                        }
                    },
                    "name": "Some User",
                    "slug": "workspace",
                    "type": "workspace",
                    "uuid": "{11111111-1111-1111-1111-111111111111}"
                }
            },
            {
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/workspace/members/%11111111-1111-1111-1111-111111111111%11"
                    }
                },
                "type": "workspace_membership",
                "user": {
                    "account_id": "222222222222222222222222",
                    "display_name": "Display Name",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/?d=httpsavatar-management--avatars.us-west-2.prod.public.atl-paas.net.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%22222222-2222-2222-2222-222222222222%11/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%22222222-2222-2222-2222-222222222222%22"
                        }
                    },
                    "nickname": "nickname",
                    "type": "user",
                    "uuid": "{22222222-2222-2222-2222-222222222222}"
                },
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/workspace/avatar/?ts=22222222"
                        },
                        "html": {
                            "href": "https://bitbucket.org/workspace/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/workspace"
                        }
                    },
                    "name": "Another User",
                    "slug": "workspace",
                    "type": "workspace",
                    "uuid": "{222222222-2222-2222-2222-222222222222}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### The list of all the workspace members
>| Name         |AccountId|
--------------|---|---|
>| Some User | 111111111111111111111111 |
>| Another User | 222222222222222222222222 |

