Pack for handling Bitbucket operations
This integration was integrated and tested with version xx of Bitbucket

## Configure Bitbucket on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Bitbucket.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Workspace |  | True |
    | Server Url |  | True |
    | User Name | &amp;lt;a href="https://developer.atlassian.com/cloud/bitbucket/rest/intro/\#app-passwords" target="_blank"&amp;gt;click to open a link to create the app password&amp;lt;/a&amp;gt; | True |
    | App Password |  | True |
    | Repository |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### bitbucket-project-list
***
 


#### Base Command

`bitbucket-project-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_key | Must be uppercase. | Optional | 
| limit | The maximum number of projects. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Project.type | String | The type of the action. | 
| Bitbucket.Project.owner.display_name | String | The project owner name. | 
| Bitbucket.Project.owner.links.self.href | String | The link to a json with the information about the owner of the project. | 
| Bitbucket.Project.owner.links.avatar.href | String | A link to the project owner photo. | 
| Bitbucket.Project.owner.links.html.href | String | A link to the project owner repositories. | 
| Bitbucket.Project.owner.type | String | The type of the project owner. | 
| Bitbucket.Project.owner.uuid | String | The project owner universal unique id. | 
| Bitbucket.Project.owner.account_id | String | The project owner account id. | 
| Bitbucket.Project.owner.nickname | String | The project owner nickname. | 
| Bitbucket.Project.workspace.type | String | The type of the workspace. | 
| Bitbucket.Project.workspace.uuid | String | The project workspace universal unique id. | 
| Bitbucket.Project.workspace.name | String | The name of the project workspace. | 
| Bitbucket.Project.workspace.slug | String | The slug of the project workspace. | 
| Bitbucket.Project.workspace.links.avatar.href | String | A link to the project workspace photo. | 
| Bitbucket.Project.workspace.links.html.href | String | A link to the project workspace repositories. | 
| Bitbucket.Project.workspace.links.self.href | String | A link to the result json. | 
| Bitbucket.Project.key | String | The project key. | 
| Bitbucket.Project.uuid | String | the project universal unique id. | 
| Bitbucket.Project.is_private | Boolean | Is the project private or not. | 
| Bitbucket.Project.name | String | The project name. | 
| Bitbucket.Project.description | String | The project description. | 
| Bitbucket.Project.links.self.href | String | A link to the result json. | 
| Bitbucket.Project.links.html.href | String | A link to the project repositories. | 
| Bitbucket.Project.links.repositories.href | String | A link to the project repositories. | 
| Bitbucket.Project.links.avatar.href | String | A link to the project photo. | 
| Bitbucket.Project.created_on | String | The date the project was created. | 
| Bitbucket.Project.updated_on | String | The date the project was updated. | 
| Bitbucket.Project.has_publicly_visible_repos | Boolean | Does the project has a publicly visible repositories or not. | 

#### Command example
```!bitbucket-project-list```
#### Context Example
```json
{
    "Bitbucket": {
        "Project": [
            {
                "created_on": "2022-08-24T09:25:07.002184+00:00",
                "description": "description",
                "has_publicly_visible_repos": false,
                "is_private": true,
                "key": "AP",
                "links": {
                    "avatar": {
                        "href": "https://bitbucket.org/account/user/rotemamit/projects/AP/avatar/32?ts=1661333107"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/workspace/projects/AP"
                    },
                    "repositories": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit?q=project.key=\"AP\""
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit/projects/AP"
                    }
                },
                "name": "Another Project",
                "owner": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "type": "project",
                "updated_on": "2022-08-24T09:25:07.002201+00:00",
                "uuid": "{c78fdeee-e6b1-4a60-b9c7-7d0991e3f792}",
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/rotemamit/avatar/?ts=1661077643"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit"
                        }
                    },
                    "name": "Rotem Amit",
                    "slug": "rotemamit",
                    "type": "workspace",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "created_on": "2022-08-21T13:19:18.691929+00:00",
                "description": null,
                "has_publicly_visible_repos": false,
                "is_private": false,
                "key": "TES",
                "links": {
                    "avatar": {
                        "href": "https://bitbucket.org/account/user/rotemamit/projects/TES/avatar/32?ts=1661087958"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/workspace/projects/TES"
                    },
                    "repositories": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit?q=project.key=\"TES\""
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit/projects/TES"
                    }
                },
                "name": "testId",
                "owner": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "type": "project",
                "updated_on": "2022-08-21T13:19:18.691943+00:00",
                "uuid": "{9358454f-0ac8-472d-aaa7-572b23a286d6}",
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/rotemamit/avatar/?ts=1661077643"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit"
                        }
                    },
                    "name": "Rotem Amit",
                    "slug": "rotemamit",
                    "type": "workspace",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the projects in rotemamit
>|Key|Name|Description|IsPrivate|
>|---|---|---|---|
>| AP | Another Project | description | true |
>| TES | testId |  | false |


### bitbucket-open-branch-list
***
 


#### Base Command

`bitbucket-open-branch-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | the repository name or slug. | Optional | 
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Branch.name | String | The branch name. | 
| Bitbucket.Branch.target.type | String | The type of the last action in the branch | 
| Bitbucket.Branch.target.hash | String | The hash of the last action in the branch. | 
| Bitbucket.Branch.target.date | Date | The creation date of the last action in the branch. | 
| Bitbucket.Branch.target.author.type | String | The type of the author of the last action. | 
| Bitbucket.Branch.target.author.raw | String | The raw information about the author of the last action. | 
| Bitbucket.Branch.target.author.user.display_name | String | The display name of the author of the last action. | 
| Bitbucket.Branch.target.author.user.links.self.href | String | The link to a json with the information about the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.links.avatar.href | String | A link to the image of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.links.html.href | String | A link to the user repository | 
| Bitbucket.Branch.target.author.user.type | String | The type of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.author.user.uuid | String | The unique user id of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.author.user.account_id | String | The account id of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.author.user.nickname | String | The nickname of the user who made the last action in the branch. | 
| Bitbucket.Branch.target.message | String | The message assigned to the last action in the branch. | 
| Bitbucket.Branch.target.links | String | The links associated with this command. | 
| Bitbucket.Branch.target.parents.type | String | The type of the parent who created the branch. | 
| Bitbucket.Branch.target.parents.hash | String | The hash of the parent who created the branch. | 
| Bitbucket.Branch.target.parents.links | String | The links associated with the parents of the command | 
| Bitbucket.Branch.target.repository.type | String | The repository type. | 
| Bitbucket.Branch.target.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Branch.target.repository.links.self.href | String | The api request to the repository | 
| Bitbucket.Branch.target.repository.links.html.href | String | A link to the repository. | 
| Bitbucket.Branch.target.repository.links.avatar.href | String | A link to the repository image | 
| Bitbucket.Branch.target.repository.name | String | The name of the repository | 
| Bitbucket.Branch.target.repository.uuid | String | The repository unique id. | 
| Bitbucket.Branch.links.self.href | String | The api request to the branch. | 
| Bitbucket.Branch.links.commits.href | String | A link to api request to the commits of the branch. | 
| Bitbucket.Branch.links.html.href | String | A link to the commits in the branch. | 
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
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/master"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/branch/master"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/master"
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
                        "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                        "type": "author",
                        "user": {
                            "account_id": "62cf63f7e546e8eab8eee042",
                            "display_name": "Rotem Amit",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                                }
                            },
                            "nickname": "Rotem Amit",
                            "type": "user",
                            "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                        }
                    },
                    "date": "2022-09-18T08:56:56+00:00",
                    "hash": "3f77114f285c8b1bd5c0254aad639b4e840d07db",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c8b1bd5c0254aad639b4e840d07db/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c8b1bd5c0254aad639b4e840d07db/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/3f77114f285c8b1bd5c0254aad639b4e840d07db"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/3f77114f285c8b1bd5c0254aad639b4e840d07db"
                        },
                        "patch": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/3f77114f285c8b1bd5c0254aad639b4e840d07db"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c8b1bd5c0254aad639b4e840d07db"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c8b1bd5c0254aad639b4e840d07db/statuses"
                        }
                    },
                    "message": "delete the new file",
                    "parents": [
                        {
                            "hash": "151c21c5942be1dc522c12433c8d391960bce646",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/rotemamit/start_repo/commits/151c21c5942be1dc522c12433c8d391960bce646"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/151c21c5942be1dc522c12433c8d391960bce646"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "type": "commit"
                },
                "type": "branch"
            },
            {
                "default_merge_strategy": "merge_commit",
                "links": {
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/branch"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/branch/branch"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/branch"
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
                        "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                        "type": "author",
                        "user": {
                            "account_id": "62cf63f7e546e8eab8eee042",
                            "display_name": "Rotem Amit",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                                }
                            },
                            "nickname": "Rotem Amit",
                            "type": "user",
                            "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                        }
                    },
                    "date": "2022-09-08T14:59:22+00:00",
                    "hash": "280b06eee03270de0e7061fc9ddc1074813fb673",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/280b06eee03270de0e7061fc9ddc1074813fb673/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/280b06eee03270de0e7061fc9ddc1074813fb673/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/280b06eee03270de0e7061fc9ddc1074813fb673"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/280b06eee03270de0e7061fc9ddc1074813fb673"
                        },
                        "patch": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/280b06eee03270de0e7061fc9ddc1074813fb673"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/280b06eee03270de0e7061fc9ddc1074813fb673"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/280b06eee03270de0e7061fc9ddc1074813fb673/statuses"
                        }
                    },
                    "message": "something",
                    "parents": [
                        {
                            "hash": "55bd85ede00629cb008dfa15981e7d4167bdb2da",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/rotemamit/start_repo/commits/55bd85ede00629cb008dfa15981e7d4167bdb2da"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/55bd85ede00629cb008dfa15981e7d4167bdb2da"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "type": "commit"
                },
                "type": "branch"
            },
            {
                "default_merge_strategy": "merge_commit",
                "links": {
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/new-branch-test"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/branch/new-branch-test"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/new-branch-test"
                    }
                },
                "merge_strategies": [
                    "merge_commit",
                    "squash",
                    "fast_forward"
                ],
                "name": "new-branch-test",
                "target": {
                    "author": {
                        "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                        "type": "author",
                        "user": {
                            "account_id": "62cf63f7e546e8eab8eee042",
                            "display_name": "Rotem Amit",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                                }
                            },
                            "nickname": "Rotem Amit",
                            "type": "user",
                            "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                        }
                    },
                    "date": "2022-09-08T12:15:52+00:00",
                    "hash": "a34489d3e51252c2fbc5f466cb9b6364251031a1",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a34489d3e51252c2fbc5f466cb9b6364251031a1/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a34489d3e51252c2fbc5f466cb9b6364251031a1/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/a34489d3e51252c2fbc5f466cb9b6364251031a1"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/a34489d3e51252c2fbc5f466cb9b6364251031a1"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a34489d3e51252c2fbc5f466cb9b6364251031a1"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a34489d3e51252c2fbc5f466cb9b6364251031a1/statuses"
                        }
                    },
                    "message": "Merged in new-b-2 (pull request #5)\n\nmerge new-b-2 branch",
                    "parents": [
                        {
                            "hash": "4aebd5fb3b624d02c6e6b8df75f0cf76324d7f7a",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/rotemamit/start_repo/commits/4aebd5fb3b624d02c6e6b8df75f0cf76324d7f7a"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/4aebd5fb3b624d02c6e6b8df75f0cf76324d7f7a"
                                }
                            },
                            "type": "commit"
                        },
                        {
                            "hash": "d478b19e9c972caceb36776a97e6ea6ae919429d",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/rotemamit/start_repo/commits/d478b19e9c972caceb36776a97e6ea6ae919429d"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d478b19e9c972caceb36776a97e6ea6ae919429d"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "type": "commit"
                },
                "type": "branch"
            },
            {
                "default_merge_strategy": "merge_commit",
                "links": {
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/somethingNew"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/branch/somethingNew"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/somethingNew"
                    }
                },
                "merge_strategies": [
                    "merge_commit",
                    "squash",
                    "fast_forward"
                ],
                "name": "somethingNew",
                "target": {
                    "author": {
                        "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                        "type": "author",
                        "user": {
                            "account_id": "62cf63f7e546e8eab8eee042",
                            "display_name": "Rotem Amit",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                                }
                            },
                            "nickname": "Rotem Amit",
                            "type": "user",
                            "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                        }
                    },
                    "date": "2022-09-08T14:42:10+00:00",
                    "hash": "8c16852446a18f554dd7a4c1831324e7b8e875a5",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8c16852446a18f554dd7a4c1831324e7b8e875a5/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8c16852446a18f554dd7a4c1831324e7b8e875a5/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/8c16852446a18f554dd7a4c1831324e7b8e875a5"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/8c16852446a18f554dd7a4c1831324e7b8e875a5"
                        },
                        "patch": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/8c16852446a18f554dd7a4c1831324e7b8e875a5"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8c16852446a18f554dd7a4c1831324e7b8e875a5"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8c16852446a18f554dd7a4c1831324e7b8e875a5/statuses"
                        }
                    },
                    "message": "adding hola",
                    "parents": [
                        {
                            "hash": "a34489d3e51252c2fbc5f466cb9b6364251031a1",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/rotemamit/start_repo/commits/a34489d3e51252c2fbc5f466cb9b6364251031a1"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a34489d3e51252c2fbc5f466cb9b6364251031a1"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "type": "commit"
                },
                "type": "branch"
            },
            {
                "default_merge_strategy": "merge_commit",
                "links": {
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/test"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/branch/test"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/test"
                    }
                },
                "merge_strategies": [
                    "merge_commit",
                    "squash",
                    "fast_forward"
                ],
                "name": "test",
                "target": {
                    "author": {
                        "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                        "type": "author",
                        "user": {
                            "account_id": "62cf63f7e546e8eab8eee042",
                            "display_name": "Rotem Amit",
                            "links": {
                                "avatar": {
                                    "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                                },
                                "html": {
                                    "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                                }
                            },
                            "nickname": "Rotem Amit",
                            "type": "user",
                            "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                        }
                    },
                    "date": "2022-09-15T15:30:00+00:00",
                    "hash": "01bc3d6f96a449a854ee64ee28492a572dca4192",
                    "links": {
                        "approve": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192/approve"
                        },
                        "comments": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192/comments"
                        },
                        "diff": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/01bc3d6f96a449a854ee64ee28492a572dca4192"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/01bc3d6f96a449a854ee64ee28492a572dca4192"
                        },
                        "patch": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/01bc3d6f96a449a854ee64ee28492a572dca4192"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192"
                        },
                        "statuses": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192/statuses"
                        }
                    },
                    "message": "delete message file1",
                    "parents": [
                        {
                            "hash": "024b71da753f6202b83b095e631b42a9594b4c88",
                            "links": {
                                "html": {
                                    "href": "https://bitbucket.org/rotemamit/start_repo/commits/024b71da753f6202b83b095e631b42a9594b4c88"
                                },
                                "self": {
                                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/024b71da753f6202b83b095e631b42a9594b4c88"
                                }
                            },
                            "type": "commit"
                        }
                    ],
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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

>### The list of open branches
>|Name|LastCommitCreatedBy|LastCommitCreatedAt|LastCommitHash|
>|---|---|---|---|
>| master | Rotem Amit | 2022-09-18T08:56:56+00:00 | 3f77114f285c8b1bd5c0254aad639b4e840d07db |
>| branch | Rotem Amit | 2022-09-08T14:59:22+00:00 | 280b06eee03270de0e7061fc9ddc1074813fb673 |
>| new-branch-test | Rotem Amit | 2022-09-08T12:15:52+00:00 | a34489d3e51252c2fbc5f466cb9b6364251031a1 |
>| somethingNew | Rotem Amit | 2022-09-08T14:42:10+00:00 | 8c16852446a18f554dd7a4c1831324e7b8e875a5 |
>| test | Rotem Amit | 2022-09-15T15:30:00+00:00 | 01bc3d6f96a449a854ee64ee28492a572dca4192 |


### bitbucket-branch-get
***
 


#### Base Command

`bitbucket-branch-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name, should be given here or in the instance arguments. | Optional | 
| branch_name | The name of the wanted branch. | Required | 


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
| Bitbucket.Branch.target.author.user.uuid | String | The unique unique universal id of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.account_id | String | The account id of the author of the last action in the branch. | 
| Bitbucket.Branch.target.author.user.nickname | String | The nickname of the author of the last action in the branch. | 
| Bitbucket.Branch.target.message | String | The message associated with last action in the branch. | 
| Bitbucket.Branch.target.links | String | The links of the last action in the branch. | 
| Bitbucket.Branch.target.parents.type | String | The type of the parents of last action in the branch. | 
| Bitbucket.Branch.target.parents.hash | String | The hash of the parents of last action in the branch. | 
| Bitbucket.Branch.target.parents.links | String | The link about the parents of the parent of last action in the branch. | 
| Bitbucket.Branch.target.repository.type | String | The type of the branch repository. | 
| Bitbucket.Branch.target.repository.full_name | String | The name of the branch repository. | 
| Bitbucket.Branch.target.repository.links | String | Links with information about the branch repository. | 
| Bitbucket.Branch.target.repository.name | String | the name of the repository. | 
| Bitbucket.Branch.target.repository.uuid | String | The unique id of the repository. | 
| Bitbucket.Branch.links | String | Links with information about the branch. | 
| Bitbucket.Branch.type | String | The type of the branch | 
| Bitbucket.Branch.merge_strategies | String | The merge strategy of the branch | 
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
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/master"
                },
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/branch/master"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/master"
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
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-18T08:07:38+00:00",
                "hash": "5d03502e3f5c79f8ec79d7d005d8918403562153",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/statuses"
                    }
                },
                "message": "delete the new file",
                "parents": [
                    {
                        "hash": "7dc2d5ed593c87736046b6a8621e01c81416181d",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/7dc2d5ed593c87736046b6a8621e01c81416181d"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "type": "commit"
            },
            "type": "branch"
        }
    }
}
```

#### Human Readable Output

>### Information about the branch master
>|Name|LastCommitCreatedBy|LastCommitCreatedAt|LastCommitHash|
>|---|---|---|---|
>| master | Rotem Amit | 2022-09-18T08:07:38+00:00 | 5d03502e3f5c79f8ec79d7d005d8918403562153 |


### bitbucket-branch-create
***
 


#### Base Command

`bitbucket-branch-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| name | The name of the new branch. | Required | 
| target_branch | The name of the branch from which the new branch will be created. | Required | 


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
| Bitbucket.Branch.target.author.user.type | String | The user  type of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.uuid | String | The unique id of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.account_id | String | The account id of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.author.user.nickname | String | The nickname of the author of the last action in the target branch. | 
| Bitbucket.Branch.target.message | String | The message in the last action in the target branch. | 
| Bitbucket.Branch.target.links | String | The links with the information about the target branch. | 
| Bitbucket.Branch.target.parents.type | String | The type of the parent action of the last action in the target branch. | 
| Bitbucket.Branch.target.parents.hash | String | The hash of the parent action of the last action in the target branch. | 
| Bitbucket.Branch.target.parents.links | String | The links to the parent action information. | 
| Bitbucket.Branch.target.repository.type | String | The type of the repository of the target branch. | 
| Bitbucket.Branch.target.repository.full_name | String | The full name of the repository of the target branch. | 
| Bitbucket.Branch.target.repository.links | String | The links with the information about the repository of the target branch. | 
| Bitbucket.Branch.target.repository.name | String | The name of the repository of the target branch. | 
| Bitbucket.Branch.target.repository.uuid | String | The unique id of the repository of the target branch. | 
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
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commits/testing"
                },
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/branch/testing"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/refs/branches/testing"
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
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-18T08:07:38+00:00",
                "hash": "5d03502e3f5c79f8ec79d7d005d8918403562153",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/statuses"
                    }
                },
                "message": "delete the new file",
                "parents": [
                    {
                        "hash": "7dc2d5ed593c87736046b6a8621e01c81416181d",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/7dc2d5ed593c87736046b6a8621e01c81416181d"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "type": "commit"
            },
            "type": "branch"
        }
    }
}
```

#### Human Readable Output

>The branch testing was created successfully.

### bitbucket-branch-delete
***
 


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
 


#### Base Command

`bitbucket-commit-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| message | Commit a message with the file. | Required | 
| branch | This branch will be associated with the commited file. | Required | 
| file_name | The name of the file to commit. | Optional | 
| file_content | The content of the file to commit. | Optional | 
| entry_id | The entry_id of the file to commit. | Optional | 
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
 


#### Base Command

`bitbucket-commit-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| file_path | Will limit the results to commits that affect that path. | Optional | 
| excluded_branches | Should be comma separated. Will return only commits that are not in the excluded branches list. | Optional | 
| included_branches | Should be comma separated. Will return only commits that are related to the included branches list. | Optional | 
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


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
| Bitbucket.Commit.author.user.type | String | The type of the user of the author. | 
| Bitbucket.Commit.author.user.uuid | String | The user unique key of the author. | 
| Bitbucket.Commit.author.user.account_id | String | The user account id of the author. | 
| Bitbucket.Commit.author.user.nickname | String | The user nickname of the author. | 
| Bitbucket.Commit.message | String | The commit message | 
| Bitbucket.Commit.summary.type | String | The type of the summary. | 
| Bitbucket.Commit.summary.raw | String | The raw summary of the commit. | 
| Bitbucket.Commit.summary.markup | String | The text styling type, such as markdown. | 
| Bitbucket.Commit.summary.html | String | The summary in html format. | 
| Bitbucket.Commit.links | String | Links with information about the commit. | 
| Bitbucket.Commit.parents.type | String | The type of the commit parents. | 
| Bitbucket.Commit.parents.hash | String | The hash of the commit parents | 
| Bitbucket.Commit.parents.links | String | Links with information about the parents. | 
| Bitbucket.Commit.repository.type | String | The type of the repository. | 
| Bitbucket.Commit.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Commit.repository.links.self.href | String | Links with information about the repository. | 
| Bitbucket.Commit.repository.name | String | The name of the repository. | 
| Bitbucket.Commit.repository.uuid | String | The unique id of the repository | 

#### Command example
```!bitbucket-commit-list```
#### Context Example
```json
{
    "Bitbucket": {
        "Commit": [
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-18T08:56:51+00:00",
                "hash": "151c21c5942be1dc522c12433c8d391960bce646",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/151c21c5942be1dc522c12433c8d391960bce646/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/151c21c5942be1dc522c12433c8d391960bce646/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/151c21c5942be1dc522c12433c8d391960bce646"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/151c21c5942be1dc522c12433c8d391960bce646"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/151c21c5942be1dc522c12433c8d391960bce646"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/151c21c5942be1dc522c12433c8d391960bce646"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/151c21c5942be1dc522c12433c8d391960bce646/statuses"
                    }
                },
                "message": "checking master",
                "parents": [
                    {
                        "hash": "5d03502e3f5c79f8ec79d7d005d8918403562153",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/5d03502e3f5c79f8ec79d7d005d8918403562153"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153"
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
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-18T08:07:38+00:00",
                "hash": "5d03502e3f5c79f8ec79d7d005d8918403562153",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5d03502e3f5c79f8ec79d7d005d8918403562153/statuses"
                    }
                },
                "message": "delete the new file",
                "parents": [
                    {
                        "hash": "7dc2d5ed593c87736046b6a8621e01c81416181d",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/7dc2d5ed593c87736046b6a8621e01c81416181d"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d"
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
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete the new file</p>",
                    "markup": "markdown",
                    "raw": "delete the new file",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-18T08:04:24+00:00",
                "hash": "7dc2d5ed593c87736046b6a8621e01c81416181d",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/7dc2d5ed593c87736046b6a8621e01c81416181d"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/7dc2d5ed593c87736046b6a8621e01c81416181d"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/7dc2d5ed593c87736046b6a8621e01c81416181d"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7dc2d5ed593c87736046b6a8621e01c81416181d/statuses"
                    }
                },
                "message": "checking master",
                "parents": [
                    {
                        "hash": "a34489d3e51252c2fbc5f466cb9b6364251031a1",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/a34489d3e51252c2fbc5f466cb9b6364251031a1"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a34489d3e51252c2fbc5f466cb9b6364251031a1"
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
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T15:30:00+00:00",
                "hash": "01bc3d6f96a449a854ee64ee28492a572dca4192",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/01bc3d6f96a449a854ee64ee28492a572dca4192"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/01bc3d6f96a449a854ee64ee28492a572dca4192"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/01bc3d6f96a449a854ee64ee28492a572dca4192"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a449a854ee64ee28492a572dca4192/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "024b71da753f6202b83b095e631b42a9594b4c88",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/024b71da753f6202b83b095e631b42a9594b4c88"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/024b71da753f6202b83b095e631b42a9594b4c88"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T15:29:54+00:00",
                "hash": "024b71da753f6202b83b095e631b42a9594b4c88",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/024b71da753f6202b83b095e631b42a9594b4c88/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/024b71da753f6202b83b095e631b42a9594b4c88/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/024b71da753f6202b83b095e631b42a9594b4c88"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/024b71da753f6202b83b095e631b42a9594b4c88"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/024b71da753f6202b83b095e631b42a9594b4c88"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/024b71da753f6202b83b095e631b42a9594b4c88"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/024b71da753f6202b83b095e631b42a9594b4c88/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "5306a6e291141abf66de66aecdea8619f7eb69d5",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/5306a6e291141abf66de66aecdea8619f7eb69d5"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5306a6e291141abf66de66aecdea8619f7eb69d5"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T15:27:53+00:00",
                "hash": "5306a6e291141abf66de66aecdea8619f7eb69d5",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5306a6e291141abf66de66aecdea8619f7eb69d5/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5306a6e291141abf66de66aecdea8619f7eb69d5/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/5306a6e291141abf66de66aecdea8619f7eb69d5"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/5306a6e291141abf66de66aecdea8619f7eb69d5"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/5306a6e291141abf66de66aecdea8619f7eb69d5"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5306a6e291141abf66de66aecdea8619f7eb69d5"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5306a6e291141abf66de66aecdea8619f7eb69d5/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "826055c13c6f129153e900002f0c592aae28423f",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/826055c13c6f129153e900002f0c592aae28423f"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/826055c13c6f129153e900002f0c592aae28423f"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T15:27:47+00:00",
                "hash": "826055c13c6f129153e900002f0c592aae28423f",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/826055c13c6f129153e900002f0c592aae28423f/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/826055c13c6f129153e900002f0c592aae28423f/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/826055c13c6f129153e900002f0c592aae28423f"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/826055c13c6f129153e900002f0c592aae28423f"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/826055c13c6f129153e900002f0c592aae28423f"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/826055c13c6f129153e900002f0c592aae28423f"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/826055c13c6f129153e900002f0c592aae28423f/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "38337a5636bf0eba20814f9ec30b1d458713c418",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/38337a5636bf0eba20814f9ec30b1d458713c418"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/38337a5636bf0eba20814f9ec30b1d458713c418"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:44:33+00:00",
                "hash": "38337a5636bf0eba20814f9ec30b1d458713c418",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/38337a5636bf0eba20814f9ec30b1d458713c418/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/38337a5636bf0eba20814f9ec30b1d458713c418/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/38337a5636bf0eba20814f9ec30b1d458713c418"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/38337a5636bf0eba20814f9ec30b1d458713c418"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/38337a5636bf0eba20814f9ec30b1d458713c418"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/38337a5636bf0eba20814f9ec30b1d458713c418"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/38337a5636bf0eba20814f9ec30b1d458713c418/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "491e5b318c78d5964a2249b1c55020ff4f1ac2f8",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/491e5b318c78d5964a2249b1c55020ff4f1ac2f8"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/491e5b318c78d5964a2249b1c55020ff4f1ac2f8"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:44:26+00:00",
                "hash": "491e5b318c78d5964a2249b1c55020ff4f1ac2f8",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/491e5b318c78d5964a2249b1c55020ff4f1ac2f8/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/491e5b318c78d5964a2249b1c55020ff4f1ac2f8/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/491e5b318c78d5964a2249b1c55020ff4f1ac2f8"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/491e5b318c78d5964a2249b1c55020ff4f1ac2f8"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/491e5b318c78d5964a2249b1c55020ff4f1ac2f8"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/491e5b318c78d5964a2249b1c55020ff4f1ac2f8"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/491e5b318c78d5964a2249b1c55020ff4f1ac2f8/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "b34fca58dce227ef9d66ad27177573a3e808beb9",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/b34fca58dce227ef9d66ad27177573a3e808beb9"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b34fca58dce227ef9d66ad27177573a3e808beb9"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:40:47+00:00",
                "hash": "b34fca58dce227ef9d66ad27177573a3e808beb9",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b34fca58dce227ef9d66ad27177573a3e808beb9/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b34fca58dce227ef9d66ad27177573a3e808beb9/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/b34fca58dce227ef9d66ad27177573a3e808beb9"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/b34fca58dce227ef9d66ad27177573a3e808beb9"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/b34fca58dce227ef9d66ad27177573a3e808beb9"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b34fca58dce227ef9d66ad27177573a3e808beb9"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b34fca58dce227ef9d66ad27177573a3e808beb9/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "b8e564f69a22d0b0a3696fc272946ee4a0a59716",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/b8e564f69a22d0b0a3696fc272946ee4a0a59716"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b8e564f69a22d0b0a3696fc272946ee4a0a59716"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:40:41+00:00",
                "hash": "b8e564f69a22d0b0a3696fc272946ee4a0a59716",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b8e564f69a22d0b0a3696fc272946ee4a0a59716/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b8e564f69a22d0b0a3696fc272946ee4a0a59716/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/b8e564f69a22d0b0a3696fc272946ee4a0a59716"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/b8e564f69a22d0b0a3696fc272946ee4a0a59716"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/b8e564f69a22d0b0a3696fc272946ee4a0a59716"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b8e564f69a22d0b0a3696fc272946ee4a0a59716"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b8e564f69a22d0b0a3696fc272946ee4a0a59716/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "b4849a829ef3b2e94ad6fa6862c14b416664b993",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/b4849a829ef3b2e94ad6fa6862c14b416664b993"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b4849a829ef3b2e94ad6fa6862c14b416664b993"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:37:37+00:00",
                "hash": "b4849a829ef3b2e94ad6fa6862c14b416664b993",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b4849a829ef3b2e94ad6fa6862c14b416664b993/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b4849a829ef3b2e94ad6fa6862c14b416664b993/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/b4849a829ef3b2e94ad6fa6862c14b416664b993"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/b4849a829ef3b2e94ad6fa6862c14b416664b993"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/b4849a829ef3b2e94ad6fa6862c14b416664b993"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b4849a829ef3b2e94ad6fa6862c14b416664b993"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b4849a829ef3b2e94ad6fa6862c14b416664b993/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "59c0666c0e2ab3ce8011c2e6c784f4a667bb2738",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:37:31+00:00",
                "hash": "59c0666c0e2ab3ce8011c2e6c784f4a667bb2738",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/59c0666c0e2ab3ce8011c2e6c784f4a667bb2738/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "6fc2daed6483df82f826e706147cb4c8414d11f9",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/6fc2daed6483df82f826e706147cb4c8414d11f9"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6fc2daed6483df82f826e706147cb4c8414d11f9"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T12:35:04+00:00",
                "hash": "6fc2daed6483df82f826e706147cb4c8414d11f9",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6fc2daed6483df82f826e706147cb4c8414d11f9/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6fc2daed6483df82f826e706147cb4c8414d11f9/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/6fc2daed6483df82f826e706147cb4c8414d11f9"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/6fc2daed6483df82f826e706147cb4c8414d11f9"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/6fc2daed6483df82f826e706147cb4c8414d11f9"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6fc2daed6483df82f826e706147cb4c8414d11f9"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6fc2daed6483df82f826e706147cb4c8414d11f9/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "7a28ca0deea544e69e1252df796ae5da8359b930",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/7a28ca0deea544e69e1252df796ae5da8359b930"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a28ca0deea544e69e1252df796ae5da8359b930"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:08:02+00:00",
                "hash": "7a28ca0deea544e69e1252df796ae5da8359b930",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a28ca0deea544e69e1252df796ae5da8359b930/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a28ca0deea544e69e1252df796ae5da8359b930/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/7a28ca0deea544e69e1252df796ae5da8359b930"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/7a28ca0deea544e69e1252df796ae5da8359b930"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/7a28ca0deea544e69e1252df796ae5da8359b930"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a28ca0deea544e69e1252df796ae5da8359b930"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a28ca0deea544e69e1252df796ae5da8359b930/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "8b2ff5cef178646ec7344e0176530673d48ca0d8",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/8b2ff5cef178646ec7344e0176530673d48ca0d8"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8b2ff5cef178646ec7344e0176530673d48ca0d8"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:07:55+00:00",
                "hash": "8b2ff5cef178646ec7344e0176530673d48ca0d8",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8b2ff5cef178646ec7344e0176530673d48ca0d8/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8b2ff5cef178646ec7344e0176530673d48ca0d8/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/8b2ff5cef178646ec7344e0176530673d48ca0d8"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/8b2ff5cef178646ec7344e0176530673d48ca0d8"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/8b2ff5cef178646ec7344e0176530673d48ca0d8"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8b2ff5cef178646ec7344e0176530673d48ca0d8"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8b2ff5cef178646ec7344e0176530673d48ca0d8/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "fc37daaacb702275bbd41433cd7d20bde245dc13",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/fc37daaacb702275bbd41433cd7d20bde245dc13"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fc37daaacb702275bbd41433cd7d20bde245dc13"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:07:24+00:00",
                "hash": "fc37daaacb702275bbd41433cd7d20bde245dc13",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fc37daaacb702275bbd41433cd7d20bde245dc13/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fc37daaacb702275bbd41433cd7d20bde245dc13/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/fc37daaacb702275bbd41433cd7d20bde245dc13"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/fc37daaacb702275bbd41433cd7d20bde245dc13"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/fc37daaacb702275bbd41433cd7d20bde245dc13"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fc37daaacb702275bbd41433cd7d20bde245dc13"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fc37daaacb702275bbd41433cd7d20bde245dc13/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "92fac9a857d9eb93d257c547e7aa09f127611273",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/92fac9a857d9eb93d257c547e7aa09f127611273"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/92fac9a857d9eb93d257c547e7aa09f127611273"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:07:18+00:00",
                "hash": "92fac9a857d9eb93d257c547e7aa09f127611273",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/92fac9a857d9eb93d257c547e7aa09f127611273/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/92fac9a857d9eb93d257c547e7aa09f127611273/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/92fac9a857d9eb93d257c547e7aa09f127611273"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/92fac9a857d9eb93d257c547e7aa09f127611273"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/92fac9a857d9eb93d257c547e7aa09f127611273"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/92fac9a857d9eb93d257c547e7aa09f127611273"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/92fac9a857d9eb93d257c547e7aa09f127611273/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "cc1c333081e8ffadcb0261fcff8eb05057d6151a",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/cc1c333081e8ffadcb0261fcff8eb05057d6151a"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cc1c333081e8ffadcb0261fcff8eb05057d6151a"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:05:34+00:00",
                "hash": "cc1c333081e8ffadcb0261fcff8eb05057d6151a",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cc1c333081e8ffadcb0261fcff8eb05057d6151a/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cc1c333081e8ffadcb0261fcff8eb05057d6151a/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/cc1c333081e8ffadcb0261fcff8eb05057d6151a"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/cc1c333081e8ffadcb0261fcff8eb05057d6151a"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/cc1c333081e8ffadcb0261fcff8eb05057d6151a"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cc1c333081e8ffadcb0261fcff8eb05057d6151a"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cc1c333081e8ffadcb0261fcff8eb05057d6151a/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:05:28+00:00",
                "hash": "83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:03:40+00:00",
                "hash": "23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "fa30601cd2fbf68acb255cfcb0825e3502749c75",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/fa30601cd2fbf68acb255cfcb0825e3502749c75"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fa30601cd2fbf68acb255cfcb0825e3502749c75"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T11:03:34+00:00",
                "hash": "fa30601cd2fbf68acb255cfcb0825e3502749c75",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fa30601cd2fbf68acb255cfcb0825e3502749c75/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fa30601cd2fbf68acb255cfcb0825e3502749c75/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/fa30601cd2fbf68acb255cfcb0825e3502749c75"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/fa30601cd2fbf68acb255cfcb0825e3502749c75"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/fa30601cd2fbf68acb255cfcb0825e3502749c75"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fa30601cd2fbf68acb255cfcb0825e3502749c75"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/fa30601cd2fbf68acb255cfcb0825e3502749c75/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "7a2f3c451505cd6ef0b0acaa81a2d072db979afb",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/7a2f3c451505cd6ef0b0acaa81a2d072db979afb"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a2f3c451505cd6ef0b0acaa81a2d072db979afb"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T10:43:21+00:00",
                "hash": "7a2f3c451505cd6ef0b0acaa81a2d072db979afb",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a2f3c451505cd6ef0b0acaa81a2d072db979afb/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a2f3c451505cd6ef0b0acaa81a2d072db979afb/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/7a2f3c451505cd6ef0b0acaa81a2d072db979afb"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/7a2f3c451505cd6ef0b0acaa81a2d072db979afb"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/7a2f3c451505cd6ef0b0acaa81a2d072db979afb"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a2f3c451505cd6ef0b0acaa81a2d072db979afb"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/7a2f3c451505cd6ef0b0acaa81a2d072db979afb/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "78af4a5b82c093b5318ce38b70f060000c7b6589",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/78af4a5b82c093b5318ce38b70f060000c7b6589"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/78af4a5b82c093b5318ce38b70f060000c7b6589"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T10:43:15+00:00",
                "hash": "78af4a5b82c093b5318ce38b70f060000c7b6589",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/78af4a5b82c093b5318ce38b70f060000c7b6589/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/78af4a5b82c093b5318ce38b70f060000c7b6589/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/78af4a5b82c093b5318ce38b70f060000c7b6589"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/78af4a5b82c093b5318ce38b70f060000c7b6589"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/78af4a5b82c093b5318ce38b70f060000c7b6589"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/78af4a5b82c093b5318ce38b70f060000c7b6589"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/78af4a5b82c093b5318ce38b70f060000c7b6589/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "ff030e26759e989bf365e2bffa194efa78fe7797",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/ff030e26759e989bf365e2bffa194efa78fe7797"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ff030e26759e989bf365e2bffa194efa78fe7797"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T09:59:42+00:00",
                "hash": "ff030e26759e989bf365e2bffa194efa78fe7797",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ff030e26759e989bf365e2bffa194efa78fe7797/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ff030e26759e989bf365e2bffa194efa78fe7797/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/ff030e26759e989bf365e2bffa194efa78fe7797"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/ff030e26759e989bf365e2bffa194efa78fe7797"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/ff030e26759e989bf365e2bffa194efa78fe7797"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ff030e26759e989bf365e2bffa194efa78fe7797"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ff030e26759e989bf365e2bffa194efa78fe7797/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "83d0ee6d3dcce37756b44604be1bf18870885ac2",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/83d0ee6d3dcce37756b44604be1bf18870885ac2"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83d0ee6d3dcce37756b44604be1bf18870885ac2"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T09:59:36+00:00",
                "hash": "83d0ee6d3dcce37756b44604be1bf18870885ac2",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83d0ee6d3dcce37756b44604be1bf18870885ac2/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83d0ee6d3dcce37756b44604be1bf18870885ac2/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/83d0ee6d3dcce37756b44604be1bf18870885ac2"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/83d0ee6d3dcce37756b44604be1bf18870885ac2"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/83d0ee6d3dcce37756b44604be1bf18870885ac2"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83d0ee6d3dcce37756b44604be1bf18870885ac2"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/83d0ee6d3dcce37756b44604be1bf18870885ac2/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "a4def6746cc0d76650b14393385fef6982757555",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/a4def6746cc0d76650b14393385fef6982757555"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a4def6746cc0d76650b14393385fef6982757555"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T09:58:08+00:00",
                "hash": "a4def6746cc0d76650b14393385fef6982757555",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a4def6746cc0d76650b14393385fef6982757555/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a4def6746cc0d76650b14393385fef6982757555/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/a4def6746cc0d76650b14393385fef6982757555"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/a4def6746cc0d76650b14393385fef6982757555"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/a4def6746cc0d76650b14393385fef6982757555"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a4def6746cc0d76650b14393385fef6982757555"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/a4def6746cc0d76650b14393385fef6982757555/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T09:58:02+00:00",
                "hash": "d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T08:58:24+00:00",
                "hash": "3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "e8cd1d37f44d287bb0070e922e5ed138731265e5",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/e8cd1d37f44d287bb0070e922e5ed138731265e5"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8cd1d37f44d287bb0070e922e5ed138731265e5"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T08:58:18+00:00",
                "hash": "e8cd1d37f44d287bb0070e922e5ed138731265e5",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8cd1d37f44d287bb0070e922e5ed138731265e5/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8cd1d37f44d287bb0070e922e5ed138731265e5/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/e8cd1d37f44d287bb0070e922e5ed138731265e5"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/e8cd1d37f44d287bb0070e922e5ed138731265e5"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/e8cd1d37f44d287bb0070e922e5ed138731265e5"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8cd1d37f44d287bb0070e922e5ed138731265e5"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8cd1d37f44d287bb0070e922e5ed138731265e5/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "62037ead3b3c22343f19ceaf8b8b30a017e07f6e",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/62037ead3b3c22343f19ceaf8b8b30a017e07f6e"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/62037ead3b3c22343f19ceaf8b8b30a017e07f6e"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T08:57:46+00:00",
                "hash": "62037ead3b3c22343f19ceaf8b8b30a017e07f6e",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/62037ead3b3c22343f19ceaf8b8b30a017e07f6e/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/62037ead3b3c22343f19ceaf8b8b30a017e07f6e/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/62037ead3b3c22343f19ceaf8b8b30a017e07f6e"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/62037ead3b3c22343f19ceaf8b8b30a017e07f6e"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/62037ead3b3c22343f19ceaf8b8b30a017e07f6e"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/62037ead3b3c22343f19ceaf8b8b30a017e07f6e"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/62037ead3b3c22343f19ceaf8b8b30a017e07f6e/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "ce7826c474e513686e969092d3636bbd66668179",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/ce7826c474e513686e969092d3636bbd66668179"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ce7826c474e513686e969092d3636bbd66668179"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T08:57:39+00:00",
                "hash": "ce7826c474e513686e969092d3636bbd66668179",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ce7826c474e513686e969092d3636bbd66668179/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ce7826c474e513686e969092d3636bbd66668179/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/ce7826c474e513686e969092d3636bbd66668179"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/ce7826c474e513686e969092d3636bbd66668179"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/ce7826c474e513686e969092d3636bbd66668179"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ce7826c474e513686e969092d3636bbd66668179"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ce7826c474e513686e969092d3636bbd66668179/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "6400fd2b3bca6130eac327a59e20a84ce8b33b27",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/6400fd2b3bca6130eac327a59e20a84ce8b33b27"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6400fd2b3bca6130eac327a59e20a84ce8b33b27"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T08:57:13+00:00",
                "hash": "6400fd2b3bca6130eac327a59e20a84ce8b33b27",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6400fd2b3bca6130eac327a59e20a84ce8b33b27/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6400fd2b3bca6130eac327a59e20a84ce8b33b27/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/6400fd2b3bca6130eac327a59e20a84ce8b33b27"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/6400fd2b3bca6130eac327a59e20a84ce8b33b27"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/6400fd2b3bca6130eac327a59e20a84ce8b33b27"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6400fd2b3bca6130eac327a59e20a84ce8b33b27"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6400fd2b3bca6130eac327a59e20a84ce8b33b27/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "c5c7b3b4475a752433721c0525efef627a1c0fce",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/c5c7b3b4475a752433721c0525efef627a1c0fce"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/c5c7b3b4475a752433721c0525efef627a1c0fce"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T08:57:07+00:00",
                "hash": "c5c7b3b4475a752433721c0525efef627a1c0fce",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/c5c7b3b4475a752433721c0525efef627a1c0fce/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/c5c7b3b4475a752433721c0525efef627a1c0fce/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/c5c7b3b4475a752433721c0525efef627a1c0fce"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/c5c7b3b4475a752433721c0525efef627a1c0fce"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/c5c7b3b4475a752433721c0525efef627a1c0fce"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/c5c7b3b4475a752433721c0525efef627a1c0fce"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/c5c7b3b4475a752433721c0525efef627a1c0fce/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "b54796d1472a1ceb648bdd903d5b2226339c494d",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/b54796d1472a1ceb648bdd903d5b2226339c494d"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b54796d1472a1ceb648bdd903d5b2226339c494d"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:45:29+00:00",
                "hash": "b54796d1472a1ceb648bdd903d5b2226339c494d",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b54796d1472a1ceb648bdd903d5b2226339c494d/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b54796d1472a1ceb648bdd903d5b2226339c494d/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/b54796d1472a1ceb648bdd903d5b2226339c494d"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/b54796d1472a1ceb648bdd903d5b2226339c494d"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/b54796d1472a1ceb648bdd903d5b2226339c494d"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b54796d1472a1ceb648bdd903d5b2226339c494d"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/b54796d1472a1ceb648bdd903d5b2226339c494d/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "cdff6a51b785c44d6b15b47616dcade3ce359a34",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/cdff6a51b785c44d6b15b47616dcade3ce359a34"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cdff6a51b785c44d6b15b47616dcade3ce359a34"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:45:22+00:00",
                "hash": "cdff6a51b785c44d6b15b47616dcade3ce359a34",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cdff6a51b785c44d6b15b47616dcade3ce359a34/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cdff6a51b785c44d6b15b47616dcade3ce359a34/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/cdff6a51b785c44d6b15b47616dcade3ce359a34"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/cdff6a51b785c44d6b15b47616dcade3ce359a34"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/cdff6a51b785c44d6b15b47616dcade3ce359a34"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cdff6a51b785c44d6b15b47616dcade3ce359a34"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/cdff6a51b785c44d6b15b47616dcade3ce359a34/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "ec884e3d29a362e7fe3663ea2dfc3d19e4147598",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/ec884e3d29a362e7fe3663ea2dfc3d19e4147598"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ec884e3d29a362e7fe3663ea2dfc3d19e4147598"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:44:00+00:00",
                "hash": "ec884e3d29a362e7fe3663ea2dfc3d19e4147598",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ec884e3d29a362e7fe3663ea2dfc3d19e4147598/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ec884e3d29a362e7fe3663ea2dfc3d19e4147598/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/ec884e3d29a362e7fe3663ea2dfc3d19e4147598"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/ec884e3d29a362e7fe3663ea2dfc3d19e4147598"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/ec884e3d29a362e7fe3663ea2dfc3d19e4147598"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ec884e3d29a362e7fe3663ea2dfc3d19e4147598"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ec884e3d29a362e7fe3663ea2dfc3d19e4147598/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "e8f7b3cad94982c7e81b6718474c6e32bb604f1c",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/e8f7b3cad94982c7e81b6718474c6e32bb604f1c"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8f7b3cad94982c7e81b6718474c6e32bb604f1c"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:43:50+00:00",
                "hash": "e8f7b3cad94982c7e81b6718474c6e32bb604f1c",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8f7b3cad94982c7e81b6718474c6e32bb604f1c/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8f7b3cad94982c7e81b6718474c6e32bb604f1c/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/e8f7b3cad94982c7e81b6718474c6e32bb604f1c"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/e8f7b3cad94982c7e81b6718474c6e32bb604f1c"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/e8f7b3cad94982c7e81b6718474c6e32bb604f1c"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8f7b3cad94982c7e81b6718474c6e32bb604f1c"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/e8f7b3cad94982c7e81b6718474c6e32bb604f1c/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "6645e17710735cdd2ba6999282745b90822834b7",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/6645e17710735cdd2ba6999282745b90822834b7"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6645e17710735cdd2ba6999282745b90822834b7"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:41:43+00:00",
                "hash": "6645e17710735cdd2ba6999282745b90822834b7",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6645e17710735cdd2ba6999282745b90822834b7/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6645e17710735cdd2ba6999282745b90822834b7/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/6645e17710735cdd2ba6999282745b90822834b7"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/6645e17710735cdd2ba6999282745b90822834b7"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/6645e17710735cdd2ba6999282745b90822834b7"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6645e17710735cdd2ba6999282745b90822834b7"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6645e17710735cdd2ba6999282745b90822834b7/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "465a1dbd3fde618e7084db359b9d6c28103ab275",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/465a1dbd3fde618e7084db359b9d6c28103ab275"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/465a1dbd3fde618e7084db359b9d6c28103ab275"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:41:36+00:00",
                "hash": "465a1dbd3fde618e7084db359b9d6c28103ab275",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/465a1dbd3fde618e7084db359b9d6c28103ab275/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/465a1dbd3fde618e7084db359b9d6c28103ab275/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/465a1dbd3fde618e7084db359b9d6c28103ab275"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/465a1dbd3fde618e7084db359b9d6c28103ab275"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/465a1dbd3fde618e7084db359b9d6c28103ab275"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/465a1dbd3fde618e7084db359b9d6c28103ab275"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/465a1dbd3fde618e7084db359b9d6c28103ab275/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "10ba6d48a470622448d634377923221abd08b27c",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/10ba6d48a470622448d634377923221abd08b27c"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/10ba6d48a470622448d634377923221abd08b27c"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:40:27+00:00",
                "hash": "10ba6d48a470622448d634377923221abd08b27c",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/10ba6d48a470622448d634377923221abd08b27c/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/10ba6d48a470622448d634377923221abd08b27c/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/10ba6d48a470622448d634377923221abd08b27c"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/10ba6d48a470622448d634377923221abd08b27c"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/10ba6d48a470622448d634377923221abd08b27c"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/10ba6d48a470622448d634377923221abd08b27c"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/10ba6d48a470622448d634377923221abd08b27c/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "6e333e2865e13fddcafe53f930c20bf592ea33cb",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/6e333e2865e13fddcafe53f930c20bf592ea33cb"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6e333e2865e13fddcafe53f930c20bf592ea33cb"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:40:19+00:00",
                "hash": "6e333e2865e13fddcafe53f930c20bf592ea33cb",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6e333e2865e13fddcafe53f930c20bf592ea33cb/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6e333e2865e13fddcafe53f930c20bf592ea33cb/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/6e333e2865e13fddcafe53f930c20bf592ea33cb"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/6e333e2865e13fddcafe53f930c20bf592ea33cb"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/6e333e2865e13fddcafe53f930c20bf592ea33cb"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6e333e2865e13fddcafe53f930c20bf592ea33cb"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6e333e2865e13fddcafe53f930c20bf592ea33cb/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "ad9c667f264573cd4b4fdc313d73962973226736",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/ad9c667f264573cd4b4fdc313d73962973226736"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ad9c667f264573cd4b4fdc313d73962973226736"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:40:00+00:00",
                "hash": "ad9c667f264573cd4b4fdc313d73962973226736",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ad9c667f264573cd4b4fdc313d73962973226736/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ad9c667f264573cd4b4fdc313d73962973226736/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/ad9c667f264573cd4b4fdc313d73962973226736"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/ad9c667f264573cd4b4fdc313d73962973226736"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/ad9c667f264573cd4b4fdc313d73962973226736"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ad9c667f264573cd4b4fdc313d73962973226736"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/ad9c667f264573cd4b4fdc313d73962973226736/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "33e41c8e6428a1ea315eac0b59c76c813ea86cf6",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/33e41c8e6428a1ea315eac0b59c76c813ea86cf6"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/33e41c8e6428a1ea315eac0b59c76c813ea86cf6"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:10:33+00:00",
                "hash": "33e41c8e6428a1ea315eac0b59c76c813ea86cf6",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/33e41c8e6428a1ea315eac0b59c76c813ea86cf6/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/33e41c8e6428a1ea315eac0b59c76c813ea86cf6/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/33e41c8e6428a1ea315eac0b59c76c813ea86cf6"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/33e41c8e6428a1ea315eac0b59c76c813ea86cf6"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/33e41c8e6428a1ea315eac0b59c76c813ea86cf6"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/33e41c8e6428a1ea315eac0b59c76c813ea86cf6"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/33e41c8e6428a1ea315eac0b59c76c813ea86cf6/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "252c3f7bf5ad2d0aae74e36d97fa7da24e534080",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/252c3f7bf5ad2d0aae74e36d97fa7da24e534080"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/252c3f7bf5ad2d0aae74e36d97fa7da24e534080"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-15T07:10:26+00:00",
                "hash": "252c3f7bf5ad2d0aae74e36d97fa7da24e534080",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/252c3f7bf5ad2d0aae74e36d97fa7da24e534080/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/252c3f7bf5ad2d0aae74e36d97fa7da24e534080/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/252c3f7bf5ad2d0aae74e36d97fa7da24e534080"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/252c3f7bf5ad2d0aae74e36d97fa7da24e534080"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/252c3f7bf5ad2d0aae74e36d97fa7da24e534080"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/252c3f7bf5ad2d0aae74e36d97fa7da24e534080"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/252c3f7bf5ad2d0aae74e36d97fa7da24e534080/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "30086ce1c1d94d510687b4a910af9adab82603a0",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/30086ce1c1d94d510687b4a910af9adab82603a0"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/30086ce1c1d94d510687b4a910af9adab82603a0"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-14T16:00:30+00:00",
                "hash": "30086ce1c1d94d510687b4a910af9adab82603a0",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/30086ce1c1d94d510687b4a910af9adab82603a0/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/30086ce1c1d94d510687b4a910af9adab82603a0/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/30086ce1c1d94d510687b4a910af9adab82603a0"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/30086ce1c1d94d510687b4a910af9adab82603a0"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/30086ce1c1d94d510687b4a910af9adab82603a0"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/30086ce1c1d94d510687b4a910af9adab82603a0"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/30086ce1c1d94d510687b4a910af9adab82603a0/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "d6db12d5770d73cfe9e6f90068e759feb2379fa9",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/d6db12d5770d73cfe9e6f90068e759feb2379fa9"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d6db12d5770d73cfe9e6f90068e759feb2379fa9"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-14T16:00:24+00:00",
                "hash": "d6db12d5770d73cfe9e6f90068e759feb2379fa9",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d6db12d5770d73cfe9e6f90068e759feb2379fa9/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d6db12d5770d73cfe9e6f90068e759feb2379fa9/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/d6db12d5770d73cfe9e6f90068e759feb2379fa9"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/d6db12d5770d73cfe9e6f90068e759feb2379fa9"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/d6db12d5770d73cfe9e6f90068e759feb2379fa9"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d6db12d5770d73cfe9e6f90068e759feb2379fa9"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/d6db12d5770d73cfe9e6f90068e759feb2379fa9/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "6ca807a2e6a7102777da46cb35c7d8c7389e21a0",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/6ca807a2e6a7102777da46cb35c7d8c7389e21a0"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6ca807a2e6a7102777da46cb35c7d8c7389e21a0"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-14T15:55:36+00:00",
                "hash": "6ca807a2e6a7102777da46cb35c7d8c7389e21a0",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6ca807a2e6a7102777da46cb35c7d8c7389e21a0/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6ca807a2e6a7102777da46cb35c7d8c7389e21a0/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/6ca807a2e6a7102777da46cb35c7d8c7389e21a0"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/6ca807a2e6a7102777da46cb35c7d8c7389e21a0"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/6ca807a2e6a7102777da46cb35c7d8c7389e21a0"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6ca807a2e6a7102777da46cb35c7d8c7389e21a0"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/6ca807a2e6a7102777da46cb35c7d8c7389e21a0/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "5eb6b5b1019a459233ae8128198df57b16dc35b8",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/5eb6b5b1019a459233ae8128198df57b16dc35b8"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5eb6b5b1019a459233ae8128198df57b16dc35b8"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-14T15:55:30+00:00",
                "hash": "5eb6b5b1019a459233ae8128198df57b16dc35b8",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5eb6b5b1019a459233ae8128198df57b16dc35b8/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5eb6b5b1019a459233ae8128198df57b16dc35b8/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/5eb6b5b1019a459233ae8128198df57b16dc35b8"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/5eb6b5b1019a459233ae8128198df57b16dc35b8"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/5eb6b5b1019a459233ae8128198df57b16dc35b8"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5eb6b5b1019a459233ae8128198df57b16dc35b8"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/5eb6b5b1019a459233ae8128198df57b16dc35b8/statuses"
                    }
                },
                "message": "message",
                "parents": [
                    {
                        "hash": "64670d127131d28a816cc07c001bec52a07ae921",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/64670d127131d28a816cc07c001bec52a07ae921"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/64670d127131d28a816cc07c001bec52a07ae921"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>message</p>",
                        "markup": "markdown",
                        "raw": "message",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>message</p>",
                    "markup": "markdown",
                    "raw": "message",
                    "type": "rendered"
                },
                "type": "commit"
            },
            {
                "author": {
                    "raw": "Rotem Amit <ramit@paloaltonetworks.com>",
                    "type": "author",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
                },
                "date": "2022-09-14T15:54:05+00:00",
                "hash": "64670d127131d28a816cc07c001bec52a07ae921",
                "links": {
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/64670d127131d28a816cc07c001bec52a07ae921/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/64670d127131d28a816cc07c001bec52a07ae921/comments"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/64670d127131d28a816cc07c001bec52a07ae921"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/commits/64670d127131d28a816cc07c001bec52a07ae921"
                    },
                    "patch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/patch/64670d127131d28a816cc07c001bec52a07ae921"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/64670d127131d28a816cc07c001bec52a07ae921"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/64670d127131d28a816cc07c001bec52a07ae921/statuses"
                    }
                },
                "message": "delete message file1",
                "parents": [
                    {
                        "hash": "390778d4256b71c073c4b6b9360b5ba1803f3af1",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/390778d4256b71c073c4b6b9360b5ba1803f3af1"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/390778d4256b71c073c4b6b9360b5ba1803f3af1"
                            }
                        },
                        "type": "commit"
                    }
                ],
                "rendered": {
                    "message": {
                        "html": "<p>delete message file1</p>",
                        "markup": "markdown",
                        "raw": "delete message file1",
                        "type": "rendered"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "summary": {
                    "html": "<p>delete message file1</p>",
                    "markup": "markdown",
                    "raw": "delete message file1",
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
>| Rotem Amit <ramit@paloaltonetworks.com> | 151c21c5942be1dc522c12433c8d391960bce646 | checking master | 2022-09-18T08:56:51+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 5d03502e3f5c79f8ec79d7d005d8918403562153 | delete the new file | 2022-09-18T08:07:38+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 7dc2d5ed593c87736046b6a8621e01c81416181d | checking master | 2022-09-18T08:04:24+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 01bc3d6f96a449a854ee64ee28492a572dca4192 | delete message file1 | 2022-09-15T15:30:00+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 024b71da753f6202b83b095e631b42a9594b4c88 | message | 2022-09-15T15:29:54+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 5306a6e291141abf66de66aecdea8619f7eb69d5 | delete message file1 | 2022-09-15T15:27:53+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 826055c13c6f129153e900002f0c592aae28423f | message | 2022-09-15T15:27:47+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 38337a5636bf0eba20814f9ec30b1d458713c418 | delete message file1 | 2022-09-15T12:44:33+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 491e5b318c78d5964a2249b1c55020ff4f1ac2f8 | message | 2022-09-15T12:44:26+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | b34fca58dce227ef9d66ad27177573a3e808beb9 | delete message file1 | 2022-09-15T12:40:47+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | b8e564f69a22d0b0a3696fc272946ee4a0a59716 | message | 2022-09-15T12:40:41+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | b4849a829ef3b2e94ad6fa6862c14b416664b993 | delete message file1 | 2022-09-15T12:37:37+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 59c0666c0e2ab3ce8011c2e6c784f4a667bb2738 | message | 2022-09-15T12:37:31+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 6fc2daed6483df82f826e706147cb4c8414d11f9 | message | 2022-09-15T12:35:04+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 7a28ca0deea544e69e1252df796ae5da8359b930 | delete message file1 | 2022-09-15T11:08:02+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 8b2ff5cef178646ec7344e0176530673d48ca0d8 | message | 2022-09-15T11:07:55+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | fc37daaacb702275bbd41433cd7d20bde245dc13 | delete message file1 | 2022-09-15T11:07:24+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 92fac9a857d9eb93d257c547e7aa09f127611273 | message | 2022-09-15T11:07:18+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | cc1c333081e8ffadcb0261fcff8eb05057d6151a | delete message file1 | 2022-09-15T11:05:34+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 83415b641f8f316a5f5f8d38612a6c3e6b7fbbcc | message | 2022-09-15T11:05:28+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 23ff89d0f5f7b37c121ff5f0b7ec0824c0a9ae3d | delete message file1 | 2022-09-15T11:03:40+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | fa30601cd2fbf68acb255cfcb0825e3502749c75 | message | 2022-09-15T11:03:34+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 7a2f3c451505cd6ef0b0acaa81a2d072db979afb | delete message file1 | 2022-09-15T10:43:21+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 78af4a5b82c093b5318ce38b70f060000c7b6589 | message | 2022-09-15T10:43:15+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | ff030e26759e989bf365e2bffa194efa78fe7797 | delete message file1 | 2022-09-15T09:59:42+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 83d0ee6d3dcce37756b44604be1bf18870885ac2 | message | 2022-09-15T09:59:36+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | a4def6746cc0d76650b14393385fef6982757555 | delete message file1 | 2022-09-15T09:58:08+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | d7eb766b5b4cfedcaada3b9642cfa396f0ce6f2b | message | 2022-09-15T09:58:02+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 3dd4d6ab9480273bb4d442aa1c6b40ae7675ab99 | delete message file1 | 2022-09-15T08:58:24+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | e8cd1d37f44d287bb0070e922e5ed138731265e5 | message | 2022-09-15T08:58:18+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 62037ead3b3c22343f19ceaf8b8b30a017e07f6e | delete message file1 | 2022-09-15T08:57:46+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | ce7826c474e513686e969092d3636bbd66668179 | message | 2022-09-15T08:57:39+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 6400fd2b3bca6130eac327a59e20a84ce8b33b27 | delete message file1 | 2022-09-15T08:57:13+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | c5c7b3b4475a752433721c0525efef627a1c0fce | message | 2022-09-15T08:57:07+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | b54796d1472a1ceb648bdd903d5b2226339c494d | delete message file1 | 2022-09-15T07:45:29+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | cdff6a51b785c44d6b15b47616dcade3ce359a34 | message | 2022-09-15T07:45:22+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | ec884e3d29a362e7fe3663ea2dfc3d19e4147598 | delete message file1 | 2022-09-15T07:44:00+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | e8f7b3cad94982c7e81b6718474c6e32bb604f1c | message | 2022-09-15T07:43:50+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 6645e17710735cdd2ba6999282745b90822834b7 | delete message file1 | 2022-09-15T07:41:43+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 465a1dbd3fde618e7084db359b9d6c28103ab275 | message | 2022-09-15T07:41:36+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 10ba6d48a470622448d634377923221abd08b27c | delete message file1 | 2022-09-15T07:40:27+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 6e333e2865e13fddcafe53f930c20bf592ea33cb | message | 2022-09-15T07:40:19+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | ad9c667f264573cd4b4fdc313d73962973226736 | message | 2022-09-15T07:40:00+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 33e41c8e6428a1ea315eac0b59c76c813ea86cf6 | delete message file1 | 2022-09-15T07:10:33+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 252c3f7bf5ad2d0aae74e36d97fa7da24e534080 | message | 2022-09-15T07:10:26+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 30086ce1c1d94d510687b4a910af9adab82603a0 | delete message file1 | 2022-09-14T16:00:30+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | d6db12d5770d73cfe9e6f90068e759feb2379fa9 | message | 2022-09-14T16:00:24+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 6ca807a2e6a7102777da46cb35c7d8c7389e21a0 | delete message file1 | 2022-09-14T15:55:36+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 5eb6b5b1019a459233ae8128198df57b16dc35b8 | message | 2022-09-14T15:55:30+00:00 |
>| Rotem Amit <ramit@paloaltonetworks.com> | 64670d127131d28a816cc07c001bec52a07ae921 | delete message file1 | 2022-09-14T15:54:05+00:00 |


### bitbucket-file-delete
***
 


#### Base Command

`bitbucket-file-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| message | Commit a message with the file. | Required | 
| branch | This branch will be associated with the commited file. | Required | 
| file_name | The name of the file to commit. | Required | 
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

#### Command example
```!bitbucket-raw-file-get file_path=README.md branch=master```
#### Context Example
```json
{
    "Bitbucket": {
        "RawFile": {
            "file_content": "**Edit a file, create a new file, and clone from Bitbucket in under 2 minutes**\n\nWhen you're done, you can delete the content in this README and update the file with details for others getting started with your repository.\n\n*We recommend that you open this README in another tab as you perform the tasks below. You can [watch our video](https://youtu.be/0ocf7u76WSo) for a full demo of all the steps in this tutorial. Open the video in a new tab to avoid leaving Bitbucket.*\n\nA SMALL CHANGE :)\nJUST CHECKING\nhello everyone, do you want a merge?\n---\n\n## Edit a file\n\nYou\u00e2\u0080\u0099ll start by editing this README file to learn how to edit a file in Bitbucket.\n\n1. Click **Source** on the left side.\n2. Click the README.md link from the list of files.\n3. Click the **Edit** button.\n4. Delete the following text: *Delete this line to make a change to the README from Bitbucket.*\n5. After making your change, click **Commit** and then **Commit** again in the dialog. The commit page will open and you\u00e2\u0080\u0099ll see the change you just made.\n6. Go back to the **Source** page.\n\n---\n\n## Create a file\n\nNext, you\u00e2\u0080\u0099ll add a new file to this repository.\n\n1. Click the **New file** button at the top of the **Source** page.\n2. Give the file a filename of **contributors.txt**.\n3. Enter your name in the empty file space.\n4. Click **Commit** and then **Commit** again in the dialog.\n5. Go back to the **Source** page.\n\nBefore you move on, go ahead and explore the repository. You've already seen the **Source** page, but check out the **Commits**, **Branches**, and **Settings** pages.\n\n---\n\n## Clone a repository\n\nUse these steps to clone from SourceTree, our client for using the repository command-line free. Cloning allows you to work on your files locally. If you don't yet have SourceTree, [download and install first](https://www.sourcetreeapp.com/). If you prefer to clone from the command line, see [Clone a repository](https://confluence.atlassian.com/x/4whODQ).\n\n1. You\u00e2\u0080\u0099ll see the clone button under the **Source** heading. Click that button.\n2. Now click **Check out in SourceTree**. You may need to create a SourceTree account or log in.\n3. When you see the **Clone New** dialog in SourceTree, update the destination path and name if you\u00e2\u0080\u0099d like to and then click **Clone**.\n4. Open the directory you just created to see your repository\u00e2\u0080\u0099s files.\n\nNow that you're more familiar with your Bitbucket repository, go ahead and add a new file locally. You can [push your change back to Bitbucket with SourceTree](https://confluence.atlassian.com/x/iqyBMg), or you can [add, commit,](https://confluence.atlassian.com/x/8QhODQ) and [push from the command line](https://confluence.atlassian.com/x/NQ0zDQ).",
            "file_path": "README.md"
        }
    },
    "File": {
        "EntryID": "780@dd037e5f-7119-4218-846d-024c2ec67c1c",
        "Extension": "md",
        "Info": "md",
        "MD5": "69502080e76f06175489a9cec6387b0f",
        "Name": "README.md",
        "SHA1": "a2a0deace039c5c3b021e14955a28ce9e471bdd5",
        "SHA256": "862cc19af026969e761f8c364eba33b7a6919d796ff7ba186ced8781b7a9ec3d",
        "SHA512": "766bc1493e5be7b50281c7247dda4c748d1c258c68bc7837312916a2fefab45d2e0190768aa34d1adf928ac2453665ad32222abd63b69962d5889c4c74d53bff",
        "SSDeep": "48:D8Tf4FZcifKEUZo22bafVUuQhJ+FRBZCM6SZBrcJ5U6/5Giwrg8yXVx:RKvEUZt2bh6FRnCM6+Br2VjjXP",
        "Size": 2709,
        "Type": "Unicode text, UTF-8 text, with very long lines (357)"
    }
}
```

#### Human Readable Output

>The content of the file "README.md" is: **Edit a file, create a new file, and clone from Bitbucket in under 2 minutes**
>
>When you're done, you can delete the content in this README and update the file with details for others getting started with your repository.
>
>*We recommend that you open this README in another tab as you perform the tasks below. You can [watch our video](https:<span>//</span>youtu.be/0ocf7u76WSo) for a full demo of all the steps in this tutorial. Open the video in a new tab to avoid leaving Bitbucket.*
>
>A SMALL CHANGE :)
>JUST CHECKING
>hello everyone, do you want a merge?
>---
>
>## Edit a file
>
>Youâll start by editing this README file to learn how to edit a file in Bitbucket.
>
>1. Click **Source** on the left side.
>2. Click the README.md link from the list of files.
>3. Click the **Edit** button.
>4. Delete the following text: *Delete this line to make a change to the README from Bitbucket.*
>5. After making your change, click **Commit** and then **Commit** again in the dialog. The commit page will open and youâll see the change you just made.
>6. Go back to the **Source** page.
>
>---
>
>## Create a file
>
>Next, youâll add a new file to this repository.
>
>1. Click the **New file** button at the top of the **Source** page.
>2. Give the file a filename of **contributors.txt**.
>3. Enter your name in the empty file space.
>4. Click **Commit** and then **Commit** again in the dialog.
>5. Go back to the **Source** page.
>
>Before you move on, go ahead and explore the repository. You've already seen the **Source** page, but check out the **Commits**, **Branches**, and **Settings** pages.
>
>---
>
>## Clone a repository
>
>Use these steps to clone from SourceTree, our client for using the repository command-line free. Cloning allows you to work on your files locally. If you don't yet have SourceTree, [download and install first](https:<span>//</span>www.sourcetreeapp.com/). If you prefer to clone from the command line, see [Clone a repository](https:<span>//</span>confluence.atlassian.com/x/4whODQ).
>
>1. Youâll see the clone button under the **Source** heading. Click that button.
>2. Now click **Check out in SourceTree**. You may need to create a SourceTree account or log in.
>3. When you see the **Clone New** dialog in SourceTree, update the destination path and name if youâd like to and then click **Clone**.
>4. Open the directory you just created to see your repositoryâs files.
>
>Now that you're more familiar with your Bitbucket repository, go ahead and add a new file locally. You can [push your change back to Bitbucket with SourceTree](https:<span>//</span>confluence.atlassian.com/x/iqyBMg), or you can [add, commit,](https:<span>//</span>confluence.atlassian.com/x/8QhODQ) and [push from the command line](https:<span>//</span>confluence.atlassian.com/x/NQ0zDQ).

### bitbucket-issue-create
***
Creates an issue in Bitbucket. In order to perform this command, please create an issue tracker by clicking on the relevant repo -> Repository settings -> Issue tracker


#### Base Command

`bitbucket-issue-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| title | The title of the new issue. | Required | 
| state | The state of the issues to create. Can be 'New', 'Open', 'Resolved', 'On Hold', 'Invalid', 'Duplicate', 'Wontfix' or 'Closed'. The default is 'New'. Possible values are: new, open, resolved, on hold, invalid, duplicate, wontfix, closed. Default is new. | Optional | 
| type | The type of the issues to create. Can be 'Bug', 'Enhancement', 'Proposal', 'Task'. The default is 'Bug'. Possible values are: bug, enhancement, proposal, task. Default is bug. | Optional | 
| priority | The priority of the issues to create. Can be 'Trivial', 'Minor', 'Major', 'Critical', 'Blocker'. The default is 'Major'. Possible values are: trivial, minor, major, critical, blocker. Default is major. | Optional | 
| content | The content of the issue to create. | Optional | 
| assignee_id | The id of the assignee of the issue to create. | Optional | 
| assignee_user_name | The user name of the assignee of the issue to create. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Issue.type | String | The action type. | 
| Bitbucket.Issue.id | Number | The id of the issue. | 
| Bitbucket.Issue.repository.type | String | The type of the repository. | 
| Bitbucket.Issue.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Issue.repository.links | String | Links with information about the repository related to the issue. | 
| Bitbucket.Issue.repository.name | String | The name of the repository. | 
| Bitbucket.Issue.repository.uuid | String | The unique id of the repository. | 
| Bitbucket.Issue.links.self.href | String | An api link to the issue. | 
| Bitbucket.Issue.title | String | The title of the issue | 
| Bitbucket.Issue.content.type | String | The type of the content. | 
| Bitbucket.Issue.content.raw | String | The content of the issue. | 
| Bitbucket.Issue.content.markup | String | The type of markup \(like markdown\). | 
| Bitbucket.Issue.content.html | String | The content of the issue in html format. | 
| Bitbucket.Issue.reporter.display_name | String | The display name of the reporter of the issue. | 
| Bitbucket.Issue.reporter.links | String | Links with information about the reporter. | 
| Bitbucket.Issue.reporter.type | String | The type of the reporter. | 
| Bitbucket.Issue.reporter.uuid | String | The unique id of the reporter | 
| Bitbucket.Issue.reporter.account_id | String | The account id of the reporter. | 
| Bitbucket.Issue.reporter.nickname | String | The nickname of the reporter. | 
| Bitbucket.Issue.assignee.display_name | String | The display name of the assignee to the issue. | 
| Bitbucket.Issue.assignee.links | String | Links with information about the assignee. | 
| Bitbucket.Issue.assignee.type | String | The type of the assignee. | 
| Bitbucket.Issue.assignee.uuid | String | The unique od of the assignee. | 
| Bitbucket.Issue.assignee.account_id | String | The account id of the assignee. | 
| Bitbucket.Issue.assignee.nickname | String | The nickname of the assignee. | 
| Bitbucket.Issue.created_on | String | The creation date of the issue. | 
| Bitbucket.Issue.edited_on | Unknown | The edit date of the issue. | 
| Bitbucket.Issue.updated_on | String | The update date of the issue. | 
| Bitbucket.Issue.state | String | The state odf the issue. | 
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
            "created_on": "2022-09-18T08:57:05.560996+00:00",
            "edited_on": null,
            "id": 92,
            "kind": "bug",
            "links": {
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/92"
                }
            },
            "milestone": null,
            "priority": "major",
            "reporter": {
                "account_id": "62cf63f7e546e8eab8eee042",
                "display_name": "Rotem Amit",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "nickname": "Rotem Amit",
                "type": "user",
                "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
            },
            "repository": {
                "full_name": "rotemamit/start_repo",
                "links": {
                    "avatar": {
                        "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                    }
                },
                "name": "start_repo",
                "type": "repository",
                "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
            },
            "state": "new",
            "title": "a new issue",
            "type": "issue",
            "updated_on": "2022-09-18T08:57:05.560996+00:00",
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
 


#### Base Command

`bitbucket-issue-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| issue_id | The id of the wanted issue. | Optional | 
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Issue.type | String | The action type. | 
| Bitbucket.Issue.id | Number | The id of the issue. | 
| Bitbucket.Issue.repository.type | String | he type of the repository. | 
| Bitbucket.Issue.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Issue.repository.links | String | Links with information about the repository related to the issue. | 
| Bitbucket.Issue.repository.name | String | The name of the repository. | 
| Bitbucket.Issue.repository.uuid | String | The unique id of the repository. | 
| Bitbucket.Issue.links | String | Links with information about the issue | 
| Bitbucket.Issue.title | String | The title of the issue. | 
| Bitbucket.Issue.content.type | String | The type of the content. | 
| Bitbucket.Issue.content.raw | String | The content of the issue. | 
| Bitbucket.Issue.content.markup | String | The type of markup \(like markdown\). | 
| Bitbucket.Issue.content.html | String | The content of the issue in html format. | 
| Bitbucket.Issue.reporter.display_name | String | The display name of the reporter of the issue. | 
| Bitbucket.Issue.reporter.links | String | Links with information about the reporter. | 
| Bitbucket.Issue.reporter.type | String | The type of the reporter. | 
| Bitbucket.Issue.reporter.uuid | String | The unique id of the reporter | 
| Bitbucket.Issue.reporter.account_id | String | The account id of the reporter. | 
| Bitbucket.Issue.reporter.nickname | String | The nickname of the reporter. | 
| Bitbucket.Issue.assignee.display_name | String | The display name of the assignee to the issue. | 
| Bitbucket.Issue.assignee.links | String | Links with information about the assignee. | 
| Bitbucket.Issue.assignee.type | String | The type of the assignee. | 
| Bitbucket.Issue.assignee.uuid | String | The unique od of the assignee. | 
| Bitbucket.Issue.assignee.account_id | String | The account id of the assignee. | 
| Bitbucket.Issue.assignee.nickname | String | The nickname of the assignee. | 
| Bitbucket.Issue.created_on | String | The creation date of the issue. | 
| Bitbucket.Issue.edited_on | Unknown | The edit date of the issue. | 
| Bitbucket.Issue.updated_on | String | The update date of the issue. | 
| Bitbucket.Issue.state | String | The state odf the issue. | 
| Bitbucket.Issue.kind | String | The kind of the issue. | 
| Bitbucket.Issue.milestone | Unknown | The milestones in the issue. | 
| Bitbucket.Issue.component | Unknown | The different components of the issue. | 
| Bitbucket.Issue.priority | String | The priority of the issue. | 
| Bitbucket.Issue.version | Unknown | The version of the issue. | 
| Bitbucket.Issue.votes | Number | The votes of approval of the issue. | 
| Bitbucket.Issue.watches | Number | The watchers of the issue. | 

#### Command example
```!bitbucket-issue-list```
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
                "created_on": "2022-09-18T08:57:05.560996+00:00",
                "edited_on": null,
                "id": 92,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/92/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/92/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/92/a-new-issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/92"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/92/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/92/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
                "created_on": "2022-09-18T08:13:58.934086+00:00",
                "edited_on": null,
                "id": 91,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/91/a-new-issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "a new issue",
                "type": "issue",
                "updated_on": "2022-09-18T08:17:02.212464+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T15:30:07.882172+00:00",
                "edited_on": null,
                "id": 90,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/90/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/90/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/90/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/90"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/90/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/90/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T15:30:09.024893+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T15:30:03.366671+00:00",
                "edited_on": null,
                "id": 89,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/89/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/89/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/89/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/89"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/89/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/89/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T15:30:06.602222+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T15:28:00.067899+00:00",
                "edited_on": null,
                "id": 88,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/88/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/88/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/88/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/88"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/88/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/88/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T15:28:01.191752+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T15:27:55.460445+00:00",
                "edited_on": null,
                "id": 87,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/87/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/87/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/87/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/87"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/87/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/87/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T15:27:58.624073+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:44:53.416352+00:00",
                "edited_on": null,
                "id": 86,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/86/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/86/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/86/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/86"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/86/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/86/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:54.531016+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:44:30.534834+00:00",
                "edited_on": null,
                "id": 85,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/85/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/85/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/85/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/85"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/85/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/85/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:52.012959+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:26:37.577938+00:00",
                "edited_on": null,
                "id": 77,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/77/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/77/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/77/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/77"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/77/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/77/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.137553+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:26:42.091728+00:00",
                "edited_on": null,
                "id": 78,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/78/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/78/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/78/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/78"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/78/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/78/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.101640+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T09:59:40.292533+00:00",
                "edited_on": null,
                "id": 61,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/61/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/61/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/61/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/61"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/61/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/61/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.093964+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:42:15.215067+00:00",
                "edited_on": null,
                "id": 75,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/75/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/75/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/75/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/75"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/75/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/75/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.092630+00:00",
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
                "created_on": "2022-09-15T11:16:49.920859+00:00",
                "edited_on": null,
                "id": 70,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/70/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/70/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/70/trying-reate-a-new-issue-from-pycharm"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/70"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/70/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/70/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "trying reate a new issue from pycharm",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.086065+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:32:48.819786+00:00",
                "edited_on": null,
                "id": 73,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/73/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/73/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/73/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/73"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/73/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/73/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.083718+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:34:54.501783+00:00",
                "edited_on": null,
                "id": 79,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/79/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/79/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/79/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/79"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/79/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/79/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.081878+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:40:41.347680+00:00",
                "edited_on": null,
                "id": 83,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/83/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/83/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/83/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/83"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/83/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/83/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.079596+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:37:38.615913+00:00",
                "edited_on": null,
                "id": 82,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/82/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/82/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/82/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/82"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/82/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/82/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.068691+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:03:30.471686+00:00",
                "edited_on": null,
                "id": 64,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/64/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/64/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/64/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/64"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/64/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/64/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:51.017256+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:12:43.179200+00:00",
                "edited_on": null,
                "id": 69,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/69/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/69/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/69/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/69"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/69/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/69/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.163182+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:05:28.371771+00:00",
                "edited_on": null,
                "id": 65,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/65/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/65/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/65/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/65"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/65/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/65/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.142184+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T09:58:05.902703+00:00",
                "edited_on": null,
                "id": 59,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/59/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/59/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/59/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/59"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/59/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/59/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.137869+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:08:00.607100+00:00",
                "edited_on": null,
                "id": 67,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/67/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/67/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/67/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/67"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/67/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/67/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.136858+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T08:57:36.071745+00:00",
                "edited_on": null,
                "id": 54,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/54/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/54/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/54/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/54"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/54/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/54/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.127670+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:07:18.048004+00:00",
                "edited_on": null,
                "id": 66,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/66/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/66/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/66/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/66"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/66/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/66/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.120105+00:00",
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
                "created_on": "2022-09-15T11:22:33.881728+00:00",
                "edited_on": null,
                "id": 72,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/72/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/72/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/72/try"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/72"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/72/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/72/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "try",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.116321+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T09:58:02.175333+00:00",
                "edited_on": null,
                "id": 58,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/58/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/58/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/58/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/58"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/58/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/58/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.101759+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:12:43.124830+00:00",
                "edited_on": null,
                "id": 68,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/68/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/68/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/68/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/68"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/68/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/68/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.021221+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T08:57:07.284376+00:00",
                "edited_on": null,
                "id": 52,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/52/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/52/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/52/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/52"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/52/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/52/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:50.013133+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:45:26.069019+00:00",
                "edited_on": null,
                "id": 51,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/51/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/51/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/51/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/51"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/51/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/51/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.145333+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:45:22.013251+00:00",
                "edited_on": null,
                "id": 50,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/50/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/50/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/50/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/50"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/50/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/50/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.131648+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T10:43:30.124649+00:00",
                "edited_on": null,
                "id": 63,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/63/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/63/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/63/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/63"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/63/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/63/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.122898+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:17:53.436570+00:00",
                "edited_on": null,
                "id": 71,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/71/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/71/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/71/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/71"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/71/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/71/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.121148+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T08:58:13.577482+00:00",
                "edited_on": null,
                "id": 56,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/56/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/56/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/56/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/56"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/56/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/56/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.110010+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T08:58:16.619677+00:00",
                "edited_on": null,
                "id": 57,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/57/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/57/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/57/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/57"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/57/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/57/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.105822+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T09:59:36.897169+00:00",
                "edited_on": null,
                "id": 60,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/60/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/60/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/60/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/60"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/60/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/60/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.100776+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:40:54.503310+00:00",
                "edited_on": null,
                "id": 84,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/84/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/84/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/84/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/84"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/84/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/84/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.095291+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:42:19.654666+00:00",
                "edited_on": null,
                "id": 76,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/76/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/76/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/76/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/76"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/76/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/76/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.092157+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:35:17.065253+00:00",
                "edited_on": null,
                "id": 80,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/80/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/80/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/80/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/80"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/80/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/80/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:44:49.058635+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T11:37:08.030759+00:00",
                "edited_on": null,
                "id": 74,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/74/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/74/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/74/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/74"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/74/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/74/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:40:44.574527+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T08:57:10.507042+00:00",
                "edited_on": null,
                "id": 53,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/53/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/53/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/53/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/53"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/53/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/53/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:37:34.814883+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T12:37:31.134701+00:00",
                "edited_on": null,
                "id": 81,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/81/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/81/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/81/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/81"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/81/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/81/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:37:34.812533+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T08:57:39.314220+00:00",
                "edited_on": null,
                "id": 55,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/55/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/55/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/55/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/55"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/55/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/55/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T12:37:34.812085+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T10:43:16.382541+00:00",
                "edited_on": null,
                "id": 62,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/62/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/62/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/62/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/62"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/62/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/62/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "resolved",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T12:35:12.588480+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:43:53.441923+00:00",
                "edited_on": null,
                "id": 49,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/49/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/49/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/49/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/49"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/49/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/49/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T07:43:54.614311+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:43:49.919255+00:00",
                "edited_on": null,
                "id": 48,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/48/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/48/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/48/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/48"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/48/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/48/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T07:43:49.919255+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:41:36.558119+00:00",
                "edited_on": null,
                "id": 46,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/46/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/46/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/46/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/46"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/46/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/46/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T07:41:41.525508+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>updated content</p>",
                    "markup": "markdown",
                    "raw": "updated content",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:41:40.391502+00:00",
                "edited_on": null,
                "id": 47,
                "kind": "bug",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/47/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/47/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/47/hi-i-am-new"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/47"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/47/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/47/watch"
                    }
                },
                "milestone": null,
                "priority": "major",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "Hi I am new",
                "type": "issue",
                "updated_on": "2022-09-15T07:41:41.475910+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:40:19.315706+00:00",
                "edited_on": null,
                "id": 45,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/45/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/45/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/45/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/45"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/45/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/45/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T07:40:19.315706+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:40:00.346316+00:00",
                "edited_on": null,
                "id": 44,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/44/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/44/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/44/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/44"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/44/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/44/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T07:40:00.346316+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            },
            {
                "assignee": null,
                "component": null,
                "content": {
                    "html": "<p>enhancement for an integration</p>",
                    "markup": "markdown",
                    "raw": "enhancement for an integration",
                    "type": "rendered"
                },
                "created_on": "2022-09-15T07:10:26.667900+00:00",
                "edited_on": null,
                "id": 43,
                "kind": "enhancement",
                "links": {
                    "attachments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/43/attachments"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/43/comments"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/43/test_issue"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/43"
                    },
                    "vote": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/43/vote"
                    },
                    "watch": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/43/watch"
                    }
                },
                "milestone": null,
                "priority": "minor",
                "reporter": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "state": "open",
                "title": "test_issue",
                "type": "issue",
                "updated_on": "2022-09-15T07:10:26.667900+00:00",
                "version": null,
                "votes": 0,
                "watches": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the issues
>|Id|Title|Type|Priority|Status|Votes|CreatedAt|UpdatedAt|
>|---|---|---|---|---|---|---|---|
>| 92 | a new issue | bug | major | new | 0 | 2022-09-18T08:57:05.560996+00:00 | 2022-09-18T08:57:05.560996+00:00 |
>| 91 | a new issue | bug | major | resolved | 0 | 2022-09-18T08:13:58.934086+00:00 | 2022-09-18T08:17:02.212464+00:00 |
>| 90 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T15:30:07.882172+00:00 | 2022-09-15T15:30:09.024893+00:00 |
>| 89 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T15:30:03.366671+00:00 | 2022-09-15T15:30:06.602222+00:00 |
>| 88 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T15:28:00.067899+00:00 | 2022-09-15T15:28:01.191752+00:00 |
>| 87 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T15:27:55.460445+00:00 | 2022-09-15T15:27:58.624073+00:00 |
>| 86 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T12:44:53.416352+00:00 | 2022-09-15T12:44:54.531016+00:00 |
>| 85 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T12:44:30.534834+00:00 | 2022-09-15T12:44:52.012959+00:00 |
>| 77 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T12:26:37.577938+00:00 | 2022-09-15T12:44:51.137553+00:00 |
>| 78 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T12:26:42.091728+00:00 | 2022-09-15T12:44:51.101640+00:00 |
>| 61 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T09:59:40.292533+00:00 | 2022-09-15T12:44:51.093964+00:00 |
>| 75 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:42:15.215067+00:00 | 2022-09-15T12:44:51.092630+00:00 |
>| 70 | trying reate a new issue from pycharm | bug | major | resolved | 0 | 2022-09-15T11:16:49.920859+00:00 | 2022-09-15T12:44:51.086065+00:00 |
>| 73 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:32:48.819786+00:00 | 2022-09-15T12:44:51.083718+00:00 |
>| 79 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T12:34:54.501783+00:00 | 2022-09-15T12:44:51.081878+00:00 |
>| 83 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T12:40:41.347680+00:00 | 2022-09-15T12:44:51.079596+00:00 |
>| 82 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T12:37:38.615913+00:00 | 2022-09-15T12:44:51.068691+00:00 |
>| 64 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:03:30.471686+00:00 | 2022-09-15T12:44:51.017256+00:00 |
>| 69 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:12:43.179200+00:00 | 2022-09-15T12:44:50.163182+00:00 |
>| 65 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:05:28.371771+00:00 | 2022-09-15T12:44:50.142184+00:00 |
>| 59 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T09:58:05.902703+00:00 | 2022-09-15T12:44:50.137869+00:00 |
>| 67 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:08:00.607100+00:00 | 2022-09-15T12:44:50.136858+00:00 |
>| 54 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T08:57:36.071745+00:00 | 2022-09-15T12:44:50.127670+00:00 |
>| 66 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:07:18.048004+00:00 | 2022-09-15T12:44:50.120105+00:00 |
>| 72 | try | bug | major | resolved | 0 | 2022-09-15T11:22:33.881728+00:00 | 2022-09-15T12:44:50.116321+00:00 |
>| 58 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T09:58:02.175333+00:00 | 2022-09-15T12:44:50.101759+00:00 |
>| 68 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:12:43.124830+00:00 | 2022-09-15T12:44:50.021221+00:00 |
>| 52 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T08:57:07.284376+00:00 | 2022-09-15T12:44:50.013133+00:00 |
>| 51 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T07:45:26.069019+00:00 | 2022-09-15T12:44:49.145333+00:00 |
>| 50 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T07:45:22.013251+00:00 | 2022-09-15T12:44:49.131648+00:00 |
>| 63 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T10:43:30.124649+00:00 | 2022-09-15T12:44:49.122898+00:00 |
>| 71 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:17:53.436570+00:00 | 2022-09-15T12:44:49.121148+00:00 |
>| 56 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T08:58:13.577482+00:00 | 2022-09-15T12:44:49.110010+00:00 |
>| 57 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T08:58:16.619677+00:00 | 2022-09-15T12:44:49.105822+00:00 |
>| 60 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T09:59:36.897169+00:00 | 2022-09-15T12:44:49.100776+00:00 |
>| 84 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T12:40:54.503310+00:00 | 2022-09-15T12:44:49.095291+00:00 |
>| 76 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T11:42:19.654666+00:00 | 2022-09-15T12:44:49.092157+00:00 |
>| 80 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T12:35:17.065253+00:00 | 2022-09-15T12:44:49.058635+00:00 |
>| 74 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T11:37:08.030759+00:00 | 2022-09-15T12:40:44.574527+00:00 |
>| 53 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T08:57:10.507042+00:00 | 2022-09-15T12:37:34.814883+00:00 |
>| 81 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T12:37:31.134701+00:00 | 2022-09-15T12:37:34.812533+00:00 |
>| 55 | Hi I am new | bug | major | resolved | 0 | 2022-09-15T08:57:39.314220+00:00 | 2022-09-15T12:37:34.812085+00:00 |
>| 62 | test_issue | enhancement | minor | resolved | 0 | 2022-09-15T10:43:16.382541+00:00 | 2022-09-15T12:35:12.588480+00:00 |
>| 49 | Hi I am new | bug | major | open | 0 | 2022-09-15T07:43:53.441923+00:00 | 2022-09-15T07:43:54.614311+00:00 |
>| 48 | test_issue | enhancement | minor | open | 0 | 2022-09-15T07:43:49.919255+00:00 | 2022-09-15T07:43:49.919255+00:00 |
>| 46 | test_issue | enhancement | minor | open | 0 | 2022-09-15T07:41:36.558119+00:00 | 2022-09-15T07:41:41.525508+00:00 |
>| 47 | Hi I am new | bug | major | open | 0 | 2022-09-15T07:41:40.391502+00:00 | 2022-09-15T07:41:41.475910+00:00 |
>| 45 | test_issue | enhancement | minor | open | 0 | 2022-09-15T07:40:19.315706+00:00 | 2022-09-15T07:40:19.315706+00:00 |
>| 44 | test_issue | enhancement | minor | open | 0 | 2022-09-15T07:40:00.346316+00:00 | 2022-09-15T07:40:00.346316+00:00 |
>| 43 | test_issue | enhancement | minor | open | 0 | 2022-09-15T07:10:26.667900+00:00 | 2022-09-15T07:10:26.667900+00:00 |


### bitbucket-issue-update
***
Updates an issue in Bitbucket. In order to perform this command, please create an issue tracker by clicking on the relevant repo -> Repository settings -> Issue tracker


#### Base Command

`bitbucket-issue-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| title | The title of the new issue. | Required | 
| issue_id | The id of the issue to update. To get the issue id, use the command bitbucket-issue-list. | Required | 
| state | The state of the issues to create. Can be 'New', 'Open', 'Resolved', 'On Hold', 'Invalid', 'Duplicate', 'Wontfix' or 'Closed'. Possible values are: new, open, resolved, on hold, invalid, duplicate, wontfix, closed. | Optional | 
| type | The type of the issues to create. Can be 'Bug', 'Enhancement', 'Proposal', 'Task'. Possible values are: bug, enhancement, proposal, task. | Optional | 
| priority | The priority of the issues to create. Can be 'Trivial', 'Minor', 'Major', 'Critical', 'Blocker'. Possible values are: trivial, minor, major, critical, blocker. | Optional | 
| content | The content of the issue to create. | Optional | 
| assignee_id | The id of the assignee of the issue to create. | Optional | 
| assignee_user_name | The user name of the assignee of the issue to create. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.Issue.type | String | The action type. | 
| Bitbucket.Issue.id | Number | The id of the issue. | 
| Bitbucket.Issue.repository.type | String | he type of the repository. | 
| Bitbucket.Issue.repository.full_name | String | The full name of the repository. | 
| Bitbucket.Issue.repository.links | String | Links with information about the repository related to the issue. | 
| Bitbucket.Issue.repository.name | String | The name of the repository. | 
| Bitbucket.Issue.repository.uuid | String | The unique id of the repository. | 
| Bitbucket.Issue.links | String | Links with information about the issue | 
| Bitbucket.Issue.title | String | The title of the issue. | 
| Bitbucket.Issue.content.type | String | The type of the content. | 
| Bitbucket.Issue.content.raw | String | The content of the issue. | 
| Bitbucket.Issue.content.markup | String | The type of markup \(like markdown\). | 
| Bitbucket.Issue.content.html | String | The content of the issue in html format. | 
| Bitbucket.Issue.reporter.display_name | String | The display name of the reporter of the issue. | 
| Bitbucket.Issue.reporter.links | String | Links with information about the reporter. | 
| Bitbucket.Issue.reporter.type | String | The type of the reporter. | 
| Bitbucket.Issue.reporter.uuid | String | The unique id of the reporter | 
| Bitbucket.Issue.reporter.account_id | String | The account id of the reporter. | 
| Bitbucket.Issue.reporter.nickname | String | The nickname of the reporter. | 
| Bitbucket.Issue.assignee.display_name | String | The display name of the assignee to the issue. | 
| Bitbucket.Issue.assignee.links | String | Links with information about the assignee. | 
| Bitbucket.Issue.assignee.type | String | The type of the assignee. | 
| Bitbucket.Issue.assignee.uuid | String | The unique od of the assignee. | 
| Bitbucket.Issue.assignee.account_id | String | The account id of the assignee. | 
| Bitbucket.Issue.assignee.nickname | String | The nickname of the assignee. | 
| Bitbucket.Issue.created_on | String | The creation date of the issue. | 
| Bitbucket.Issue.edited_on | Unknown | The edit date of the issue. | 
| Bitbucket.Issue.updated_on | String | The update date of the issue. | 
| Bitbucket.Issue.state | String | The state odf the issue. | 
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
            "created_on": "2022-09-18T08:13:58.934086+00:00",
            "edited_on": null,
            "id": 91,
            "kind": "bug",
            "links": {
                "attachments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/attachments"
                },
                "comments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/comments"
                },
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/issues/91/a-new-issue"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91"
                },
                "vote": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/vote"
                },
                "watch": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/91/watch"
                }
            },
            "milestone": null,
            "priority": "major",
            "reporter": {
                "account_id": "62cf63f7e546e8eab8eee042",
                "display_name": "Rotem Amit",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "nickname": "Rotem Amit",
                "type": "user",
                "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
            },
            "repository": {
                "full_name": "rotemamit/start_repo",
                "links": {
                    "avatar": {
                        "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                    }
                },
                "name": "start_repo",
                "type": "repository",
                "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
            },
            "state": "resolved",
            "title": "a new issue",
            "type": "issue",
            "updated_on": "2022-09-18T08:57:09.230244+00:00",
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
 


#### Base Command

`bitbucket-pull-request-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| title | The title of the new pull request. | Required | 
| source_branch | The branch to merge. | Required | 
| destination_branch | The branch to merge to. | Optional | 
| reviewer_id | The id of the account of the person to review the pull request. | Optional | 
| description | A description of the pull request. | Optional | 
| close_source_branch | Should the source branch be closed after the pull request. Possible values are: yes, no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequest.comment_count | Number | How many comments there are in the pull request. | 
| Bitbucket.PullRequest.task_count | Number | How many tasks there are in the pull request. | 
| Bitbucket.PullRequest.type | String | The type of the request. | 
| Bitbucket.PullRequest.id | Number | The pull request id. | 
| Bitbucket.PullRequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequest.description | String | The description of the pull request. | 
| Bitbucket.PullRequest.rendered.title.type | String | The type of the title of the request. | 
| Bitbucket.PullRequest.rendered.title.raw | String | The content of the rendered title. | 
| Bitbucket.PullRequest.rendered.title.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.rendered.title.html | String | The html format of the pull request title. | 
| Bitbucket.PullRequest.rendered.description.type | String | The type of the pull request description | 
| Bitbucket.PullRequest.rendered.description.raw | String | The content of the description of the pull request. | 
| Bitbucket.PullRequest.rendered.description.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.rendered.description.html | String | Html format of the description content. | 
| Bitbucket.PullRequest.state | String | The status of the pull request. | 
| Bitbucket.PullRequest.merge_commit | Unknown | Is it a merge commit. | 
| Bitbucket.PullRequest.close_source_branch | Boolean | Should the branch be closed after the merge. | 
| Bitbucket.PullRequest.closed_by | Unknown | The user that closed the pull request. | 
| Bitbucket.PullRequest.author.display_name | String | The display name of the author of the pull request. | 
| Bitbucket.PullRequest.author.links | String | Links with information about the author of the pull request. | 
| Bitbucket.PullRequest.author.type | String | The type of the author | 
| Bitbucket.PullRequest.author.uuid | String | The unique universal id of the author. | 
| Bitbucket.PullRequest.author.account_id | String | The account id of the author of the pull request. | 
| Bitbucket.PullRequest.author.nickname | String | The nickname of the author. | 
| Bitbucket.PullRequest.reason | String | The reason to create the request. | 
| Bitbucket.PullRequest.created_on | String | The creation date of the request. | 
| Bitbucket.PullRequest.updated_on | String | The date of the last update of the pull request. | 
| Bitbucket.PullRequest.destination.branch.name | String | The name of the destination branch, the branch to merge to. | 
| Bitbucket.PullRequest.destination.commit.type | String | The type of the commit. | 
| Bitbucket.PullRequest.destination.commit.hash | String | The hash of the commit. | 
| Bitbucket.PullRequest.destination.commit.links | String | Links with information about the commit. | 
| Bitbucket.PullRequest.destination.repository.type | String | The type of the repository. | 
| Bitbucket.PullRequest.destination.repository.full_name | String | The full name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.links | String | Links with information about The repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.name | String | The name of the repository. | 
| Bitbucket.PullRequest.destination.repository.uuid | String | The unique id of the repository. | 
| Bitbucket.PullRequest.source.branch.name | String | The name of the source branch, The branch with the changes that will be merged. | 
| Bitbucket.PullRequest.source.commit.type | String | The type of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.hash | String | The hash of the commit in the source branch | 
| Bitbucket.PullRequest.source.commit.links | String | Links with information about the commit in source branch. | 
| Bitbucket.PullRequest.source.repository.type | String | The type of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.full_name | String | The full name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.links.self.href | String | Links with information about the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.name | String | The name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.uuid | String | The unique id of the repository of the source branch. | 
| Bitbucket.PullRequest.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequest.summary.type | String | The type of the pull request. | 
| Bitbucket.PullRequest.summary.raw | String | The description of the pull request. | 
| Bitbucket.PullRequest.summary.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.summary.html | String | The description of the pull request in html format. | 

#### Command example
```!bitbucket-pull-request-create source_branch=test title="pull_request"```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequest": {
            "author": {
                "account_id": "62cf63f7e546e8eab8eee042",
                "display_name": "Rotem Amit",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "nickname": "Rotem Amit",
                "type": "user",
                "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
            },
            "close_source_branch": false,
            "closed_by": null,
            "comment_count": 12,
            "created_on": "2022-09-12T09:51:55.458494+00:00",
            "description": "",
            "destination": {
                "branch": {
                    "name": "master"
                },
                "commit": {
                    "hash": "3f77114f285c",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/3f77114f285c"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                }
            },
            "id": 8,
            "links": {
                "activity": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/activity"
                },
                "approve": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/approve"
                },
                "comments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/comments"
                },
                "commits": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/commits"
                },
                "decline": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/decline"
                },
                "diff": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/rotemamit/start_repo:01bc3d6f96a4%0D3f77114f285c?from_pullrequest_id=8&topic=true"
                },
                "diffstat": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diffstat/rotemamit/start_repo:01bc3d6f96a4%0D3f77114f285c?from_pullrequest_id=8&topic=true"
                },
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/8"
                },
                "merge": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/merge"
                },
                "request-changes": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/request-changes"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8"
                },
                "statuses": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/statuses"
                }
            },
            "merge_commit": null,
            "participants": [
                {
                    "approved": false,
                    "participated_on": "2022-09-15T12:37:36.810654+00:00",
                    "role": "PARTICIPANT",
                    "state": null,
                    "type": "participant",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
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
            "reviewers": [],
            "source": {
                "branch": {
                    "name": "test"
                },
                "commit": {
                    "hash": "01bc3d6f96a4",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/01bc3d6f96a4"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a4"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
            "updated_on": "2022-09-18T08:57:20.815479+00:00"
        }
    }
}
```

#### Human Readable Output

>The pull request was created successfully

### bitbucket-pull-request-update
***
 


#### Base Command

`bitbucket-pull-request-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The id of the pull request to update. In order to get the pull_request_id, use the command bitbucket-pull-request-list. | Required | 
| title | The title of the new pull request. | Optional | 
| source_branch | The branch to merge. | Optional | 
| destination_branch | The branch to merge to. | Optional | 
| reviewer_id | The id of the account of the person to review the pull request. | Optional | 
| description | A description of the pull request. | Optional | 
| close_source_branch | Should the source branch be closed after the pull request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequest.comment_count | Number | The number of comments in the pull request. | 
| Bitbucket.PullRequest.task_count | Number | The number of tasks in the pull request. | 
| Bitbucket.PullRequest.type | String | The type of the request. | 
| Bitbucket.PullRequest.id | Number | The pull request id. | 
| Bitbucket.PullRequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequest.description | String | The description of the pull request. | 
| Bitbucket.PullRequest.rendered.title.type | String | The type of the title of the request. | 
| Bitbucket.PullRequest.rendered.title.raw | String | The content of the rendered title. | 
| Bitbucket.PullRequest.rendered.title.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.rendered.title.html | String | The html format of the pull request title. | 
| Bitbucket.PullRequest.rendered.description.type | String | The type of the pull request description | 
| Bitbucket.PullRequest.rendered.description.raw | String | The content of the description of the pull request. | 
| Bitbucket.PullRequest.rendered.description.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.rendered.description.html | String | Html format of the description content. | 
| Bitbucket.PullRequest.state | String | The status of the pull request. | 
| Bitbucket.PullRequest.merge_commit | Unknown | Is it a merge commit. | 
| Bitbucket.PullRequest.close_source_branch | Boolean | Should the branch be closed after the merge. | 
| Bitbucket.PullRequest.closed_by | Unknown | The user that closed the pull request. | 
| Bitbucket.PullRequest.author.display_name | String | The display name of the author of the pull request. | 
| Bitbucket.PullRequest.author.links | String | Links with information about the author of the pull request. | 
| Bitbucket.PullRequest.author.type | String | The type of the author. | 
| Bitbucket.PullRequest.author.uuid | String | The unique universal id of the author. | 
| Bitbucket.PullRequest.author.account_id | String | The account id of the author of the pull request. | 
| Bitbucket.PullRequest.author.nickname | String | The nickname of the author. | 
| Bitbucket.PullRequest.reason | String | The reason to create the request. | 
| Bitbucket.PullRequest.created_on | String | The creation date of the request. | 
| Bitbucket.PullRequest.updated_on | String | The date of the last update of the pull request. | 
| Bitbucket.PullRequest.destination.branch.name | String | The name of the destination branch, the branch to merge to. | 
| Bitbucket.PullRequest.destination.commit.type | String | The type of the commit. | 
| Bitbucket.PullRequest.destination.commit.hash | String | The hash of the commit. | 
| Bitbucket.PullRequest.destination.commit.links | String | Links with information about the commit. | 
| Bitbucket.PullRequest.destination.repository.type | String | The type of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.full_name | String | The full name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.links | String | Links with information about The repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.name | String | The name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.uuid | String | The unique id of the repository of the destination branch. | 
| Bitbucket.PullRequest.source.branch.name | String | The name of the source branch, The branch with the changes that will be merged. | 
| Bitbucket.PullRequest.source.commit.type | String | The type of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.hash | String | The hash of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.links | String | Links with information about the commit in source branch. | 
| Bitbucket.PullRequest.source.repository.type | String | The type of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.full_name | String | The full name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.links | String | Links with information about the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.name | String | The name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.uuid | String | The unique id of the repository of the source branch. | 
| Bitbucket.PullRequest.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequest.summary.type | String | The type of the pull request. | 
| Bitbucket.PullRequest.summary.raw | String | The description of the pull request. | 
| Bitbucket.PullRequest.summary.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.summary.html | String | The description of the pull request in html format. | 

#### Command example
```!bitbucket-pull-request-update pull_request_id=8 description="updating description"```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequest": {
            "author": {
                "account_id": "62cf63f7e546e8eab8eee042",
                "display_name": "Rotem Amit",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "nickname": "Rotem Amit",
                "type": "user",
                "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
            },
            "close_source_branch": false,
            "closed_by": null,
            "comment_count": 12,
            "created_on": "2022-09-12T09:51:55.458494+00:00",
            "description": "updating description",
            "destination": {
                "branch": {
                    "name": "master"
                },
                "commit": {
                    "hash": "3f77114f285c",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/3f77114f285c"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                }
            },
            "id": 8,
            "links": {
                "activity": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/activity"
                },
                "approve": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/approve"
                },
                "comments": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/comments"
                },
                "commits": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/commits"
                },
                "decline": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/decline"
                },
                "diff": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/rotemamit/start_repo:01bc3d6f96a4%0D3f77114f285c?from_pullrequest_id=8&topic=true"
                },
                "diffstat": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diffstat/rotemamit/start_repo:01bc3d6f96a4%0D3f77114f285c?from_pullrequest_id=8&topic=true"
                },
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/8"
                },
                "merge": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/merge"
                },
                "request-changes": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/request-changes"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8"
                },
                "statuses": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/statuses"
                }
            },
            "merge_commit": null,
            "participants": [
                {
                    "approved": false,
                    "participated_on": "2022-09-15T12:37:36.810654+00:00",
                    "role": "PARTICIPANT",
                    "state": null,
                    "type": "participant",
                    "user": {
                        "account_id": "62cf63f7e546e8eab8eee042",
                        "display_name": "Rotem Amit",
                        "links": {
                            "avatar": {
                                "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                            },
                            "html": {
                                "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                            }
                        },
                        "nickname": "Rotem Amit",
                        "type": "user",
                        "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                    }
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
            "reviewers": [],
            "source": {
                "branch": {
                    "name": "test"
                },
                "commit": {
                    "hash": "01bc3d6f96a4",
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/commits/01bc3d6f96a4"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a4"
                        }
                    },
                    "type": "commit"
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                }
            },
            "state": "OPEN",
            "summary": {
                "html": "<p>updating description</p>",
                "markup": "markdown",
                "raw": "updating description",
                "type": "rendered"
            },
            "task_count": 0,
            "title": "pull_request",
            "type": "pullrequest",
            "updated_on": "2022-09-18T08:57:24.121609+00:00"
        }
    }
}
```

#### Human Readable Output

>The pull request 8 was updated successfully

### bitbucket-pull-request-list
***
Returns a list of the pull requests. If a state is provided than the list will contain only PR with the wanted status. If a state is not provided, by default a list of the open pull requests will return.


#### Base Command

`bitbucket-pull-request-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The id of the pull request to update. | Optional | 
| state | The state of the pull requests to see. Possible values are: OPEN, MERGED, DECLINED, SUPERSEDED, ALL. | Optional | 
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequest.comment_count | Number | The number of comments in the pull request. | 
| Bitbucket.PullRequest.task_count | Number | The number of tasks in the pull request. | 
| Bitbucket.PullRequest.type | String | The type of the request. | 
| Bitbucket.PullRequest.id | Number | The pull request id. | 
| Bitbucket.PullRequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequest.description | String | The description of the pull request. | 
| Bitbucket.PullRequest.state | String | The status of the pull request. | 
| Bitbucket.PullRequest.merge_commit.type | String | The type of the merge commit. | 
| Bitbucket.PullRequest.merge_commit.hash | String | The hash of the merged commit. | 
| Bitbucket.PullRequest.merge_commit.links | String | Links with information about the merged commit. | 
| Bitbucket.PullRequest.close_source_branch | Boolean | Should the branch be closed after the merge. | 
| Bitbucket.PullRequest.closed_by.display_name | String | The display name of the user that closed the pull request. | 
| Bitbucket.PullRequest.closed_by.links | String | Links with information about the user that closed the pull request. | 
| Bitbucket.PullRequest.closed_by.type | String | The type of user that closed the pull request. | 
| Bitbucket.PullRequest.closed_by.uuid | String | The unique id of the user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.account_id | String | The account id of the user who closed the pull request. | 
| Bitbucket.PullRequest.closed_by.nickname | String | The nickname of the user who closed the pull request. | 
| Bitbucket.PullRequest.author.display_name | String | The display name of the author of the pull request. | 
| Bitbucket.PullRequest.author.links.self.href | String | Links with information about the author of the pull request. | 
| Bitbucket.PullRequest.author.type | String | The type of the author. | 
| Bitbucket.PullRequest.author.uuid | String | The unique universal id of the author. | 
| Bitbucket.PullRequest.author.account_id | String | The account id of the author of the pull request. | 
| Bitbucket.PullRequest.author.nickname | String | The nickname of the author. | 
| Bitbucket.PullRequest.reason | String | The reason to create the request. | 
| Bitbucket.PullRequest.created_on | String | The creation date of the request. | 
| Bitbucket.PullRequest.updated_on | String | The date of the last update of the pull request. | 
| Bitbucket.PullRequest.destination.branch.name | String | The name of the destination branch, the branch to merge to. | 
| Bitbucket.PullRequest.destination.commit.type | String | The type of the commit. | 
| Bitbucket.PullRequest.destination.commit.hash | String | The hash of the commit. | 
| Bitbucket.PullRequest.destination.commit.links | String | Links with information about the commit. | 
| Bitbucket.PullRequest.destination.repository.type | String | The type of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.full_name | String | The full name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.links | String | Links with information about The repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.name | String | The name of the repository of the destination branch. | 
| Bitbucket.PullRequest.destination.repository.uuid | String | The unique id of the repository of the destination branch. | 
| Bitbucket.PullRequest.source.branch.name | String | The name of the source branch, The branch with the changes that will be merged. | 
| Bitbucket.PullRequest.source.commit.type | String | The type of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.hash | String | The hash of the commit in the source branch. | 
| Bitbucket.PullRequest.source.commit.links | String | Links with information about the commit in source branch. | 
| Bitbucket.PullRequest.source.repository.type | String | The type of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.full_name | String | The full name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.links | String | Links with information about the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.name | String | The name of the repository of the source branch. | 
| Bitbucket.PullRequest.source.repository.uuid | String | The unique id of the repository of the source branch. | 
| Bitbucket.PullRequest.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequest.summary.type | String | The type of the pull request. | 
| Bitbucket.PullRequest.summary.raw | String | The description of the pull request. | 
| Bitbucket.PullRequest.summary.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequest.summary.html | String | The description of the pull request in html format. | 

#### Command example
```!bitbucket-pull-request-list```
#### Context Example
```json
{
    "Bitbucket": {
        "PullRequest": [
            {
                "author": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "close_source_branch": false,
                "closed_by": null,
                "comment_count": 12,
                "created_on": "2022-09-12T09:51:55.458494+00:00",
                "description": "",
                "destination": {
                    "branch": {
                        "name": "master"
                    },
                    "commit": {
                        "hash": "3f77114f285c",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/3f77114f285c"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    }
                },
                "id": 8,
                "links": {
                    "activity": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/activity"
                    },
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/comments"
                    },
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/commits"
                    },
                    "decline": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/decline"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/rotemamit/start_repo:01bc3d6f96a4%0D3f77114f285c?from_pullrequest_id=8&topic=true"
                    },
                    "diffstat": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diffstat/rotemamit/start_repo:01bc3d6f96a4%0D3f77114f285c?from_pullrequest_id=8&topic=true"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/8"
                    },
                    "merge": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/merge"
                    },
                    "request-changes": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/request-changes"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/8/statuses"
                    }
                },
                "merge_commit": null,
                "reason": "",
                "source": {
                    "branch": {
                        "name": "test"
                    },
                    "commit": {
                        "hash": "01bc3d6f96a4",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/01bc3d6f96a4"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/01bc3d6f96a4"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
                "updated_on": "2022-09-18T08:57:20.815479+00:00"
            },
            {
                "author": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "close_source_branch": true,
                "closed_by": null,
                "comment_count": 10,
                "created_on": "2022-09-08T12:23:04.303626+00:00",
                "description": "updates description",
                "destination": {
                    "branch": {
                        "name": "master"
                    },
                    "commit": {
                        "hash": "3f77114f285c",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/3f77114f285c"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    }
                },
                "id": 6,
                "links": {
                    "activity": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/activity"
                    },
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/comments"
                    },
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/commits"
                    },
                    "decline": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/decline"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/rotemamit/start_repo:280b06eee032%0D3f77114f285c?from_pullrequest_id=6&topic=true"
                    },
                    "diffstat": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diffstat/rotemamit/start_repo:280b06eee032%0D3f77114f285c?from_pullrequest_id=6&topic=true"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/6"
                    },
                    "merge": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/merge"
                    },
                    "request-changes": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/request-changes"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/6/statuses"
                    }
                },
                "merge_commit": null,
                "reason": "",
                "source": {
                    "branch": {
                        "name": "branch"
                    },
                    "commit": {
                        "hash": "280b06eee032",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/280b06eee032"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/280b06eee032"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
                "updated_on": "2022-09-15T12:44:45.785951+00:00"
            },
            {
                "author": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "close_source_branch": true,
                "closed_by": null,
                "comment_count": 4,
                "created_on": "2022-09-08T14:46:29.927284+00:00",
                "description": "updates description",
                "destination": {
                    "branch": {
                        "name": "master"
                    },
                    "commit": {
                        "hash": "3f77114f285c",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/3f77114f285c"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/3f77114f285c"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    }
                },
                "id": 7,
                "links": {
                    "activity": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/activity"
                    },
                    "approve": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/approve"
                    },
                    "comments": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/comments"
                    },
                    "commits": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/commits"
                    },
                    "decline": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/decline"
                    },
                    "diff": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diff/rotemamit/start_repo:8c16852446a1%0D3f77114f285c?from_pullrequest_id=7&topic=true"
                    },
                    "diffstat": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/diffstat/rotemamit/start_repo:8c16852446a1%0D3f77114f285c?from_pullrequest_id=7&topic=true"
                    },
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/7"
                    },
                    "merge": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/merge"
                    },
                    "request-changes": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/request-changes"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7"
                    },
                    "statuses": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/7/statuses"
                    }
                },
                "merge_commit": null,
                "reason": "",
                "source": {
                    "branch": {
                        "name": "somethingNew"
                    },
                    "commit": {
                        "hash": "8c16852446a1",
                        "links": {
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo/commits/8c16852446a1"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/commit/8c16852446a1"
                            }
                        },
                        "type": "commit"
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
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
                "title": "creating",
                "type": "pullrequest",
                "updated_on": "2022-09-15T12:44:45.767727+00:00"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the pull requests
>|Id|Title|Description|SourceBranch|DestinationBranch|State|CreatedBy|CreatedAt|UpdatedAt|
>|---|---|---|---|---|---|---|---|---|
>| 8 | pull_request |  | test | master | OPEN | Rotem Amit | 2022-09-12T09:51:55.458494+00:00 | 2022-09-18T08:57:20.815479+00:00 |
>| 6 | uuuupdate | updates description | branch | master | OPEN | Rotem Amit | 2022-09-08T12:23:04.303626+00:00 | 2022-09-15T12:44:45.785951+00:00 |
>| 7 | creating | updates description | somethingNew | master | OPEN | Rotem Amit | 2022-09-08T14:46:29.927284+00:00 | 2022-09-15T12:44:45.767727+00:00 |


### bitbucket-issue-comment-create
***
Creates a comment on an issue in Bitbucket.


#### Base Command

`bitbucket-issue-comment-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| issue_id | The id of the issue to comment on. | Required | 
| content | The content of the comment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.IssueComment.type | String | The action type. | 
| Bitbucket.IssueComment.id | Number | The id of the comment on the issue. | 
| Bitbucket.IssueComment.created_on | String | The creation date of the comment. | 
| Bitbucket.IssueComment.updated_on | Unknown | When the comment was updated. | 
| Bitbucket.IssueComment.content.type | String | The type of the content. | 
| Bitbucket.IssueComment.content.raw | String | The content of the comment. | 
| Bitbucket.IssueComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.IssueComment.content.html | String | The content of the comment in html format. | 
| Bitbucket.IssueComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.IssueComment.user.links | String | Links with information about the user who created the comment. | 
| Bitbucket.IssueComment.user.type | String | The type of the user who created the comment. | 
| Bitbucket.IssueComment.user.uuid | String | The unique id of the user who created the comment. | 
| Bitbucket.IssueComment.user.account_id | String | The account id of the user who created the comment. | 
| Bitbucket.IssueComment.user.nickname | String | The nickname of the user of who created the comment. | 
| Bitbucket.IssueComment.issue.type | String | The type of the issue. | 
| Bitbucket.IssueComment.issue.id | Number | The id of the issue. | 
| Bitbucket.IssueComment.issue.repository.type | String | The type of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.full_name | String | The full name of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.links | String | Links to information about the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.name | String | The name of the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.uuid | String | The unique id of the relevant repository. | 
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
            "created_on": "2022-09-18T08:56:58.995422+00:00",
            "id": 64107498,
            "issue": {
                "id": 1,
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "title": "new issue",
                "type": "issue"
            },
            "links": {
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64107498"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64107498"
                }
            },
            "type": "issue_comment",
            "updated_on": null,
            "user": {
                "account_id": "62cf63f7e546e8eab8eee042",
                "display_name": "Rotem Amit",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "nickname": "Rotem Amit",
                "type": "user",
                "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
            }
        }
    }
}
```

#### Human Readable Output

>The comment on the issue 1 was created successfully

### bitbucket-issue-comment-delete
***
Deletes a comment on an issue in Bitbucket.


#### Base Command

`bitbucket-issue-comment-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| issue_id | The id of the issue to comment on. | Required | 
| comment_id | The id of the comment to delete. In order to get the comment id, use the command "bitbucket-issue-comment-list". | Required | 


#### Context Output

There is no context output for this command.
### bitbucket-issue-comment-list
***
Returns a list of comments on a specific issue. If a comment_id is given it will return information only about the specific comment.


#### Base Command

`bitbucket-issue-comment-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| issue_id | The id of the issue to comment on. In order to get the issue_id please use the command bitbucket-issue-list. | Required | 
| comment_id | The id of the comment to delete. | Optional | 
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.IssueComment.type | String | The action type. | 
| Bitbucket.IssueComment.id | Number | The id of comment on the issue. | 
| Bitbucket.IssueComment.created_on | String | The creation date of the comment. | 
| Bitbucket.IssueComment.updated_on | Unknown | When the comment was updated. | 
| Bitbucket.IssueComment.content.type | String | The type of the content. | 
| Bitbucket.IssueComment.content.raw | String | The content of the comment. | 
| Bitbucket.IssueComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.IssueComment.content.html | String | The content of the comment in html format. | 
| Bitbucket.IssueComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.IssueComment.user.links | String | Links with information about the user who created the comment. | 
| Bitbucket.IssueComment.user.type | String | The type of the user who created the comment. | 
| Bitbucket.IssueComment.user.uuid | String | The unique id of the user who created the comment. | 
| Bitbucket.IssueComment.user.account_id | String | The account id of the user who created the comment. | 
| Bitbucket.IssueComment.user.nickname | String | The nickname of the user of who created the comment. | 
| Bitbucket.IssueComment.issue.type | String | The type of the issue. | 
| Bitbucket.IssueComment.issue.id | Number | The id of the issue. | 
| Bitbucket.IssueComment.issue.repository.type | String | The type of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.full_name | String | The full name of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.links | String | Links to information about the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.name | String | The name of the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.uuid | String | The unique id of the relevant repository. | 
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
                "created_on": "2022-09-06T14:23:03.776275+00:00",
                "id": 64048615,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64048615"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64048615"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>just a comment</p>",
                    "markup": "markdown",
                    "raw": "just a comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-11T10:54:14.356238+00:00",
                "id": 64081478,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64081478"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64081478"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "",
                    "markup": "markdown",
                    "raw": null,
                    "type": "rendered"
                },
                "created_on": "2022-09-14T13:29:36.690382+00:00",
                "id": 64094764,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64094764"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64094764"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>The new and updated comment</p>",
                    "markup": "markdown",
                    "raw": "The new and updated comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:08:07.927023+00:00",
                "id": 64095289,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095289"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095289"
                    }
                },
                "type": "issue_comment",
                "updated_on": "2022-09-14T15:08:16.941773+00:00",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>check creating comment</p>",
                    "markup": "markdown",
                    "raw": "check creating comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:12:15.044163+00:00",
                "id": 64095367,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095367"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095367"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>check creating comment</p>",
                    "markup": "markdown",
                    "raw": "check creating comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:14:24.319117+00:00",
                "id": 64095439,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095439"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095439"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>helllo</p>",
                    "markup": "markdown",
                    "raw": "helllo",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:15:10.175231+00:00",
                "id": 64095472,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095472"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095472"
                    }
                },
                "type": "issue_comment",
                "updated_on": "2022-09-14T15:15:13.232925+00:00",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>helllo</p>",
                    "markup": "markdown",
                    "raw": "helllo",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:15:56.372321+00:00",
                "id": 64095506,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095506"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095506"
                    }
                },
                "type": "issue_comment",
                "updated_on": "2022-09-14T15:15:59.475790+00:00",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>check creating comment</p>",
                    "markup": "markdown",
                    "raw": "check creating comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:17:42.183953+00:00",
                "id": 64095567,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095567"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095567"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>updating content info</p>",
                    "markup": "markdown",
                    "raw": "updating content info",
                    "type": "rendered"
                },
                "created_on": "2022-09-14T15:17:45.471957+00:00",
                "id": 64095597,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095597"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095597"
                    }
                },
                "type": "issue_comment",
                "updated_on": "2022-09-18T08:13:09.153870+00:00",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "content": {
                    "html": "<p>some comment</p>",
                    "markup": "markdown",
                    "raw": "some comment",
                    "type": "rendered"
                },
                "created_on": "2022-09-18T08:56:58.995422+00:00",
                "id": 64107498,
                "issue": {
                    "id": 1,
                    "links": {
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                        }
                    },
                    "repository": {
                        "full_name": "rotemamit/start_repo",
                        "links": {
                            "avatar": {
                                "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                            },
                            "html": {
                                "href": "https://bitbucket.org/rotemamit/start_repo"
                            },
                            "self": {
                                "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                            }
                        },
                        "name": "start_repo",
                        "type": "repository",
                        "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                    },
                    "title": "new issue",
                    "type": "issue"
                },
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64107498"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64107498"
                    }
                },
                "type": "issue_comment",
                "updated_on": null,
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
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
>| 64048615 | new bug | Rotem Amit | 2022-09-06T14:23:03.776275+00:00 |  | 1 | new issue |
>| 64081478 | just a comment | Rotem Amit | 2022-09-11T10:54:14.356238+00:00 |  | 1 | new issue |
>| 64094764 |  | Rotem Amit | 2022-09-14T13:29:36.690382+00:00 |  | 1 | new issue |
>| 64095289 | The new and updated comment | Rotem Amit | 2022-09-14T15:08:07.927023+00:00 | 2022-09-14T15:08:16.941773+00:00 | 1 | new issue |
>| 64095367 | check creating comment | Rotem Amit | 2022-09-14T15:12:15.044163+00:00 |  | 1 | new issue |
>| 64095439 | check creating comment | Rotem Amit | 2022-09-14T15:14:24.319117+00:00 |  | 1 | new issue |
>| 64095472 | helllo | Rotem Amit | 2022-09-14T15:15:10.175231+00:00 | 2022-09-14T15:15:13.232925+00:00 | 1 | new issue |
>| 64095506 | helllo | Rotem Amit | 2022-09-14T15:15:56.372321+00:00 | 2022-09-14T15:15:59.475790+00:00 | 1 | new issue |
>| 64095567 | check creating comment | Rotem Amit | 2022-09-14T15:17:42.183953+00:00 |  | 1 | new issue |
>| 64095597 | updating content info | Rotem Amit | 2022-09-14T15:17:45.471957+00:00 | 2022-09-18T08:13:09.153870+00:00 | 1 | new issue |
>| 64107498 | some comment | Rotem Amit | 2022-09-18T08:56:58.995422+00:00 |  | 1 | new issue |


### bitbucket-issue-comment-update
***
Updates a specific comment on a given issue.


#### Base Command

`bitbucket-issue-comment-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| issue_id | The id of the issue to comment on. In order to get the issue_id please use the command bitbucket-issue-list. | Required | 
| comment_id | The id of the comment to delete. In order to get the issue_id please use the command bitbucket-issue-comment-list. | Required | 
| content | The new content of the comment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.IssueComment.type | String | The action type. | 
| Bitbucket.IssueComment.id | Number | The id of the comment on the issue. | 
| Bitbucket.IssueComment.created_on | String | The creation date of the comment. | 
| Bitbucket.IssueComment.updated_on | Unknown | When the comment was updated. | 
| Bitbucket.IssueComment.content.type | String | The type of the content. | 
| Bitbucket.IssueComment.content.raw | String | The content of the comment. | 
| Bitbucket.IssueComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.IssueComment.content.html | String | The content of the comment in html format. | 
| Bitbucket.IssueComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.IssueComment.user.links | String | Links with information about the user who created the comment. | 
| Bitbucket.IssueComment.user.type | String | The type of the user who created the comment. | 
| Bitbucket.IssueComment.user.uuid | String | The unique id of the user who created the comment. | 
| Bitbucket.IssueComment.user.account_id | String | The account id of the user who created the comment. | 
| Bitbucket.IssueComment.user.nickname | String | The nickname of the user of who created the comment. | 
| Bitbucket.IssueComment.issue.type | String | The type of the issue. | 
| Bitbucket.IssueComment.issue.id | Number | The id of the issue. | 
| Bitbucket.IssueComment.issue.repository.type | String | The type of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.full_name | String | The full name of the repository connected to the relevant issue. | 
| Bitbucket.IssueComment.issue.repository.links | String | Links to information about the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.name | String | The name of the relevant repository. | 
| Bitbucket.IssueComment.issue.repository.uuid | String | The unique id of the relevant repository. | 
| Bitbucket.IssueComment.issue.links | String | Links with information about the issue. | 
| Bitbucket.IssueComment.issue.title | String | The title of the issue. | 
| Bitbucket.IssueComment.links | String | Links to information about the comment. | 

#### Command example
```!bitbucket-issue-comment-update issue_id=1 comment_id=64095597 content="updating content info"```
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
            "created_on": "2022-09-14T15:17:45.471957+00:00",
            "id": 64095597,
            "issue": {
                "id": 1,
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1"
                    }
                },
                "repository": {
                    "full_name": "rotemamit/start_repo",
                    "links": {
                        "avatar": {
                            "href": "https://bytebucket.org/ravatar/%7B6310bc4c-8fa2-4f07-a05a-19c5721747a8%7D?ts=default"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo"
                        }
                    },
                    "name": "start_repo",
                    "type": "repository",
                    "uuid": "{6310bc4c-8fa2-4f07-a05a-19c5721747a8}"
                },
                "title": "new issue",
                "type": "issue"
            },
            "links": {
                "html": {
                    "href": "https://bitbucket.org/rotemamit/start_repo/issues/1#comment-64095597"
                },
                "self": {
                    "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/issues/1/comments/64095597"
                }
            },
            "type": "issue_comment",
            "updated_on": "2022-09-18T08:57:03.786647+00:00",
            "user": {
                "account_id": "62cf63f7e546e8eab8eee042",
                "display_name": "Rotem Amit",
                "links": {
                    "avatar": {
                        "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                    },
                    "html": {
                        "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "nickname": "Rotem Amit",
                "type": "user",
                "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
            }
        }
    }
}
```

#### Human Readable Output

>The comment "64095597" on issue "1" was updated successfully

### bitbucket-pull-request-comment-create
***
Creates a new comment on a pull request.


#### Base Command

`bitbucket-pull-request-comment-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The id of the pull request to comment on. | Required | 
| content | The content of the comment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequestComment.id | Number | The id of the comment in the pull request. | 
| Bitbucket.PullRequestComment.created_on | String | The creation date of the pull request comment. | 
| Bitbucket.PullRequestComment.updated_on | String | The update date of the pull request comment. | 
| Bitbucket.PullRequestComment.content.type | String | The type of the content, like rendered. | 
| Bitbucket.PullRequestComment.content.raw | String | The actual content of the comment. | 
| Bitbucket.PullRequestComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequestComment.content.html | String | The content of the comment in html format. | 
| Bitbucket.PullRequestComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.PullRequestComment.user.links | String | Links to information about the user | 
| Bitbucket.PullRequestComment.user.type | String | The type of the user. | 
| Bitbucket.PullRequestComment.user.uuid | String | The unique id of the user. | 
| Bitbucket.PullRequestComment.user.account_id | String | The account id of the user. | 
| Bitbucket.PullRequestComment.user.nickname | String | The nickname of the user. | 
| Bitbucket.PullRequestComment.deleted | Boolean | Is the comment deleted. | 
| Bitbucket.PullRequestComment.type | String | The type of the action. | 
| Bitbucket.PullRequestComment.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.type | String | The type of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.id | Number | The id of the pull request. | 
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
                "created_on": "2022-09-18T08:57:13.848266+00:00",
                "deleted": false,
                "id": 331374035,
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/1/_/diff#comment-331374035"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/1/comments/331374035"
                    }
                },
                "pullrequest": {
                    "id": 1,
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/1"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/1"
                        }
                    },
                    "title": "change 2",
                    "type": "pullrequest"
                },
                "type": "pullrequest_comment",
                "updated_on": "2022-09-18T08:57:13.848309+00:00",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>The comment on the pull request "1" was created successfully

### bitbucket-pull-request-comment-list
***
returns a list of comments of a specific pull request.


#### Base Command

`bitbucket-pull-request-comment-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The id of the pull request. | Required | 
| comment_id | The id of the comment. | Optional | 
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequestComment.id | Number | The id of the comment in the pull request. | 
| Bitbucket.PullRequestComment.created_on | String | The creation date of the pull request comment. | 
| Bitbucket.PullRequestComment.updated_on | String | The update date of the pull request comment. | 
| Bitbucket.PullRequestComment.content.type | String | The type of the content, like rendered. | 
| Bitbucket.PullRequestComment.content.raw | String | The actual content of the comment. | 
| Bitbucket.PullRequestComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequestComment.content.html | String | The content of the comment in html format. | 
| Bitbucket.PullRequestComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.PullRequestComment.user.links | String | Links to information about the user | 
| Bitbucket.PullRequestComment.user.type | String | The type of the user. | 
| Bitbucket.PullRequestComment.user.uuid | String | The unique id of the user. | 
| Bitbucket.PullRequestComment.user.account_id | String | The account id of the user. | 
| Bitbucket.PullRequestComment.user.nickname | String | The nickname of the user. | 
| Bitbucket.PullRequestComment.deleted | Boolean | Is the comment deleted. | 
| Bitbucket.PullRequestComment.type | String | The type of the action. | 
| Bitbucket.PullRequestComment.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.type | String | The type of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.id | Number | The id of the pull request. | 
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
                "created_on": "2022-09-18T08:57:13.848266+00:00",
                "deleted": false,
                "id": 331374035,
                "links": {
                    "html": {
                        "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/1/_/diff#comment-331374035"
                    },
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/1/comments/331374035"
                    }
                },
                "pullrequest": {
                    "id": 1,
                    "links": {
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/start_repo/pull-requests/1"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/repositories/rotemamit/start_repo/pullrequests/1"
                        }
                    },
                    "title": "change 2",
                    "type": "pullrequest"
                },
                "type": "pullrequest_comment",
                "updated_on": "2022-09-18T08:57:13.848309+00:00",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### List of the comments on pull request number "1"
>|Id|Content|CreatedBy|CreatedAt|UpdatedAt|
>|---|---|---|---|---|
>| 331374035 | new comment on a pull request | Rotem Amit | 2022-09-18T08:57:13.848266+00:00 | 2022-09-18T08:57:13.848309+00:00 |


### bitbucket-pull-request-comment-update
***
updates a comment in a specific pull request.


#### Base Command

`bitbucket-pull-request-comment-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The id of the pull request. | Required | 
| comment_id | The id of the comment. | Required | 
| content | The id of the comment. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.PullRequestComment.id | Number | The id of the comment in the pull request. | 
| Bitbucket.PullRequestComment.created_on | String | The creation date of the pull request comment. | 
| Bitbucket.PullRequestComment.updated_on | String | The update date of the pull request comment. | 
| Bitbucket.PullRequestComment.content.type | String | The type of the content, like rendered. | 
| Bitbucket.PullRequestComment.content.raw | String | The actual content of the comment. | 
| Bitbucket.PullRequestComment.content.markup | String | The text styling type, such as markdown. | 
| Bitbucket.PullRequestComment.content.html | String | The content of the comment in html format. | 
| Bitbucket.PullRequestComment.user.display_name | String | The display name of the user who created the comment. | 
| Bitbucket.PullRequestComment.user.links | String | Links to information about the user | 
| Bitbucket.PullRequestComment.user.type | String | The type of the user. | 
| Bitbucket.PullRequestComment.user.uuid | String | The unique id of the user. | 
| Bitbucket.PullRequestComment.user.account_id | String | The account id of the user. | 
| Bitbucket.PullRequestComment.user.nickname | String | The nickname of the user. | 
| Bitbucket.PullRequestComment.deleted | Boolean | Is the comment deleted. | 
| Bitbucket.PullRequestComment.type | String | The type of the action. | 
| Bitbucket.PullRequestComment.links | String | Links to information about the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.type | String | The type of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.id | Number | The id of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.title | String | The title of the pull request. | 
| Bitbucket.PullRequestComment.pullrequest.links | String | Links to information about the pull request. | 

### bitbucket-pull-request-comment-delete
***
deletes a comment in a specific pull request.


#### Base Command

`bitbucket-pull-request-comment-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| repo | The repository name or slug. | Optional | 
| pull_request_id | The id of the pull request. In order to get the pull request id use the command "!bitbucket-pull-request-list". | Required | 
| comment_id | The id of the comment. In order to get the comment id use the command "bitbucket-pull-request-comment-list". | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!bitbucket-pull-request-comment-delete comment_id=331372169 pull_request_id=1```
#### Human Readable Output

>The comment on pull request number 1 was deleted successfully.

### bitbucket-workspace-member-list
***
returns a list of all the members in the workspace.


#### Base Command

`bitbucket-workspace-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items in the list. | Optional | 
| page | The specific result page to display. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Bitbucket.WorkspaceMember.type | String | The action type. | 
| Bitbucket.WorkspaceMember.user.display_name | String | The display name of the user. | 
| Bitbucket.WorkspaceMember.user.links | String | Links with information about the user. | 
| Bitbucket.WorkspaceMember.user.type | String | The type of the user. | 
| Bitbucket.WorkspaceMember.user.uuid | String | The unique id of the user. | 
| Bitbucket.WorkspaceMember.user.account_id | String | The account id of the user. | 
| Bitbucket.WorkspaceMember.user.nickname | String | The nickname of the user. | 
| Bitbucket.WorkspaceMember.workspace.type | String | The type of the workspace. | 
| Bitbucket.WorkspaceMember.workspace.uuid | String | The unique id of the workspace. | 
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
                        "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit/members/%7B8e185f04-f48c-4f6a-a51b-da5b7ca4e7ce%7D"
                    }
                },
                "type": "workspace_membership",
                "user": {
                    "account_id": "6321cf22ed8abffd7ffce489",
                    "display_name": "Moishy",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/1c2db91125de81b4c222c8aa59248101?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FM-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B8e185f04-f48c-4f6a-a51b-da5b7ca4e7ce%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B8e185f04-f48c-4f6a-a51b-da5b7ca4e7ce%7D"
                        }
                    },
                    "nickname": "Moishy",
                    "type": "user",
                    "uuid": "{8e185f04-f48c-4f6a-a51b-da5b7ca4e7ce}"
                },
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/rotemamit/avatar/?ts=1661077643"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit"
                        }
                    },
                    "name": "Rotem Amit",
                    "slug": "rotemamit",
                    "type": "workspace",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit/members/%7B862dfe06-df10-404a-afa1-537735d1e791%7D"
                    }
                },
                "type": "workspace_membership",
                "user": {
                    "account_id": "62a0609e122dfd0069061cf2",
                    "display_name": "Moishy Matyas",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/f348c31a1030e7c53138568d4dd09bda?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FMM-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7B862dfe06-df10-404a-afa1-537735d1e791%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7B862dfe06-df10-404a-afa1-537735d1e791%7D"
                        }
                    },
                    "nickname": "Moishy Matyas",
                    "type": "user",
                    "uuid": "{862dfe06-df10-404a-afa1-537735d1e791}"
                },
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/rotemamit/avatar/?ts=1661077643"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit"
                        }
                    },
                    "name": "Rotem Amit",
                    "slug": "rotemamit",
                    "type": "workspace",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            },
            {
                "links": {
                    "self": {
                        "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit/members/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                    }
                },
                "type": "workspace_membership",
                "user": {
                    "account_id": "62cf63f7e546e8eab8eee042",
                    "display_name": "Rotem Amit",
                    "links": {
                        "avatar": {
                            "href": "https://secure.gravatar.com/avatar/2f032b23f3fda8fdea02c46b1601da76?d=https%3A%2F%2Favatar-management--avatars.us-west-2.prod.public.atl-paas.net%2Finitials%2FRA-4.png"
                        },
                        "html": {
                            "href": "https://bitbucket.org/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/users/%7Bbd5b5904-7709-42f4-8c7a-224e652840ad%7D"
                        }
                    },
                    "nickname": "Rotem Amit",
                    "type": "user",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                },
                "workspace": {
                    "links": {
                        "avatar": {
                            "href": "https://bitbucket.org/workspaces/rotemamit/avatar/?ts=1661077643"
                        },
                        "html": {
                            "href": "https://bitbucket.org/rotemamit/"
                        },
                        "self": {
                            "href": "https://api.bitbucket.org/2.0/workspaces/rotemamit"
                        }
                    },
                    "name": "Rotem Amit",
                    "slug": "rotemamit",
                    "type": "workspace",
                    "uuid": "{bd5b5904-7709-42f4-8c7a-224e652840ad}"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### The list of all the workspace members
>|Name|AccountId|
>|---|---|
>| Moishy | 6321cf22ed8abffd7ffce489 |
>| Moishy Matyas | 62a0609e122dfd0069061cf2 |
>| Rotem Amit | 62cf63f7e546e8eab8eee042 |

