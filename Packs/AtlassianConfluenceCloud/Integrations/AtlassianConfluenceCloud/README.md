Atlassian Confluence Cloud allows users to interact with confluence entities like content, space, users and groups. Users can also manage the space permissions.
This integration was integrated and tested with version 1000.0.0-847bdcbfcd00 of Atlassian Confluence Cloud.

## Configure Atlassian Confluence Cloud in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Site Name (e.g., https://${site-name}.atlassian.net) | Site name of the Confluence cloud the user wants to connect to. | True |
| Email | The Atlassian account email. | True |
| API Token |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Events Fetch Interval |  | False |
| Max number of events per fetch |  | False |
| Fetch Events |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### confluence-cloud-space-create
***
Creates a new space.<br/>
Note: If no permissions are specified, the default space permissions defined by the Confluence cloud account admin will be used.

#### Create Space with permissions
- The command arguments 'permission_account_id', 'permission_group_name', and 'permission_operations' can be used to limit access of the space to one individual or one group.<br/>
For Example: !confluence-cloud-space-create unique_key=”Demo” name=”DemoSpace”  permission_account_id=”123af245667” permission_group_name=”administrators” permission_operations=”read:space,write:page”
  
- To limit access of the space to a specific number of people or groups, 'advanced_permissions' should contain a valid JSON.<br/>
A valid JSON schema can be found [here](https://developer.atlassian.com/cloud/confluence/rest/api-group-space/#api-wiki-rest-api-space-post).
  
#### Base Command

`confluence-cloud-space-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unique_key | The key for the new space. It can contain any alphanumeric character (a-z, 0-9). The maximum length is 255 characters.<br/><br/>Note: unique_key cannot change after the space is created. | Required | 
| name | The name of the new space. The maximum length is 200 characters. | Required | 
| description | The description of the new space. | Optional | 
| is_private_space | Whether the user wants to create a private space.<br/><br/>Note: If this option is set to true, permission cannot be applied. <br/><br/>Default is false. | Optional | 
| permission_account_id | The account ID of the user to whom permission should be granted. <br/><br/>Note: To retrieve the account ID, execute the confluence-cloud-user-list command. | Optional | 
| permission_group_name | The group name to whom permission should be granted. <br/><br/>Note: To retrieve the group name, execute the confluence-cloud-group-list command. | Optional | 
| permission_operations | A comma-separated list of the permissions that should be applied.<br/><br/>Note: Requires either permission_account_id or permission_group_name.<br/><br/>Format accepted: operation1:targetType1, operation2:targetType2<br/><br/>For example: read:space, create:page<br/><br/>Possible values for operations: create, read, delete, export, administer.<br/>Possible values for targetType: space, page, blogpost, comment, attachment. | Optional | 
| advanced_permissions | Specify 'advanced_permissions' to grant access to multiple users or groups. 'advanced_permissions' has priority over 'permission_operations'. <br/><br/>Note: Add backslash(\\) before quotes.<br/><br/>For example: [ { \"subjects\": { \"user\": { \"results\": [ { \"accountId\": \"5ff2e30b4d2179006ea18449\" } ] }, \"group\": { \"results\": [ { \"name\": \"administrators\" } ] } }, \"operation\": { \"operation\": \"read\", \"targetType\": \"space\" }, \"anonymousAccess\": false, \"unlicensedAccess\": false } ]<br/><br/>To prepare a valid JSON for advanced_permissions, navigate to https://developer.atlassian.com/cloud/confluence/rest/api-group-space/#api-wiki-rest-api-space-post and see the permission parameter in it. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Space.id | Number | ID of the space. | 
| ConfluenceCloud.Space.key | String | Key of the space. | 
| ConfluenceCloud.Space.name | String | Name of the space. | 
| ConfluenceCloud.Space.description.view.value | String | The description of the space in view format. | 
| ConfluenceCloud.Space.description.view.representation | String | Representation format of the description in view format. | 
| ConfluenceCloud.Space.description.plain.value | String | The description of the space in plain format. | 
| ConfluenceCloud.Space.description.plain.representation | String | Representation format of the description in plain format. | 
| ConfluenceCloud.Space.homepage.id | String | ID of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.type | String | Type of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.status | String | Status of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.title | String | Title of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Space.homepage._links.self | String | Link to the homepage of the space. | 
| ConfluenceCloud.Space.homepage._links.tinyui | String | Tiny link to the homepage of the space. | 
| ConfluenceCloud.Space.homepage._links.editui | String | Edit the user interface link to the homepage of the space. | 
| ConfluenceCloud.Space.homepage._links.webui | String | Web user interface link to the homepage of the space. | 
| ConfluenceCloud.Space.type | String | Type of the space. | 
| ConfluenceCloud.Space.permissions.id | Number | ID of the space permission. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.type | String | Type of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.accountId | String | Account ID of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.accountType | String | Account type of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.email | String | Email of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.publicName | String | Public name of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.path | String | Path of the user's profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.width | Number | Width in pixels of the user's profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.height | Number | Height in pixels of the user's profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.isDefault | Boolean | Whether the profile picture of the user is default picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.displayName | String | Display name of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.isExternalCollaborator | Boolean | Whether the user is an external collaborator user. | 
| ConfluenceCloud.Space.permissions.subjects.user.results._links.self | String | Link to the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.size | Number | Size of the list of users for a given space. | 
| ConfluenceCloud.Space.permissions.subjects.group.results.type | String | Type of the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.results.name | String | Name of the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.results.id | String | ID of the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.results._links.self | String | Link to the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.size | Number | Size of the list of groups for the given space. | 
| ConfluenceCloud.Space.permissions.operation.operation | String | Name of the permission operation. | 
| ConfluenceCloud.Space.permissions.operation.targetType | String | The space or content type that the operation applies to. | 
| ConfluenceCloud.Space.permissions.anonymousAccess | Boolean | Whether anonymous users have permission to use the operation. | 
| ConfluenceCloud.Space.permissions.unlicensedAccess | Boolean | Whether unlicensed users have access from JIRA Service Desk when used with the read space operation. | 
| ConfluenceCloud.Space.status | String | Status of the space. | 
| ConfluenceCloud.Space._links.webui | String | Web user interface link of the space. | 
| ConfluenceCloud.Space._links.context | String | Context link of the space. | 
| ConfluenceCloud.Space._links.self | String | Link to the space. | 
| ConfluenceCloud.Space._links.collection | String | Collection link of the space. | 
| ConfluenceCloud.Space._links.base | String | Base link to the space. | 


#### Command Example
```!confluence-cloud-space-create name="hello_world" unique_key="helloworld111"```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Space": {
            "_expandable": {
                "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=helloworld111",
                "settings": "/rest/api/space/helloworld111/settings",
                "theme": "/rest/api/space/helloworld111/theme"
            },
            "_links": {
                "base": "https://xsoar-bd.atlassian.net/wiki",
                "collection": "/rest/api/space",
                "context": "/wiki",
                "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/helloworld111",
                "webui": "/spaces/helloworld111"
            },
            "description": {
                "plain": {
                    "representation": "plain"
                }
            },
            "homepage": {
                "_expandable": {
                    "children": "/rest/api/content/16711835/child",
                    "container": "/rest/api/space/helloworld111",
                    "descendants": "/rest/api/content/16711835/descendant",
                    "history": "/rest/api/content/16711835/history",
                    "restrictions": "/rest/api/content/16711835/restriction/byOperation",
                    "space": "/rest/api/space/helloworld111"
                },
                "_links": {
                    "editui": "/pages/resumedraft.action?draftId=16711835",
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711835",
                    "tinyui": "/x/mwD-/",
                    "webui": "/spaces/helloworld111/overview"
                },
                "extensions": {
                    "position": 797
                },
                "id": "16711835",
                "status": "current",
                "title": "hello_world Home",
                "type": "page"
            },
            "id": 16711682,
            "key": "helloworld111",
            "name": "hello_world",
            "permissions": [
                {
                    "anonymousAccess": false,
                    "id": 16711685,
                    "operation": {
                        "operation": "create",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711686,
                    "operation": {
                        "operation": "delete",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711687,
                    "operation": {
                        "operation": "restrict_content",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711688,
                    "operation": {
                        "operation": "delete",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711689,
                    "operation": {
                        "operation": "delete",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711690,
                    "operation": {
                        "operation": "delete",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711691,
                    "operation": {
                        "operation": "export",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711693,
                    "operation": {
                        "operation": "restrict_content",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711694,
                    "operation": {
                        "operation": "create",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711695,
                    "operation": {
                        "operation": "delete",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711696,
                    "operation": {
                        "operation": "create",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711697,
                    "operation": {
                        "operation": "create",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711698,
                    "operation": {
                        "operation": "create",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711699,
                    "operation": {
                        "operation": "create",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711700,
                    "operation": {
                        "operation": "create",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711701,
                    "operation": {
                        "operation": "delete",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711702,
                    "operation": {
                        "operation": "create",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711704,
                    "operation": {
                        "operation": "read",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711705,
                    "operation": {
                        "operation": "administer",
                        "targetType": "space"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711706,
                    "operation": {
                        "operation": "delete",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711708,
                    "operation": {
                        "operation": "administer",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711709,
                    "operation": {
                        "operation": "read",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711710,
                    "operation": {
                        "operation": "create",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711711,
                    "operation": {
                        "operation": "restrict_content",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711714,
                    "operation": {
                        "operation": "delete",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711715,
                    "operation": {
                        "operation": "read",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711716,
                    "operation": {
                        "operation": "delete",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711717,
                    "operation": {
                        "operation": "delete",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711718,
                    "operation": {
                        "operation": "create",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711719,
                    "operation": {
                        "operation": "create",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711720,
                    "operation": {
                        "operation": "delete",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711721,
                    "operation": {
                        "operation": "administer",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711722,
                    "operation": {
                        "operation": "delete",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711723,
                    "operation": {
                        "operation": "delete",
                        "targetType": "space"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711725,
                    "operation": {
                        "operation": "delete",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711726,
                    "operation": {
                        "operation": "delete",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711727,
                    "operation": {
                        "operation": "export",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711728,
                    "operation": {
                        "operation": "create",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711729,
                    "operation": {
                        "operation": "delete",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711730,
                    "operation": {
                        "operation": "create",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711731,
                    "operation": {
                        "operation": "delete",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711732,
                    "operation": {
                        "operation": "delete",
                        "targetType": "page"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711733,
                    "operation": {
                        "operation": "delete",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711735,
                    "operation": {
                        "operation": "administer",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711737,
                    "operation": {
                        "operation": "delete",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711738,
                    "operation": {
                        "operation": "create",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711739,
                    "operation": {
                        "operation": "create",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711740,
                    "operation": {
                        "operation": "delete",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711741,
                    "operation": {
                        "operation": "administer",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711742,
                    "operation": {
                        "operation": "administer",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711743,
                    "operation": {
                        "operation": "export",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711744,
                    "operation": {
                        "operation": "restrict_content",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711745,
                    "operation": {
                        "operation": "delete",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711746,
                    "operation": {
                        "operation": "delete",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711747,
                    "operation": {
                        "operation": "read",
                        "targetType": "space"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711748,
                    "operation": {
                        "operation": "create",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711749,
                    "operation": {
                        "operation": "create",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711750,
                    "operation": {
                        "operation": "read",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711751,
                    "operation": {
                        "operation": "delete",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711752,
                    "operation": {
                        "operation": "create",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711754,
                    "operation": {
                        "operation": "delete",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711755,
                    "operation": {
                        "operation": "delete",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711756,
                    "operation": {
                        "operation": "restrict_content",
                        "targetType": "space"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711757,
                    "operation": {
                        "operation": "restrict_content",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711758,
                    "operation": {
                        "operation": "create",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711760,
                    "operation": {
                        "operation": "create",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711761,
                    "operation": {
                        "operation": "delete",
                        "targetType": "attachment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/system-administrators"
                                    },
                                    "id": "2fda36d1-e4e0-4307-bc5f-ed0044f6ff2c",
                                    "name": "system-administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711762,
                    "operation": {
                        "operation": "archive",
                        "targetType": "page"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711763,
                    "operation": {
                        "operation": "read",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711764,
                    "operation": {
                        "operation": "export",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711765,
                    "operation": {
                        "operation": "create",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711767,
                    "operation": {
                        "operation": "create",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711768,
                    "operation": {
                        "operation": "create",
                        "targetType": "page"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711769,
                    "operation": {
                        "operation": "create",
                        "targetType": "page"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711770,
                    "operation": {
                        "operation": "delete",
                        "targetType": "blogpost"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/site-admins"
                                    },
                                    "id": "b7e24fd2-0faa-4eaa-9f87-b764ae157ae7",
                                    "name": "site-admins",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711771,
                    "operation": {
                        "operation": "export",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                                    },
                                    "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                                    "name": "confluence-users",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711772,
                    "operation": {
                        "operation": "delete",
                        "targetType": "space"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9"
                                    },
                                    "id": "5178e800-9b33-4b4b-9854-1fdd6776bd42",
                                    "name": "trusted-users-9704e596-7b55-4a8b-a77b-f617d67cffd9",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711773,
                    "operation": {
                        "operation": "export",
                        "targetType": "space"
                    },
                    "subjects": {
                        "user": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                                    },
                                    "accountId": "5ff2e30b4d2179006ea18449",
                                    "accountType": "atlassian",
                                    "displayName": "John Doe",
                                    "email": "dummy.dummy@dummy.com",
                                    "isExternalCollaborator": false,
                                    "profilePicture": {
                                        "height": 48,
                                        "isDefault": false,
                                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                                        "width": 48
                                    },
                                    "publicName": "John Doe",
                                    "type": "known"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                },
                {
                    "anonymousAccess": false,
                    "id": 16711774,
                    "operation": {
                        "operation": "delete",
                        "targetType": "comment"
                    },
                    "subjects": {
                        "group": {
                            "results": [
                                {
                                    "_links": {
                                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                                    },
                                    "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                                    "name": "administrators",
                                    "type": "group"
                                }
                            ],
                            "size": 1
                        }
                    },
                    "unlicensedAccess": false
                }
            ],
            "status": "current",
            "type": "global"
        }
    }
}
```

#### Human Readable Output

>### Space
>|ID|Name|Type|Status|
>|---|---|---|---|
>| 16711682 | [hello_world](https://xsoar-bd.atlassian.net/wiki/spaces/helloworld111) | global | current |


### confluence-cloud-content-create
***
Creates a page or blogpost for a given space.<br/>
Note: To view the expansion of content properties, execute confluence-cloud-content-list and confluence-cloud-content-search commands.


#### Base Command

`confluence-cloud-content-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | The title of the content.<br/><br/>Note: The maximum title length is 255 characters. | Required | 
| type | The type of the new content. <br/>Possible values: page, blogpost. | Required | 
| space_key | The space key that the content is being created in. | Required | 
| status | The status of the new content. <br/>Possible values: current, trashed, draft. <br/><br/>Note: The term 'current' refers to the content that is currently active.<br/><br/>Default is current. | Optional | 
| body_value | The body of the new content.<br/><br/>Note: 'body_value' must be a string. In order to reflect 'body_value', 'body_representation' is required. | Optional | 
| body_representation | The content format type. <br/>Possible values: view, export_view, styled_view, storage, editor2, anonymous_export_view. | Optional | 
| ancestor_id | The ID of the parent content to create the child content.<br/><br/>Note: Supported for content type page only. To retrieve the ancestor_id, execute the confluence-cloud-content-search command using the query="type=page" argument. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Content.id | String | The ID of the content. | 
| ConfluenceCloud.Content.type | String | Type of the content. | 
| ConfluenceCloud.Content.status | String | Status of the content. | 
| ConfluenceCloud.Content.title | String | Title of the content. | 
| ConfluenceCloud.Content.childTypes.attachment.value | Boolean | Whether the attachment has the given content. | 
| ConfluenceCloud.Content.childTypes.attachment._links.self | String | Link to the attachment with the given content. | 
| ConfluenceCloud.Content.childTypes.comment.value | Boolean | Whether a comment is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.comment._links.self | String | Link to the comment associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page.value | Boolean | Whether the page is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page._links.self | String | Link to the page associated with given content. | 
| ConfluenceCloud.Content.space.id | Number | ID of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.key | String | Key of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.name | String | Name of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.type | String | Type of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.status | String | Status of the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.webui | String | Web user interface link to the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.self | String | Link to the space that the content is being created in. | 
| ConfluenceCloud.Content.history.latest | Boolean | Whether the content is the latest content. | 
| ConfluenceCloud.Content.history.createdBy.type | String | Type of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.accountId | String | Account ID of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.accountType | String | Account type of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.email | String | Email of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.publicName | String | Public name of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.path | String | Profile picture path of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.width | Number | Width in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.height | Number | Height in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Content.history.createdBy.displayName | String | Display name of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.history.createdBy._links.self | String | Link to the creator of the content. | 
| ConfluenceCloud.Content.history.createdDate | Date | Date and time, in ISO 8601 format, when the content was created. | 
| ConfluenceCloud.Content.history._links.self | String | Link to the history of the content | 
| ConfluenceCloud.Content.version.by.type | String | Type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountId | String | Account ID of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountType | String | Account type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.email | String | Email of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.publicName | String | Public name of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.path | String | Profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.width | Number | Width in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.height | Number | Height in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Content.version.by.displayName | String | Display name of the user  who last updated the content. | 
| ConfluenceCloud.Content.version.by.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.version.by._links.self | String | Link to the user who last updated the content. | 
| ConfluenceCloud.Content.version.when | Date | Date and time, in ISO 8601 format, when the content was updated. | 
| ConfluenceCloud.Content.version.friendlyWhen | String | Displays when the content was created. | 
| ConfluenceCloud.Content.version.message | String | Message of the updated content. | 
| ConfluenceCloud.Content.version.number | Number | Version number of the updated content. | 
| ConfluenceCloud.Content.version.minorEdit | Boolean | Whether the edit was minor. | 
| ConfluenceCloud.Content.version.confRev | String | The revision ID provided by Confluence to be used as a revision in Synchrony. | 
| ConfluenceCloud.Content.version.contentTypeModified | Boolean | True if the content type is modified in the version. \(e.g., page to blog\) | 
| ConfluenceCloud.Content.version._links.self | String | Link to the new version of the content. | 
| ConfluenceCloud.Content.ancestors.id | String | ID of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.type | String | Type of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.status | String | Status of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.title | String | Title of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Content.ancestors._links.self | String | Link to the parent page of the content. | 
| ConfluenceCloud.Content.ancestors._links.tinyui | String | Tiny link to the parent page of the content. | 
| ConfluenceCloud.Content.ancestors._links.editui | String | Edit user interface link to the parent page of the content. | 
| ConfluenceCloud.Content.ancestors._links.webui | String | Web user interface link to the parent page of the content. | 
| ConfluenceCloud.Content.container.id | Number | ID of the container of the content. | 
| ConfluenceCloud.Content.container.key | String | Key of the container of the content. | 
| ConfluenceCloud.Content.container.name | String | Name of the container of the content. | 
| ConfluenceCloud.Content.container.type | String | Type of the container of the content. | 
| ConfluenceCloud.Content.container.status | String | Status of the container of the content. | 
| ConfluenceCloud.Content.container._links.webui | String | Web user interface link to the container of the content. | 
| ConfluenceCloud.Content.container._links.self | String | Link to the container of the content. | 
| ConfluenceCloud.Content.body.storage.value | String | The body of the new content. | 
| ConfluenceCloud.Content.body.storage.representation | String | Representation format of the content. | 
| ConfluenceCloud.Content.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Content._links.editui | String | Edit user interface link of the content. | 
| ConfluenceCloud.Content._links.webui | String | Web user interface link of the content. | 
| ConfluenceCloud.Content._links.context | String | Context link of the content. | 
| ConfluenceCloud.Content._links.self | String | Link to the content. | 
| ConfluenceCloud.Content._links.tinyui | String | Tiny link of the content. | 
| ConfluenceCloud.Content._links.collection | String | Collection link of the content. | 
| ConfluenceCloud.Content._links.base | String | Base link to the content. | 


#### Command Example
```!confluence-cloud-content-create title="XSOAR_Page_234567" type=page space_key="XSOAR"```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Content": {
            "_expandable": {
                "children": "/rest/api/content/16711862/child",
                "descendants": "/rest/api/content/16711862/descendant",
                "restrictions": "/rest/api/content/16711862/restriction/byOperation"
            },
            "_links": {
                "base": "https://xsoar-bd.atlassian.net/wiki",
                "collection": "/rest/api/content",
                "context": "/wiki",
                "editui": "/pages/resumedraft.action?draftId=16711862",
                "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711862",
                "tinyui": "/x/tgD-/",
                "webui": "/spaces/XSOAR/pages/16711862/XSOAR_Page_234567"
            },
            "body": {
                "storage": {
                    "_expandable": {
                        "content": "/rest/api/content/16711862"
                    },
                    "representation": "storage"
                }
            },
            "container": {
                "_expandable": {
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=XSOAR",
                    "settings": "/rest/api/space/XSOAR/settings",
                    "theme": "/rest/api/space/XSOAR/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/XSOAR",
                    "webui": "/spaces/XSOAR"
                },
                "history": {
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-06T06:18:11.470Z"
                },
                "id": 2064386,
                "key": "XSOAR",
                "name": "XSOAR_Project",
                "status": "current",
                "type": "global"
            },
            "extensions": {
                "position": 618
            },
            "history": {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711862/history"
                },
                "createdBy": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                    },
                    "accountId": "5ff2e30b4d2179006ea18449",
                    "accountType": "atlassian",
                    "displayName": "John Doe",
                    "email": "dummy.dummy@dummy.com",
                    "isExternalCollaborator": false,
                    "profilePicture": {
                        "height": 48,
                        "isDefault": false,
                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                        "width": 48
                    },
                    "publicName": "John Doe",
                    "type": "known"
                },
                "createdDate": "2021-09-02T06:36:33.937Z",
                "latest": true
            },
            "id": "16711862",
            "space": {
                "_expandable": {
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=XSOAR",
                    "settings": "/rest/api/space/XSOAR/settings",
                    "theme": "/rest/api/space/XSOAR/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/XSOAR",
                    "webui": "/spaces/XSOAR"
                },
                "id": 2064386,
                "key": "XSOAR",
                "name": "XSOAR_Project",
                "status": "current",
                "type": "global"
            },
            "status": "current",
            "title": "XSOAR_Page_234567",
            "type": "page",
            "version": {
                "_expandable": {
                    "content": "/rest/api/content/16711862"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711862/version/1"
                },
                "by": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                    },
                    "accountId": "5ff2e30b4d2179006ea18449",
                    "accountType": "atlassian",
                    "displayName": "John Doe",
                    "email": "dummy.dummy@dummy.com",
                    "isExternalCollaborator": false,
                    "profilePicture": {
                        "height": 48,
                        "isDefault": false,
                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                        "width": 48
                    },
                    "publicName": "John Doe",
                    "type": "known"
                },
                "confRev": "confluence$content$16711862.2",
                "contentTypeModified": false,
                "friendlyWhen": "just a moment ago",
                "minorEdit": false,
                "number": 1,
                "when": "2021-09-02T06:36:33.937Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Content
>|ID|Title|Type|Status|Space Name|Created By|Created At|
>|---|---|---|---|---|---|---|
>| 16711862 | [XSOAR_Page_234567](https://xsoar-bd.atlassian.net/wiki/spaces/XSOAR/pages/16711862/XSOAR_Page_234567) | page | current | XSOAR_Project | John Doe | 2021-09-02T06:36:33.937Z |


### confluence-cloud-comment-create
***
Creates a comment for the given content.<br/>
Note: To view the expansion of content properties, execute the confluence-cloud-content-list and confluence-cloud-content-search commands.


#### Base Command

`confluence-cloud-comment-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the new content. <br/>Possible values: current, trashed, draft. <br/><br/>Note: The term 'current' refers to the comment that is currently active.<br/><br/>Default is current. | Optional | 
| body_value | The body of the new content.<br/><br/>Note: 'body_value' must be a string. | Required | 
| body_representation | The content format type. <br/>Possible values: storage, editor2, editor. | Required | 
| ancestor_id |The ID of the parent comment for which to create the child comment. <br/><br/>Note: To retrieve the ancestor_id, execute the confluence-cloud-content-search command using the query="type=comment" argument. | Optional | 
| container_id | The ID of the container for which to create a comment. <br/><br/>Note: To retrieve the container_id, execute the confluence-cloud-content-list command. | Required | 
| container_type | The type of the container. <br/>Possible values: page, blogpost. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Comment.id | String | The ID of the comment. | 
| ConfluenceCloud.Comment.type | String | Type of the comment. | 
| ConfluenceCloud.Comment.status | String | Status of the comment. | 
| ConfluenceCloud.Comment.title | String | Title of the comment. | 
| ConfluenceCloud.Comment.childTypes.attachment.value | Boolean | Whether the attachment has the given comment. | 
| ConfluenceCloud.Comment.childTypes.attachment._links.self | String | Link to the attachment with the given comment. | 
| ConfluenceCloud.Comment.childTypes.comment.value | Boolean | Whether a comment is associated with the given comment. | 
| ConfluenceCloud.Comment.childTypes.comment._links.self | String | Link to the comment associated with the given comment. | 
| ConfluenceCloud.Comment.childTypes.page.value | Boolean | Whether the page is associated with the given comment. | 
| ConfluenceCloud.Comment.childTypes.page._links.self | String | Link to the page associated with the given comment. | 
| ConfluenceCloud.Comment.space.id | Number | ID of the space that the comment is being created in. | 
| ConfluenceCloud.Comment.space.key | String | Key of the space that the comment is being created in. | 
| ConfluenceCloud.Comment.space.name | String | Name of the space that the comment is being created in. | 
| ConfluenceCloud.Comment.space.type | String | Type of the space that the comment is being created in. | 
| ConfluenceCloud.Comment.space.status | String | Status of the space that the comment is being created in. | 
| ConfluenceCloud.Comment.space._links.webui | String | Web user interface link to the space that the comment is being created in. | 
| ConfluenceCloud.Comment.space._links.self | String | Link to the space that the comment is being created in. | 
| ConfluenceCloud.Comment.history.latest | Boolean | Whether the comment is the latest comment. | 
| ConfluenceCloud.Comment.history.createdBy.type | String | Type of the user who created the comment. | 
| ConfluenceCloud.Comment.history.createdBy.accountId | String | Account ID of the user creating the comment. | 
| ConfluenceCloud.Comment.history.createdBy.accountType | String | Account type of the user creating the comment. | 
| ConfluenceCloud.Comment.history.createdBy.email | String | Email of the user creating the comment. | 
| ConfluenceCloud.Comment.history.createdBy.publicName | String | Public name of the user creating the comment. | 
| ConfluenceCloud.Comment.history.createdBy.profilePicture.path | String | Profile picture path of the user creating the comment. | 
| ConfluenceCloud.Comment.history.createdBy.profilePicture.width | Number | Width in pixels of the profile picture of the user. | 
| ConfluenceCloud.Comment.history.createdBy.profilePicture.height | Number | Height in pixels of the profile picture of the user. | 
| ConfluenceCloud.Comment.history.createdBy.profilePicture.isDefault | Boolean | Whether the profile picture is default. | 
| ConfluenceCloud.Comment.history.createdBy.displayName | String | Display name of the user who created the comment. | 
| ConfluenceCloud.Comment.history.createdBy.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Comment.history.createdBy._links.self | String | Link to the creator of the comment. | 
| ConfluenceCloud.Comment.history.createdDate | Date | Date and time, in ISO 8601 format, when the comment was created. | 
| ConfluenceCloud.Comment.history._links.self | String | Link to the history of the comment. | 
| ConfluenceCloud.Comment.version.by.type | String | Type of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.accountId | String | Account ID of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.accountType | String | Account type of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.email | String | Email of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.publicName | String | Public name of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.profilePicture.path | String | Profile picture of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.profilePicture.width | Number | Width in pixels of the profile picture of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.profilePicture.height | Number | Height in pixels of the profile picture of the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Comment.version.by.displayName | String | Display name of the user  who last updated the comment. | 
| ConfluenceCloud.Comment.version.by.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Comment.version.by._links.self | String | Link to the user who last updated the comment. | 
| ConfluenceCloud.Comment.version.when | Date | Date and time, in ISO 8601 format, when the comment was updated. | 
| ConfluenceCloud.Comment.version.friendlyWhen | String | Displays when the content was created. | 
| ConfluenceCloud.Comment.version.message | String | Message of the updated comment. | 
| ConfluenceCloud.Comment.version.number | Number | Version number of the updated comment. | 
| ConfluenceCloud.Comment.version.minorEdit | Boolean | Whether the edit was minor. | 
| ConfluenceCloud.Comment.version.confRev | String | The revision ID provided by Confluence to be used as a revision in Synchrony. | 
| ConfluenceCloud.Comment.version.contentTypeModified | Boolean | True if the comment type is modified in the version. \(e.g., page to blog\) | 
| ConfluenceCloud.Comment.version._links.self | String | Link to the new version of the comment. | 
| ConfluenceCloud.Comment.ancestors.id | String | ID of the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors.type | String | Type of the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors.status | String | Status of the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors.title | String | Title of the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors.extensions.location | String | Location of the comment. | 
| ConfluenceCloud.Comment.ancestors._links.self | String | Link to the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors._links.tinyui | String | Tiny link to the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors._links.editui | String | Edit user interface link to the parent page of the comment. | 
| ConfluenceCloud.Comment.ancestors._links.webui | String | Web user interface link to the parent page of the comment. | 
| ConfluenceCloud.Comment.container.id | Number | ID of the container of the comment. | 
| ConfluenceCloud.Comment.container.key | String | Key of the container of the comment. | 
| ConfluenceCloud.Comment.container.name | String | Name of the container of the comment. | 
| ConfluenceCloud.Comment.container.type | String | Type of the container of the comment. | 
| ConfluenceCloud.Comment.container.status | String | Status of the container of the comment. | 
| ConfluenceCloud.Comment.container._links.webui | String | Web user interface link to the container of the comment. | 
| ConfluenceCloud.Comment.container._links.self | String | Link to the container of the comment. | 
| ConfluenceCloud.Comment.body.storage.value | String | The body of the new comment. | 
| ConfluenceCloud.Comment.body.storage.representation | String | Representation format of the comment. | 
| ConfluenceCloud.Comment.extensions.location | String | Location of the comment. | 
| ConfluenceCloud.Comment._links.editui | String | Edit user interface link of the comment. | 
| ConfluenceCloud.Comment._links.webui | String | Web user interface link of the comment. | 
| ConfluenceCloud.Comment._links.context | String | Context link of the comment. | 
| ConfluenceCloud.Comment._links.self | String | Link to the comment. | 
| ConfluenceCloud.Comment._links.tinyui | String | Tiny link of the comment. | 
| ConfluenceCloud.Comment._links.collection | String | Collection link of the comment. | 
| ConfluenceCloud.Comment._links.base | String | Base link to the comment. | 


#### Command Example
```!confluence-cloud-comment-create body_value="hello" body_representation="storage" container_id=2031630```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Comment": {
            "_expandable": {
                "children": "/rest/api/content/16711873/child",
                "descendants": "/rest/api/content/16711873/descendant",
                "restrictions": "/rest/api/content/16711873/restriction/byOperation"
            },
            "_links": {
                "base": "https://xsoar-bd.atlassian.net/wiki",
                "collection": "/rest/api/content",
                "context": "/wiki",
                "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711873",
                "webui": "/spaces/XSOAR/blog/2021/08/06/2031630/XSOAR_blogpost?focusedCommentId=16711873#comment-16711873"
            },
            "body": {
                "storage": {
                    "_expandable": {
                        "content": "/rest/api/content/16711873"
                    },
                    "representation": "storage",
                    "value": "hello"
                }
            },
            "container": {
                "_expandable": {
                    "children": "/rest/api/content/2031630/child",
                    "container": "/rest/api/space/XSOAR",
                    "descendants": "/rest/api/content/2031630/descendant",
                    "restrictions": "/rest/api/content/2031630/restriction/byOperation",
                    "space": "/rest/api/space/XSOAR"
                },
                "_links": {
                    "editui": "/pages/resumedraft.action?draftId=2031630",
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/2031630",
                    "tinyui": "/x/DgAf",
                    "webui": "/spaces/XSOAR/blog/2021/08/06/2031630/XSOAR_blogpost"
                },
                "history": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/2031630/history"
                    },
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-06T06:59:04.777Z",
                    "latest": true
                },
                "id": "2031630",
                "status": "current",
                "title": "XSOAR_blogpost",
                "type": "blogpost",
                "version": {
                    "_expandable": {
                        "content": "/rest/api/content/2031630"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/2031630/version/1"
                    },
                    "by": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "confRev": "confluence$content$2031630.4",
                    "contentTypeModified": false,
                    "friendlyWhen": "Aug 06, 2021",
                    "minorEdit": false,
                    "number": 1,
                    "syncRev": "0.confluence$content$2031630.3",
                    "syncRevSource": "synchrony-ack",
                    "when": "2021-08-06T06:59:04.777Z"
                }
            },
            "extensions": {
                "location": "footer"
            },
            "history": {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711873/history"
                },
                "createdBy": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                    },
                    "accountId": "5ff2e30b4d2179006ea18449",
                    "accountType": "atlassian",
                    "displayName": "John Doe",
                    "email": "dummy.dummy@dummy.com",
                    "isExternalCollaborator": false,
                    "profilePicture": {
                        "height": 48,
                        "isDefault": false,
                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                        "width": 48
                    },
                    "publicName": "John Doe",
                    "type": "known"
                },
                "createdDate": "2021-09-02T06:36:36.737Z",
                "latest": true
            },
            "id": "16711873",
            "space": {
                "_expandable": {
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=XSOAR",
                    "settings": "/rest/api/space/XSOAR/settings",
                    "theme": "/rest/api/space/XSOAR/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/XSOAR",
                    "webui": "/spaces/XSOAR"
                },
                "id": 2064386,
                "key": "XSOAR",
                "name": "XSOAR_Project",
                "status": "current",
                "type": "global"
            },
            "status": "current",
            "title": "Re: XSOAR_blogpost",
            "type": "comment",
            "version": {
                "_expandable": {
                    "content": "/rest/api/content/16711873"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/16711873/version/1"
                },
                "by": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                    },
                    "accountId": "5ff2e30b4d2179006ea18449",
                    "accountType": "atlassian",
                    "displayName": "John Doe",
                    "email": "dummy.dummy@dummy.com",
                    "isExternalCollaborator": false,
                    "profilePicture": {
                        "height": 48,
                        "isDefault": false,
                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                        "width": 48
                    },
                    "publicName": "John Doe",
                    "type": "known"
                },
                "contentTypeModified": false,
                "friendlyWhen": "just a moment ago",
                "minorEdit": false,
                "number": 1,
                "when": "2021-09-02T06:36:36.737Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Comment
>|ID|Title|Type|Status|Space Name|Created By|Created At|
>|---|---|---|---|---|---|---|
>| 16711873 | [Re: XSOAR_blogpost](https://xsoar-bd.atlassian.net/wiki/spaces/XSOAR/blog/2021/08/06/2031630/XSOAR_blogpost?focusedCommentId=16711873#comment-16711873) | comment | current | XSOAR_Project | John Doe | 2021-09-02T06:36:36.737Z |


### confluence-cloud-space-list
***
Returns a list of all Confluence spaces.


#### Base Command

`confluence-cloud-space-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of records to retrieve in the response.<br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 50. | Optional | 
| offset | The starting index of the returned spaces.<br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 0. | Optional | 
| space_key | The space key to retrieve the specific space.<br/><br/>Note: Supports a comma-separated list of values. | Optional | 
| space_id | The space ID to retrieve the specific space.<br/><br/>Note: Supports a comma-separated list of values. | Optional | 
| status | Filter the results to list the spaces based on their status. <br/>Possible values: current, archived.<br/><br/>Note: The term 'current' refers to the space that is currently active. | Optional | 
| type | Filter the results to list the spaces based on their type. <br/>Possible values: global, personal. | Optional | 
| favourite | Filter the results to the favorite spaces of the current user. <br/>Possible values: true, false. | Optional | 
| expand | Indicates which properties to expand. <br/>For reference, visit https://developer.atlassian.com/cloud/confluence/rest/api-group-space/#api-wiki-rest-api-space-get.<br/><br/>Note: To separate multiple values, use commas. Expanded properties will be populated in context data only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Space.id | Number | ID of the space. | 
| ConfluenceCloud.Space.key | String | Key of the space. | 
| ConfluenceCloud.Space.name | String | Name of the space. | 
| ConfluenceCloud.Space.description.view.value | String | The description of the space in view format. | 
| ConfluenceCloud.Space.description.view.representation | String | Representation format of the description in view format. | 
| ConfluenceCloud.Space.description.plain.value | String | The description of the space in plain format. | 
| ConfluenceCloud.Space.description.plain.representation | String | Representation format of the description in plain format. | 
| ConfluenceCloud.Space.homepage.id | String | ID of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.type | String | Type of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.status | String | Status of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.title | String | Title of the homepage of the space. | 
| ConfluenceCloud.Space.homepage.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Space.homepage._links.self | String | Link to the homepage of the space. | 
| ConfluenceCloud.Space.homepage._links.tinyui | String | Tiny link to the homepage of the space. | 
| ConfluenceCloud.Space.homepage._links.editui | String | Edit the user interface link to the homepage of the space. | 
| ConfluenceCloud.Space.homepage._links.webui | String | Web user interface link to the homepage of the space. | 
| ConfluenceCloud.Space.type | String | Type of the space. | 
| ConfluenceCloud.Space.permissions.id | Number | ID of the space permission. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.type | String | Type of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.accountId | String | Account ID of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.accountType | String | Account type of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.email | String | Email of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.publicName | String | Public name to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.path | String | Path of the user's profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.width | Number | Width in pixels of the user's profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.height | Number | Height in pixels of the user's profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.profilePicture.isDefault | Boolean | Whether the profile picture of the user is the default profile picture to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.displayName | String | Display name of the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.results.isExternalCollaborator | Boolean | Whether the user is an external collaborator user. | 
| ConfluenceCloud.Space.permissions.subjects.user.results._links.self | String | Link to the user to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.user.size | Number | Size of the list of users for a given space. | 
| ConfluenceCloud.Space.permissions.subjects.group.results.type | String | Type of the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.results.name | String | Name of the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.results.id | String | ID of the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.results._links.self | String | Link to the group to whom the space permission applies. | 
| ConfluenceCloud.Space.permissions.subjects.group.size | Number | Size of the list of groups for the given space. | 
| ConfluenceCloud.Space.permissions.operation.operation | String | Name of the permission operation. | 
| ConfluenceCloud.Space.permissions.operation.targetType | String | The space or content type that the operation applies to. | 
| ConfluenceCloud.Space.permissions.anonymousAccess | Boolean | Whether anonymous users have permission to use the operation. | 
| ConfluenceCloud.Space.permissions.unlicensedAccess | Boolean | Whether unlicensed users have access from JIRA Service Desk when used with the read space operation. | 
| ConfluenceCloud.Space.status | String | Status of the space. | 
| ConfluenceCloud.Space._links.webui | String | Web user interface link of the space. | 
| ConfluenceCloud.Space._links.context | String | Context link of the space. | 
| ConfluenceCloud.Space._links.self | String | Link to the space. | 
| ConfluenceCloud.Space._links.collection | String | Collection link of the space. | 
| ConfluenceCloud.Space._links.base | String | Base link to the space. | 


#### Command Example
```!confluence-cloud-space-list limit=2```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Space": [
            {
                "_expandable": {
                    "homepage": "/rest/api/content/12943822",
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=unique2",
                    "settings": "/rest/api/space/unique2/settings",
                    "theme": "/rest/api/space/unique2/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/unique2",
                    "webui": "/spaces/unique2"
                },
                "history": {
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-26T08:50:12.879Z"
                },
                "id": 12943669,
                "key": "unique2",
                "name": "11Nam quis nulla. Integer malesuada. In in enim a arcu imperdiet malesuada. Sed vel lectus. Donec odio urna, tempus molestie, porttitor ut, iaculis quis, sem. Phasellus rhoncus. Aenean id metus id velit",
                "status": "current",
                "type": "global"
            },
            {
                "_expandable": {
                    "homepage": "/rest/api/content/12976407",
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=unique22",
                    "settings": "/rest/api/space/unique22/settings",
                    "theme": "/rest/api/space/unique22/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/unique22",
                    "webui": "/spaces/unique22"
                },
                "history": {
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-26T13:19:25.526Z"
                },
                "id": 12976314,
                "key": "unique22",
                "name": "11Nam quis nulla. Integer malesuada. In in enim a arcu imperdiet malesuada. Sed vel lectus. Donec odio urna, tempus molestie, porttitor ut, iaculis quis, sem. Phasellus rhoncus. Aenean id metus id velit",
                "status": "current",
                "type": "global"
            }
        ]
    }
}
```

#### Human Readable Output

>### Space(s)
>|ID|Space Key|Name|Type|Status|Created By|Created At|
>|---|---|---|---|---|---|---|
>| 12943669 | unique2 | [11Nam quis nulla. Integer malesuada. In in enim a arcu imperdiet malesuada. Sed vel lectus. Donec odio urna, tempus molestie, porttitor ut, iaculis quis, sem. Phasellus rhoncus. Aenean id metus id velit](https://xsoar-bd.atlassian.net/wiki/spaces/unique2) | global | current | John Doe | 2021-08-26T08:50:12.879Z |
>| 12976314 | unique22 | [11Nam quis nulla. Integer malesuada. In in enim a arcu imperdiet malesuada. Sed vel lectus. Donec odio urna, tempus molestie, porttitor ut, iaculis quis, sem. Phasellus rhoncus. Aenean id metus id velit](https://xsoar-bd.atlassian.net/wiki/spaces/unique22) | global | current | John Doe | 2021-08-26T13:19:25.526Z |


### confluence-cloud-content-list
***
Returns the list of content of Confluence.


#### Base Command

`confluence-cloud-content-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of records to retrieve in the response.<br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 50. | Optional | 
| offset | The starting index of the returned content.<br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 0. | Optional | 
| space_key | The space key to retrieve the contents of a specific space. | Optional | 
| type | The type to retrieve the contents. <br/>Possible values: page, blogpost. <br/><br/>Default is page. | Optional | 
| sort_order | Order in which the response will be sorted. <br/>Possible values: asc, desc.<br/><br/>Note: If ‘sort_key’ is specified, the default value for ‘sort_order’ is ascending. | Optional | 
| sort_key | Key based on which the response will be sorted.<br/><br/>Note: If 'sort_order' is specified, 'sort_key' is required. | Optional | 
| creation_date | The date from which to return the content created on that specific date. <br/>Formats accepted: 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd. | Optional | 
| status | Filter the results to a set of content based on their status. If set to any, content with any status is returned. <br/>Possible values: any, current, trashed, draft, archived.<br/><br/>Note: The term 'current' refers to the content that is currently active. | Optional | 
| expand | Indicates which properties to expand. <br/>For reference, visit https://developer.atlassian.com/cloud/confluence/rest/api-group-content/#api-wiki-rest-api-content-get.<br/><br/>Note: To separate multiple values, use commas. Expanded properties will be populated in context data only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Content.id | String | The ID of the content. | 
| ConfluenceCloud.Content.type | String | Type of the content. | 
| ConfluenceCloud.Content.status | String | Status of the content. | 
| ConfluenceCloud.Content.title | String | Title of the content. | 
| ConfluenceCloud.Content.childTypes.attachment.value | Boolean | Whether the attachment has the given content. | 
| ConfluenceCloud.Content.childTypes.attachment._links.self | String | Link to the attachment with the given content. | 
| ConfluenceCloud.Content.childTypes.comment.value | Boolean | Whether a comment is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.comment._links.self | String | Link to the comment associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page.value | Boolean | Whether the page is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page._links.self | String | Link to page associated with given content. | 
| ConfluenceCloud.Content.space.id | Number | ID of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.key | String | Key of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.name | String | Name of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.type | String | Type of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.status | String | Status of the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.webui | String | Web user interface link to the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.self | String | Link to the space that the content is being created in. | 
| ConfluenceCloud.Content.history.latest | Boolean | Whether the content is the latest content. | 
| ConfluenceCloud.Content.history.createdBy.type | String | Type of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.accountId | String | Account ID of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.accountType | String | Account type of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.email | String | Email of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.publicName | String | Public name of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.path | String | Profile picture path of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.width | Number | Width in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.height | Number | Height in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Content.history.createdBy.displayName | String | Display name of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.history.createdBy._links.self | String | Link to the creator of the content. | 
| ConfluenceCloud.Content.history.createdDate | Date | Date and time, in ISO 8601 format, when the content was created. | 
| ConfluenceCloud.Content.history._links.self | String | Link to the history of the content. | 
| ConfluenceCloud.Content.version.by.type | String | Type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountId | String | Account ID of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountType | String | Account type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.email | String | Email of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.publicName | String | Public name of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.path | String | Profile picture path of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.width | Number | Width in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.height | Number | Height in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Content.version.by.displayName | String | Display name of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.version.by._links.self | String | Link to the user who last updated the content. | 
| ConfluenceCloud.Content.version.when | Date | Date and time, in ISO 8601 format, when the content was updated. | 
| ConfluenceCloud.Content.version.friendlyWhen | String | Displays when the content was created. | 
| ConfluenceCloud.Content.version.message | String | Message of the updated content. | 
| ConfluenceCloud.Content.version.number | Number | Version number of the updated content. | 
| ConfluenceCloud.Content.version.minorEdit | Boolean | Whether the edit was minor. | 
| ConfluenceCloud.Content.version.confRev | String | The revision ID provided by Confluence to be used as a revision in Synchrony | 
| ConfluenceCloud.Content.version.contentTypeModified | Boolean | True if the content type is modified in the version. \(e.g., page to blog\) | 
| ConfluenceCloud.Content.version._links.self | String | Link to the new version of the content. | 
| ConfluenceCloud.Content.ancestors.id | String | ID of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.type | String | Type of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.status | String | Status of the parent page of the content. | 
| ConfluenceCloud.Content.container.id | Number | ID of the container of the content. | 
| ConfluenceCloud.Content.container.key | String | Key of the container of the content. | 
| ConfluenceCloud.Content.container.name | String | Name of the container of the content. | 
| ConfluenceCloud.Content.container.type | String | Type of the container of the content. | 
| ConfluenceCloud.Content.container.status | String | Status of the container of the content. | 
| ConfluenceCloud.Content.container._links.webui | String | Web user interface link to the container of the content. | 
| ConfluenceCloud.Content.container._links.self | String | Link to the container of the content. | 
| ConfluenceCloud.Content.body.storage.value | String | The body of the new content. | 
| ConfluenceCloud.Content.body.storage.representation | String | Representation format of the content. | 
| ConfluenceCloud.Content.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Content._links.editui | String | Edit the user interface link of the content. | 
| ConfluenceCloud.Content._links.webui | String | Web user interface link of the content. | 
| ConfluenceCloud.Content._links.self | String | Link to the content. | 
| ConfluenceCloud.Content._links.tinyui | String | Tiny link of the content. | 


#### Command Example
```!confluence-cloud-content-list limit=2```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Content": [
            {
                "_expandable": {
                    "children": "/rest/api/content/65639/child",
                    "descendants": "/rest/api/content/65639/descendant",
                    "restrictions": "/rest/api/content/65639/restriction/byOperation"
                },
                "_links": {
                    "editui": "/pages/resumedraft.action?draftId=65639",
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639",
                    "tinyui": "/x/ZwAB",
                    "webui": "/spaces/~680738455/pages/65639/demo"
                },
                "childTypes": {
                    "attachment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639/child/attachment"
                        },
                        "value": false
                    },
                    "comment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639/child/comment"
                        },
                        "value": true
                    },
                    "page": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639/child/page"
                        },
                        "value": true
                    }
                },
                "container": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=~680738455",
                        "settings": "/rest/api/space/~680738455/settings",
                        "theme": "/rest/api/space/~680738455/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/~680738455",
                        "webui": "/spaces/~680738455"
                    },
                    "id": 65538,
                    "key": "~680738455",
                    "name": "John Doe",
                    "status": "current",
                    "type": "personal"
                },
                "extensions": {
                    "position": "none"
                },
                "history": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639/history"
                    },
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-02T09:53:05.077Z",
                    "latest": true
                },
                "id": "65639",
                "space": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=~680738455",
                        "settings": "/rest/api/space/~680738455/settings",
                        "theme": "/rest/api/space/~680738455/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/~680738455",
                        "webui": "/spaces/~680738455"
                    },
                    "id": 65538,
                    "key": "~680738455",
                    "name": "John Doe",
                    "status": "current",
                    "type": "personal"
                },
                "status": "current",
                "title": "demo",
                "type": "page",
                "version": {
                    "_expandable": {
                        "content": "/rest/api/content/65639"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639/version/4"
                    },
                    "by": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "confRev": "confluence$content$65639.32",
                    "contentTypeModified": false,
                    "friendlyWhen": "yesterday at 11:39 AM",
                    "minorEdit": false,
                    "number": 4,
                    "syncRev": "0.confluence$content$65639.30",
                    "syncRevSource": "synchrony-ack",
                    "when": "2021-09-01T06:09:38.912Z"
                }
            },
            {
                "_expandable": {
                    "children": "/rest/api/content/65656/child",
                    "descendants": "/rest/api/content/65656/descendant",
                    "restrictions": "/rest/api/content/65656/restriction/byOperation"
                },
                "_links": {
                    "editui": "/pages/resumedraft.action?draftId=65656",
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65656",
                    "tinyui": "/x/eAAB",
                    "webui": "/spaces/~680738455/pages/65656/Product+requirements"
                },
                "ancestors": [
                    {
                        "_expandable": {
                            "children": "/rest/api/content/65639/child",
                            "container": "/rest/api/space/~680738455",
                            "descendants": "/rest/api/content/65639/descendant",
                            "history": "/rest/api/content/65639/history",
                            "restrictions": "/rest/api/content/65639/restriction/byOperation",
                            "space": "/rest/api/space/~680738455"
                        },
                        "_links": {
                            "editui": "/pages/resumedraft.action?draftId=65639",
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65639",
                            "tinyui": "/x/ZwAB",
                            "webui": "/spaces/~680738455/pages/65639/demo"
                        },
                        "extensions": {
                            "position": "none"
                        },
                        "id": "65639",
                        "status": "current",
                        "title": "demo",
                        "type": "page"
                    }
                ],
                "childTypes": {
                    "attachment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65656/child/attachment"
                        },
                        "value": false
                    },
                    "comment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65656/child/comment"
                        },
                        "value": true
                    },
                    "page": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65656/child/page"
                        },
                        "value": false
                    }
                },
                "container": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=~680738455",
                        "settings": "/rest/api/space/~680738455/settings",
                        "theme": "/rest/api/space/~680738455/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/~680738455",
                        "webui": "/spaces/~680738455"
                    },
                    "id": 65538,
                    "key": "~680738455",
                    "name": "John Doe",
                    "status": "current",
                    "type": "personal"
                },
                "extensions": {
                    "position": 499279072
                },
                "history": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65656/history"
                    },
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-02T09:53:05.312Z",
                    "latest": true
                },
                "id": "65656",
                "space": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=~680738455",
                        "settings": "/rest/api/space/~680738455/settings",
                        "theme": "/rest/api/space/~680738455/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/~680738455",
                        "webui": "/spaces/~680738455"
                    },
                    "id": 65538,
                    "key": "~680738455",
                    "name": "John Doe",
                    "status": "current",
                    "type": "personal"
                },
                "status": "current",
                "title": "Product requirements",
                "type": "page",
                "version": {
                    "_expandable": {
                        "content": "/rest/api/content/65656"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/65656/version/1"
                    },
                    "by": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "confRev": "confluence$content$65656.5",
                    "contentTypeModified": false,
                    "friendlyWhen": "Aug 02, 2021",
                    "minorEdit": false,
                    "number": 1,
                    "syncRev": "0.confluence$content$65656.2",
                    "syncRevSource": "synchrony-ack",
                    "when": "2021-08-02T09:53:05.312Z"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Content(s)
>|ID|Title|Type|Status|Space Name|Created By|Created At|Version
>|---|---|---|---|---|---|---|---|
>| 65639 | [demo](https://xsoar-bd.atlassian.net/wiki/spaces/~680738455/pages/65639/demo) | page | current | John Doe | John Doe | 2021-08-02T09:53:05.077Z | 2 |
>| 65656 | [Product requirements](https://xsoar-bd.atlassian.net/wiki/spaces/~680738455/pages/65656/Product+requirements) | page | current | John Doe | John Doe | 2021-08-02T09:53:05.312Z | 2 |


### confluence-cloud-content-delete
***
Delete the content depending on the content's type and status.<br/><br/>
Note: If the content's type is page or blogpost, it should be moved to trash before deleting permanently.


#### Base Command

`confluence-cloud-content-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_id | The ID of the content to be deleted. | Required | 
| deletion_type | The deletion type for the content to be deleted.<br/>Possible values: move to trash (current), permanent delete (trashed), permanent delete draft (draft). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!confluence-cloud-content-delete content_id="3704312"```

#### Human Readable Output

>Content with Id 3704312 is deleted successfully.

### confluence-cloud-content-update
***
Update the existing content with new content.<br/>
Note: Updating draft content is currently not supported.


#### Base Command

`confluence-cloud-content-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| content_id | The ID of the content to be updated. | Required | 
| status | The updated status of the content.<br/>Possible values: current, trashed, historical, draft.<br/><br/>Note: The term 'current' refers to the content that is currently active.<br/><br/>Default is current. | Optional | 
| version | The new version for the updated content. Set the version to the current version number incremented by one. If the status changed to 'draft', then it must be 1.<br/><br/>Note: To retrieve the current version, execute the confluence-cloud-content-search command using the query="id={content_id}" argument. | Required | 
| title | The updated title of the content. If the field is not changing, set the title to the current title.<br/><br/>Note: The maximum title length is 255 characters. | Required | 
| type | The type of content. Set the type to the current type of the content. <br/>Possible values: page, blogpost, comment, attachment. | Required | 
| body_value | The body of the content in the relevant format. | Optional | 
| body_representation | The content format type.<br/>Possible values: view, export_view, styled_view, storage, editor2, anonymous_export_view.<br/><br/>Note: If type is comment, possible values are editor, editor2 or storage. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Content.id | String | The ID of the content. | 
| ConfluenceCloud.Content.type | String | Type of the content. | 
| ConfluenceCloud.Content.status | String | Status of the content. | 
| ConfluenceCloud.Content.title | String | Title of the content. | 
| ConfluenceCloud.Content.childTypes.attachment.value | Boolean | Whether the attachment has the given content. | 
| ConfluenceCloud.Content.childTypes.attachment._links.self | String | Link to the attachment with the given content. | 
| ConfluenceCloud.Content.childTypes.comment.value | Boolean | Whether a comment is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.comment._links.self | String | Link to the comment associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page.value | Boolean | Whether the page is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page._links.self | String | Link to the page associated with the given content. | 
| ConfluenceCloud.Content.space.id | Number | ID of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.key | String | Key of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.name | String | Name of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.type | String | Type of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.status | String | Status of the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.webui | String | Web user interface link to the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.self | String | Link to the space that the content is being created in. | 
| ConfluenceCloud.Content.history.latest | Boolean | Whether the content is the latest content. | 
| ConfluenceCloud.Content.history.createdBy.type | String | Type of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.accountId | String | Account ID of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.accountType | String | Account type of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.email | String | Email of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.publicName | String | Public name of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.path | String | Profile picture path of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.width | Number | Width in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.height | Number | Height in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.isDefault | Boolean | Whether the profile picture is default. | 
| ConfluenceCloud.Content.history.createdBy.displayName | String | Display name of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.history.createdBy._links.self | String | Link to the creator of the content. | 
| ConfluenceCloud.Content.history.createdDate | Date | Date and time, in ISO 8601 format, when the content was created. | 
| ConfluenceCloud.Content.history._links.self | String | Link to the history of the content. | 
| ConfluenceCloud.Content.version.by.type | String | Type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountId | String | Account ID of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountType | String | Account type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.email | String | Email of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.publicName | String | Public name of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.path | String | Profile picture path of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.width | Number | Width in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.height | Number | Height in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.isDefault | Boolean | Whether the profile picture is default. | 
| ConfluenceCloud.Content.version.by.displayName | String | Display name of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.version.by._links.self | String | Link to the user who last updated the content. | 
| ConfluenceCloud.Content.version.when | Date | Date and time, in ISO 8601 format, when the content was updated. | 
| ConfluenceCloud.Content.version.friendlyWhen | String | Display the information of when the content was created. | 
| ConfluenceCloud.Content.version.message | String | Message of the updated content. | 
| ConfluenceCloud.Content.version.number | Number | Version number of the updated content. | 
| ConfluenceCloud.Content.version.minorEdit | Boolean | Whether the edit was minor. | 
| ConfluenceCloud.Content.version.confRev | String | The revision ID provided by Confluence to be used as a revision in Synchrony. | 
| ConfluenceCloud.Content.version.contentTypeModified | Boolean | True if the content type is modified in the version. \(e.g. page to blog\) | 
| ConfluenceCloud.Content.version._links.self | String | Link to the new version of the content. | 
| ConfluenceCloud.Content.ancestors.id | String | ID of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.type | String | Type of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.status | String | Status of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.title | String | Title of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Content.ancestors._links.self | String | Link to the parent page of the content. | 
| ConfluenceCloud.Content.ancestors._links.tinyui | String | Tiny link to the parent page of the content. | 
| ConfluenceCloud.Content.ancestors._links.editui | String | Edit the user interface link to the parent page of the content. | 
| ConfluenceCloud.Content.ancestors._links.webui | String | Web user interface link to the parent page of the content. | 
| ConfluenceCloud.Content.container.id | Number | ID of the container of the content. | 
| ConfluenceCloud.Content.container.key | String | Key of the container of the content. | 
| ConfluenceCloud.Content.container.name | String | Name of the container of the content. | 
| ConfluenceCloud.Content.container.type | String | Type of the container of the content. | 
| ConfluenceCloud.Content.container.status | String | Status of the container of the content. | 
| ConfluenceCloud.Content.container._links.webui | String | Web user interface link to the container of the content. | 
| ConfluenceCloud.Content.container._links.self | String | Link to the container of the content. | 
| ConfluenceCloud.Content.body.storage.value | String | The body of the new content. | 
| ConfluenceCloud.Content.body.storage.representation | String | Representation format of the content. | 
| ConfluenceCloud.Content.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Content._links.editui | String | Edit the user interface link of the content. | 
| ConfluenceCloud.Content._links.webui | String | Web user interface link of the content. | 
| ConfluenceCloud.Content._links.context | String | Context link of the content. | 
| ConfluenceCloud.Content._links.self | String | Link to the content. | 
| ConfluenceCloud.Content._links.tinyui | String | Tiny link of the content. | 
| ConfluenceCloud.Content._links.collection | String | Collection link of the content. | 
| ConfluenceCloud.Content._links.base | String | Base link to the content. | 


#### Command Example
```!confluence-cloud-content-update content_id=2097159 title="testing123" type=page version=5```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Content": {
            "_expandable": {
                "children": "/rest/api/content/2097159/child",
                "descendants": "/rest/api/content/2097159/descendant",
                "restrictions": "/rest/api/content/2097159/restriction/byOperation"
            },
            "_links": {
                "base": "https://xsoar-bd.atlassian.net/wiki",
                "collection": "/rest/api/content",
                "context": "/wiki",
                "editui": "/pages/resumedraft.action?draftId=2097159",
                "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/2097159",
                "tinyui": "/x/BwAg",
                "webui": "/spaces/XSOAR/pages/2097159/testing123"
            },
            "body": {
                "storage": {
                    "_expandable": {
                        "content": "/rest/api/content/2097159"
                    },
                    "representation": "storage"
                }
            },
            "container": {
                "_expandable": {
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=XSOAR",
                    "settings": "/rest/api/space/XSOAR/settings",
                    "theme": "/rest/api/space/XSOAR/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/XSOAR",
                    "webui": "/spaces/XSOAR"
                },
                "history": {
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-06T06:18:11.470Z"
                },
                "id": 2064386,
                "key": "XSOAR",
                "name": "XSOAR_Project",
                "status": "current",
                "type": "global"
            },
            "extensions": {
                "position": "none"
            },
            "history": {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/2097159/history"
                },
                "createdBy": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                    },
                    "accountId": "5ff2e30b4d2179006ea18449",
                    "accountType": "atlassian",
                    "displayName": "John Doe",
                    "email": "dummy.dummy@dummy.com",
                    "isExternalCollaborator": false,
                    "profilePicture": {
                        "height": 48,
                        "isDefault": false,
                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                        "width": 48
                    },
                    "publicName": "John Doe",
                    "type": "known"
                },
                "createdDate": "2021-08-06T06:23:36.076Z",
                "latest": true
            },
            "id": "2097159",
            "space": {
                "_expandable": {
                    "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=XSOAR",
                    "settings": "/rest/api/space/XSOAR/settings",
                    "theme": "/rest/api/space/XSOAR/theme"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/XSOAR",
                    "webui": "/spaces/XSOAR"
                },
                "id": 2064386,
                "key": "XSOAR",
                "name": "XSOAR_Project",
                "status": "current",
                "type": "global"
            },
            "status": "current",
            "title": "testing123",
            "type": "page",
            "version": {
                "_expandable": {
                    "content": "/rest/api/content/2097159"
                },
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/2097159/version/4"
                },
                "by": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                    },
                    "accountId": "5ff2e30b4d2179006ea18449",
                    "accountType": "atlassian",
                    "displayName": "John Doe",
                    "email": "dummy.dummy@dummy.com",
                    "isExternalCollaborator": false,
                    "profilePicture": {
                        "height": 48,
                        "isDefault": false,
                        "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                        "width": 48
                    },
                    "publicName": "John Doe",
                    "type": "known"
                },
                "confRev": "confluence$content$2097159.25",
                "contentTypeModified": false,
                "friendlyWhen": "38 minutes ago",
                "minorEdit": false,
                "number": 4,
                "syncRev": "0.confluence$content$2097159.22",
                "syncRevSource": "synchrony-ack",
                "when": "2021-09-02T05:58:18.823Z"
            }
        }
    }
}
```

#### Human Readable Output

>### Content
>|ID|Title|Type|Status|Space Name|Created By|Created At|
>|---|---|---|---|---|---|---|
>| 2097159 | [testing123](https://xsoar-bd.atlassian.net/wiki/spaces/XSOAR/pages/2097159/testing123) | page | current | XSOAR_Project | John Doe | 2021-08-06T06:23:36.076Z |


### confluence-cloud-content-search
***
Retrieves a list of content using the Confluence Query Language (CQL).<br/><br/>For more information on CQL, see: https://developer.atlassian.com/cloud/confluence/advanced-searching-using-cql/.


#### Base Command

`confluence-cloud-content-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The CQL (Confluence Query Language) string that is used to find the requested content. | Required | 
| limit | Number of records to retrieve in the response. <br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 50. | Optional | 
| content_status | Filter the result based on the content status.<br/>Possible values: current, draft, archived.<br/><br/>Note: Supports multiple comma-separated values. | Optional | 
| next_page_token | Retrieves the next page records for the given query (next_page_token retrieved in previous content response). | Optional | 
| expand | Indicates which properties to expand. <br/>For reference, visit https://developer.atlassian.com/cloud/confluence/rest/api-group-content/#api-wiki-rest-api-content-search-get.<br/><br/>Note: To separate multiple values, use commas. Expanded properties will be populated in context data only. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Content.id | String | The ID of the content. | 
| ConfluenceCloud.Content.type | String | Type of the content. | 
| ConfluenceCloud.Content.status | String | Status of the content. | 
| ConfluenceCloud.Content.title | String | Title of the content. | 
| ConfluenceCloud.Content.childTypes.attachment.value | Boolean | Whether the attachment has the given content. | 
| ConfluenceCloud.Content.childTypes.attachment._links.self | String | Link to the attachment with the given content. | 
| ConfluenceCloud.Content.childTypes.comment.value | Boolean | Whether a comment is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.comment._links.self | String | Link to the comment associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page.value | Boolean | Whether the page is associated with the given content. | 
| ConfluenceCloud.Content.childTypes.page._links.self | String | Link to the page associated with given content. | 
| ConfluenceCloud.Content.space.id | Number | ID of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.key | String | Key of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.name | String | Name of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.type | String | Type of the space that the content is being created in. | 
| ConfluenceCloud.Content.space.status | String | Status of the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.webui | String | Web user interface link to the space that the content is being created in. | 
| ConfluenceCloud.Content.space._links.self | String | Link to the space that the content is being created in. | 
| ConfluenceCloud.Content.history.latest | Boolean | Whether the content is the latest content. | 
| ConfluenceCloud.Content.history.createdBy.type | String | Type of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.accountId | String | Account ID of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.accountType | String | Account type of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.email | String | Email of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.publicName | String | Public name of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.path | String | Profile picture path of the user creating the content. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.width | Number | Width in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.height | Number | Height in pixels of the profile picture of the user. | 
| ConfluenceCloud.Content.history.createdBy.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Content.history.createdBy.displayName | String | Display name of the user who created the content. | 
| ConfluenceCloud.Content.history.createdBy.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.history.createdBy._links.self | String | Link to the creator of the content. | 
| ConfluenceCloud.Content.history.createdDate | Date | Date and time, in ISO 8601 format, when the content was created. | 
| ConfluenceCloud.Content.history._links.self | String | Link to the history of the content. | 
| ConfluenceCloud.Content.version.by.type | String | Type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountId | String | Account ID of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.accountType | String | Account type of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.email | String | Email of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.publicName | String | Public name of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.path | String | Profile picture path of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.width | Number | Width in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.height | Number | Height in pixels of the profile picture of the user who last updated the content. | 
| ConfluenceCloud.Content.version.by.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.Content.version.by.displayName | String | Display name of the user  who last updated the content. | 
| ConfluenceCloud.Content.version.by.isExternalCollaborator | Boolean | Whether the user is an external collaborator. | 
| ConfluenceCloud.Content.version.by._links.self | String | Link to the user who last updated the content. | 
| ConfluenceCloud.Content.version.when | Date | Date and time, in ISO 8601 format, when the content was updated. | 
| ConfluenceCloud.Content.version.friendlyWhen | String | Displays when the content was created. | 
| ConfluenceCloud.Content.version.message | String | Message of the updated content. | 
| ConfluenceCloud.Content.version.number | Number | Version number of the updated content. | 
| ConfluenceCloud.Content.version.minorEdit | Boolean | Whether the edit was minor. | 
| ConfluenceCloud.Content.version.confRev | String | The revision ID provided by Confluence to be used as a revision in Synchrony. | 
| ConfluenceCloud.Content.version.contentTypeModified | Boolean | True if the content type is modified in the version. \(e.g., page to blog\) | 
| ConfluenceCloud.Content.version._links.self | String | Link to the new version of the content. | 
| ConfluenceCloud.Content.ancestors.id | String | ID of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.type | String | Type of the parent page of the content. | 
| ConfluenceCloud.Content.ancestors.status | String | Status of the parent page of the content. | 
| ConfluenceCloud.Content.container.id | Number | ID of the container of the content. | 
| ConfluenceCloud.Content.container.key | String | Key of the container of the content. | 
| ConfluenceCloud.Content.container.name | String | Name of the container of the content. | 
| ConfluenceCloud.Content.container.type | String | Type of the container of the content. | 
| ConfluenceCloud.Content.container.status | String | Status of the container of the content. | 
| ConfluenceCloud.Content.container._links.webui | String | Web user interface link to the container of the content. | 
| ConfluenceCloud.Content.container._links.self | String | Link to the container of the content. | 
| ConfluenceCloud.Content.body.storage.value | String | The body of the new content. | 
| ConfluenceCloud.Content.body.storage.representation | String | Representation format of the content. | 
| ConfluenceCloud.Content.extensions.position | Number | The content extension position. | 
| ConfluenceCloud.Content._links.editui | String | Edit the user interface link of the content. | 
| ConfluenceCloud.Content._links.webui | String | Web user interface link of the content. | 
| ConfluenceCloud.Content._links.self | String | Link to the content. | 
| ConfluenceCloud.Content._links.tinyui | String | Tiny link of the content. | 
| ConfluenceCloud.PageToken.name | String | The command name. | 
| ConfluenceCloud.PageToken.next_token | String | The next page token. | 


#### Command Example
```!confluence-cloud-content-search query="type=page" limit=2```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Content": [
            {
                "_expandable": {
                    "children": "/rest/api/content/8912897/child",
                    "descendants": "/rest/api/content/8912897/descendant",
                    "restrictions": "/rest/api/content/8912897/restriction/byOperation"
                },
                "_links": {
                    "editui": "/pages/resumedraft.action?draftId=8912897",
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8912897",
                    "tinyui": "/x/AQCI",
                    "webui": "/spaces/TRIAL/pages/8912897/Trial_1"
                },
                "ancestors": [
                    {
                        "_expandable": {
                            "children": "/rest/api/content/7798799/child",
                            "container": "/rest/api/space/TRIAL",
                            "descendants": "/rest/api/content/7798799/descendant",
                            "history": "/rest/api/content/7798799/history",
                            "restrictions": "/rest/api/content/7798799/restriction/byOperation",
                            "space": "/rest/api/space/TRIAL"
                        },
                        "_links": {
                            "editui": "/pages/resumedraft.action?draftId=7798799",
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/7798799",
                            "tinyui": "/x/DwB3",
                            "webui": "/spaces/TRIAL/pages/7798799/Trial1212"
                        },
                        "extensions": {
                            "position": 4059
                        },
                        "id": "7798799",
                        "status": "current",
                        "title": "Trial1212",
                        "type": "page"
                    }
                ],
                "childTypes": {
                    "attachment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8912897/child/attachment"
                        },
                        "value": false
                    },
                    "comment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8912897/child/comment"
                        },
                        "value": false
                    },
                    "page": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8912897/child/page"
                        },
                        "value": false
                    }
                },
                "container": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=TRIAL",
                        "settings": "/rest/api/space/TRIAL/settings",
                        "theme": "/rest/api/space/TRIAL/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/TRIAL",
                        "webui": "/spaces/TRIAL"
                    },
                    "id": 33012,
                    "key": "TRIAL",
                    "name": "Trial",
                    "status": "current",
                    "type": "global"
                },
                "extensions": {
                    "position": 96200139
                },
                "history": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8912897/history"
                    },
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-19T09:11:19.755Z",
                    "latest": true
                },
                "id": "8912897",
                "space": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=TRIAL",
                        "settings": "/rest/api/space/TRIAL/settings",
                        "theme": "/rest/api/space/TRIAL/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/TRIAL",
                        "webui": "/spaces/TRIAL"
                    },
                    "id": 33012,
                    "key": "TRIAL",
                    "name": "Trial",
                    "status": "current",
                    "type": "global"
                },
                "status": "current",
                "title": "Trial_1",
                "type": "page",
                "version": {
                    "_expandable": {
                        "content": "/rest/api/content/8912897"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8912897/version/1"
                    },
                    "by": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "confRev": "confluence$content$8912897.4",
                    "contentTypeModified": false,
                    "friendlyWhen": "Aug 19, 2021",
                    "minorEdit": false,
                    "number": 1,
                    "syncRev": "0.confluence$content$8912897.2",
                    "syncRevSource": "synchrony-ack",
                    "when": "2021-08-19T09:11:19.755Z"
                }
            },
            {
                "_expandable": {
                    "children": "/rest/api/content/8847372/child",
                    "descendants": "/rest/api/content/8847372/descendant",
                    "restrictions": "/rest/api/content/8847372/restriction/byOperation"
                },
                "_links": {
                    "editui": "/pages/resumedraft.action?draftId=8847372",
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8847372",
                    "tinyui": "/x/DACH",
                    "webui": "/spaces/TRIAL/pages/8847372/Testing_XSOAR"
                },
                "ancestors": [
                    {
                        "_expandable": {
                            "children": "/rest/api/content/7798799/child",
                            "container": "/rest/api/space/TRIAL",
                            "descendants": "/rest/api/content/7798799/descendant",
                            "history": "/rest/api/content/7798799/history",
                            "restrictions": "/rest/api/content/7798799/restriction/byOperation",
                            "space": "/rest/api/space/TRIAL"
                        },
                        "_links": {
                            "editui": "/pages/resumedraft.action?draftId=7798799",
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/7798799",
                            "tinyui": "/x/DwB3",
                            "webui": "/spaces/TRIAL/pages/7798799/Trial1212"
                        },
                        "extensions": {
                            "position": 4059
                        },
                        "id": "7798799",
                        "status": "current",
                        "title": "Trial1212",
                        "type": "page"
                    }
                ],
                "childTypes": {
                    "attachment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8847372/child/attachment"
                        },
                        "value": false
                    },
                    "comment": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8847372/child/comment"
                        },
                        "value": false
                    },
                    "page": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8847372/child/page"
                        },
                        "value": false
                    }
                },
                "container": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=TRIAL",
                        "settings": "/rest/api/space/TRIAL/settings",
                        "theme": "/rest/api/space/TRIAL/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/TRIAL",
                        "webui": "/spaces/TRIAL"
                    },
                    "id": 33012,
                    "key": "TRIAL",
                    "name": "Trial",
                    "status": "current",
                    "type": "global"
                },
                "extensions": {
                    "position": 633071049
                },
                "history": {
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8847372/history"
                    },
                    "createdBy": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "createdDate": "2021-08-19T10:09:37.066Z",
                    "latest": true
                },
                "id": "8847372",
                "space": {
                    "_expandable": {
                        "lookAndFeel": "/rest/api/settings/lookandfeel?spaceKey=TRIAL",
                        "settings": "/rest/api/space/TRIAL/settings",
                        "theme": "/rest/api/space/TRIAL/theme"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/space/TRIAL",
                        "webui": "/spaces/TRIAL"
                    },
                    "id": 33012,
                    "key": "TRIAL",
                    "name": "Trial",
                    "status": "current",
                    "type": "global"
                },
                "status": "current",
                "title": "Testing_XSOAR",
                "type": "page",
                "version": {
                    "_expandable": {
                        "content": "/rest/api/content/8847372"
                    },
                    "_links": {
                        "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/content/8847372/version/1"
                    },
                    "by": {
                        "_links": {
                            "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5ff2e30b4d2179006ea18449"
                        },
                        "accountId": "5ff2e30b4d2179006ea18449",
                        "accountType": "atlassian",
                        "displayName": "John Doe",
                        "email": "dummy.dummy@dummy.com",
                        "isExternalCollaborator": false,
                        "profilePicture": {
                            "height": 48,
                            "isDefault": false,
                            "path": "/wiki/aa-avatar/5ff2e30b4d2179006ea18449",
                            "width": 48
                        },
                        "publicName": "John Doe",
                        "type": "known"
                    },
                    "confRev": "confluence$content$8847372.4",
                    "contentTypeModified": false,
                    "friendlyWhen": "Aug 19, 2021",
                    "minorEdit": false,
                    "number": 1,
                    "syncRev": "0.confluence$content$8847372.2",
                    "syncRevSource": "synchrony-ack",
                    "when": "2021-08-19T10:09:37.066Z"
                }
            }
        ],
        "PageToken": {
            "Content": {
                "name": "confluence-cloud-content-search",
                "next_token": "_sa_WyJcdDg4NDczNzIgUU5aRTlIVzxbclZnSitSZXBSTU4gY3AiXQ=="
            }
        }
    }
}
```

#### Human Readable Output

>### Content(s)
>|ID|Title|Type|Status|Space Name|Created By|Created At|Version|
>|---|---|---|---|---|---|---|---|
>| 8912897 | [Trial_1](https://xsoar-bd.atlassian.net/wiki/spaces/TRIAL/pages/8912897/Trial_1) | page | current | Trial | John Doe | 2021-08-19T09:11:19.755Z | 3 |
>| 8847372 | [Testing_XSOAR](https://xsoar-bd.atlassian.net/wiki/spaces/TRIAL/pages/8847372/Testing_XSOAR) | page | current | Trial | John Doe | 2021-08-19T10:09:37.066Z | 3 |
Run the command with argument next_page_token=_sa_WyJcdDg4NDczNzIgUU5aRTlIVzxbclZnSitSZXBSTU4gY3AiXQ== to see the next set of contents.


### confluence-cloud-user-list
***
Returns a list of users.


#### Base Command

`confluence-cloud-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of records to retrieve in the response. <br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 50. | Optional | 
| offset | The starting index of the returned users. <br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.User.type | String | Type of the user. | 
| ConfluenceCloud.User.accountId | String | Account ID of the user. | 
| ConfluenceCloud.User.accountType | String | Account type of the user. | 
| ConfluenceCloud.User.publicName | String | The public name or nickname of the user. | 
| ConfluenceCloud.User.profilePicture.path | String | Path of the user's profile picture. | 
| ConfluenceCloud.User.profilePicture.width | Number | Width in pixels of the user's profile picture. | 
| ConfluenceCloud.User.profilePicture.height | Number | Height in pixels of the user's profile picture. | 
| ConfluenceCloud.User.profilePicture.isDefault | Boolean | Whether the profile picture is the default profile picture. | 
| ConfluenceCloud.User.displayName | String | Display name of the user. | 
| ConfluenceCloud.User.isExternalCollaborator | Boolean | Whether the user is an external collaborator user. | 
| ConfluenceCloud.User._links.self | String | Link to the user. | 


#### Command Example
```!confluence-cloud-user-list limit=2```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "User": [
            {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5d9afe0010f4800c341a2bba"
                },
                "accountId": "5d9afe0010f4800c341a2bba",
                "displayName": "Opsgenie Incident Timeline",
                "isExternalCollaborator": false,
                "profilePicture": {
                    "height": 48,
                    "isDefault": false,
                    "path": "/wiki/aa-avatar/5d9afe0010f4800c341a2bba",
                    "width": 48
                },
                "publicName": "Opsgenie Incident Timeline",
                "type": "known"
            },
            {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/api/user?accountId=5d9b2860cd50b80dcea8a5b7"
                },
                "accountId": "5d9b2860cd50b80dcea8a5b7",
                "displayName": "Opsgenie Incident Timeline",
                "isExternalCollaborator": false,
                "profilePicture": {
                    "height": 48,
                    "isDefault": false,
                    "path": "/wiki/aa-avatar/5d9b2860cd50b80dcea8a5b7",
                    "width": 48
                },
                "publicName": "Opsgenie Incident Timeline",
                "type": "known"
            }
        ]
    }
}
```

#### Human Readable Output

>### User(s)
>|Account ID|Name|User Type|
>|---|---|---|
>| 5d9afe0010f4800c341a2bba | Opsgenie Incident Timeline | known |
>| 5d9b2860cd50b80dcea8a5b7 | Opsgenie Incident Timeline | known |


### confluence-cloud-group-list
***
Returns all user groups.


#### Base Command

`confluence-cloud-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Number of records to retrieve in the response.<br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 50. | Optional | 
| offset | The starting index of the returned groups.<br/><br/>Note: The minimum value supported is 0 and the maximum value supported is int32. <br/><br/>Default is 0. | Optional | 
| access_type | The group permission level for which to filter results. <br/>Possible values: user, admin, site-admin. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Group.type | String | Type of the group. | 
| ConfluenceCloud.Group.name | String | Name of the group. | 
| ConfluenceCloud.Group.id | String | ID of the group. | 
| ConfluenceCloud.Group._links.self | String | Link to the group. | 


#### Command Example
```!confluence-cloud-group-list limit=2```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Group": [
            {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/administrators"
                },
                "id": "10453df5-f7fc-47be-8ca7-bc2949c1bd5b",
                "name": "administrators",
                "type": "group"
            },
            {
                "_links": {
                    "self": "https://xsoar-bd.atlassian.net/wiki/rest/experimental/group/confluence-users"
                },
                "id": "e50e7fe6-7961-4775-9bbf-99e4b50f8701",
                "name": "confluence-users",
                "type": "group"
            }
        ]
    }
}
```

#### Human Readable Output

>### Group(s)
>|ID|Name|
>|---|---|
>| 10453df5-f7fc-47be-8ca7-bc2949c1bd5b | administrators |
>| e50e7fe6-7961-4775-9bbf-99e4b50f8701 | confluence-users |

### confluence-cloud-get-events

***
Retrieves a list of events from the Atlassian Confluence Cloud instance.

#### Base Command

`confluence-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Optional | 
| start_date | Filters the results to the records on or after the start date. The start date must be specified as epoch time in milliseconds. | Optional | 
| limit | The maximum number of records to return per page. Note, this may be restricted by fixed system limits. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ConfluenceCloud.Event.author.type | String | The type of author who created this event. | 
| ConfluenceCloud.Event.author.displayName | String | The display nName of the author who created this event. | 
| ConfluenceCloud.Event.author.operations | String | Nullable. Author's operations. | 
| ConfluenceCloud.Event.author.username | String | Username of the author of this event. | 
| ConfluenceCloud.Event.author.userKey | String | User key of the author of this event. | 
| ConfluenceCloud.Event.author.accountId | String | Account ID of the author of this event. | 
| ConfluenceCloud.Event.author.accountType | String | Type of account of the author of this event. | 
| ConfluenceCloud.Event.author.externalCollaborator | Boolean | Deprecated. Is the author of this event an external collaborator. | 
| ConfluenceCloud.Event.author.isExternalCollaborator | Boolean | Deprecated. Is the author of this event an external collaborator. | 
| ConfluenceCloud.Event.author.publicName | String | The public name of the author of this event. | 
| ConfluenceCloud.Event.remoteAddress | String | The remote address from which the event was performed. | 
| ConfluenceCloud.Event.creationDate | Number | The creation date-time of the audit record, as a timestamp. | 
| ConfluenceCloud.Event.summary | Strings | Summary of the audit. | 
| ConfluenceCloud.Event.description | String | Description of the audit. | 
| ConfluenceCloud.Event.category | String | Category of the event. | 
| ConfluenceCloud.Event.sysAdmin | Boolean | Was the event created by a system administrator. | 
| ConfluenceCloud.Event.superAdmin | Boolean | Was the event created by a super administrator. | 
| ConfluenceCloud.Event.affectedObject.name | String | Name of the object affected by the event. | 
| ConfluenceCloud.Event.affectedObject.objectType | String | Type of the object affected by the event. | 
| ConfluenceCloud.Event.changedValues.name | String | Name of the changed value. | 
| ConfluenceCloud.Event.changedValues.oldValue | String | The old value before the change the event describes. | 
| ConfluenceCloud.Event.changedValues.hiddenOldValue | String | The old hidden value before the change the event describes. | 
| ConfluenceCloud.Event.changedValues.newValue | String | The new value after the change the event describes. | 
| ConfluenceCloud.Event.changedValues.hiddenNewValue | String | The new hidden value after the change the event describes. | 
| ConfluenceCloud.Event.associatedObjects.name | String | Name of the associated object. | 
| ConfluenceCloud.Event.associatedObjects.objectType | String | Type of the associated object. | 

#### Command Example
```!confluence-cloud-get-events limit=1```

#### Context Example
```json
{
    "ConfluenceCloud": {
        "Event": [
            {
                "author": {
                    "type": "user",
                    "displayName": "<string>",
                    "operations": {},
                    "username": "<string>",
                    "userKey": "<string>",
                    "accountId": "<string>",
                    "accountType": "<string>",
                    "externalCollaborator": true,
                    "isExternalCollaborator": true,
                    "publicName": "<string>"
                },
                "remoteAddress": "<string>",
                "creationDate": 59,
                "summary": "<string>",
                "description": "<string>",
                "category": "<string>",
                "sysAdmin": true,
                "superAdmin": true,
                "affectedObject": {
                    "name": "<string>",
                    "objectType": "<string>"
                },
                "changedValues": [
                    {
                        "name": "<string>",
                        "oldValue": "<string>",
                        "hiddenOldValue": "<string>",
                        "newValue": "<string>",
                        "hiddenNewValue": "<string>"
                    }
                ],
                "associatedObjects": [
                    {
                        "name": "<string>",
                        "objectType": "<string>"
                    }
                ]
            }
        ]
    }
}
```
