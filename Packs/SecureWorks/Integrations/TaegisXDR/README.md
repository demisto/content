
## Configure Taegis XDR in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Taegis Environment | The environment to utilize | True |
| Client ID | Client ID as described in the [Taegis Documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) | True |
| Client Secret | Client Secret as described in the [Taegis Documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) | True |
| Use system proxy settings | Defines whether the system proxy is used or not | False |



## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.


### taegis-archive-investigation

#### Base Command

`!taegis-archive-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The investigation id to archive | True |

#### Command Example

```
!taegis-archive-investigation id=c207ca4c-8a78-4408-a056-49f05d6eb77d
```

#### Context Example

```
{
    "TaegisXDR": {
        "ArchivedInvestigation": {
            "id": "c207ca4c-8a78-4408-a056-49f05d6eb77d"
        }
    }
}
```


### taegis-create-comment

#### Base Command

`!taegis-create-comment`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | The comment string to add to the investigation | True |
| parent_id | The investigation ID to add the comment to | True |

#### Command Example

```
!taegis-create-comment comment="This is a test comment" parent_id="219da0ee-8642-4363-827c-8a6fbd479082"
```

#### Context Example

```
{
    "TaegisXDR": {
        "CommentCreate": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4"
        }
    }
}
```


### taegis-create-investigation

#### Base Command

`!taegis-create-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The subject or description of the investigation | True |
| priority | The priority for the investigiation [Default: 3] | False |

#### Command Example

```
!taegis-create-investigation priority=1 description="XSOAR Created Investigation"
```

#### Context Example

```
{
    "TaegisXDR": {
        "Investigation": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4"
        }
    }
}
```


### taegis-execute-playbook

#### Base Command
`!taegis-execute-playbook`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Playbook instance ID to execute | True |
| inputs | JSON object of inputs to pass into the playbook execution | False |

#### Command Example

```
!taegis-execute-playbook id=UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg=
!taegis-execute-playbook id=UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg= inputs=`{'myvar': 'myval'}`
```

#### Context Example

```
{
    "id": "UGxheWJvb2tFeGVjdXRpb246NGYwZDZiNGQtNWNiZS00NDkxLTg3YzYtMDZkNjkxYzMwMTg4"
}
```


### taegis-fetch-alerts

#### Base Command

`!taegis-fetch-alerts`

#### Input

| **Argument Name** | **Description** | Default | **Required** |
| --- | --- | --- | --- |
| ids | A list of alerts by IDs | `936c1cc1-db8f-430c-837c-1c914fcca35a` | False |
| limit | Number of results to when `ids` is not defined | `10` | False |
| offset | The result to start from when `ids` is not defined | `0` | False |
| cql_query | The query to utilize when searching for Alerts | `from alert severity >= 0.6 and status='OPEN'` | False |

#### Command Examples

```
!taegis-fetch-alerts ids=`["6594e97f-a898-5b28-82b2-ea03293cdaa1"]`
```

#### Context Example

```
{
    "TaegisXDR": {
        "Alerts": [
            {
                "id": "c4f33b53-eaba-47ac-8272-199af0f7935b",
                "metadata": {
                    "title": "Test Alert",
                    "description": "This is a test alert",
                    "severity": 0.5,
                }
            }
        ]
    }
}
```


### taegis-fetch-assets

#### Base Command

`!taegis-fetch-assets`

#### Input

| **Argument Name** | **Description** | Default | **Required** |
| --- | --- | --- | --- |
| page | | `0` | False |
| page_size | | `10` | False |
| endpoint_type | | | False |
| host_id | ID of the asset to fetch | `e43b545a-580a-4047-b489-4338c1cc4ba1` | False |
| hostname | | | False |
| investigation_id | | | False |
| ip_address | | | False |
| mac_address | | | False |
| os_family | | | False |
| os_version | | | False |
| sensor_version | | | False |
| username | | | False |

#### Command Examples

```
!taegis-fetch-assets
!taegis-fetch-assets page=1 page_size=5
!taegis-fetch-assets hostname=MyHostname01
!taegis-fetch-assets host_id=e43b545a-580a-4047-b489-4338c1cc4ba1
```

#### Context Example

```
{
    "TaegisXDR": {
        "Assets": [
            {
              "id": "",
              "ingestTime": "",
              "createdAt": "",
              "updatedAt": "",
              "deletedAt": "",
              "biosSerial": "",
              "firstDiskSerial": "",
              "systemVolumeSerial": "",
              "sensorVersion": "",
              "endpointPlatform": "",
              "hostnames": [{"id": ", "hostname": ""],
              "architecture": "",
              "osFamily": "",
              "osVersion": "",
              "osDistributor": "",
              "osRelease": "",
              "systemType": "",
              "osCodename": "",
              "kernelRelease": "",
              "kernelVersion": "",
              "tags": [ "key": "", "tag": ""],
              "endpointType": "",
              "hostId": "",
              "sensorId": "",
            }
        ]
    }
}
```


### taegis-fetch-comment

#### Base Command

`!taegis-fetch-comment`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the comment to fetch | True |

#### Command Example

```
!taegis-fetch-comment id=ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f
```

#### Context Example

```
{
    "TaegisXDR": {
        "Comment": {
            "author_user": {
                "email_normalized": "myuser@email.com",
                "given_name": "John",
                "family_name": "Smith",
                "id": "auth0|000000000000000000000001",
            },
            "id": "ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f",
            "comment": "This is a comment in an investigation",
            "created_at": "2022-01-01T13:04:57.17234Z",
            "deleted_at": None,
            "modified_at": None,
            "parent_id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
            "parent_type": "investigation",
        }
    }
}
```


### taegis-fetch-comments

#### Base Command

`!taegis-create-comments`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| parent_id | The investigation ID to fetch comments for | True |

#### Command Example

```
!taegis-fetch-comments parent_id=c2e09554-833e-41a1-bc9d-8160aec0d70d
```

#### Context Example

```
{
    "TaegisXDR": {
        "Comments": [
            {
                "author_user": {
                    "email_normalized": "myuser@email.com",
                    "given_name": "John",
                    "family_name": "Smith",
                    "id": "auth0|000000000000000000000001",
                },
                "id": "ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f",
                "comment": "This is a comment in an investigation",
                "created_at": "2022-01-01T13:04:57.17234Z",
                "deleted_at": None,
                "modified_at": None,
                "parent_id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
                "parent_type": "investigation",
            },
            {
                "author_user": {
                    "email_normalized": "myuser@email.com",
                    "given_name": "John",
                    "family_name": "Smith",
                    "id": "auth0|000000000000000000000001",
                },
                "id": "ff9ca818-4749-4ccb-883a-2ccc6f6c1234",
                "comment": "This is another comment",
                "created_at": "2022-01-02T13:04:57.17234Z",
                "deleted_at": None,
                "modified_at": None,
                "parent_id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
                "parent_type": "investigation",
            }
        ]
    }
}
```


### taegis-fetch-endpoint

#### Base Command
`!taegis-fetch-endpoint`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Endpoint ID to fetch | True |

#### Command Example

```
!taegis-fetch-endpoint id=ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f
```

#### Context Example

```
{
    "TaegisXDR": {
        "assetEndpointInfo": {
            "hostId": "",
            "hostName": "",
            "actualIsolationStatus": "",
            "allowedDomain": "",
            "desiredIsolationStatus": "",
            "firstConnectTime": "",
            "moduleHealth": {
                "enabled": ""
                "lastRunningTime": "",
                "moduleDisplayName": "",
            }
            "lastConnectAddress": "",
            "lastConnectTime": "",
            "sensorVersion": ""
        }
    }
}
```


### taegis-fetch-investigation

#### Base Command
`!taegis-fetch-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID to lookup | True |

#### Command Example

```
!taegis-fetch-investigation id=936c1cc1-db8f-430c-837c-1c914fcca35a
```

#### Context Example

```
{
    "TaegisXDR": {
        "Investigations": [
            {
                "archived_at": None,
                "created_at": "2022-02-02T13:53:35Z",
                "description": "Test Investigation",
                "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
                "key_findings": "",
                "priority": 2,
                "service_desk_id": "",
                "service_desk_type": "",
                "status": "Open",
                "alerts2": [],
                "url": "https://ctpx.secureworks.com/investigations/c2e09554-833e-41a1-bc9d-8160aec0d70d",
            }
        ]
    }
}
```


### taegis-fetch-investigation-alerts

#### Base Command
`!taegis-fetch-investigation-alerts`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID to lookup | True |

#### Command Example

```
!taegis-fetch-investigation-alerts id=936c1cc1-db8f-430c-837c-1c914fcca35a
```

#### Context Example

```
{
    "TaegisXDR": {
        "InvestigationAlerts": [
            {
                "id": "c4f33b53-eaba-47ac-8272-199af0f7935b",
                "description": "Test Alert",
                "message": "This is a test alert",
                "severity": 0.5,
            }
        ]
    }
}
```



### taegis-fetch-investigations

#### Base Command
`!taegis-fetch-investigations`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page |  | False |
| page_size | | False |

#### Command Example

```
!taegis-fetch-investigations
```

#### Context Example

```
{
    "TaegisXDR": {
        "Investigations": [
            {
                "description": "Test Investigation",
                "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
                "key_findings": "",
                "priority": 2,
                "service_desk_id": "",
                "service_desk_type": "",
                "status": "Open"
            }
        ]
    }
}
```


### taegis-fetch-playbook-execution

#### Base Command
`!taegis-fetch-playbook-execution`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Playbook execution ID to fetch | True |

#### Command Example

```
!taegis-fetch-playbook-execution id=UGxheWJvb2tFeGVjdXRpb246NGYwZDZiNGQtNWNiZS00NDkxLTg3YzYtMDZkNjkxYzMwMTg4
```

#### Context Example

```
{
    "TaegisXDR": {
        "PlaybookExecution": {
            "createdAt": "2022-01-01T13:51:24Z",
            "executionTime": 1442,
            "id": "UGxheWJvb2tFeGVjdXRpb246NGYwZDZiNGQtNWNiZS00NDkxLTg3YzYtMDZkNjkxYzMwMTg4",
            "inputs": {
                "alert": {
                    "message": "Test Alert",
                }
            },
            "instance": {
                "name": "Test Alert Instance",
                "playbook": {
                    "name": "Taegis.PagerDutyAlertEvent"
                }
            },
            "outputs": "d6b65662-c1da-4109-8553-c5664918c952",
            "state": "Completed",
            "updatedAt": "2022-01-01T13:51:31Z"
        }
    }
}
```


### taegis-fetch-users

#### Base Command
`!taegis-fetch-users`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The id of the user, in `auth0` format | False |
| email | The email of the user | False |
| status | The users to find based on status | False |
| page |  | False |
| page_size | | False |

#### Command Example

```
!taegis-fetch-users id="auth0|123456"
```

#### Context Example

```
{
    "TaegisXDR": {
        "Users": [
            {
                "email": "myuser@email.com",
                "family_name": "Smith",
                "given_name": "John",
                "status": "Registered",
                "user_id": "auth0|123456"
            }
        ]
    }
}
```


### taegis-isolate-asset

#### Base Command

`!taegis-isolate-asset`

#### Input

| **Argument Name** | **Description** | Default | **Required** |
| --- | --- | --- | --- |
| id | ID of the asset to isolate | `e43b545a-580a-4047-b489-4338c1cc4ba1` | True |
| reason | The reason for the isolation | `See ticket 12345` | True |

#### Command Examples

```
!taegis-isolate-asset id="e43b545a-580a-4047-b489-4338c1cc4ba1" reason="See ticket 12345"
```

#### Context Example

```
{
    "TaegisXDR": {
        "AssetIsolation": {
            "id": "e43b545a-580a-4047-b489-4338c1cc4ba1"
        }
    }
}
```


### taegis-update-alert-status

#### Base Command

`!taegis-update-alert-status`

#### Input

| **Argument Name** | **Description** | Default | **Required** |
| --- | --- | --- | --- |
| ids | A comma-separated list of alerts by IDs | `alert://priv:crowdstrike:11772:1666269058114:59284e28-4ec8-542b-a4a1-452c3688bc1a` | True |
| status | The status to update the alert(s) with | `FALSE_POSITIVE` | True |
| reason | A comment/reason for the alert status update | `See ticket 13245` | False |

##### Permitted Status Values

* FALSE_POSITIVE
* NOT_ACTIONABLE
* OPEN
* TRUE_POSITIVE_BENIGN
* TRUE_POSITIVE_MALICIOUS


#### Command Examples

```
!taegis-update-alert-status ids="alert://priv:crowdstrike:11772:1677742145475:07e2d9cc-0a04-55ec-890a-97f39d63698e" status=NOT_ACTIONABLE reason="Test Reason"
```

#### Context Example

```
{
    "TaegisXDR": {
        "AlertStatusUpdate": {
            "reason": "feedback updates successfully applied",
            "resolution_status": "SUCCESS"
        }
    }
}
```


### taegis-update-comment

#### Base Command

`!taegis-update-comment`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment | The comment string to add to the investigation | True |
| id | The comment ID to update | True |

#### Command Example

```
!taegis-update-comment id="ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f" comment="Newly updated comment"
```

#### Context Example

```
{
    "TaegisXDR": {
        "CommentUpdate": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4"
        }
    }
}
```


### taegis-update-investigation

#### Base Command
`!taegis-update-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID to update | True |
| key_findings | | False |
| prioirity | The priority of the Investigation (1-5) | False |
| service_desk_id | An ID or ticket # to relate to an Investigation | False |
| service_desk_type | The type of id related to an investigation (e.g. Jira) | False |
| status | The current status of the Investigation | False |
| assignee_id | The id of a user to assign, in `auth0|12345` format | False |

Note: At least 1 of the above inputs (in addition to id) must be defined

##### Permitted Status Values

* Active
* Awaiting Action
* Closed: Authorized Activity
* Closed: Confirmed Security Incident
* Closed: False Positive Alert
* Closed: Inconclusive
* Closed: Informational
* Closed: Not Vulnerable
* Closed: Threat Mitigated
* Open
* Suspended

#### Command Example

```
!taegis-update-investigation id="936c1cc1-db8f-430c-837c-1c914fcca35a" priority=3 status="Open" service_desk_id="XDR-1234" service_desk_type="Jira"
```

#### Context Example

```
{
    "TaegisXDR": {
        "InvestigationUpdate": {
            "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d"
        }
    }
}
```


### taegis-unarchive-investigation

#### Base Command

`!taegis-unarchive-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The investigation id to unarchive | True |

#### Command Example

```
!taegis-unarchive-investigation id=c207ca4c-8a78-4408-a056-49f05d6eb77d
```

#### Context Example

```
{
    "TaegisXDR": {
        "UnarchivedInvestigation": {
            "id": "c207ca4c-8a78-4408-a056-49f05d6eb77d"
        }
    }
}
```