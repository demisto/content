
## Configure Taegis XDR in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Taegis Environment | The environment to utilize | True |
| Client ID | Client ID as described in the [Taegis Documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) | True |
| Client Secret | Client Secret as described in the [Taegis Documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) | True |
| Use system proxy settings | Defines whether the system proxy is used or not | False |
| Fetch Incident Type | The type of incident to fetch from Taegis (Alerts or Investigations) | True |
| Include Assets in Fetch | When using the Investigations fetch type, should assets be included? This can cause API failures or latency and should only be enabled if necessary | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### taegis-add-evidence-to-investigation

#### Base Command

`!taegis-add-evidence-to-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The investigation id to update | True |
| alerts | A list of alert IDs to add to an investigation | False |
| events | A list of event IDs to add to an investigation | False |
| alert_query | A Taegis CQL query for alerts to add to the investigation | False |

At least one of the inputs `alerts`, `events`, or `alert_query` MUST be defined

#### Command Example

```
`!taegis-add-evidence-to-investigation` id=c207ca4c-8a78-4408-a056-49f05d6eb77d alerts="alert://priv:crowdstrike:11772:1677742145475:07e2d9cc-0a04-55ec-890a-97f39d63698e"
```

#### Context Example

```
{
    "TaegisXDR": {
        "InvestigationEvidenceUpdate": {
            "investigationId": "c207ca4c-8a78-4408-a056-49f05d6eb77d"
        }
    }
}
```

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
| id | The investigation ID to add the comment to | True |

#### Command Example

```
!taegis-create-comment comment="This is a test comment" id="219da0ee-8642-4363-827c-8a6fbd479082"
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
| title | The subject or description of the investigation | True |
| priority | The priority for the investigiation [Default: 3] | False |
| status | The status for the investigation [Default: OPEN] | False |
| alerts | A list of alert IDs to add to the investigation [Default: []] | False |
| keyFindings | The Key Findings for the investigation | False |
| type | The investigation type [Default: SECURITY_INVESTIGATION] | False |
| assigneeId | The assignee for the investigation [Default: @secureworks] | False |
| serviceDeskId | A 3rd party ticket number for tracking purposes | False |
| serviceDeskType | The type of 3rd party ticket number | False |
| tags | A list of tags to add to the investigation [Default: []] | False |

#### Command Example

```
!taegis-create-investigation priority=1 title="XSOAR Created Investigation"
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

### taegis-create-sharelink

#### Base Command

`!taegis-create-sharelink`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the Taegis element to create a sharelink to | True |
| type | The type of Taegis element to create a sharelink with | True |

#### Command Example

```
!taegis-create-sharelink type=investigationId id=219da0ee-8642-4363-827c-8a6fbd479082
```

#### Context Example

```
{
    "TaegisXDR": {
        "ShareLink": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
            "url": "https://ctpx.secureworks.com/share/593fa115-abad-4a52-9fc4-2ec403a8a1e4"
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
                },
                "url": "https://ctpx.secureworks.com/alerts/c4f33b53-eaba-47ac-8272-199af0f7935b"
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
| id | The investigation ID to fetch comments for | True |
| page | Search page number [Default: 0] | False |
| page_size | Number of results per page [Default: 10] | False |
| order_direction | The order direction [Default: DESCENDING] | False |

#### Command Example

```
!taegis-fetch-comments id=c2e09554-833e-41a1-bc9d-8160aec0d70d
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
| id | Investigation ID to lookup | False |
| query | If not using ID, the query to utilize when searching investigations [Default: deleted_at is null] | False |
| page | Search page number [Default: 0] | False |
| page_size | Number of results per page [Default: 10] | False |
| order_by | The field to order results by [Default: created_at] | False |
| order_direction | The order direction [Default: DESCENDING] | False |

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
| page | Search page number [Default: 0] | False |
| page_size | Number of results per page [Default: 10] | False |

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

### taegis-fetch-events

> **Beta Command:** This is a beta command, which lets you implement and test pre-release software. Since the command is beta, it might contain bugs. Updates to the command during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the command to help us identify issues, fix them, and continually improve.

#### Base Command

`taegis-fetch-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | A comma-separated list of event IDs to return. | False |
| cql_query | The Taegis CQL query string to use for searching events (e.g. `FROM process EARLIEST=-1d \| head 10`). If not defined, defaults to `FROM * EARLIEST=-1m \| head 50`. | False |
| limit | The maximum number of events to return. For standard CQL searches, the limit is passed as a GraphQL variable. For user-provided queries, embed the limit directly in the CQL string (e.g., `\| head 100`). Default is 50. | False |
| offset | The number of events to skip before returning results. Default is 0. | False |
| next | The pagination cursor token returned from a previous `taegis-fetch-events` call. Use this to retrieve the next page of results. | False |
| fields | The fields to return from the query. | False |
| tenant_id | The tenant to run against if using an MSP. If no tenant is provided, the tenant of the generated credentials is used. | False |

#### CQL Query Time Field Reference

| Scenario | Use This Field | Why? |
| --- | --- | --- |
| Incident Reconstruction | event_time | You need to see the exact sequence of the attacker's steps. |
| Real-time Monitoring | EARLIEST=-1m | You want to see everything that hits the platform in the last 60 seconds. |
| Compliance/Audit | ingest_time | You need to prove when Secureworks actually received the record. |
| Offline Host Sync | ingest_time | You want to find data from a laptop that was just turned back on after a weekend. |

#### Command example

```
!taegis-fetch-events
!taegis-fetch-events cql_query="FROM process EARLIEST=-1d | head 10"
!taegis-fetch-events cql_query="FROM dnsquery WHERE query_name MATCHES ('*.xyz', '*.top') EARLIEST=-24h" limit=100
!taegis-fetch-events ids="event-12345-67890,event-12345-67891"
!taegis-fetch-events next="eyJvZmZzZXQiOiAxMH0="
```

#### Context Example

```json
[
    {
        "TaegisXDR": {
            "Events": [
                {
                    "id": "event-12345-67890",
                    "metadata": {
                        "event_type": "process",
                        "event_time": "2024-05-20T14:30:05.123Z",
                        "tenant_id": "999-000-111",
                        "sensor_id": "win-endpoint-01"
                    },
                    "parent_process_id": "456",
                    "image_path": "C:\\Windows\\System32\\cmd.exe",
                    "commandline": "cmd.exe /c \"whoami\"",
                    "username": "admin_user",
                    "next": "CursorToken_Batch01_Seq99"
                },
                {
                    "id": "event-12345-67891",
                    "metadata": {
                        "event_type": "netflow",
                        "event_time": "2024-05-20T14:30:10.456Z",
                        "tenant_id": "999-000-111",
                        "sensor_id": "fw-edge-02"
                    },
                    "source_ip": "1.1.1.1",
                    "destination_ip": "8.8.8.8",
                    "destination_port": 53,
                    "protocol": "UDP",
                    "next": "CursorToken_Batch01_Seq99"
                }
            ]
        }
    }
]
```

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TaegisXDR.Events.id | String | The unique identifier of the event. |
| TaegisXDR.Events.metadata.event_type | String | The type of event (e.g., process, netflow, dnsquery). |
| TaegisXDR.Events.metadata.event_time | String | The timestamp when the event occurred. |
| TaegisXDR.Events.metadata.tenant_id | String | The tenant ID associated with the event. |
| TaegisXDR.Events.metadata.sensor_id | String | The sensor ID that generated the event. |
| TaegisXDR.Events.parent_process_id | String | The parent process ID (process events). |
| TaegisXDR.Events.image_path | String | The image/executable path (process events). |
| TaegisXDR.Events.commandline | String | The command line string (process events). |
| TaegisXDR.Events.username | String | The username associated with the event. |
| TaegisXDR.Events.source_ip | String | The source IP address (netflow events). |
| TaegisXDR.Events.destination_ip | String | The destination IP address (netflow events). |
| TaegisXDR.Events.destination_port | Number | The destination port number (netflow events). |
| TaegisXDR.Events.protocol | String | The network protocol (netflow events). |
| TaegisXDR.Events.next | String | Pagination cursor token for retrieving the next page of results. |

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
* OTHER

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
| title | The title of the investigation | False |
| keyFindings | The investigation Key Findings | False |
| prioirity | The priority of the Investigation (1-5) | False |
| status | The current status of the Investigation | False |
| assigneeId | The id of a user to assign, in `auth0|12345` format | False |
| serviceDeskId | A 3rd party ticket number for tracking purposes | False |
| serviceDeskType | The type of 3rd party ticket number | False |
| tags | A list of tags to add to the investigation [Default: []] | False |

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
!taegis-update-investigation id="936c1cc1-db8f-430c-837c-1c914fcca35a" priority=3 status="OPEN"
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
