Rapid7 AppSec integration allows the management of applications vulnerabilities and scans.
This integration was integrated and tested with version 1 of rapid7appsec.

## Configure Rapid7AppSec in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |
| API Key | True |
| Password | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### app-sec-vulnerability-update

***
Update the severity or The status of the vulnerability.

#### Base Command

`app-sec-vulnerability-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the vulnerability (use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| severity | The severity of the vulnerability. Possible values are: Safe, Informational, Low, Medium, High. | Optional |
| status | The status of the vulnerability. Possible values are: Unreviewed, False Positive, Verified, Ignored, Remediated, Duplicate. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-vulnerability-update vulnerability_id=1111 severity=High```
#### Human Readable Output

>Vulnerability "1111" was successfully updated.

### app-sec-vulnerability-list

***
List vulnerabilities. Vulnerabilities are aspects of your app that can make it susceptible to attackers. If a vulnerability_id is given, the command will return the information about that specific vulnerability.

#### Base Command

`app-sec-vulnerability-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The vulnerability ID to get. If using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Vulnerability.id | String | The ID of the vulnerability. |
| Rapid7AppSec.Vulnerability.app_id | String | The ID of the app of the vulnerability \(use app-sec-app-list to get more information about the app\). |
| Rapid7AppSec.Vulnerability.root_cause_url | String | The vulnerability root cause URL. For example: test.com |
| Rapid7AppSec.Vulnerability.root_cause_method | String | The vulnerability root cause method. For example: GET. |
| Rapid7AppSec.Vulnerability.root_cause_parameter | String | The vulnerability root cause parameter. For example: password. |
| Rapid7AppSec.Vulnerability.severity | String | The severity of the vulnerability. |
| Rapid7AppSec.Vulnerability.status | String | The status of the vulnerability. |
| Rapid7AppSec.Vulnerability.first_discovered | Date | The date the vulnerability was first discovered. |
| Rapid7AppSec.Vulnerability.last_discovered | Date | The date the vulnerability was last discovered. |
| Rapid7AppSec.Vulnerability.newly_discovered | Boolean | Whether the vulnerability is newly discovered. |
| Rapid7AppSec.Vulnerability.Variances.id | String | The ID of the vulnerability variance. |
| Rapid7AppSec.Vulnerability.Variances.original_exchange.id | String | The ID of the original exchange. Original exchange contains the request and the response of the variance. |
| Rapid7AppSec.Vulnerability.Variances.original_exchange.request | String | The request details. |
| Rapid7AppSec.Vulnerability.Variances.original_exchange.response | String | The response details. |
| Rapid7AppSec.Vulnerability.Variances.module_id | String | The module ID. Module ID is a reference to the Model Type that related to the vulnerability \(use app-sec-module-list to get more information about the module\). |
| Rapid7AppSec.Vulnerability.Variances.attack_id | String | The attack ID. The attack ID is a reference to the attack that is related to the model type \(use app-sec-attack-get or app-sec-attack-documentation-get to get more information about the attack\). |
| Rapid7AppSec.Vulnerability.Variances.message | String | The attack variance message. |
| Rapid7AppSec.Vulnerability.Variances.proof | String | The attack variance proof. |
| Rapid7AppSec.Vulnerability.Variances.proof_description | String | The attack variance proof description. |
| Rapid7AppSec.Vulnerability.vector_string | String | A compressed textual representation of the values used to derive the CVSS score. |
| Rapid7AppSec.Vulnerability.vulnerability_score | Number | The vulnerability CVSS Score. |

#### Command example
```!app-sec-vulnerability-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "Vulnerability": {
            "Variances": [
                {
                    "attack_id": "1111",
                    "id": "1111",
                    "message": "The form action points to an HTTP site",
                    "module_id": "1111",
                    "original_exchange_id": "1111",
                    "original_exchange_request": "test",
                    "proof": "",
                    "proof_description": "The form action points to an HTTP site"
                }
            ],
            "app_id": "1111",
            "first_discovered": "2023-07-24T13:40:07.64407",
            "id": "1111",
            "insight_ui_url": "test",
            "last_discovered": "2023-09-07T07:11:59.108573",
            "newly_discovered": false,
            "root_cause_method": "GET",
            "root_cause_url": "http://test/user/password",
            "severity": "HIGH",
            "status": "UNREVIEWED",
            "vector_string": "1111",
            "vulnerability_score": 2.8
        }
    }
}
```

#### Human Readable Output

>### Vulnerability
>|Id|App Id|Root Cause Url|Severity|Status|First Discovered|Last Discovered|Newly Discovered|Vulnerability Score|
>|---|---|---|---|---|---|---|---|---|
>| 1111 | 1111 | http:<span>//</span>test/user/password | HIGH | UNREVIEWED | 2023-07-24T13:40:07.64407 | 2023-09-07T07:11:59.108573 | false | 2.8 |


### app-sec-vulnerability-history-list

***
List the history of changes for a vulnerability.

#### Base Command

`app-sec-vulnerability-history-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the vulnerability for which to display the history (use app-sec-vulnerability-list to get all vulnerability IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.VulnerabilityHistory.vulnerability_id | String | The ID of the vulnerability. |
| Rapid7AppSec.VulnerabilityHistory.id | String | The ID of the vulnerability history. |
| Rapid7AppSec.VulnerabilityHistory.create_time | Date | The time the vulnerability was created. |
| Rapid7AppSec.VulnerabilityHistory.source_type | String | The vulnerability source type. |
| Rapid7AppSec.VulnerabilityHistory.source_id | String | The ID of the vulnerability source. |
| Rapid7AppSec.VulnerabilityHistory.Changes.field | String | The vulnerability change's field. |
| Rapid7AppSec.VulnerabilityHistory.Changes.previous_value | String | The vulnerability previous value. |
| Rapid7AppSec.VulnerabilityHistory.Changes.new_value | String | The vulnerability new value. |

#### Command example
```!app-sec-vulnerability-history-list vulnerability_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "VulnerabilityHistory": {
            "Changes": [
                {
                    "field": "SEVERITY",
                    "new_value": "HIGH",
                    "previous_value": "MEDIUM"
                }
            ],
            "create_time": "2023-09-10T10:20:29.202337",
            "id": "1111",
            "source_id": "1111",
            "source_type": "USER",
            "vulnerability_id": "1111"
        }
    }
}
```

#### Human Readable Output

>### Vulnerability History
>|Vulnerability Id|Id|Create Time|Source Id|Source Type|Changes|
>|---|---|---|---|---|---|
>| 1111 | 1111 | 2023-09-10T10:20:29.202337 | 1111 | USER | {'field': 'SEVERITY', 'previous_value': 'MEDIUM', 'new_value': 'HIGH'} |


### app-sec-vulnerability-comment-create

***
Create a new vulnerability comment. A vulnerability comment is a resource that allows users to add context to the vulnerability.

#### Base Command

`app-sec-vulnerability-comment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the vulnerability for which to create a comment (use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_content | The content of the vulnerability comment. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-vulnerability-comment-create vulnerability_id=1111 comment_content="test"```
#### Human Readable Output

>Vulnerability Comment was successfully added to vulnerability "1111".

### app-sec-vulnerability-comment-update

***
Update an existing vulnerability comment.

#### Base Command

`app-sec-vulnerability-comment-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the vulnerability for which to update a comment (use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_id | The ID of the Comment to update (use app-sec-vulnerability-comment-list to get all comment IDs). | Required |
| comment_content | The new content of the vulnerability comment. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-vulnerability-comment-update vulnerability_id=1111 comment_id=1111 comment_content="test2"```
#### Human Readable Output

>Vulnerability Comment "1111" was successfully updated.

### app-sec-vulnerability-comment-delete

***
Delete an existing vulnerability comment.

#### Base Command

`app-sec-vulnerability-comment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the vulnerability for which to delete a comment (use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_id | The ID of the comment to delete (use app-sec-vulnerability-comment-list to get all comment IDs). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-vulnerability-comment-delete vulnerability_id=1111 comment_id=1111```
#### Human Readable Output

>Vulnerability Comment "1111" was successfully deleted.

### app-sec-vulnerability-comment-list

***
List the vulnerability comments. If a comment_id is given, the command will return the information about the specific comment.

#### Base Command

`app-sec-vulnerability-comment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the vulnerability for which to get comments (use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_id | The ID of the comment to get (use app-sec-vulnerability-comment-list to get all vulnerability comment IDs). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.VulnerabilityComment.vulnerability_id | String | The ID of the vulnerability. |
| Rapid7AppSec.VulnerabilityComment.id | String | The ID of the comment. |
| Rapid7AppSec.VulnerabilityComment.author_id | String | The ID of the author who created the comment. |
| Rapid7AppSec.VulnerabilityComment.last_update_author_id | String | The ID of the author who last updated the comment. |
| Rapid7AppSec.VulnerabilityComment.content | String | The comment content attached to the vulnerability. |
| Rapid7AppSec.VulnerabilityComment.create_time | Date | The date the comment was created. |
| Rapid7AppSec.VulnerabilityComment.update_time | Date | The date the comment was updated. |

#### Command example
```!app-sec-vulnerability-comment-list vulnerability_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "VulnerabilityComment": [
            {
                "author_id": "1111",
                "content": "test",
                "create_time": "2023-09-10T10:20:38.784939",
                "id": "1111",
                "last_update_author_id": "1111",
                "update_time": "2023-09-10T10:20:38.784939",
                "vulnerability_id": "1111"
            },
            {
                "author_id": "1111",
                "content": "test",
                "create_time": "2023-09-10T10:23:19.119359",
                "id": "1111",
                "last_update_author_id": "1111",
                "update_time": "2023-09-10T10:23:19.119359",
                "vulnerability_id": "1111"
            }
        ]
    }
}
```

#### Human Readable Output

>### Vulnerability Comment
>|Content|Id|Vulnerability Id|Author Id|Create Time|Update Time|
>|---|---|---|---|---|---|
>| test | 1111 | 1111 | 1111 | 2023-09-10T10:20:38.784939 | 2023-09-10T10:20:38.784939 |
>| test | 1111 | 1111 | 1111 | 2023-09-10T10:23:19.119359 | 2023-09-10T10:23:19.119359 |


### app-sec-attack-get

***
Get the metadata of an attack. AppSec can attempt multiple variations of the same attack on a URL to ensure the security of your applications against a variety of attacks.

#### Base Command

`app-sec-attack-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module_id | The ID of the module of the attack (use app-sec-vulnerability-list in order to get the module ID of vulnerability). | Required |
| attack_id | The ID of the attack (use app-sec-vulnerability-list in order to get the attack ID of vulnerability). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Attack.id | String | The ID of the attack. |
| Rapid7AppSec.Attack.module_id | String | The ID of the attack module. |
| Rapid7AppSec.Attack.type | String | The type of the attack. |
| Rapid7AppSec.Attack.class | String | The class of the attack. |
| Rapid7AppSec.Attack.description | String | Description about the attack. |

#### Command example
```!app-sec-attack-get module_id=1111 attack_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "Attack": {
            "class": "Best Practice",
            "description": "test.",
            "id": "1111",
            "module_id": "1111",
            "type": "CSPHeaders"
        }
    }
}
```

#### Human Readable Output

>### Attack metadata
>|Id|Module Id|Type|Class|Description|
>|---|---|---|---|---|
>| 1111 | 1111 | CSPHeaders | Best Practice | test. |


### app-sec-attack-documentation-get

***
Get the documentation of an attack. The documentation contains the references and description about the attack and recommendations for handling it.

#### Base Command

`app-sec-attack-documentation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module_id | The ID of the module of the attack (use app-sec-vulnerability-list in order to get the module ID of vulnerability). | Required |
| attack_id | The ID of the attack (use app-sec-vulnerability-list in order to get the attack ID of vulnerability). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.AttackDocumentation.id | String | The ID of the attack. |
| Rapid7AppSec.Attack.module_id | String | The ID of the attack module. |
| Rapid7AppSec.AttackDocumentation.references | String | The attack reference type and link. |
| Rapid7AppSec.AttackDocumentation.description | String | The attack documentation description. |
| Rapid7AppSec.AttackDocumentation.recommendation | String | The attack documentation recommendation. |

#### Command example
```!app-sec-attack-documentation-get module_id=1111 attack_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "AttackDocumentation": {
            "description": "test.",
            "id": "1111",
            "module_id": "1111",
            "recommendation": "test.",
            "references": {
                "test3": "test3",
                "test2": "test2",
                "test": "test"
            }
        }
    }
}
```

#### Human Readable Output

>### Attack Documentation
>|Module Id|Id|References|Description|Recommendation|
>|---|---|---|---|---|
>| 1111 | 1111 | test2: test<br/>test: test<br/>test3: test | test. | test. |


### app-sec-scan-submit

***
Submit a new scan. A scan encapsulates all the information for a single execution of the criteria defined in the provided scan configuration.

#### Base Command

`app-sec-scan-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_config_id | The ID of the scan configuration (use app-sec-scan-config-list to get all scan config IDs). | Required |
| scan_type | The type of the scan. Incremental scans reference the crawl map of the previous scan to identify and attack only new and updated code. Validation/ Verification scans automatically change the vulnerability status depending on whether the vulnerability was found, not found, or unknown when run against the parent_scan_id. Regular scans are designed to crawl all URLs listed in the scan config and provide in-depth results that are relevant to your needs. Possible values are: Regular, Verification, Incremental, Validation. Default is Regular. | Optional |
| parent_scan_id | The ID of the parent scan. Relevant when scant_type=Validation/ Verification. The parent scan ID is the scan that will be updated (in case vulnerability statuses have changed) after submitting the scan. (use app-sec-scan-list to get all scan IDs). | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-scan-submit scan_config_id=1111```
#### Human Readable Output

>Scan was successfully submitted.

### app-sec-scan-action-get

***
Get any current scan action. Scan actions values are: "PAUSE", "RESUME", "STOP", "AUTHENTICATE", and "CANCEL". Relevant when the scan is Running and when the scan is on an action (Scan is on an action when moving between statuses. For example: After submitting a new action, the scan has an action before the new status is updated).

#### Base Command

`app-sec-scan-action-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get the action (use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Scan.id | String | The ID of the scan. |
| Rapid7AppSec.Scan.action | String | The scan action. Scan actions values are: "PAUSE", "RESUME", "STOP", "AUTHENTICATE", and "CANCEL". |

#### Command example
```!app-sec-scan-action-get scan_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "Scan": {
            "action": "RESUME",
            "id": "1111"
        }
    }
}
```

#### Human Readable Output

>### Scan
>|Id|Action|
>|---|---|
>| 1111 | RESUME |


### app-sec-scan-action-submit

***
Submit a new scan action. Scan actions values are: "PAUSE", "RESUME", "STOP", "AUTHENTICATE", and "CANCEL". Relevant when the scan status is Running. In case the action is Stop/ Cancel, the status of the scan should be Queued/ Pending/ Running/ Provisioning.

#### Base Command

`app-sec-scan-action-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to submit the action (use app-sec-scan-list to get all scan IDs). | Required |
| action | The action to submit. Possible values are: Pause, Resume, Stop, Authenticate, Cancel. | Required |
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional |
| timeout_in_seconds | The timeout in seconds until polling ends. Default is 600. | Optional |
| first_run | First polling run. Default is 0. | Required |

#### Context Output

There is no context output for this command.
### app-sec-scan-delete

***
Delete a scan. The scan must be FAILED or marked as FutureObsolete to be deleted.

#### Base Command

`app-sec-scan-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to delete (use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-scan-delete scan_id=1111```
#### Human Readable Output

>Scan "1111" was successfully deleted.

### app-sec-scan-list

***
List scans. Scans attack the URLs in your app to identify behaviors that could be exploited by attackers. The specific attack types, URLs, and many other options are set in the scan configuration.  If a scan_id is given, the command will return the information about the specific scan.

#### Base Command

`app-sec-scan-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get. If using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Scan.id | String | The ID of the scan. |
| Rapid7AppSec.Scan.app_id | String | The ID of the app that is related to the scan. |
| Rapid7AppSec.Scan.scan_config_id | String | The ID of the scan configuration. |
| Rapid7AppSec.Scan.submitter_type | String | The type of the submitter of the scan. The values are: USER or ORGANIZATION. |
| Rapid7AppSec.Scan.submitter_id | String | The ID of the submitter of the scan. |
| Rapid7AppSec.Scan.submit_time | Date | The submit time. |
| Rapid7AppSec.Scan.completion_time | Date | The completion time. |
| Rapid7AppSec.Scan.status | String | The scan status. For example: COMPLETE or FAILED. |
| Rapid7AppSec.Scan.failure_reason | String | The failure reason \(In case the scan was failed\). |
| Rapid7AppSec.Scan.scan_type | String | The scan type. The values are: REGULAR, VERIFICATION, INCREMENTAL, VALIDATION. |

#### Command example
```!app-sec-scan-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "Scan": {
            "app_id": "1111",
            "completion_time": "2023-09-07T07:12:57.372961",
            "id": "1111",
            "scan_config_id": "1111",
            "scan_type": "VERIFICATION",
            "status": "COMPLETE",
            "submit_time": "2023-09-07T06:58:18.724285",
            "submitter_id": "1111",
            "submitter_type": "USER",
            "validation_parent_scan_id": "1111"
        }
    }
}
```

#### Human Readable Output

>### Scan list
>|Id|Status|Scan Type|Submit Time|Completion Time|App Id|Scan Config Id|Submitter Id|Validation Parent Scan Id|
>|---|---|---|---|---|---|---|---|---|
>| 1111 | COMPLETE | VERIFICATION | 2023-09-07T06:58:18.724285 | 2023-09-07T07:12:57.372961 | 1111 | 1111 | 1111 | 1111 |


### app-sec-scan-engine-event-list

***
List the engine events from a scan. These logs typically capture specific events that occur during the scanning process.

#### Base Command

`app-sec-scan-engine-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID for which to get the engine events (use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.EngineEvent.scan_id | String | The ID of the scan. |
| Rapid7AppSec.EngineEvent.Event.time | Date | The time of the event. |
| Rapid7AppSec.EngineEvent.Event.event | String | Description about the event. |

#### Command example
```!app-sec-scan-engine-event-list scan_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "EngineEvent": {
            "Event": [
                {
                    "event": "Initializing Scan",
                    "time": "2023-09-06T14:00:24"
                },
                {
                    "event": "Engine Version:  (64-bit)",
                    "time": "2023-09-06T14:00:24"
                }
            ],
            "scan_id": "1111"
        }
    }
}
```

#### Human Readable Output

>### Engine Event
>|Time|Event|
>|---|---|
>| 2023-09-06T14:00:24 | Initializing Scan |
>| 2023-09-06T14:00:24 | Engine Version:  (64-bit) |


### app-sec-scan-platform-event-list

***
List the platform events from a scan. Platform logs are broader in scope and usually cover various activities and events related to the platform hosting the security scanning tool.

#### Base Command

`app-sec-scan-platform-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID for which to get the platform events (use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.PlatformEvent.scan_id | String | The ID of the scan. |
| Rapid7AppSec.PlatformEvent.Event.time | Date | The time of the event. |
| Rapid7AppSec.PlatformEvent.Event.event | String | Description about the event. |

#### Command example
```!app-sec-scan-platform-event-list scan_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "PlatformEvent": {
            "Event": [
                {
                    "event": "Gathering Seed URLs from app",
                    "time": "2023-09-06T13:51:55.236413"
                },
                {
                    "event": "Gathering Seed URLs from scan config",
                    "time": "2023-09-06T13:51:55.242736"
                }
            ],
            "scan_id": "1111"
        }
    }
}
```

#### Human Readable Output

>### Platform Event
>|Time|Event|
>|---|---|
>| 2023-09-06T13:51:55.236413 | Gathering Seed URLs from app |
>| 2023-09-06T13:51:55.242736 | Gathering Seed URLs from scan config |


### app-sec-scan-execution-details-get

***
Get real-time details of the execution of a scan (for example: Coverage, Attack, and Network details).

#### Base Command

`app-sec-scan-execution-details-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID for which to get the platform events (use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.ExecutionDetail.id | String | The ID of the scan. |
| Rapid7AppSec.ExecutionDetail.logged_in | Boolean | Whether the scan succeeded to log in to the app \(in case the scan should log in\). |
| Rapid7AppSec.ExecutionDetail.links_in_queue | Number | The number of links in the queue. |
| Rapid7AppSec.ExecutionDetail.links_crawled | Number | The number of links crawled. |
| Rapid7AppSec.ExecutionDetail.attacks_in_queue | Number | The number of attacks in the queue. |
| Rapid7AppSec.ExecutionDetail.attacked | Number | The number of attacks attempted. |
| Rapid7AppSec.ExecutionDetail.vulnerable | Number | The number of vulnerabilities. |
| Rapid7AppSec.ExecutionDetail.requests | Number | The number of network requests. |
| Rapid7AppSec.ExecutionDetail.failed_requests | Number | The number of failed network requests. |
| Rapid7AppSec.ExecutionDetail.network_speed | Number | The network speed. |
| Rapid7AppSec.ExecutionDetail.drip_delay | Number | The the delay enforced \(in milliseconds\) between requests to not overload a target web server. |

#### Command example
```!app-sec-scan-execution-details-get scan_id=1111```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "ExecutionDetail": {
            "attacked": 8860,
            "attacks_in_queue": 0,
            "drip_delay": 0,
            "failed_requests": 0,
            "id": "1111",
            "links_crawled": 151,
            "links_in_queue": 0,
            "logged_in": false,
            "network_speed": 215687,
            "requests": 2049,
            "vulnerable": 328
        }
    }
}
```

#### Human Readable Output

>### Execution Detail
>|Id|Logged In|Links In Queue|Links Crawled|Attacks In Queue|Attacked|Vulnerable|Requests|Failed Requests|Network Speed|Drip Delay|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 1111 | false | 0 | 151 | 0 | 8860 | 328 | 2049 | 0 | 215687 | 0 |


### app-sec-scan-config-list

***
List the scan configuration. A scan configuration defines all the necessary information required to perform a scan of an app. If a scan_config_id is given, the command will return the information about the specific scan configuration. Mainly used to submit scans.

#### Base Command

`app-sec-scan-config-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_config_id | The scan config ID to get. If using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.ScanConfig.id | String | The ID of the scan configuration. |
| Rapid7AppSec.ScanConfig.name | String | The name of the scan configuration. |
| Rapid7AppSec.ScanConfig.app_id | String | The ID of the app that is related to the scan configuration \(use app-sec-app-list to get all app IDs\). |
| Rapid7AppSec.ScanConfig.attack_template_id | String | The ID of the attack template that is related to the scan configuration \(use app-sec-attack-template-list to get more information about the attack template\). |
| Rapid7AppSec.ScanConfig.incremental | Boolean | Whether incremental scanning is enabled. |
| Rapid7AppSec.ScanConfig.assignment_type | String | The type of the assignment. For example: ENGINE_GROUP. |
| Rapid7AppSec.ScanConfig.assignment_id | String | The ID of the assignment \(supported for On-Premise engines\) \(use app-sec-engine-group-list to get more information about the assignment ID\). |
| Rapid7AppSec.ScanConfig.assignment_environment | String | The environment of the assignment. Values can be CLOUD and ON_PREMISE. |

#### Command example
```!app-sec-scan-config-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "ScanConfig": {
            "app_id": "1111",
            "assignment_environment": "CLOUD",
            "assignment_type": "ENGINE_GROUP",
            "attack_template_id": "1111",
            "id": "1111",
            "incremental": false,
            "name": "All Attack Modules (No Auth)"
        }
    }
}
```

#### Human Readable Output

>### Scan Config list
>|Id|Name|App Id|Incremental|Attack Template Id|Assignment Type|Assignment Environment|
>|---|---|---|---|---|---|---|
>| 1111 | All Attack Modules (No Auth) | 1111 | false | 1111 | ENGINE_GROUP | CLOUD |


### app-sec-app-list

***
List apps. An app owns scan configurations, schedules, scans, and vulnerabilities.  Mainly used to understand vulnerabilities and scan configuration outputs. If an app_id is given, the command will return the information about the specific app.

#### Base Command

`app-sec-app-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The app ID to get. In case of using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.App.id | String | The ID of the app. |
| Rapid7AppSec.App.name | String | The name of the app. |

#### Command example
```!app-sec-app-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "App": {
            "id": "1111",
            "name": "test"
        }
    }
}
```

#### Human Readable Output

>### App list
>|Id|Name|
>|---|---|
>| 1111 | test |


### app-sec-module-list

***
List the modules. If a module_id is given, the command will return the information about the specific module. Mainly used to understand the vulnerability outputs.

#### Base Command

`app-sec-module-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module_id | The module ID to get. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Module.id | String | The ID of the module. |
| Rapid7AppSec.Module.name | String | The name of the module. |
| Rapid7AppSec.Module.description | String | Description about the module. |

#### Command example
```!app-sec-module-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "Module": [
            {
                "description": "test..",
                "id": "1111",
                "name": "Brute Force (Form Auth)"
            },
            {
                "description": "Check for OpenSSL Heartbleed Vulnerability",
                "id": "1111",
                "name": "Heartbleed Check"
            }
        ]
    }
}
```

#### Human Readable Output

>### Module
>|Id|Name|Description|
>|---|---|---|
>| 1111 | Brute Force (Form Auth) | test.. |
>| 1111 | Heartbleed Check | Check for OpenSSL Heartbleed Vulnerability |


### app-sec-attack-template-list

***
List the attack templates. An attack template describes if and how attacks should be executed during the execution of a scan. Mainly used to understand the scan configuration outputs. If an attack_template_id is given, the command will return the information about the specific attack.

#### Base Command

`app-sec-attack-template-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_template_id | The attack template ID to get. If using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.AttackTemplate.id | String | The ID of the module. |
| Rapid7AppSec.AttackTemplate.name | String | The name of the module. |
| Rapid7AppSec.AttackTemplate.system_defined | String | Whether the attack template was defined by the system. |
| Rapid7AppSec.AttackTemplate.browser_encoding_enabled | String | A flag that is used to enforce browser encoding on all attacks. |
| Rapid7AppSec.AttackTemplate.attack_prioritization | String | The attack prioritization type. The values are: SEQUENTIAL, SMART, and RANDOMIZED. |
| Rapid7AppSec.AttackTemplate.advanced_attacks_enabled | String | A flag to enable advanced attacks. |

#### Command example
```!app-sec-attack-template-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "AttackTemplate": {
            "advanced_attacks_enabled": false,
            "attack_prioritization": "SMART",
            "browser_encoding_enabled": false,
            "id": "1111",
            "name": "All API Modules",
            "system_defined": true
        }
    }
}
```

#### Human Readable Output

>### Attack Template list
>|Id|Name|System Defined|Browser Encoding Enabled|Attack Prioritization|Advanced Attacks Enabled|
>|---|---|---|---|---|---|
>| 1111 | All API Modules | true | false | SMART | false |


### app-sec-engine-list

***
List the engines. An engine encapsulates the state and high-level attributes of the components which may be installed and running on a specific on-premise host. If an engine_id is given, the command will return the information about the specific engine.

#### Base Command

`app-sec-engine-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine_id | The engine ID to get. If using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Engine.id | String | The ID of the engine. |
| Rapid7AppSec.Engine.name | String | The name of the engine. |
| Rapid7AppSec.Engine.engine_group_id | String | The ID of the engine group. |
| Rapid7AppSec.Engine.failure_reason | String | Failure reason \(in case it failed\). |
| Rapid7AppSec.Engine.status | String | The engine status. |
| Rapid7AppSec.Engine.auto_upgrade | String | Whether the engine is auto upgraded. |
| Rapid7AppSec.Engine.latest_version | String | Whether the engine has the latest version. |
| Rapid7AppSec.Engine.upgradeable | String | Whether the engine is upgradeable. |

#### Command example
```!app-sec-engine-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "Engine": {
            "auto_upgrade": true,
            "engine_group_id": "1111",
            "id": "1111",
            "latest_version": false,
            "name": "engine-test",
            "upgradeable": false
        }
    }
}
```

#### Human Readable Output

>### Engine
>|Id|Name|Engine Group Id|Latest Version|Upgradeable|Auto Upgrade|
>|---|---|---|---|---|---|
>| 1111 | engine-test | 1111 | false | false | true |


### app-sec-engine-group-list

***
List the engine groups. An engine group is a resource which defines a container for a logical grouping of engines and therefore the purpose of assigning scans to one of those engines. Mainly used to understand the scan configuration outputs. If an engine_group_id is given, the command will return the information about the specific engine group.

#### Base Command

`app-sec-engine-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine_group_id | The engine group ID to get. If using this argument, the pagination arguments are not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value: 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.EngineGroup.id | String | The ID of the engine group. |
| Rapid7AppSec.EngineGroup.name | String | The name of the engine group. |
| Rapid7AppSec.EngineGroup.description | String | Description about the engine group. |

#### Command example
```!app-sec-engine-group-list limit=1```
#### Context Example
```json
{
    "Rapid7AppSec": {
        "EngineGroup": {
            "description": "string",
            "id": "1111",
            "name": "string"
        }
    }
}
```

#### Human Readable Output

>### Engine Group
>|Id|Name|Description|
>|---|---|---|
>| 1111 | string | string |