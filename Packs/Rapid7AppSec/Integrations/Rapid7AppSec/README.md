Rapid7 AppSec integration allows the management of applications vulnerabilities and scans.
This integration was integrated and tested with version xx of rapid7appsec.

## Configure Rapid7AppSec on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rapid7AppSec.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |
    | API Key | True |
    | Password | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### app-sec-vulnerability-update

***
Update the severity or the status of the vulnerability.

#### Base Command

`app-sec-vulnerability-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the Vulnerability (dependencies - use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| severity | The severity of the Vulnerability. Possible values are: Safe, Informational, Low, Medium, High. | Optional |
| status | The status of the Vulnerability. Possible values are: Unreviewed, False Positive, Verified, Ignored, Remediated, Duplicate. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-vulnerability-update vulnerability_id=1111 severity=High```
#### Human Readable Output

>Vulnerability "1111" was successfully updated.

### app-sec-vulnerability-list

***
List vulnerabilities. Vulnerabilities are aspects of your app that can make it susceptible to attackers. If a vulnerability_id is given, the command will return the information about the wanted vulnerability.

#### Base Command

`app-sec-vulnerability-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The vulnerability ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Vulnerability.id | String | The ID of the vulnerability. |
| Rapid7AppSec.Vulnerability.app_id | String | The ID of the app of the vulnerability \(dependencies - use app-sec-app-list to get more information about the app\). |
| Rapid7AppSec.Vulnerability.root_cause_url | String | The vulnerability root cause URL. For example: test.com |
| Rapid7AppSec.Vulnerability.root_cause_method | String | The vulnerability root cause method. For example: GET. |
| Rapid7AppSec.Vulnerability.root_cause_parameter | String | The vulnerability root cause parameter. For example: password. |
| Rapid7AppSec.Vulnerability.severity | String | The severity of the vulnerability. |
| Rapid7AppSec.Vulnerability.status | String | The status of the vulnerability. |
| Rapid7AppSec.Vulnerability.first_discovered | Date | First discover time. |
| Rapid7AppSec.Vulnerability.last_discovered | Date | Last discover time. |
| Rapid7AppSec.Vulnerability.newly_discovered | Boolean | Whether the vulnerability is newly discovered. |
| Rapid7AppSec.Vulnerability.Variances.id | String | The ID of the vulnerability variance. |
| Rapid7AppSec.Vulnerability.Variances.original_exchange.id | String | The ID of the original exchange. Original exchange contains the request and the response of the variance. |
| Rapid7AppSec.Vulnerability.Variances.original_exchange.request | String | The request details. |
| Rapid7AppSec.Vulnerability.Variances.original_exchange.response | String | The response details. |
| Rapid7AppSec.Vulnerability.Variances.module_id | String | The module ID. Module ID is a reference to the Model Type that related to the vulnerability \(dependencies - use app-sec-module-list to get more information about the module\). |
| Rapid7AppSec.Vulnerability.Variances.attack_id | String | The attack ID. The attack ID is a reference to the attack that related to the Model Type \(dependencies - use app-sec-attack-get or app-sec-attack-documentation-get to get more information about the attack\). |
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
| vulnerability_id | The ID of the Vulnerability to show history (dependencies - use app-sec-vulnerability-list to get all vulnerability IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.VulnerabilityHistory.vulnerability_id | String | The ID of the vulnerability. |
| Rapid7AppSec.VulnerabilityHistory.id | String | The ID of the Vulnerability History. |
| Rapid7AppSec.VulnerabilityHistory.create_time | Date | The vulnerability created time. |
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
Create a new Vulnerability Comment. A vulnerability comment is a resource that allows users to add context to the vulnerability.

#### Base Command

`app-sec-vulnerability-comment-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the Vulnerability to create a comment (dependencies - use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_content | The content of the Vulnerability Comment. | Required |

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
| vulnerability_id | The ID of the Vulnerability to update a comment (dependencies - use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_id | The ID of the Comment to update (dependencies - use app-sec-vulnerability-comment-list to get all comment IDs). | Required |
| comment_content | The new content of the Vulnerability Comment. | Required |

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
| vulnerability_id | The ID of the Vulnerability to delete a comment (dependencies - use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_id | The ID of the Comment to delete (dependencies - use app-sec-vulnerability-comment-list to get all comment IDs). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-vulnerability-comment-delete vulnerability_id=1111 comment_id=1111```
#### Human Readable Output

>Vulnerability Comment "1111" was successfully deleted.

### app-sec-vulnerability-comment-list

***
List vulnerabilities comments. If a comment_id is given, the command will return the information about the wanted comment.

#### Base Command

`app-sec-vulnerability-comment-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | The ID of the Vulnerability to get it comments (dependencies - use app-sec-vulnerability-list to get all vulnerability IDs). | Required |
| comment_id | The ID of the Comment to get (dependencies - use app-sec-vulnerability-comment-list to get all vulnerability comment IDs). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.VulnerabilityComment.vulnerability_id | String | The ID of the vulnerability. |
| Rapid7AppSec.VulnerabilityComment.id | String | The ID of the comment. |
| Rapid7AppSec.VulnerabilityComment.author_id | String | The ID of the author that created the comment. |
| Rapid7AppSec.VulnerabilityComment.last_update_author_id | String | The ID of the last updated author of the comment. |
| Rapid7AppSec.VulnerabilityComment.content | String | The comment content attached to the vulnerability. |
| Rapid7AppSec.VulnerabilityComment.create_time | Date | Comment created time. |
| Rapid7AppSec.VulnerabilityComment.update_time | Date | Comment updated time. |

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
| module_id | The ID of the module of the attack (dependencies - use app-sec-vulnerability-list in order to get the module ID of vulnerability). | Required |
| attack_id | The ID of the attack (dependencies - use app-sec-vulnerability-list in order to get the attack ID of vulnerability). | Required |

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
Get the documentation of an attack. The documentation contains the references of the attack, description about the attack and recommendations for handling it.

#### Base Command

`app-sec-attack-documentation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| module_id | The ID of the module of the attack (dependencies - use app-sec-vulnerability-list in order to get the module ID of vulnerability). | Required |
| attack_id | The ID of the attack (dependencies - use app-sec-vulnerability-list in order to get the attack ID of vulnerability). | Required |

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
                "test": "test/"
            }
        }
    }
}
```

#### Human Readable Output

>### Attack Documentation
>|Module Id|Id|References|Description|Recommendation|
>|---|---|---|---|---|
>| 1111 | 1111 | test2: https:<span>//</span>test<br/>test: https:<span>//</span>test/<br/>test3: https:<span>//</span>test | test. | test. |


### app-sec-scan-submit

***
Submit a new Scan. A scan encapsulates all the information for a single execution of the criteria defined in the provided Scan Config.

#### Base Command

`app-sec-scan-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_config_id | The ID of the scan configuration (dependencies - use app-sec-scan-config-list to get all scan config IDs). | Required |
| scan_type | The type of the scan. Incremental scans reference the crawl map of the previous scan to identify and attack only new and updated code. Validation/ Verification scans automatically change the vulnerability status depending on whether the vulnerability was found, not found, or unknown when run against the parent_scan_id. Regular scans are designed to crawl all URLs listed in the scan config and provide in-depth results that are relevant to your needs. Possible values are: Regular, Verification, Incremental, Validation. Default is Regular. | Optional |
| parent_scan_id | The ID of the parent scan. Relevant when scant_type=Validation/ Verification. The parent scan ID is the scan that will be updated (In case vulnerability statuses has changed) after submitting the scan. (dependencies - use app-sec-scan-list to get all scan IDs). | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-scan-submit scan_config_id=1111```
#### Human Readable Output

>Scan was successfully submitted.

### app-sec-scan-action-get

***
Get any current scan action. Scan actions values are: "PAUSE", "RESUME", "STOP", "AUTHENTICATE", and "CANCEL". Relevant when Scan is RUNNING and when scan is on action (Scan is on action when moving between statuses. For example: after submitting new action, the scan has an action before the new status is updated).

#### Base Command

`app-sec-scan-action-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get the action (dependencies - use app-sec-scan-list to get all scan IDs). | Required |

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
Submit a new scan action. “Scan actions values are: "PAUSE", "RESUME", "STOP", "AUTHENTICATE", and "CANCEL". Relevant when Scan status is RUNNING.

#### Base Command

`app-sec-scan-action-submit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to submit the action (dependencies - use app-sec-scan-list to get all scan IDs). | Required |
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
| scan_id | The scan ID to delete (dependencies - use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!app-sec-scan-delete scan_id=1111```
#### Human Readable Output

>Scan "1111" was successfully deleted.

### app-sec-scan-list

***
List scans. Scans attack the URLs in your app to identify behaviors that could be exploited by attackers. The specific attack types, URLs, and many other options are set in the scan configs.  If a scan_id is given, the command will return the information about the wanted scan.

#### Base Command

`app-sec-scan-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Scan.id | String | The ID of the scan. |
| Rapid7AppSec.Scan.app_id | String | The ID of the app that related to the scan. |
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
List the engine events from a Scan. These logs typically capture specific events that occur during the scanning process.

#### Base Command

`app-sec-scan-engine-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get the engine events (dependencies - use app-sec-scan-list to get all scan IDs). | Required |

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
                },
                {
                    "event": "License Verification Completed",
                    "time": "2023-09-06T14:00:25"
                },
                {
                    "event": "Proxy settings for Internet Explorer will be used for scan.",
                    "time": "2023-09-06T14:00:31"
                },
                {
                    "event": "The following browser will be used in the scan: Chrome",
                    "time": "2023-09-06T14:00:32"
                },
                {
                    "event": "Initialized validation scan with 333 findings",
                    "time": "2023-09-06T14:01:40"
                },
                {
                    "event": "Initialization completed",
                    "time": "2023-09-06T14:01:48"
                },
                {
                    "event": "Running 'Verification' scan",
                    "time": "2023-09-06T14:01:48"
                },
                {
                    "event": "Scanning Started",
                    "time": "2023-09-06T14:01:48"
                },
                {
                    "event": "Performing Logout in session 'Default non-authenticated Session'",
                    "time": "2023-09-06T14:05:47"
                },
                {
                    "event": "Starting Second Stage of Scanning: Crawling and Attacking Links that Can Affect Login State",
                    "time": "2023-09-06T14:05:47"
                },
                {
                    "event": "Scanning Completed",
                    "time": "2023-09-06T14:05:47"
                },
                {
                    "event": "Destroying accumulated temporary data.",
                    "time": "2023-09-06T14:05:47"
                },
                {
                    "event": "Generating Report",
                    "time": "2023-09-06T14:05:48"
                },
                {
                    "event": "Report generation interfaces successfully obtained... report proceeding.",
                    "time": "2023-09-06T14:05:52"
                },
                {
                    "event": "Gathering statistics from database...",
                    "time": "2023-09-06T14:05:52"
                },
                {
                    "event": "Calculating various report structures...",
                    "time": "2023-09-06T14:08:41"
                },
                {
                    "event": "******* GRAPHS/IMAGES *******",
                    "time": "2023-09-06T14:08:41"
                },
                {
                    "event": "Generating static images...",
                    "time": "2023-09-06T14:08:41"
                },
                {
                    "event": "Generating technical summary trend graphs...",
                    "time": "2023-09-06T14:08:42"
                },
                {
                    "event": "Generating vulnerability graphs...",
                    "time": "2023-09-06T14:08:42"
                },
                {
                    "event": "Generating security status graphs...",
                    "time": "2023-09-06T14:08:43"
                },
                {
                    "event": "Generating site analysis graphs...",
                    "time": "2023-09-06T14:08:44"
                },
                {
                    "event": "Generating executive summary graphs...",
                    "time": "2023-09-06T14:08:44"
                },
                {
                    "event": "Generating application threat modeling graphs...",
                    "time": "2023-09-06T14:08:44"
                },
                {
                    "event": "Generating technical summary graphs...",
                    "time": "2023-09-06T14:08:44"
                },
                {
                    "event": "******* HTML PAGES *******",
                    "time": "2023-09-06T14:08:47"
                },
                {
                    "event": "Generating OWASP2021.html...",
                    "time": "2023-09-06T14:08:48"
                },
                {
                    "event": "Generating OWASP2023API.html...",
                    "time": "2023-09-06T14:08:49"
                },
                {
                    "event": "Generating index.html...",
                    "time": "2023-09-06T14:08:49"
                },
                {
                    "event": "Generating Validation_1.html...",
                    "time": "2023-09-06T14:08:52"
                },
                {
                    "event": "Generating Validation_2.html...",
                    "time": "2023-09-06T14:08:54"
                },
                {
                    "event": "Zipping report...",
                    "time": "2023-09-06T14:09:02"
                },
                {
                    "event": "Report Generation Completed",
                    "time": "2023-09-06T14:09:09"
                },
                {
                    "event": "Scan Completed",
                    "time": "2023-09-06T14:09:09"
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
>| 2023-09-06T14:00:25 | License Verification Completed |
>| 2023-09-06T14:00:31 | Proxy settings for Internet Explorer will be used for scan. |
>| 2023-09-06T14:00:32 | The following browser will be used in the scan: Chrome |
>| 2023-09-06T14:01:40 | Initialized validation scan with 333 findings |
>| 2023-09-06T14:01:48 | Initialization completed |
>| 2023-09-06T14:01:48 | Running 'Verification' scan |
>| 2023-09-06T14:01:48 | Scanning Started |
>| 2023-09-06T14:05:47 | Performing Logout in session 'Default non-authenticated Session' |
>| 2023-09-06T14:05:47 | Starting Second Stage of Scanning: Crawling and Attacking Links that Can Affect Login State |
>| 2023-09-06T14:05:47 | Scanning Completed |
>| 2023-09-06T14:05:47 | Destroying accumulated temporary data. |
>| 2023-09-06T14:05:48 | Generating Report |
>| 2023-09-06T14:05:52 | Report generation interfaces successfully obtained... report proceeding. |
>| 2023-09-06T14:05:52 | Gathering statistics from database... |
>| 2023-09-06T14:08:41 | Calculating various report structures... |
>| 2023-09-06T14:08:41 | ******* GRAPHS/IMAGES ******* |
>| 2023-09-06T14:08:41 | Generating static images... |
>| 2023-09-06T14:08:42 | Generating technical summary trend graphs... |
>| 2023-09-06T14:08:42 | Generating vulnerability graphs... |
>| 2023-09-06T14:08:43 | Generating security status graphs... |
>| 2023-09-06T14:08:44 | Generating site analysis graphs... |
>| 2023-09-06T14:08:44 | Generating executive summary graphs... |
>| 2023-09-06T14:08:44 | Generating application threat modeling graphs... |
>| 2023-09-06T14:08:44 | Generating technical summary graphs... |
>| 2023-09-06T14:08:47 | ******* HTML PAGES ******* |
>| 2023-09-06T14:08:48 | Generating OWASP2021.html... |
>| 2023-09-06T14:08:49 | Generating OWASP2023API.html... |
>| 2023-09-06T14:08:49 | Generating index.html... |
>| 2023-09-06T14:08:52 | Generating Validation_1.html... |
>| 2023-09-06T14:08:54 | Generating Validation_2.html... |
>| 2023-09-06T14:09:02 | Zipping report... |
>| 2023-09-06T14:09:09 | Report Generation Completed |
>| 2023-09-06T14:09:09 | Scan Completed |


### app-sec-scan-platform-event-list

***
List the platform events from a Scan. Platform logs are broader in scope and usually cover various activities and events related to the platform hosting the security scanning tool.

#### Base Command

`app-sec-scan-platform-event-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get the platform events (dependencies - use app-sec-scan-list to get all scan IDs). | Required |

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
                },
                {
                    "event": "Gathered a total of 1 Seed URLs",
                    "time": "2023-09-06T13:51:55.242744"
                },
                {
                    "event": "Detecting files attached to scan config",
                    "time": "2023-09-06T13:51:55.242752"
                },
                {
                    "event": "Attempting to gather ATTACK_VECTORS from parent scan 1111",
                    "time": "2023-09-06T13:52:11.115666"
                },
                {
                    "event": "Captured CRAWL_RESULTS as input file 1111",
                    "time": "2023-09-06T13:52:07.580851"
                },
                {
                    "event": "Captured FINDINGS as input file 1111",
                    "time": "2023-09-06T13:52:11.115645"
                },
                {
                    "event": "Attempting to gather WEB_RESOURCES from parent scan 1111",
                    "time": "2023-09-06T13:52:11.265139"
                },
                {
                    "event": "Captured WEB_RESOURCES as input file 1111",
                    "time": "2023-09-06T13:52:11.532536"
                },
                {
                    "event": "Attempting to gather CRAWL_RESULTS from parent scan 1111",
                    "time": "2023-09-06T13:51:56.793425"
                },
                {
                    "event": "Attempting to gather FINDINGS from parent scan 1111",
                    "time": "2023-09-06T13:52:07.580881"
                },
                {
                    "event": "Gathered FINDINGS from parent scan, capturing as input file",
                    "time": "2023-09-06T13:52:10.851788"
                },
                {
                    "event": "Gathered CRAWL_RESULTS from parent scan, capturing as input file",
                    "time": "2023-09-06T13:52:06.700751"
                },
                {
                    "event": "Captured ATTACK_VECTORS as input file 1111",
                    "time": "2023-09-06T13:52:11.265122"
                },
                {
                    "event": "Gathered WEB_RESOURCES from parent scan, capturing as input file",
                    "time": "2023-09-06T13:52:11.313793"
                },
                {
                    "event": "Gathered ATTACK_VECTORS from parent scan, capturing as input file",
                    "time": "2023-09-06T13:52:11.132421"
                },
                {
                    "event": "Target validation successful",
                    "time": "2023-09-06T13:52:12.48987"
                },
                {
                    "event": "Checking for any active blackouts",
                    "time": "2023-09-06T13:52:13.016882"
                },
                {
                    "event": "Scan awaiting assignment to an engine",
                    "time": "2023-09-06T13:52:13.589718"
                },
                {
                    "event": "Verifying no applicable blackout is active",
                    "time": "2023-09-06T13:59:03.959547"
                },
                {
                    "event": "Scan assigned to engine 1111",
                    "time": "2023-09-06T13:59:05.381121"
                },
                {
                    "event": "Sending scan prepare command to engine",
                    "time": "2023-09-06T13:59:05.381126"
                },
                {
                    "event": "Sending 4 scan files to engine",
                    "time": "2023-09-06T13:59:10.166493"
                },
                {
                    "event": "Subscribing to engine for logs",
                    "time": "2023-09-06T14:00:12.061747"
                },
                {
                    "event": "Subscribing to engine for live findings",
                    "time": "2023-09-06T14:00:12.06178"
                },
                {
                    "event": "Sending scan state action VERIFY",
                    "time": "2023-09-06T14:00:19.489607"
                },
                {
                    "event": "Preparing scan logs upload",
                    "time": "2023-09-06T14:09:49.897323"
                },
                {
                    "event": "Executing scan logs upload",
                    "time": "2023-09-06T14:09:56.493389"
                },
                {
                    "event": "Completing scan logs upload",
                    "time": "2023-09-06T14:10:03.944577"
                },
                {
                    "event": "Preparing scan auth video upload",
                    "time": "2023-09-06T14:10:05.39766"
                },
                {
                    "event": "Executing scan auth video upload",
                    "time": "2023-09-06T14:10:11.457145"
                },
                {
                    "event": "Completing scan auth video upload",
                    "time": "2023-09-06T14:10:17.250949"
                },
                {
                    "event": "Preparing scan result upload",
                    "time": "2023-09-06T14:10:18.143819"
                },
                {
                    "event": "Executing scan result upload",
                    "time": "2023-09-06T14:10:23.530098"
                },
                {
                    "event": "Completing scan result upload",
                    "time": "2023-09-06T14:10:30.174612"
                },
                {
                    "event": "Requesting scan cleanup on engine",
                    "time": "2023-09-06T14:10:31.095866"
                },
                {
                    "event": "Scan result has been uploaded and is being processed",
                    "time": "2023-09-06T14:10:36.341567"
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
>| 2023-09-06T13:51:55.242744 | Gathered a total of 1 Seed URLs |
>| 2023-09-06T13:51:55.242752 | Detecting files attached to scan config |
>| 2023-09-06T13:52:11.115666 | Attempting to gather ATTACK_VECTORS from parent scan 1111 |
>| 2023-09-06T13:52:07.580851 | Captured CRAWL_RESULTS as input file 1111 |
>| 2023-09-06T13:52:11.115645 | Captured FINDINGS as input file 1111 |
>| 2023-09-06T13:52:11.265139 | Attempting to gather WEB_RESOURCES from parent scan 1111 |
>| 2023-09-06T13:52:11.532536 | Captured WEB_RESOURCES as input file 1111 |
>| 2023-09-06T13:51:56.793425 | Attempting to gather CRAWL_RESULTS from parent scan 1111 |
>| 2023-09-06T13:52:07.580881 | Attempting to gather FINDINGS from parent scan 1111 |
>| 2023-09-06T13:52:10.851788 | Gathered FINDINGS from parent scan, capturing as input file |
>| 2023-09-06T13:52:06.700751 | Gathered CRAWL_RESULTS from parent scan, capturing as input file |
>| 2023-09-06T13:52:11.265122 | Captured ATTACK_VECTORS as input file 1111 |
>| 2023-09-06T13:52:11.313793 | Gathered WEB_RESOURCES from parent scan, capturing as input file |
>| 2023-09-06T13:52:11.132421 | Gathered ATTACK_VECTORS from parent scan, capturing as input file |
>| 2023-09-06T13:52:12.48987 | Target validation successful |
>| 2023-09-06T13:52:13.016882 | Checking for any active blackouts |
>| 2023-09-06T13:52:13.589718 | Scan awaiting assignment to an engine |
>| 2023-09-06T13:59:03.959547 | Verifying no applicable blackout is active |
>| 2023-09-06T13:59:05.381121 | Scan assigned to engine 1111 |
>| 2023-09-06T13:59:05.381126 | Sending scan prepare command to engine |
>| 2023-09-06T13:59:10.166493 | Sending 4 scan files to engine |
>| 2023-09-06T14:00:12.061747 | Subscribing to engine for logs |
>| 2023-09-06T14:00:12.06178 | Subscribing to engine for live findings |
>| 2023-09-06T14:00:19.489607 | Sending scan state action VERIFY |
>| 2023-09-06T14:09:49.897323 | Preparing scan logs upload |
>| 2023-09-06T14:09:56.493389 | Executing scan logs upload |
>| 2023-09-06T14:10:03.944577 | Completing scan logs upload |
>| 2023-09-06T14:10:05.39766 | Preparing scan auth video upload |
>| 2023-09-06T14:10:11.457145 | Executing scan auth video upload |
>| 2023-09-06T14:10:17.250949 | Completing scan auth video upload |
>| 2023-09-06T14:10:18.143819 | Preparing scan result upload |
>| 2023-09-06T14:10:23.530098 | Executing scan result upload |
>| 2023-09-06T14:10:30.174612 | Completing scan result upload |
>| 2023-09-06T14:10:31.095866 | Requesting scan cleanup on engine |
>| 2023-09-06T14:10:36.341567 | Scan result has been uploaded and is being processed |


### app-sec-scan-execution-details-get

***
Get real-time details of the execution of a Scan (for example: Coverage, Attack, and Network details).

#### Base Command

`app-sec-scan-execution-details-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The scan ID to get the platform events (dependencies - use app-sec-scan-list to get all scan IDs). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.ExecutionDetail.id | String | The ID of the scan. |
| Rapid7AppSec.ExecutionDetail.logged_in | Boolean | Whether the scan succeeded to log in to the app \(in case the scan should log in\). |
| Rapid7AppSec.ExecutionDetail.links_in_queue | Number | The number of links in queue. |
| Rapid7AppSec.ExecutionDetail.links_crawled | Number | The number of links crawled. |
| Rapid7AppSec.ExecutionDetail.attacks_in_queue | Number | The number of attacks in queue. |
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
List scan configs. A Scan Config defines all the necessary information required to perform a scan of an app. If a scan_config_id is given, the command will return the information about the wanted scan config. Mainly used to submit scans.

#### Base Command

`app-sec-scan-config-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_config_id | The scan config ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.ScanConfig.id | String | The ID of the scan config. |
| Rapid7AppSec.ScanConfig.name | String | The name of the scan config. |
| Rapid7AppSec.ScanConfig.app_id | String | The ID of the app that related to the scan config \(dependencies - use app-sec-app-list to get all app IDs\). |
| Rapid7AppSec.ScanConfig.attack_template_id | String | The ID of the attack template that related to the scan config \(dependencies - use app-sec-attack-template-list to get more information about the attack template\). |
| Rapid7AppSec.ScanConfig.incremental | Boolean | Whether incremental scanning is enabled. |
| Rapid7AppSec.ScanConfig.assignment_type | String | The type of the assignment. For example: ENGINE_GROUP. |
| Rapid7AppSec.ScanConfig.assignment_id | String | The ID of the assignment \(Supported for On-Premise engines\) \(dependencies - use app-sec-engine-group-list to get more information about the assignment ID\). |
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
List apps. An App owns Scan Configs, Schedules, Scans, and Vulnerabilities.  Mainly used to understand vulnerabilities and scan config outputs. If a app_id is given, the command will return the information about the wanted app.

#### Base Command

`app-sec-app-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| app_id | The app ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
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
List modules. If a module_id is given, the command will return the information about the wanted module. Mainly used to understand vulnerabilities outputs.

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
List attack templates. An Attack Template describes if and how Attacks should be executed during the execution of a Scan. Mainly used to understand the scan config outputs. If a attack_template_id is given, the command will return the information about the wanted attack.

#### Base Command

`app-sec-attack-template-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_template_id | The attack template ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.AttackTemplate.id | String | The ID of the module. |
| Rapid7AppSec.AttackTemplate.name | String | The name of the module. |
| Rapid7AppSec.AttackTemplate.system_defined | String | Whether the attack templated defined by system. |
| Rapid7AppSec.AttackTemplate.browser_encoding_enabled | String | A flag that is used to enforce browser encoding on all attacks. |
| Rapid7AppSec.AttackTemplate.attack_prioritization | String | The Attack Prioritization type. The values are: SEQUENTIAL, SMART, and RANDOMIZED". |
| Rapid7AppSec.AttackTemplate.advanced_attacks_enabled | String | A flag to enable advanced Attacks. |

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
List engines. An Engine encapsulates the state and high-level attributes of the components which may be installed and running on a specific On-Premise host. If a engine_id is given, the command will return the information about the wanted engine.

#### Base Command

`app-sec-engine-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine_id | The engine ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Rapid7AppSec.Engine.id | String | The ID of the engine. |
| Rapid7AppSec.Engine.name | String | The name of the engine. |
| Rapid7AppSec.Engine.engine_group_id | String | The ID of the engine group. |
| Rapid7AppSec.Engine.failure_reason | String | Failure reason \(In case it failed\). |
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
List engine groups. An Engine Group is a resource which defines a container for a logical grouping of Engines and therefore the purpose of assigning Scans to one of those Engines. Mainly used to understand the scan config outputs. If a engine_group_id is given, the command will return the information about the wanted engine group.

#### Base Command

`app-sec-engine-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine_group_id | The engine group ID to get. In case of using this argument, the pagination arguments not relevant. | Optional |
| page | Page number of paginated results. Minimum value: 1. | Optional |
| page_size | The number of items per page. Maximum value is 1000. | Optional |
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
