This integration enables real-time ingestion of Contrast Security incidents and issues into XSOAR via a webhook.

### Authorization

The Contrast Security username, API key, service key, and organization ID can be found in the Contrast Security platform by clicking on the profile icon.

### Instance Configuration

1. Configure a Contrast Security integration instance with valid credentials.
2. Click **Test** to validate the connection between XSOAR and the Contrast Security platform.
3. To fetch events from Contrast Security, select the event type from the dropdown and configure the parameters below. Note: The following parameters are required after enabling **Long Running Instance**: Listening Port, Webhook Username, Webhook Password, and Event Type.
4. The Contrast Security username, service key, API key, and organization ID can be found in the Contrast Security platform by clicking on the profile icon. These credentials are used to establish connectivity between the Contrast Security REST API and XSOAR.

### Contrast Security Webhook configuration

1. To configure a Contrast Security webhook integration, go to **Administration** > **Integrations** > **Palo Alto Networks Cortex XSOAR** in the Contrast Security platform.
2. Enter the webhook URL provided by XSOAR. For XSOAR 8, use the result link URL displayed in the integration instance.
3. Enter the username and password credentials.
4. Click **Test** to validate the connection between XSOAR and the Contrast Security platform.

The following table provides detailed information about each configuration parameter of the integration instance:

## Configure Contrast Security in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Long running instance | A Cortex XSOAR integration instance that runs continuously, listening on a specified port to receive real-time events such as webhooks from Contrast Security. | False |
| Listening Port | Runs the service on this port from within Cortex XSOAR. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. Note: If you click the \*\*Test\*\* button more than once, a failure may occur mistakenly indicating that the port is already in use. | False |
| Webhook Username | Username are required for webhook authentication. Required when "Long running instance" is enabled. | False |
| Webhook Password | Password are required for webhook authentication. Required when "Long running instance" is enabled. | False |
| Event Type | Select event type to fetch from Contrast Security platform. Contrast Security recommends selecting "Contrast Incident" as the event type to fetch via webhook. | False |
| Incident type |  | False |
| Contrast Security Server URL | Server URL of the Contrast Security platform. | True |
| Contrast Security Username (Email) | Username used for Contrast Security platform. Email address is used as the username for Contrast Security platform. | True |
| Contrast Security Service Key | Service key used for Contrast Security platform. | True |
| Contrast Security API Key | API key used for secure communication with Contrast Security platform. | True |
| Contrast Security Organization ID | The organization ID used for the Contrast Security platform. | True |
| Certificate (Required for HTTPS) | \(For Cortex XSOAR 6.x\) For use with HTTPS - the certificate that the service should use. \(For Cortex XSOAR 8 and Cortex XSIAM\) Custom certificates are not supported. | False |
| Private Key (Required for HTTPS) | \(For Cortex XSOAR 6.x\) For use with HTTPS - the private key that the service should use. \(For Cortex XSOAR 8 and Cortex XSIAM\) When using an engine, configure a private API key. Not supported on the Cortex XSOAR or Cortex XSIAM server. | False |
| Incident Mirroring Direction | The mirroring direction in which to mirror the incident details. | False |
| Issue Mirroring Direction | The mirroring direction in which to mirror the Issue details. | False |
| Mirror Tag for Notes | Tag value used to mirror XSOAR notes back to Contrast Security as issue or incident comments. | False |
| Reopen Incident in XSOAR When Status Changes to 'Open' in Contrast Security Incident | If selected, closed incidents will be reopened in XSOAR when the incident status in Contrast Security Incident changes to 'Open'.<br/><br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. | False |
| Close Incident in XSOAR When Status Changes to 'Closed' in Contrast Security Incident | If selected, active incidents will be closed in XSOAR when the incident status in Contrast Security Incident changes to 'Closed'.<br/><br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. | False |
| Store sample events for mapping | Because this is a push-based integration, it cannot fetch sample events in the mapping wizard. After you finish mapping, it is recommended to turn off the sample events storage to reduce performance overhead. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

### Contrast Security Long Running Instance Configuration

To configure the Contrast Security long running instance:

#### Cortex XSOAR 6.x

To configure a long running integration instance:

- **HTTP Configuration:** Configure a long running port for long running server.  
- **HTTPS Configuration:** In addition to HTTP, configure a certificate and private key.  

**Webhook URL Options:**

- Direct port-based access: `https://<CORTEX-XSOAR-URL>:<LISTEN_PORT>/`

- Instance execution endpoint: `https://<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`

For more general information on long running integrations on XSOAR6:
[XSOAR 6 Long Running Integrations](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke)

#### Cortex XSOAR 8/XSIAM

To configure a long running integration instance:

- The instance should be configured to run over **HTTP internally**.  
- HTTPS is automatically handled using the server’s certificate in XSOAR 8 / XSIAM.  
- Configure authentication using a **webhook username and webhook password**.  
- The **Long Running Port** field appears in Cortex XSOAR 8 and XSIAM only when using an engine.  

**Webhook URL:**

`https://ext-<CORTEX-TENANT-URL>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`

For more general information on long running integrations on XSOAR8:
[XSOAR 8 / XSIAM Long Running Integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations)

#### Notes

- The integration instance name must not contain special characters.

**Notes for mirroring:**

- This feature is compliant with XSOAR version 6.0 and above.
- When an incident status is active in XSOAR, it will be mapped with an open status in the Contrast Security incident. When an XSOAR incident is closed, it will be mapped with a closed status in the Contrast Security incident with provided closing notes.
- New notes from the XSOAR incident will be created as a comment in the Contrast Security incident which has provided mirroring tag.
- When mirroring is set to 'Incoming' or 'Incoming and Outgoing', the integration will update the Contrast Security incident fields, such as status and contrast score, in the XSOAR incident.
- When an Incident status is changed in XSOAR, the status will be synchronized with the corresponding Contrast Security Issue.
- New notes added to XSOAR incidents will be created as comments in the Contrast Security Issue with the provided mirroring tag.
- Incident status changes in XSOAR (Open/Closed) will be reflected in the Contrast Security Issue.
- **Reopen Incident in XSOAR When Status Changes to 'Open' in Contrast Security Incident:** If selected, closed incidents will be reopened in XSOAR when the incident status in Contrast Security Incident changes to 'Open'. Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'.
- **Close Incident in XSOAR When Status Changes to 'Closed' in Contrast Security Incident:** If selected, active incidents will be closed in XSOAR when the incident status in Contrast Security Incident changes to 'Closed'. Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'.
- Incident mirroring supports multiple directions - 'Incoming', 'Outgoing', and 'Incoming and Outgoing'. However, only 'Outgoing' mirroring is supported for issues. Users can configure only 'Outgoing' mirroring direction for the Issue Mirroring Direction parameter.
- The following fields are mirroring parameters that need to be configured in the integration instance:
  - **Incident Mirroring Direction:** This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support. Possible values are "Incoming", "Outgoing", and "Incoming and Outgoing".
  - **Issue Mirroring Direction:** This field determines the mirroring direction for the issue. It is a required field for XSOAR to enable mirroring support. Possible values are "Outgoing".
  - **Mirror Tag for Notes:** This field determines the tag for notes. It is a required field for XSOAR to enable mirroring support.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### contrastsecurity-incident-comment-add

***
Add a comment to a Contrast Security Incident.

#### Base Command

`contrastsecurity-incident-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident. | Required |
| comment | Comment text to add to the incident. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.IncidentComment.incident_id | String | The ID of the incident the comment was added to. |
| ContrastSecurity.IncidentComment.commentId | String | Unique identifier of the comment. |
| ContrastSecurity.IncidentComment.userId | String | Unique identifier of the user who made the comment. |
| ContrastSecurity.IncidentComment.userUid | String | Email address of the user who made the comment. |
| ContrastSecurity.IncidentComment.commentText | String | The actual comment text content. |
| ContrastSecurity.IncidentComment.createdTime | Date | Timestamp when the comment was created. |
| ContrastSecurity.IncidentComment.lastUpdatedTime | Date | Timestamp when the comment was last updated. |

#### Command example

```!contrastsecurity-incident-comment-add comment="this is comment from xsoar" incident_id=INC-2026-253```

#### Context Example

```json
{
    "ContrastSecurity": {
        "IncidentComment": {
            "incident_id": "INC-2026-253",
            "commentId": "c6294c84-b99d-41c5-bb3d-0e141cf02390",
            "userId": "8dc795ca-547f-41f0-8b4c-19afdbe42342",
            "userUid": "test.comment@contrastsecurity.com",
            "commentText": "this is comment from xsoar",
            "createdTime": "2026-04-06T05:22:41.602411286Z",
            "lastUpdatedTime": "2026-04-06T05:22:41.602411286Z"
        }
    }
}
```

#### Human Readable Output

>### Incident INC-2026-253 Comment Added Successfully
>
>|Comment ID|User UID|Comment Text|Created At|
>|---|---|---|---|
>| c6294c84-b99d-41c5-bb3d-0e141cf02390 | test.comment@contrastsecurity.com | this is comment from xsoar | 2026-04-06T05:22:41.602411286Z |

### contrastsecurity-incident-status-update

***
Update the status of a Contrast Security Incident.

#### Base Command

`contrastsecurity-incident-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident. | Required |
| status | Specify status of the Incident. Possible values are: Open, Closed. | Required |
| close_reason | Specify the reason for closing the incident. Required when status is set to "Closed". Possible values are: True Positive, False Positive, Benign True Positive, Other. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Incident.id | String | Unique identifier of the incident. |
| ContrastSecurity.Incident.status | String | Updated status of the incident. |
| ContrastSecurity.Incident.close_reason | String | Reason for closing the incident (if applicable). |

#### Command example

```!contrastsecurity-incident-status-update incident_id=incident-123 status=Closed close_reason="True Positive"```

#### Context Example

```json
{
  "ContrastSecurity": {
    "Incident": [
      {
        "id": "incident-123",
        "status": "Closed",
        "close_reason": "True Positive"
      }
    ]
  }
}
```

#### Human Readable Output

>### Incident Status Updated Successfully
>
>|Incident ID|Status|Close Reason|
>|---|---|---|
>| incident-123 | Closed | True Positive |

### contrastsecurity-ip-block

***
Block an IP address for a Contrast Security Incident.

#### Base Command

`contrastsecurity-ip-block`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident. | Required |
| ip_addresses | Specify the IP address to block. Supports comma-separated values. | Required |
| expiration_date | Specify the IP address expiration duration time.If no expiration date is provided, the IP addresses will be blocked for Forever.<br/><br/> Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 May 2025 04:45:33, 2025-05-17T14:05:44Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Incident.id | String | The ID of the Contrast Security incident. |
| ContrastSecurity.Incident.IpAddresses.expiration_date | Date | IP expiration duration time. |
| ContrastSecurity.Incident.IpAddresses.ips | List | List of blocked IP addresses. |

#### Command example

```!contrastsecurity-ip-block incident_id=INC-2026-80 ip_addresses=10.50.4.3,10.1.0.50 expiration_date="2 minutes"```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Incident": {
            "id": "INC-2026-80",
            "IpAddresses": {
                "ips": [
                    "10.50.4.3",
                    "10.1.0.50"
                ],
                "expiration_date": "2026-04-09T08:48:23Z"
            }
        }
    }
}
```

#### Human Readable Output

>### IP Addresses Blocked Successfully
>
>|Incident ID|Blocked IPs|Expiration Date|
>|---|---|---|
>| INC-2026-80 |10.50.4.3,10.1.0.50| 2026-04-09T08:48:23Z |

### contrastsecurity-adrpolicy-update

***
Configure ADR Policy for a Contrast Security Incident.

#### Base Command

`contrastsecurity-adrpolicy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident. | Required |
| rule_names | Specify the ADR rule name to configure. Supports comma-separated values. | Required |
| dev_mode | Specify the Blocking mode for the Development environment. Possible values are: Block at perimeter, Off, Monitor, Block. Default is Monitor. | Optional |
| qa_mode | Specify the Blocking mode for the QA environment. Possible values are: Block at perimeter, Off, Monitor, Block. Default is Monitor. | Optional |
| prod_mode | Specify the Blocking mode for the Production environment. Possible values are: Block at perimeter, Off, Monitor, Block. Default is Monitor. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Incident.id | String | The ID of the Contrast Security incident. |
| ContrastSecurity.Incident.Rules.rule | String | The rule name. |
| ContrastSecurity.Incident.Rules.devMode | String | Development environment block mode for the rule. |
| ContrastSecurity.Incident.Rules.qaMode | String | QA environment block mode for the rule. |
| ContrastSecurity.Incident.Rules.prodMode | String | Production environment block mode for the rule. |

#### Command example

```!contrastsecurity-adrpolicy-update incident_id=INC-2026-80 dev_mode="Monitor" prod_mode="Monitor" qa_mode="Monitor" rule_names="sql-injection,sql"```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Incident": {
            "id": "INC-2026-80",
            "Rules": [
                {
                    "rule": "sql-injection",
                    "devMode": "Monitor",
                    "qaMode": "Monitor",
                    "prodMode": "Monitor"
                },
                {
                    "rule": "sql",
                    "devMode": "Monitor",
                    "qaMode": "Monitor",
                    "prodMode": "Monitor"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### ADR Policy Updated Successfully
>
>|Incident ID|Rule Name|Development Mode|QA Mode|Production Mode|
>|---|---|---|---|---|
>| INC-2026-80 | sql-injection,sql | Monitor | Monitor | Monitor |

### contrastsecurity-issue-list

***
List Contrast Security Issues with provided filter parameters.

#### Base Command

`contrastsecurity-issue-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident to retrieve issues for a specific incident. If not provided, retrieves all issues. | Optional |
| page_size | Number of results to return per page. Maximum value is 100. Default is 50. | Optional |
| sort_by | Specify the field used to sort the Issues. Possible values are: cvss_score, issue_id, title, status, service_name, created_at, last_observation_at, observation_count. | Optional |
| sort_order | Specify the order used to sort the Issues. Possible values are: Asc, Desc. Default is Asc. | Optional |
| page | Page number for pagination. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Issues.issueId | String | Unique identifier for the issue. |
| ContrastSecurity.Issues.status | String | Current status of the issue. |
| ContrastSecurity.Issues.applicationId | String | Unique identifier of the application. |
| ContrastSecurity.Issues.title | String | Title of the vulnerability issue. |
| ContrastSecurity.Issues.ruleId | String | Vulnerability rule identifier \(e.g., SQL Injection\). |
| ContrastSecurity.Issues.applicationName | String | Name of the affected application. |
| ContrastSecurity.Issues.applicationLanguage | String | Programming language of the application. |
| ContrastSecurity.Issues.httpRoute | String | Affected HTTP route where the issue is found. |
| ContrastSecurity.Issues.currentIncidentId | String | Current associated incident ID. |
| ContrastSecurity.Issues.incidentCount | Number | Total number of incidents related to the issue. |
| ContrastSecurity.Issues.observationCount | Number | Number of observations recorded for the issue. |
| ContrastSecurity.Issues.attackCount | Number | Total number of attacks detected. |
| ContrastSecurity.Issues.exploitedAttackCount | Number | Number of successfully exploited attacks. |
| ContrastSecurity.Issues.suspiciousAttackCount | Number | Number of suspicious attacks detected. |
| ContrastSecurity.Issues.blockedAttackCount | Number | Number of blocked attacks. |
| ContrastSecurity.Issues.cvssScore | String | CVSS score indicating severity. |
| ContrastSecurity.Issues.cvssVector | String | CVSS vector string providing scoring details. |
| ContrastSecurity.Issues.createdAt | Date | Timestamp when the issue was created. |
| ContrastSecurity.Issues.closedAt | Date | Timestamp when the issue was closed \(if applicable\). |
| ContrastSecurity.Issues.lastAttackedAt | Date | Timestamp of the last detected attack. |
| ContrastSecurity.Issues.lastObservationAt | Date | Timestamp of the last observation. |
| ContrastSecurity.Issues.deploymentTier | Unknown | Deployment environment tier \(e.g., Development, Production\). |
| ContrastSecurity.Issues.issueLink | String | Direct link to the issue in the Contrast Security platform. |

#### Command example

```!contrastsecurity-issue-list page_size=50 page=0```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Issues": [
            {
                "issueId": "ISS-2026-1430",
                "status": "open",
                "applicationId": "1-1",
                "title": "CVEs in yaml 1",
                "ruleId": "library-vulnerability",
                "applicationName": "Test_App",
                "applicationLanguage": "",
                "httpRoute": "",
                "incidentCount": 0,
                "observationCount": 7,
                "attackCount": 0,
                "exploitedAttackCount": 0,
                "suspiciousAttackCount": 0,
                "blockedAttackCount": 0,
                "cvssScore": "7.0",
                "cvssVector": "CVSS:4.0/AV:N/AC:L",
                "createdAt": "2026-03-24T16:29:38.106Z",
                "lastObservationAt": "2026-03-24T16:29:38.106Z",
                "deploymentTier": [
                    "DEVELOPMENT"
                ],
                "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-1430"
            },
            {
                "issueId": "ISS-2026-1431",
                "status": "open",
                "applicationId": "2-2",
                "title": "CVEs in tomcat-embed-websocket 9.0.75",
                "ruleId": "library-vulnerability",
                "applicationName": "Test_App2",
                "applicationLanguage": "",
                "httpRoute": "",
                "incidentCount": 0,
                "observationCount": 23,
                "attackCount": 0,
                "exploitedAttackCount": 0,
                "suspiciousAttackCount": 0,
                "blockedAttackCount": 0,
                "cvssScore": "8.8",
                "cvssVector": "CVSS:4.0/AV:N/AC:L/AT:N",
                "createdAt": "2026-03-24T16:29:38.106Z",
                "lastObservationAt": "2026-03-24T16:29:38.106Z",
                "deploymentTier": [
                    "DEVELOPMENT"
                ],
                "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-1431"
            }
        ]
    }
}
```

#### Human Readable Output

>### Contrast Security Issues
>
>|CVSS Score|Title|Issue ID|Status|Application Name|Number of Observations|Last Observation At|CVSS Vector|Deployment Tier|
>|---|---|---|---|---|---|---|---|---|
>| 7.0 | CVEs in yaml 1 | [ISS-2026-1430](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-1430) | open | Test_App | 7 | 2026-03-24T16:29:38.106Z | CVSS:4.0/AV:N/AC:L | DEVELOPMENT |
>| 8.8 | CVEs in tomcat-embed-websocket 9.0.75 | [ISS-2026-1431](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-1431) | open | Test_App2 | 23 | 2026-03-24T16:29:38.106Z | CVSS:4.0/AV:N/AC:L/AT:N | DEVELOPMENT |

### contrastsecurity-issue-get

***
Get a specific Contrast Security Issue by ID.

#### Base Command

`contrastsecurity-issue-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Specify the ID of the Issue. Note: Use contrastsecurity-issue-list to retrieve the Issue ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Issues.issueId | String | Unique identifier for the issue. |
| ContrastSecurity.Issues.status | String | Current status of the issue. |
| ContrastSecurity.Issues.applicationId | String | Unique identifier of the application. |
| ContrastSecurity.Issues.title | String | Title of the vulnerability issue. |
| ContrastSecurity.Issues.ruleId | String | Vulnerability rule identifier \(e.g., SQL Injection\). |
| ContrastSecurity.Issues.applicationName | String | Name of the affected application. |
| ContrastSecurity.Issues.applicationLanguage | String | Programming language of the application. |
| ContrastSecurity.Issues.httpRoute | String | Affected HTTP route where the issue is found. |
| ContrastSecurity.Issues.currentIncidentId | String | Current associated incident ID. |
| ContrastSecurity.Issues.incidentCount | Number | Total number of incidents related to the issue. |
| ContrastSecurity.Issues.observationCount | Number | Number of observations recorded for the issue. |
| ContrastSecurity.Issues.attackCount | Number | Total number of attacks detected. |
| ContrastSecurity.Issues.exploitedAttackCount | Number | Number of successfully exploited attacks. |
| ContrastSecurity.Issues.suspiciousAttackCount | Number | Number of suspicious attacks detected. |
| ContrastSecurity.Issues.blockedAttackCount | Number | Number of blocked attacks. |
| ContrastSecurity.Issues.cvssScore | String | CVSS score indicating severity. |
| ContrastSecurity.Issues.cvssVector | String | CVSS vector string providing scoring details. |
| ContrastSecurity.Issues.createdAt | Date | Timestamp when the issue was created. |
| ContrastSecurity.Issues.closedAt | Date | Timestamp when the issue was closed \(if applicable\). |
| ContrastSecurity.Issues.lastAttackedAt | Date | Timestamp of the last detected attack. |
| ContrastSecurity.Issues.lastObservationAt | Date | Timestamp of the last observation. |
| ContrastSecurity.Issues.deploymentTier | Unknown | Deployment environment tier \(e.g., Development, Production\). |
| ContrastSecurity.Issues.vulnEventId | String | Unique identifier for the vulnerability event. |
| ContrastSecurity.Issues.lastAttackIdRef.appId | String | Application ID associated with the last attack. |
| ContrastSecurity.Issues.lastAttackIdRef.attackId | String | Unique identifier of the last attack. |
| ContrastSecurity.Issues.summary | String | Summary/description of the detected attack or issue. |

#### Command example

```!contrastsecurity-issue-get issue_id=ISS-2026-1326```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Issues": {
            "issueId": "ISS-2026-1430",
            "status": "open",
            "applicationId": "1-1",
            "title": "CVEs in yaml 1",
            "ruleId": "library-vulnerability",
            "applicationName": "Test_App",
            "applicationLanguage": "",
            "httpRoute": "/payments",
            "currentIncidentId": "INC-2026-269",
            "incidentCount": 0,
            "observationCount": 7,
            "attackCount": 0,
            "exploitedAttackCount": 0,
            "suspiciousAttackCount": 0,
            "blockedAttackCount": 0,
            "cvssScore": "7.0",
            "cvssVector": "CVSS:4.0/AV:N/AC:L",
            "createdAt": "2026-03-24T16:29:38.106Z",
            "lastAttackedAt": "2026-03-18T11:46:55.910Z",
            "lastObservationAt": "2026-03-24T16:29:38.106Z",
            "deploymentTier": [
                "DEVELOPMENT"
            ],
            "lastAttackIdRef": {
                "appId": "1-1",
                "attackId": "2-2"
            },
            "summary": "suspicious value accessing the application through the HTTP Request Parameter SUBMIT\n' or 112=112--"
        }
    }
}
```

#### Human Readable Output

>### Contrast Security Issue
>
>|Issue ID|Title|Summary|Status|Application Name|Application ID|Rule ID|CVSS Score|CVSS Vector|Current Incident ID|Incident Count|Created At|Last Attacked At|Last Attack ID Ref|Last Observation At|Attack Count|Blocked Attack Count|Exploited Attack Count|Observation Count|Suspicious Attack Count|Deployment Tier|HTTP Route|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [ISS-2026-1430](https://contrast.security/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-1430) | CVEs in yaml 1 | suspicious value accessing the application through the HTTP Request Parameter SUBMIT<br>' or 112=112-- | open | Test_App | 1-1 | library-vulnerability | 7.0 | CVSS:4.0/AV:N/AC:L | INC-2026-269 | 0 | 2026-03-24T16:29:38.106Z | 2026-03-18T11:46:55.910Z | ***appId***: 1-1<br>***attackId***: 2-2 | 2026-03-24T16:29:38.106Z | 0 | 0 | 0 | 7 | 0 | ***values***: DEVELOPMENT | /payments |

### contrastsecurity-issue-comment-add

***
Add a comment to a Contrast Security Issue.

#### Base Command

`contrastsecurity-issue-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Specify the ID of the Issue. | Required |
| comment | Comment text to add to the issue. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.IssueComment.issue_id | String | The ID of the issue the comment was added to. |
| ContrastSecurity.IssueComment.commentId | String | Unique identifier of the comment. |
| ContrastSecurity.IssueComment.userId | String | Unique identifier of the user who made the comment. |
| ContrastSecurity.IssueComment.userUid | String | Email address of the user who made the comment. |
| ContrastSecurity.IssueComment.commentText | String | The actual comment text content. |
| ContrastSecurity.IssueComment.createdTime | Date | Timestamp when the comment was created. |
| ContrastSecurity.IssueComment.lastUpdatedTime | Date | Timestamp when the comment was last updated. |

#### Command example

```!contrastsecurity-issue-comment-add comment="this is test comment for issue" issue_id=ISS-2026-100```

#### Context Example

```json
{
    "ContrastSecurity": {
        "IssueComment": {
            "issue_id": "ISS-2026-100",
            "commentId": "11e6d5fa-06cf-49b9-b481-9ea83ab076e3",
            "userId": "8dc795ca-547f-41f0-8b4c-19afdbe42342",
            "userUid": "user.test@contrastsecurity.com",
            "commentText": "this is test comment for issue ",
            "createdTime": "2026-04-27T09:23:32.693501406Z",
            "lastUpdatedTime": "2026-04-27T09:23:32.693501406Z"
        }
    }
}
```

#### Human Readable Output

>### Issue ISS-2026-100 Comment Added Successfully
>
>|Comment ID|User UID|Comment Text|Created At|
>|---|---|---|---|
>| 11e6d5fa-06cf-49b9-b481-9ea83ab076e3 | user.test@contrastsecurity.com | this is test comment for issue  | 2026-04-27T09:23:32.693501406Z |

### contrastsecurity-issue-status-update

***
Update the status of a Contrast Security Issue.

#### Base Command

`contrastsecurity-issue-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Specify the ID of the Issue. | Required |
| status | Specify status of the Issue. Possible values are: Open, Closed. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Issues.id | String | Unique identifier of the issue. |
| ContrastSecurity.Issues.status | String | Updated status of the issue. |

#### Command example

```!contrastsecurity-issue-status-update issue_id=ISS-2026-100 status=Closed```

#### Context Example

```json
{
  "ContrastSecurity": {
    "Issues": [
      {
        "id": "ISS-2026-100",
        "status": "Closed"
      }
    ]
  }
}
```

#### Human Readable Output

>### Issue Status Updated Successfully
>
>|Issue ID|Status|
>|---|---|
>| ISS-2026-100 | Closed |

### contrastsecurity-observation-get

***
Get a specific Contrast Security Observation by ID.

#### Base Command

`contrastsecurity-observation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| observation_id | Specify the ID of the observation. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Observations.teamserverAuthorizationFailure | Boolean | Indicates if TeamServer authorization failed. |
| ContrastSecurity.Observations.vulnEventId | String | Vulnerability event ID. |
| ContrastSecurity.Observations.eventStory | String | Story describing the event. |
| ContrastSecurity.Observations.eventRecommendation | String | Recommended action for the event. |
| ContrastSecurity.Observations.issueId | String | Unique identifier for the issue. |
| ContrastSecurity.Observations.type | String | Type of observation \(LIBRARY, ATTACK, SAST\). |
| ContrastSecurity.Observations.eventTime | Date | Timestamp when the observation event occurred. |
| ContrastSecurity.Observations.applicationId | String | Unique identifier of the affected application. |
| ContrastSecurity.Observations.applicationName | String | Name of the affected application. |
| ContrastSecurity.Observations.applicationLanguage | String | Programming language of the application. |
| ContrastSecurity.Observations.scaLibraryResponseDto.releaseDate | Date | Release date of the library. |
| ContrastSecurity.Observations.scaLibraryResponseDto.version | String | Version of the library. |
| ContrastSecurity.Observations.scaLibraryResponseDto.closestStableVersion | String | Closest stable version available. |
| ContrastSecurity.Observations.scaLibraryResponseDto.latestStableVersion | String | Latest stable version available. |
| ContrastSecurity.Observations.scaLibraryResponseDto.licenses | List | Licenses associated with the library. |
| ContrastSecurity.Observations.scaLibraryResponseDto.packageUrl | String | Package URL of the library. |
| ContrastSecurity.Observations.scaLibraryResponseDto.dependency | String | Dependency information for the library. |
| ContrastSecurity.Observations.scaLibraryResponseDto.vulnerabilities.name | String | CVE name of the vulnerability. |
| ContrastSecurity.Observations.scaLibraryResponseDto.vulnerabilities.description | String | Description of the vulnerability. |
| ContrastSecurity.Observations.scaLibraryResponseDto.vulnerabilities.epssScore | Number | EPSS score for the vulnerability. |
| ContrastSecurity.Observations.scaLibraryResponseDto.vulnerabilities.epssPercentile | Number | EPSS percentile for the vulnerability. |
| ContrastSecurity.Observations.scaLibraryResponseDto.vulnerabilities.cisa | Boolean | Whether the vulnerability is tracked by CISA. |
| ContrastSecurity.Observations.attackInsightsResponseDto.incidentId | String | Incident ID for the attack. |
| ContrastSecurity.Observations.attackInsightsResponseDto.summary | String | Summary of the attack observation. |
| ContrastSecurity.Observations.attackInsightsResponseDto.recommendedActions | String | Recommended actions to address the attack. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackValueContextText | String | Context information about the attack value. |
| ContrastSecurity.Observations.attackInsightsResponseDto.vectorAnalysisContextText | String | Context text describing the vector analysis. |
| ContrastSecurity.Observations.attackInsightsResponseDto.vectorAnalysisCodeText | String | Code related to the vector analysis. |
| ContrastSecurity.Observations.attackInsightsResponseDto.requestDetails | String | Details of the HTTP request that triggered the attack. |
| ContrastSecurity.Observations.attackInsightsResponseDto.ruleUuid | String | UUID of the security rule related to the attack. |
| ContrastSecurity.Observations.attackInsightsResponseDto.url | String | URL where the attack was detected. |
| ContrastSecurity.Observations.attackInsightsResponseDto.codeLocation.file | String | Source file where the vulnerability exists. |
| ContrastSecurity.Observations.attackInsightsResponseDto.codeLocation.method | String | Method where the vulnerability exists. |
| ContrastSecurity.Observations.attackInsightsResponseDto.codeLocation.stack | List | Stack trace of the code location. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackPayload.value | String | Actual attack payload value. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackPayload.attackerInput.name | String | Name of the attacker input field. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackPayload.attackerInput.inputType | String | Type of attacker input. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackPayload.attackerInput.confirmedAttack | Boolean | Whether the attack was confirmed. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackPayload.attackerInput.effectiveAttack | Boolean | Whether the attack was effective. |
| ContrastSecurity.Observations.attackInsightsResponseDto.attackPayload.attackerInput.applicableAttack | Boolean | Whether the attack is applicable. |
| ContrastSecurity.Observations.sastResult | String | SAST analysis result. |
| ContrastSecurity.Observations.summary | String | Summary of the observation. |
| ContrastSecurity.Observations.stackTrace.description | String | The category or classification of the stack trace (e.g., error, warning). |
| ContrastSecurity.Observations.stackTrace.type | String | Detailed description of the stack trace associated with the observation. |

#### Command example

```!contrastsecurity-observation-get observation_id=test-obs-wkmsdkw```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Observations": {
            "observationId": "test-obs-wkmsdkw",
            "issueId": "ISS-2026-2",
            "type": "LIBRARY",
            "applicationId": "12345678-1234-1234-1234-123456789012",
            "applicationName": "test-app-service",
            "eventTime": "2024-01-20T14:20:00.000Z",
            "teamserverAuthorizationFailure": false,
            "scaLibraryResponseDto": {
                "releaseDate": "2023-08-14T09:30:45Z",
                "licenses": [
                    "Unknown"
                ],
                "vulnerabilities": [
                    {
                        "name": "CVE-XXXX-1111",
                        "description": "Dummy vulnerability description for testing purposes. This is a sample vulnerability entry used in test data.",
                        "epssScore": 0.05,
                        "epssPercentile": 50.0,
                        "cisa": false
                    },
                    {
                        "name": "CVE-XXXX-2222",
                        "description": "Another dummy vulnerability description for testing. This entry is used to validate the library response handling.",
                        "epssScore": 0.02,
                        "epssPercentile": 30.0,
                        "cisa": false
                    }
                ],
                "version": "2.3.7",
                "closestStableVersion": "3.1.6",
                "latestStableVersion": "3.1.8"
            }
        }
    }
}
```

#### Human Readable Output

>### Observation Information
>
>|Observation ID|Issue ID|Type|Application ID|Application Name|Event Time|
>|---|---|---|---|---|---|
>| [test-obs-wkmsdkw](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/test-obs-wkmsdkw) | [ISS-2026-2](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-2) | LIBRARY | 12345678-1234-1234-1234-123456789012 | test-app-service | 2024-01-20T14:20:00.000Z |
>
>### Vulnerability Information
>
>|Release Date|License|Version|Closest Stable Version|Latest Stable Version|
>|---|---|---|---|---|
>| 2023-08-14T09:30:45Z | Unknown | 2.3.7 | 3.1.6 | 3.1.8 |
>
>### Vulnerabilities
>
>|CVE ID|Description|EPSS Score|EPSS Percentile|CISA|
>|---|---|---|---|---|
>| CVE-XXXX-1111 | Dummy vulnerability description for testing purposes. This is a sample vulnerability entry used in test data. | 0.05 | 50.0 | false |
>| CVE-XXXX-2222 | Another dummy vulnerability description for testing. This entry is used to validate the library response handling. | 0.02 | 30.0 | false |

### contrastsecurity-incident-observation-list

***
List Contrast Security incident Observations with provided filters.

#### Base Command

`contrastsecurity-incident-observation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident. | Required |
| page_size | Number of results to return per page. Maximum value is 1000. Default is 10. | Optional |
| sort_by | Specify the field used to sort the Observations. Possible values are: http_source_ip, http_route, rule_id, service_name, server_name, event_time, attack_event_result, attack_event_value. | Optional |
| sort_order | Specify the order used to sort the Observations. Possible values are: Asc, Desc. Default is Asc. | Optional |
| next_page_cursor | Cursor token to get the next page of Observations. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Observations.observationId | String | Unique identifier of the observation. |
| ContrastSecurity.Observations.observationOrigin | String | Origin of the observation \(VULNERABILITY, ATTACK_EVENT, etc.\). |
| ContrastSecurity.Observations.title | String | Title of the observation. |
| ContrastSecurity.Observations.httpSourceIp | String | Source IP of the HTTP request. |
| ContrastSecurity.Observations.result | String | Result of the observation \(e.g., EXPLOITED, NOT_EXPLOITED\). |
| ContrastSecurity.Observations.issueId | String | Associated issue ID. |
| ContrastSecurity.Observations.httpRoute | String | HTTP route where the observation was detected. |
| ContrastSecurity.Observations.attackValue | String | Attack payload value. |
| ContrastSecurity.Observations.dataType | String | Type of observation data \(ATTACK, LIBRARY, VULNERABILITY, etc.\). |
| ContrastSecurity.Observations.ruleId | String | Rule ID associated with the observation. |
| ContrastSecurity.Observations.ruleName | String | Rule name associated with the observation. |
| ContrastSecurity.Observations.detectedTime | Date | Timestamp when the observation was detected. |
| ContrastSecurity.Observations.severity | String | Severity level of the observation \(CRITICAL, HIGH, MEDIUM, LOW\). |
| ContrastSecurity.Observations.score | Number | Risk score of the observation. |
| ContrastSecurity.Observations.applicationId | String | Application ID where the observation was detected. |
| ContrastSecurity.Observations.applicationName | String | Application name where the observation was detected. |
| ContrastSecurity.Observations.applicationLanguage | String | Programming language of the affected application. |
| ContrastSecurity.Observations.serverId | String | Server ID where the observation was detected. |
| ContrastSecurity.Observations.serverName | String | Server name where the observation was detected. |
| ContrastSecurity.Observations.serviceInstanceId | String | Service instance ID. |
| ContrastSecurity.Observations.serviceVersion | String | Version of the service. |
| ContrastSecurity.Observations.deploymentTier | String | Deployment tier of the application \(DEVELOPMENT, PRODUCTION, etc.\). |

#### Command example

```!contrastsecurity-incident-observation-list incident_id=INC-2026-253 page_size=50 sort_by=event_time sort_order=Desc```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Observations": [
            {
                "observationId": "A-D-11111111-2222-3333-4444-555555555555-1234567890",
                "observationOrigin": "ATTACK_EVENT",
                "dataType": "ATTACK",
                "title": "Command Injection on \"/api/test\"",
                "issueId": "ISS-2026-0001",
                "ruleId": "cmd-injection",
                "ruleName": "Command Injection",
                "applicationId": "app-12345678-aaaa-bbbb-cccc-1234567890ab",
                "applicationName": "sample-webhook-service",
                "applicationLanguage": "PYTHON",
                "serverId": "1001",
                "serverName": "sample-server-agent",
                "serviceInstanceId": "instance-1234-abcd-5678-efgh",
                "serviceVersion": "1.0.0",
                "httpRoute": "/api/test",
                "httpSourceIp": "192.168.0.10",
                "deploymentTier": "DEVELOPMENT",
                "score": 9.5,
                "severity": "CRITICAL",
                "detectedTime": "2026-01-01T10:00:00.000Z",
                "result": "EXPLOITED",
                "attackValue": "example.com; malicious_command"
            },
            {
                "observationId": "A-D-66666666-7777-8888-9999-000000000000-1234567891",
                "observationOrigin": "ATTACK_EVENT",
                "dataType": "ATTACK",
                "title": "SQL Injection on \"/api/login\"",
                "issueId": "ISS-2026-0002",
                "ruleId": "sql-injection",
                "ruleName": "SQL Injection",
                "applicationId": "app-87654321-bbbb-cccc-dddd-0987654321ba",
                "applicationName": "sample-auth-service",
                "applicationLanguage": "JAVA",
                "serverId": "1002",
                "serverName": "auth-server-agent",
                "serviceInstanceId": "instance-9876-wxyz-5432-lmnop",
                "serviceVersion": "2.1.0",
                "httpRoute": "/api/login",
                "httpSourceIp": "192.168.0.20",
                "deploymentTier": "DEVELOPMENT",
                "score": 8.7,
                "severity": "HIGH",
                "detectedTime": "2026-01-02T12:30:00.000Z",
                "result": "EXPLOITED",
                "attackValue": "' OR '1'='1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Contrast Security Incident Observations
>
>|Observation ID|Title|Source IP|Result|Associated Issue ID|URL|Attack Value|Data Type|Rule ID|Rule Name|Detected At|Severity|Score|Application ID|Application Name|Application Language|Server ID|Server Name|Server Instance ID|Deployment Tier|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [A-D-11111111-2222-3333-4444-555555555555-1234567890](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-11111111-2222-3333-4444-555555555555-1234567890) | Command Injection on "/api/test" | 192.168.0.10 | EXPLOITED | [ISS-2026-0001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-0001) | /api/test | example.com; malicious_command | ATTACK | cmd-injection | Command Injection | 2026-01-01T10:00:00.000Z | CRITICAL | 9.5 | app-12345678-aaaa-bbbb-cccc-1234567890ab | sample-webhook-service | PYTHON | 1001 | sample-server-agent | instance-1234-abcd-5678-efgh | DEVELOPMENT |
>| [A-D-66666666-7777-8888-9999-000000000000-1234567891](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-66666666-7777-8888-9999-000000000000-1234567891) | SQL Injection on "/api/login" | 192.168.0.20 | EXPLOITED | [ISS-2026-0002](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-0002) | /api/login | ' OR '1'='1 | ATTACK | sql-injection | SQL Injection | 2026-01-02T12:30:00.000Z | HIGH | 8.7 | app-87654321-bbbb-cccc-dddd-0987654321ba | sample-auth-service | JAVA | 1002 | auth-server-agent | instance-9876-wxyz-5432-lmnop | DEVELOPMENT |
>
>**To Get Next page Observations:** sort_by=`event_time` sort_order=`Desc` next_page_cursor=`test_next_page_cursor`
