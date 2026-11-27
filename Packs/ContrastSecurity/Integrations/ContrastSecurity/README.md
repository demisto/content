Use the Contrast Security integration to fetch Incidents and Issues. This integration also provides commands to manage Incidents, Issues, Observations, IP blocks, and ADR rules.

### Authorization

The Contrast Security username, API key, service key, and organization ID can be found in the Contrast Security platform by clicking on the profile icon.

## Configure Contrast Security in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Contrast Security Server URL | Server URL of the Contrast Security platform. | True |
| Contrast Security Username (Email) | Username used for Contrast Security platform. Email address is used as the username for Contrast Security platform. | True |
| Contrast Security Service Key | Service key used for Contrast Security platform. | True |
| Contrast Security API Key | API key used for secure communication with Contrast Security platform. | True |
| Contrast Security Organization ID | The organization ID used for the Contrast Security platform. | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Event Type | Select the event type to fetch from Contrast Security platform. Contrast Security recommends selecting "Contrast Incident" as the event type to fetch. | False |
| First Fetch Time | The date or relative timestamp from which to begin fetching Contrast Security Incidents and Issues. Default is 3 days.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-01T14:05:44Z. | False |
| Max Fetch | The maximum number of Contrast Security Incidents or Issues to fetch per run. Default is 25.<br/><br/>Note: The maximum value is 200. | False |
| Incident Statuses | Select Contrast Security Incident statuses to fetch as incidents. Default is Open.<br/><br/>Note: Applies only when Event Type is set to "Contrast Incident". | False |
| Incident Severity Levels | Select Contrast Security Incident severity levels to fetch as incidents. Default is all.<br/><br/>Note: Applies only when Event Type is set to "Contrast Incident". | False |
| Issue Statuses | Select Contrast Security Issue statuses to fetch as incidents. Default is Open.<br/><br/>Note: Applies only when Event Type is set to "Contrast Issue". | False |
| Issue Severity Levels | Select Contrast Security Issue severity levels to fetch as incidents. Default is all.<br/><br/>Note: Applies only when Event Type is set to "Contrast Issue". | False |
| Incident Mirroring Direction | The mirroring direction in which to mirror the incident details. | False |
| Issue Mirroring Direction | The mirroring direction in which to mirror the Issue details. | False |
| Mirror Tag for Notes | Tag value used to mirror Cortex XSOAR notes back to Contrast Security as issue or incident comments. | False |
| Reopen Incident in XSOAR When Status Changes to 'Open' in Contrast Security Incident | If selected, closed incidents will be reopened in Cortex XSOAR when the incident status in Contrast Security Incident changes to 'Open'.<br/><br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. | False |
| Close Incident in XSOAR When Status Changes to 'Closed' in Contrast Security Incident | If selected, active incidents will be closed in Cortex XSOAR when the incident status in Contrast Security Incident changes to 'Closed'.<br/><br/>Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'. | False |
| Incidents Fetch Interval |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

**Notes for mirroring:**

- This feature is compliant with Cortex XSOAR version 6.0 and above.
- When an incident status is active in Cortex XSOAR, it will be mapped with an open status in the Contrast Security incident. When a Cortex XSOAR incident is closed, it will be mapped with a closed status in the Contrast Security incident with provided closing notes.
- New notes added to Cortex XSOAR incidents with the provided mirroring tag will be created as comments in the Contrast Security incident.
- When mirroring is set to 'Incoming' or 'Incoming and Outgoing', all the Contrast Security incident fields are updated in the Cortex XSOAR incident.
- When a Contrast Security incident is closed, the Cortex XSOAR incident is closed with the following close reason mapping:

  | Contrast Security Close Reason | Cortex XSOAR Close Reason |
  | --- | --- |
  | TRUE_POSITIVE | Resolved |
  | TRUE_POSITIVE_BENIGN | Resolved |
  | FALSE_POSITIVE | False Positive |
  | OTHER | Other |

- When a Cortex XSOAR incident is closed, the Contrast Security incident is closed with the following close reason mapping:

  | Cortex XSOAR Close Reason | Contrast Security Close Reason |
  | --- | --- |
  | Resolved | TRUE_POSITIVE |
  | False Positive | FALSE_POSITIVE |
  | Duplicate | OTHER |
  | Other or any other value | OTHER |

- Comments added in Contrast Security are not mirrored into Cortex XSOAR.
- Up to 5000 modified incidents are mirrored in each mirroring run.
- When an Incident status is changed in Cortex XSOAR, the status will be synchronized with the corresponding Contrast Security Issue.
- New notes added to Cortex XSOAR incidents will be created as comments in the Contrast Security Issue with the provided mirroring tag.
- Incident status changes in Cortex XSOAR (Open/Closed) will be reflected in the Contrast Security Issue.
- **Reopen Incident in XSOAR When Status Changes to 'Open' in Contrast Security Incident:** If selected, a closed Cortex XSOAR incident is reopened when its Contrast Security incident is reopened (status changes to 'Open'). Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'.
- **Close Incident in XSOAR When Status Changes to 'Closed' in Contrast Security Incident:** If selected, an active Cortex XSOAR incident is closed when its Contrast Security incident is closed (status changes to 'Closed'). Note: This parameter is only used when the incident mirroring direction is set to 'Incoming' or 'Incoming and Outgoing'.
- Incident mirroring supports multiple directions - 'Incoming', 'Outgoing', and 'Incoming and Outgoing'. However, only 'Outgoing' mirroring is supported for issues. Users can configure only 'Outgoing' mirroring direction for the Issue Mirroring Direction parameter.
- The following fields are mirroring parameters that need to be configured in the integration instance:
  - **Incident Mirroring Direction:** This field determines the mirroring direction for the incident. It is a required field for Cortex XSOAR to enable mirroring support. Possible values are "Incoming", "Outgoing", and "Incoming and Outgoing".
  - **Issue Mirroring Direction:** This field determines the mirroring direction for the issue. It is a required field for Cortex XSOAR to enable mirroring support. Possible values are "Outgoing".
  - **Mirror Tag for Notes:** This field determines the tag for notes. It is a required field for Cortex XSOAR to enable mirroring support.

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
| ContrastSecurity.IncidentComment.incidentId | String | The ID of the incident the comment was added to. |
| ContrastSecurity.IncidentComment.commentId | String | The unique identifier of the comment. |
| ContrastSecurity.IncidentComment.userId | String | The unique identifier of the user who made the comment. |
| ContrastSecurity.IncidentComment.userUid | String | The email address of the user who made the comment. |
| ContrastSecurity.IncidentComment.commentText | String | The actual comment text content. |
| ContrastSecurity.IncidentComment.createdTime | Date | The timestamp when the comment was created. |
| ContrastSecurity.IncidentComment.updatedTime | Date | The timestamp when the comment was last updated. |

#### Command example

```!contrastsecurity-incident-comment-add comment="this is comment from xsoar" incident_id=INC-2026-001```

#### Context Example

```json
{
    "ContrastSecurity": {
        "IncidentComment": {
            "incidentId": "INC-2026-001",
            "commentId": "12345678-1234-1234-1234-123456789abc",
            "userId": "87654321-4321-4321-4321-cba987654321",
            "userUid": "test.comment@contrastsecurity.com",
            "commentText": "this is comment from xsoar",
            "createdTime": "2026-04-06T05:22:41.602411286Z"
        }
    }
}
```

#### Human Readable Output

>### Comment added to Incident [INC-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/incidents/INC-2026-001)
>
>|Comment ID|User UID|Comment Text|Created At|
>|---|---|---|---|
>| 12345678\-1234\-1234\-1234\-123456789abc | test.comment@contrastsecurity.com | this is comment from xsoar | 2026\-04\-06T05:22:41.602411286Z |

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
| ContrastSecurity.Incident.incidentId | String | The unique identifier of the incident. |
| ContrastSecurity.Incident.incidentName | String | The name of the incident. |
| ContrastSecurity.Incident.status | String | The status of the incident. |
| ContrastSecurity.Incident.severity | String | The severity of the incident. |
| ContrastSecurity.Incident.score | Number | The Contrast score of the incident. |
| ContrastSecurity.Incident.createdTime | Date | The time when the incident was created. |
| ContrastSecurity.Incident.updatedTime | Date | The time when the incident was last updated. |
| ContrastSecurity.Incident.closedTime | Date | The time when the incident was closed. |
| ContrastSecurity.Incident.closedReason | String | The reason for closing the incident. |
| ContrastSecurity.Incident.observationCount | Number | The number of observations in the incident. |
| ContrastSecurity.Incident.organizationId | String | The ID of the organization the incident belongs to. |
| ContrastSecurity.Incident.url | String | The URL of the incident in the Contrast Security platform. |

#### Command example

```!contrastsecurity-incident-status-update incident_id=INC-2026-001 status=Closed close_reason="True Positive"```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Incident": {
            "incidentId": "INC-2026-001",
            "incidentName": "SQL Injection attack on /payments",
            "status": "CLOSED",
            "severity": "CRITICAL",
            "score": 10.0,
            "createdTime": "2026-03-18T11:47:02Z",
            "updatedTime": "2026-03-20T05:41:36Z",
            "closedTime": "2026-03-20T05:41:36Z",
            "closedReason": "TRUE_POSITIVE",
            "observationCount": 3,
            "organizationId": "test-org-id",
            "url": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/incidents/INC-2026-001"
        }
    }
}
```

#### Human Readable Output

>### Incident status updated successfully
>
>|Incident ID|Status|Close Reason|
>|---|---|---|
>| [INC-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/incidents/INC-2026-001) | Closed | True Positive |

### contrastsecurity-ip-block

***
Block an IP address by creating an organization-level IP policy in Contrast Security.

#### Base Command

`contrastsecurity-ip-block`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | Specify the IP address to block. | Required |
| policy_name_prefix | Specify the prefix for the IP policy name. The IP policy is created with the name in the format &lt;policy_name_prefix&gt; - &lt;ip_address&gt;. Default is XSOAR. | Optional |
| expiration_date | Specify the IP address expiration duration time. If no expiration date is provided, the IP address will be blocked forever.<br/><br/> Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 May 2025 04:45:33, 2025-05-17T14:05:44Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.IPPolicy.uuid | String | The unique identifier of the IP policy. |
| ContrastSecurity.IPPolicy.ip | String | The blocked IP address. |
| ContrastSecurity.IPPolicy.name | String | The name of the IP policy. |
| ContrastSecurity.IPPolicy.trusted | Boolean | Whether the IP address is trusted. False indicates that traffic from the IP address is blocked. |
| ContrastSecurity.IPPolicy.expirationTime | Date | The time when the IP policy expires and the block is lifted. Not present when the IP address is blocked forever. |
| ContrastSecurity.IPPolicy.environments.development | Boolean | Whether the IP policy is enforced in the development environment. |
| ContrastSecurity.IPPolicy.environments.qa | Boolean | Whether the IP policy is enforced in the QA environment. |
| ContrastSecurity.IPPolicy.environments.production | Boolean | Whether the IP policy is enforced in the production environment. |

#### Command example

```!contrastsecurity-ip-block ip_address=198.51.100.1 policy_name_prefix=INC-2026-80 expiration_date="2 days"```

#### Context Example

```json
{
    "ContrastSecurity": {
        "IPPolicy": {
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "ip": "198.51.100.1",
            "name": "INC-2026-80 - 198.51.100.1",
            "trusted": false,
            "expirationTime": "2026-12-31T00:00:00Z",
            "environments": {
                "development": true,
                "qa": true,
                "production": true
            }
        }
    }
}
```

#### Human Readable Output

>### IP address blocked successfully
>
>|Policy ID|Policy Name|Blocked IP|Expiration Date|
>|---|---|---|---|
>| 12345678\-1234\-1234\-1234\-123456789abc | INC\-2026\-80 \- 198.51.100.1 | 198.51.100.1 | 2026\-12\-31T00:00:00Z |

### contrastsecurity-adr-rule-update

***
Update the modes of an ADR rule for a Contrast Security application.

Note: At least one of the dev_mode, qa_mode or prod_mode arguments must be provided.

#### Base Command

`contrastsecurity-adr-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | Specify the ID of the application.<br/><br/>Note: The application ID is available in the Contrast Security Applications field of the incident. | Required |
| rule_id | Specify the ID of the rule to update.<br/><br/>Note: The rule ID is available in the Contrast Security Rules field of the incident. | Required |
| dev_mode | Specify the mode for the development environment.<br/><br/>Note: If not provided, the current mode of the rule for the development environment is retained. Possible values are: Off, Monitor, Block, Block at perimeter, Monitor at perimeter. | Optional |
| qa_mode | Specify the mode for the QA environment.<br/><br/>Note: If not provided, the current mode of the rule for the QA environment is retained. Possible values are: Off, Monitor, Block, Block at perimeter, Monitor at perimeter. | Optional |
| prod_mode | Specify the mode for the production environment.<br/><br/>Note: If not provided, the current mode of the rule for the production environment is retained. Possible values are: Off, Monitor, Block, Block at perimeter, Monitor at perimeter. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.AdrRule.applicationId | String | The ID of the application. |
| ContrastSecurity.AdrRule.ruleId | String | The ID of the ADR rule. |
| ContrastSecurity.AdrRule.ruleName | String | The name of the ADR rule. |
| ContrastSecurity.AdrRule.ruleDescription | String | The description of the ADR rule. |
| ContrastSecurity.AdrRule.devMode | String | The updated mode of the ADR rule for the development environment. |
| ContrastSecurity.AdrRule.qaMode | String | The updated mode of the ADR rule for the QA environment. |
| ContrastSecurity.AdrRule.prodMode | String | The updated mode of the ADR rule for the production environment. |
| ContrastSecurity.AdrRule.canBlock | Boolean | Whether the ADR rule supports the Block mode. |
| ContrastSecurity.AdrRule.canBlockAtPerimeter | Boolean | Whether the ADR rule supports the Block at perimeter mode. |
| ContrastSecurity.AdrRule.isMonitorAtPerimeter | Boolean | Whether the ADR rule supports the Monitor at perimeter mode. |

#### Command example

```!contrastsecurity-adr-rule-update application_id=12345678-1234-1234-1234-123456789012 rule_id=path-traversal dev_mode="Monitor" qa_mode="Block at perimeter" prod_mode="Monitor"```

#### Context Example

```json
{
    "ContrastSecurity": {
        "AdrRule": {
            "applicationId": "12345678-1234-1234-1234-123456789012",
            "canBlock": true,
            "canBlockAtPerimeter": true,
            "devMode": "MONITOR",
            "isMonitorAtPerimeter": false,
            "prodMode": "MONITOR",
            "qaMode": "BLOCK_AT_PERIMETER",
            "ruleDescription": "A vulnerability that allows users to control which files get opened and read by an application.",
            "ruleId": "path-traversal",
            "ruleName": "Path Traversal"
        }
    }
}
```

#### Human Readable Output

>### ADR rule updated successfully
>
>|Application ID|Rule ID|Rule Name|Rule Description|Development Mode|QA Mode|Production Mode|
>|---|---|---|---|---|---|---|
>| 12345678\-1234\-1234\-1234\-123456789012 | path\-traversal | Path Traversal | A vulnerability that allows users to control which files get opened and read by an application. | Monitor | Block at perimeter | Monitor |

### contrastsecurity-issue-list

***
List Contrast Security Issues with provided filter parameters.

#### Base Command

`contrastsecurity-issue-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident to retrieve issues for a specific incident. If not provided, retrieves all issues. When provided, only page_size and next_page_cursor are applied. | Optional |
| statuses | Filter the Issues by status. Supports comma-separated values. Not applied when incident_id is provided. Possible values are: Open, Closed. | Optional |
| severities | Filter the Issues by severity. Supports comma-separated values. Not applied when incident_id is provided. Possible values are: Critical, High, Medium, Low, Note. | Optional |
| application_ids | Filter the Issues by application ID. Supports comma-separated values. Not applied when incident_id is provided. | Optional |
| repository_ids | Filter the Issues by repository ID. Supports comma-separated values. Not applied when incident_id is provided. | Optional |
| created_after | Filter the Issues created on or after the specified time. Not applied when incident_id is provided.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-01T14:05:44Z. | Optional |
| created_before | Filter the Issues created on or before the specified time. Not applied when incident_id is provided.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-01T14:05:44Z. | Optional |
| modified_after | Filter the Issues last updated on or after the specified time. Not applied when incident_id is provided.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-01T14:05:44Z. | Optional |
| modified_before | Filter the Issues last updated on or before the specified time. Not applied when incident_id is provided.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-01T14:05:44Z. | Optional |
| page_size | Number of results to return per page. Maximum value is 200. Default is 50. | Optional |
| next_page_cursor | Cursor token to get the next page of Issues. Use the cursor returned in the previous response with the same filters and sort. | Optional |
| sort_by | Specify the field used to sort the Issues. Not applied when incident_id is provided. Possible values are: created_at, updated_at. | Optional |
| sort_order | Specify the order used to sort the Issues. Not applied when incident_id is provided. Possible values are: Asc, Desc. Default is Asc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Issue.issueId | String | The unique identifier of the issue. |
| ContrastSecurity.Issue.status | String | The status of the issue. |
| ContrastSecurity.Issue.severity | String | The severity of the issue. |
| ContrastSecurity.Issue.dataTypes | String | The data types of the issue \(e.g., VULNERABILITY, ATTACK, BEHAVIOR\). |
| ContrastSecurity.Issue.targets | String | The targets of the issue \(e.g., CODE, LIBRARY\). |
| ContrastSecurity.Issue.sensors | String | The sensors that detected the issue \(e.g., CONTRAST_AGENT\). |
| ContrastSecurity.Issue.techniques | String | The techniques used to detect the issue \(e.g., RUNTIME\). |
| ContrastSecurity.Issue.incidentCount | Number | The number of incidents related to the issue. |
| ContrastSecurity.Issue.observationCount | Number | The number of observations of the issue. |
| ContrastSecurity.Issue.createdTime | Date | The time when the issue was created. |
| ContrastSecurity.Issue.updatedTime | Date | The time when the issue was last updated. |
| ContrastSecurity.Issue.applicationId | String | The ID of the application the issue belongs to. |
| ContrastSecurity.Issue.applicationLanguage | String | The programming language of the application. |
| ContrastSecurity.Issue.applicationName | String | The name of the application the issue belongs to. |
| ContrastSecurity.Issue.closedTime | Date | The time when the issue was closed. |
| ContrastSecurity.Issue.environments | String | The environments where the issue was observed. |
| ContrastSecurity.Issue.httpRoute | String | The HTTP route where the issue was found. |
| ContrastSecurity.Issue.lastAttackedTime | Date | The time when the issue was last attacked. |
| ContrastSecurity.Issue.lastObservedTime | Date | The time when the issue was last observed. |
| ContrastSecurity.Issue.repositoryId | String | The ID of the repository the issue belongs to. |
| ContrastSecurity.Issue.repositoryName | String | The name of the repository the issue belongs to. |
| ContrastSecurity.Issue.score | Number | The Contrast score of the issue. |
| ContrastSecurity.Issue.title | String | The title of the issue. |
| ContrastSecurity.Issue.issueLink | String | The direct link to the issue in the Contrast Security platform. |
| ContrastSecurity.Issue.applicationLink | String | The direct link to the application in the Contrast Security platform. |
| ContrastSecurity.PageToken.Issue.next_page_cursor | String | The cursor to retrieve the next page of issues. |
| ContrastSecurity.PageToken.Issue.name | String | The name of the command. |
| ContrastSecurity.PageToken.Issue.has_next_page | Boolean | Whether there is a next page of issues. |

#### Command example

```!contrastsecurity-issue-list page_size=2 statuses=Open severities=High```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Issue": [
            {
                "issueId": "ISS-2026-001",
                "status": "OPEN",
                "severity": "HIGH",
                "dataTypes": [
                    "VULNERABILITY"
                ],
                "targets": [
                    "LIBRARY"
                ],
                "sensors": [
                    "CONTRAST_AGENT"
                ],
                "techniques": [
                    "RUNTIME"
                ],
                "incidentCount": 0,
                "observationCount": 40,
                "createdTime": "2026-07-16T23:42:33.205Z",
                "updatedTime": "2026-10-22T16:13:04.763Z",
                "applicationId": "12345678-1234-1234-1234-123456789abc",
                "applicationName": "sample-cargocats-dataservice",
                "environments": [
                    "QA"
                ],
                "httpRoute": "",
                "lastObservedTime": "2026-10-22T16:13:04.527Z",
                "repositoryId": "",
                "score": 8.9,
                "title": "CVEs in tomcat-embed-websocket 10.1.41",
                "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001",
                "applicationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=12345678-1234-1234-1234-123456789abc"
            },
            {
                "issueId": "ISS-2026-002",
                "status": "OPEN",
                "severity": "HIGH",
                "dataTypes": [
                    "VULNERABILITY",
                    "BEHAVIOR"
                ],
                "targets": [
                    "LIBRARY"
                ],
                "sensors": [
                    "CONTRAST_AGENT"
                ],
                "techniques": [
                    "RUNTIME"
                ],
                "incidentCount": 0,
                "observationCount": 52,
                "createdTime": "2026-07-16T23:42:15.777Z",
                "updatedTime": "2026-10-22T16:11:38.959Z",
                "applicationId": "87654321-4321-4321-4321-cba987654321",
                "applicationName": "sample-cargocats-frontgateservice",
                "environments": [
                    "QA"
                ],
                "httpRoute": "",
                "lastObservedTime": "2026-10-22T16:11:38.621Z",
                "repositoryId": "",
                "score": 8.5,
                "title": "CVEs in log4j-slf4j-impl 2.14.1",
                "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-002",
                "applicationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=87654321-4321-4321-4321-cba987654321"
            }
        ],
        "PageToken": {
            "Issue": {
                "next_page_cursor": "test-next-page-cursor",
                "name": "contrastsecurity-issue-list",
                "has_next_page": true
            }
        }
    }
}
```

#### Human Readable Output

>### Contrast Security Issues
>
>|Severity|Contrast Score|Issue|Issue ID|Status|Application Name|Application ID|Number of Observations|Last Detected|Environments|
>|---|---|---|---|---|---|---|---|---|---|
>| High | 8.9 | CVEs in tomcat\-embed\-websocket 10.1.41 | [ISS-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001) | Open | [sample-cargocats-dataservice](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=12345678-1234-1234-1234-123456789abc) | 12345678\-1234\-1234\-1234\-123456789abc | 40 | 2026\-10\-22T16:13:04.527Z | QA |
>| High | 8.5 | CVEs in log4j\-slf4j\-impl 2.14.1 | [ISS-2026-002](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-002) | Open | [sample-cargocats-frontgateservice](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=87654321-4321-4321-4321-cba987654321) | 87654321\-4321\-4321\-4321\-cba987654321 | 52 | 2026\-10\-22T16:11:38.621Z | QA |
>
>To retrieve the next set of results, run the command with the same filters and **next_page_cursor** = `test-next-page-cursor`.

### contrastsecurity-issue-get

***
Get a specific Contrast Security Issue by ID.

#### Base Command

`contrastsecurity-issue-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Specify the ID of the Issue.<br/><br/>Note: Use contrastsecurity-issue-list to retrieve the Issue ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Issue.issueId | String | The unique identifier of the issue. |
| ContrastSecurity.Issue.title | String | The title of the issue. |
| ContrastSecurity.Issue.status | String | The status of the issue. |
| ContrastSecurity.Issue.severity | String | The severity of the issue. |
| ContrastSecurity.Issue.score | Number | The Contrast score of the issue. |
| ContrastSecurity.Issue.description | String | The description of the issue. |
| ContrastSecurity.Issue.recommendation | String | The recommendation to fix the issue. |
| ContrastSecurity.Issue.runbookUrl | String | The URL of the runbook to fix the issue. |
| ContrastSecurity.Issue.cves.id | String | The ID of the CVE related to the issue. |
| ContrastSecurity.Issue.cves.url | String | The URL of the CVE related to the issue. |
| ContrastSecurity.Issue.ruleId | String | The ID of the rule that detected the issue. |
| ContrastSecurity.Issue.ruleName | String | The name of the rule that detected the issue. |
| ContrastSecurity.Issue.dataTypes | String | The data types of the issue \(e.g., VULNERABILITY, ATTACK, BEHAVIOR\). |
| ContrastSecurity.Issue.targets | String | The targets of the issue \(e.g., CODE, LIBRARY\). |
| ContrastSecurity.Issue.sensors | String | The sensors that detected the issue \(e.g., CONTRAST_AGENT\). |
| ContrastSecurity.Issue.techniques | String | The techniques used to detect the issue \(e.g., RUNTIME\). |
| ContrastSecurity.Issue.applicationId | String | The ID of the application the issue belongs to. |
| ContrastSecurity.Issue.applicationName | String | The name of the application the issue belongs to. |
| ContrastSecurity.Issue.applicationLanguage | String | The programming language of the application. |
| ContrastSecurity.Issue.repositoryId | String | The ID of the repository the issue belongs to. |
| ContrastSecurity.Issue.repositoryName | String | The name of the repository the issue belongs to. |
| ContrastSecurity.Issue.httpRoute | String | The HTTP route where the issue was found. |
| ContrastSecurity.Issue.environments | String | The environments where the issue was observed. |
| ContrastSecurity.Issue.cwes | Unknown | The CWEs related to the issue. |
| ContrastSecurity.Issue.risk | Unknown | The risk details of the issue. |
| ContrastSecurity.Issue.codeLocations | Unknown | The code locations where the issue was found. |
| ContrastSecurity.Issue.incidentCount | Number | The number of incidents related to the issue. |
| ContrastSecurity.Issue.observationCount | Number | The number of observations of the issue. |
| ContrastSecurity.Issue.attackCount | Number | The number of attacks detected for the issue. |
| ContrastSecurity.Issue.exploitedAttackCount | Number | The number of exploited attacks for the issue. |
| ContrastSecurity.Issue.suspiciousAttackCount | Number | The number of suspicious attacks for the issue. |
| ContrastSecurity.Issue.blockedAttackCount | Number | The number of blocked attacks for the issue. |
| ContrastSecurity.Issue.createdTime | Date | The time when the issue was created. |
| ContrastSecurity.Issue.updatedTime | Date | The time when the issue was last updated. |
| ContrastSecurity.Issue.closedTime | Date | The time when the issue was closed. |
| ContrastSecurity.Issue.lastAttackedTime | Date | The time when the issue was last attacked. |
| ContrastSecurity.Issue.lastObservedTime | Date | The time when the issue was last observed. |
| ContrastSecurity.Issue.issueLink | String | The direct link to the issue in the Contrast Security platform. |
| ContrastSecurity.Issue.applicationLink | String | The direct link to the application in the Contrast Security platform. |

#### Command example

```!contrastsecurity-issue-get issue_id=ISS-2026-001```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Issue": {
            "issueId": "ISS-2026-001",
            "status": "OPEN",
            "severity": "HIGH",
            "dataTypes": [
                "VULNERABILITY"
            ],
            "targets": [
                "LIBRARY"
            ],
            "sensors": [
                "CONTRAST_AGENT"
            ],
            "techniques": [
                "RUNTIME"
            ],
            "incidentCount": 0,
            "observationCount": 40,
            "createdTime": "2026-07-16T23:42:33.205Z",
            "updatedTime": "2026-10-22T16:13:04.763Z",
            "ruleId": "library-vulnerability",
            "ruleName": "Library CVEs",
            "attackCount": 0,
            "exploitedAttackCount": 0,
            "suspiciousAttackCount": 0,
            "blockedAttackCount": 0,
            "applicationId": "12345678-1234-1234-1234-123456789abc",
            "applicationName": "sample-cargocats-dataservice",
            "cves": [
                {
                    "id": "CVE-2026-0001",
                    "url": "https://test.nvd.com/vuln/detail/CVE-2026-0001"
                },
                {
                    "id": "CVE-2026-0002",
                    "url": "https://test.nvd.com/vuln/detail/CVE-2026-0002"
                }
            ],
            "description": "We analyzed the full library dependency tree from this root library and discovered 2 vulnerabilities.\n\nCVE-2026-0001 | MEDIUM | Score: 6.6 | tomcat-embed-core 10.1.41\n\nCVE-2026-0002 | HIGH | Score: 7.6 | tomcat-embed-core 10.1.41",
            "environments": [
                "QA"
            ],
            "httpRoute": "",
            "lastObservedTime": "2026-10-22T16:13:04.527Z",
            "recommendation": "Please contact the library owner to fix this vulnerability.",
            "repositoryId": "",
            "score": 8.9,
            "title": "CVEs in tomcat-embed-websocket 10.1.41",
            "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001",
            "applicationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=12345678-1234-1234-1234-123456789abc"
        }
    }
}
```

#### Human Readable Output

>### Contrast Security Issue
>
>|Issue ID|Issue|Description|Recommendation|Status|Severity|Contrast Score|Rule ID|Rule|CVEs|Application Name|Application ID|Environments|Data Types|Targets|Sensors|Techniques|Incident Count|Number of Observations|Attack Count|Blocked Attack Count|Exploited Attack Count|Suspicious Attack Count|Created|Updated|Last Detected|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [ISS-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001) | CVEs in tomcat\-embed\-websocket 10.1.41 | We analyzed the full library dependency tree from this root library and discovered 2 vulnerabilities.<br><br>CVE\-2026\-0001 \| MEDIUM \| Score: 6.6 \| tomcat\-embed\-core 10.1.41<br><br>CVE\-2026\-0002 \| HIGH \| Score: 7.6 \| tomcat\-embed\-core 10.1.41 | Please contact the library owner to fix this vulnerability. | Open | High | 8.9 | library\-vulnerability | Library CVEs | CVE\-2026\-0001, CVE\-2026\-0002 | [sample-cargocats-dataservice](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=12345678-1234-1234-1234-123456789abc) | 12345678\-1234\-1234\-1234\-123456789abc | QA | VULNERABILITY | LIBRARY | CONTRAST\_AGENT | RUNTIME | 0 | 40 | 0 | 0 | 0 | 0 | 2026\-07\-16T23:42:33.205Z | 2026\-10\-22T16:13:04.763Z | 2026\-10\-22T16:13:04.527Z |

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
| ContrastSecurity.IssueComment.issueId | String | The ID of the issue the comment was added to. |
| ContrastSecurity.IssueComment.commentId | String | The unique identifier of the comment. |
| ContrastSecurity.IssueComment.userId | String | The unique identifier of the user who made the comment. |
| ContrastSecurity.IssueComment.userUid | String | The email address of the user who made the comment. |
| ContrastSecurity.IssueComment.commentText | String | The actual comment text content. |
| ContrastSecurity.IssueComment.createdTime | Date | The timestamp when the comment was created. |
| ContrastSecurity.IssueComment.updatedTime | Date | The timestamp when the comment was last updated. |

#### Command example

```!contrastsecurity-issue-comment-add comment="this is test comment for issue" issue_id=ISS-2026-001```

#### Context Example

```json
{
    "ContrastSecurity": {
        "IssueComment": {
            "issueId": "ISS-2026-001",
            "commentId": "12345678-1234-1234-1234-123456789abc",
            "userId": "87654321-4321-4321-4321-cba987654321",
            "userUid": "test.comment@contrastsecurity.com",
            "commentText": "this is test comment for issue ",
            "createdTime": "2026-04-27T09:23:32.693501406Z"
        }
    }
}
```

#### Human Readable Output

>### Comment added to Issue [ISS-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001)
>
>|Comment ID|User UID|Comment Text|Created At|
>|---|---|---|---|
>| 12345678\-1234\-1234\-1234\-123456789abc | test.comment@contrastsecurity.com | this is test comment for issue  | 2026\-04\-27T09:23:32.693501406Z |

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
| ContrastSecurity.Issue.issueId | String | The unique identifier of the issue. |
| ContrastSecurity.Issue.title | String | The title of the issue. |
| ContrastSecurity.Issue.status | String | The status of the issue. |
| ContrastSecurity.Issue.severity | String | The severity of the issue. |
| ContrastSecurity.Issue.score | Number | The Contrast score of the issue. |
| ContrastSecurity.Issue.applicationId | String | The ID of the application the issue belongs to. |
| ContrastSecurity.Issue.applicationName | String | The name of the application the issue belongs to. |
| ContrastSecurity.Issue.environments | String | The environments where the issue was observed. |
| ContrastSecurity.Issue.incidentCount | Number | The number of incidents related to the issue. |
| ContrastSecurity.Issue.observationCount | Number | The number of observations of the issue. |
| ContrastSecurity.Issue.createdTime | Date | The time when the issue was created. |
| ContrastSecurity.Issue.updatedTime | Date | The time when the issue was last updated. |
| ContrastSecurity.Issue.closedTime | Date | The time when the issue was closed. |
| ContrastSecurity.Issue.lastObservedTime | Date | The time when the issue was last observed. |

#### Command example

```!contrastsecurity-issue-status-update issue_id=ISS-2026-001 status=Closed```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Issue": {
            "issueId": "ISS-2026-001",
            "title": "SQL Injection from \"creditCard\" Parameter on \"/payments\" page",
            "status": "CLOSED",
            "severity": "CRITICAL",
            "score": 10.0,
            "applicationId": "12345678-1234-1234-1234-123456789abc",
            "applicationName": "sample-payments-service",
            "environments": [
                "DEVELOPMENT"
            ],
            "incidentCount": 1,
            "observationCount": 3,
            "createdTime": "2026-03-18T11:47:02Z",
            "updatedTime": "2026-03-20T05:41:36Z",
            "closedTime": "2026-03-20T05:41:36Z",
            "lastObservedTime": "2026-03-18T11:47:02Z"
        }
    }
}
```

#### Human Readable Output

>### Issue status updated successfully
>
>|Issue ID|Status|
>|---|---|
>| [ISS-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001) | Closed |

### contrastsecurity-observation-get

***
Get a specific Contrast Security Observation by ID.

#### Base Command

`contrastsecurity-observation-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| observation_id | Specify the ID of the observation.<br/><br/>Note: Use contrastsecurity-incident-observation-list to retrieve the observation ID. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Observation.observationId | String | The unique identifier of the observation. |
| ContrastSecurity.Observation.organizationId | String | The ID of the organization the observation belongs to. |
| ContrastSecurity.Observation.applicationId | String | The ID of the application where the observation was detected. |
| ContrastSecurity.Observation.issueId | String | The ID of the issue associated with the observation. |
| ContrastSecurity.Observation.dataType | String | The data type of the observation \(e.g., ATTACK, VULNERABILITY, BEHAVIOR\). |
| ContrastSecurity.Observation.target | String | The artifact type targeted by the detection \(e.g., CODE, LIBRARY\). |
| ContrastSecurity.Observation.technique | String | The technique used to detect the observation \(e.g., RUNTIME, STATIC\). |
| ContrastSecurity.Observation.server.id | String | The ID of the server where the observation was detected. |
| ContrastSecurity.Observation.server.name | String | The name of the server where the observation was detected. |
| ContrastSecurity.Observation.application.id | String | The ID of the application where the observation was detected. |
| ContrastSecurity.Observation.application.name | String | The name of the application where the observation was detected. |
| ContrastSecurity.Observation.language | String | The programming language of the application. |
| ContrastSecurity.Observation.sourceIp | String | The source IP address of the request. |
| ContrastSecurity.Observation.result | String | The result of the observation \(e.g., EXPLOITED, EXPOSED, SUSPICIOUS, BLOCKED, BLOCKED_AT_PERIMETER, PROBED\). |
| ContrastSecurity.Observation.ruleId | String | The ID of the rule associated with the observation. |
| ContrastSecurity.Observation.ruleName | String | The name of the rule associated with the observation. |
| ContrastSecurity.Observation.severity | String | The severity of the observation. |
| ContrastSecurity.Observation.detectedTime | Date | The time when the observation was detected. |
| ContrastSecurity.Observation.uiUrl | String | The link to the observation in the Contrast Security UI. |
| ContrastSecurity.Observation.mitreTactics.id | String | The ID of the MITRE ATT&CK tactic associated with the observation. |
| ContrastSecurity.Observation.mitreTactics.name | String | The name of the MITRE ATT&CK tactic associated with the observation. |
| ContrastSecurity.Observation.mitreTactics.url | String | The URL of the MITRE ATT&CK tactic page. |
| ContrastSecurity.Observation.mitreCapec | Unknown | The MITRE CAPEC attack patterns associated with the observation. |
| ContrastSecurity.Observation.environment | String | The environment where the observation was detected \(e.g., DEVELOPMENT, QA, PRODUCTION\). |
| ContrastSecurity.Observation.httpRoute | String | The HTTP route where the observation was detected. |
| ContrastSecurity.Observation.url | String | The URL targeted by the request that triggered the observation. |
| ContrastSecurity.Observation.agentVersion | String | The version of the Contrast agent that recorded the observation. |
| ContrastSecurity.Observation.attackPayload.url | String | The URL targeted by the attack. |
| ContrastSecurity.Observation.attackPayload.value | String | The attack payload value. |
| ContrastSecurity.Observation.virtualPatchUuid | String | The UUID of the virtual patch that handled the observation. |
| ContrastSecurity.Observation.denyListUuid | String | The UUID of the IP deny list policy that triggered the observation. |
| ContrastSecurity.Observation.request.method | String | The HTTP method of the request that triggered the observation. |
| ContrastSecurity.Observation.request.protocol | String | The protocol of the request. |
| ContrastSecurity.Observation.request.protocolVersion | String | The protocol version of the request. |
| ContrastSecurity.Observation.request.headers | Unknown | The headers of the request. |
| ContrastSecurity.Observation.request.parameters | Unknown | The parameters of the request. |
| ContrastSecurity.Observation.request.body | String | The body of the request. |
| ContrastSecurity.Observation.request.queryString | String | The query string of the request. |
| ContrastSecurity.Observation.vectorAnalysis.vectorFields | Unknown | The rule-specific fields of the vector analysis. |
| ContrastSecurity.Observation.vectorAnalysis.callLocation | String | The call location within the application where the vector was detected. |
| ContrastSecurity.Observation.codeLocation.file | String | The source file where the observation was detected. |
| ContrastSecurity.Observation.codeLocation.line | Number | The line number in the source file. |
| ContrastSecurity.Observation.codeLocation.snippet | String | The code snippet at the code location. |
| ContrastSecurity.Observation.applicationMetadata | Unknown | The application metadata key-value pairs. |
| ContrastSecurity.Observation.observationLink | String | The direct link to the observation in the Contrast Security platform. |
| ContrastSecurity.Observation.issueLink | String | The direct link to the associated issue in the Contrast Security platform. |
| ContrastSecurity.Observation.applicationLink | String | The direct link to the application in the Contrast Security platform. |

#### Command example

```!contrastsecurity-observation-get observation_id=A-D-11111111-2222-3333-4444-555555555555-1234567890```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Observation": {
            "observationId": "A-D-11111111-2222-3333-4444-555555555555-1234567890",
            "detectedTime": "2026-10-13T16:28:24.255Z",
            "uiUrl": "https://test.contrast.com/Contrast/cs/index.html#/11111111-aaaa-bbbb-cccc-111111111111/observations/A-D-11111111-2222-3333-4444-555555555555-1234567890",
            "agentVersion": "6.35.1",
            "application": {
                "id": "app-12345678-aaaa-bbbb-cccc-1234567890ab",
                "name": "sample-webhook-service"
            },
            "applicationId": "app-12345678-aaaa-bbbb-cccc-1234567890ab",
            "attackPayload": {
                "url": "http://example.com/login",
                "value": "/bin/sh -c whoami"
            },
            "codeLocation": {
                "file": "java.lang.ProcessImpl"
            },
            "dataType": "ATTACK",
            "environment": "DEVELOPMENT",
            "httpRoute": "/login",
            "issueId": "ISS-2026-0001",
            "language": "JAVA",
            "mitreTactics": [
                {
                    "id": "TA0040",
                    "name": "Impact",
                    "url": "https://attack.mitre.org/tactics/TA0040"
                },
                {
                    "id": "TA0002",
                    "name": "Execution",
                    "url": "https://attack.mitre.org/tactics/TA0002"
                }
            ],
            "organizationId": "11111111-aaaa-bbbb-cccc-111111111111",
            "request": {
                "body": "{\"username\":\"admin\",\"password\":\"password\"}",
                "headers": {
                    "accept": [
                        "*/*"
                    ],
                    "accept-encoding": [
                        "gzip, deflate"
                    ],
                    "content-length": [
                        "42"
                    ],
                    "content-type": [
                        "application/json"
                    ],
                    "Cookie": [
                        "JSESSIONID=SAMPLESESSIONID"
                    ],
                    "host": [
                        "example.com"
                    ],
                    "user-agent": [
                        "python-requests/2.31.0"
                    ],
                    "x-forwarded-host": [
                        "example.com"
                    ],
                    "x-forwarded-port": [
                        "80"
                    ],
                    "x-forwarded-proto": [
                        "http"
                    ],
                    "x-forwarded-scheme": [
                        "http"
                    ],
                    "x-real-ip": [
                        "192.168.0.10"
                    ],
                    "x-request-id": [
                        "sample-request-id"
                    ],
                    "x-scheme": [
                        "http"
                    ]
                },
                "method": "POST",
                "parameters": {
                    "username": [
                        "admin"
                    ],
                    "password": [
                        "contrast-redacted-authentication-info"
                    ]
                },
                "protocol": "http",
                "protocolVersion": "1.1"
            },
            "result": "SUSPICIOUS",
            "ruleId": "cmd-injection",
            "ruleName": "Command Injection",
            "server": {
                "id": "1001",
                "name": "sample-server-agent"
            },
            "severity": "CRITICAL",
            "sourceIp": "192.168.0.10",
            "target": "CODE",
            "technique": "RUNTIME",
            "url": "http://example.com/login",
            "vectorAnalysis": {
                "callLocation": "org.apache.commons.collections4.functors.InvokerTransformer.transform(InvokerTransformer.java:129)",
                "vectorFields": {
                    "command": "/bin/sh -c whoami",
                    "ruleUuid": "cmd-injection"
                }
            },
            "observationLink": "https://test.contrast.com/Contrast/cs/index.html#/11111111-aaaa-bbbb-cccc-111111111111/observations/A-D-11111111-2222-3333-4444-555555555555-1234567890",
            "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-0001",
            "applicationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=app-12345678-aaaa-bbbb-cccc-1234567890ab"
        }
    }
}
```

#### Human Readable Output

>### Observation Information
>
>|Observation ID|Issue ID|Type|Severity|Rule Name|Rule ID|Result|Application Name|Application ID|Application Language|Server|Server ID|Environment|HTTP Route|Target|Technique|MITRE Tactics|Agent Version|Detected|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [A-D-11111111-2222-3333-4444-555555555555-1234567890](https://test.contrast.com/Contrast/cs/index.html#/11111111-aaaa-bbbb-cccc-111111111111/observations/A-D-11111111-2222-3333-4444-555555555555-1234567890) | [ISS-2026-0001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-0001) | Attack | Critical | Command Injection | cmd\-injection | Suspicious | [sample-webhook-service](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=app-12345678-aaaa-bbbb-cccc-1234567890ab) | app\-12345678\-aaaa\-bbbb\-cccc\-1234567890ab | JAVA | sample\-server\-agent | 1001 | DEVELOPMENT | /login | Code | Runtime | Impact, Execution | 6.35.1 | 2026\-10\-13T16:28:24.255Z |
>
>### Attack Value
>
>|Source IP|URL|Attack Payload Value|
>|---|---|---|
>| 192.168.0.10 | http://example.com/login | /bin/sh \-c whoami |
>
>### Vector Analysis
>
>|Vector Fields|Call Location|
>|---|---|
>| command: /bin/sh \-c whoami, ruleUuid: cmd\-injection | org.apache.commons.collections4.functors.InvokerTransformer.transform\(InvokerTransformer.java:129\) |
>
>### Request Details
>
>|Request Details|
>|---|
>| POST /login HTTP/1.1<br>accept: \*/\*<br>accept\-encoding: gzip, deflate<br>content\-length: 42<br>content\-type: application/json<br>Cookie: JSESSIONID=SAMPLESESSIONID<br>host: example.com<br>user\-agent: python\-requests/2.31.0<br>x\-forwarded\-host: example.com<br>x\-forwarded\-port: 80<br>x\-forwarded\-proto: http<br>x\-forwarded\-scheme: http<br>x\-real\-ip: 192.168.0.10<br>x\-request\-id: sample\-request\-id<br>x\-scheme: http<br><br>\{"username":"admin","password":"password"\} |
>
>### Code Location
>
>|File|
>|---|
>| java.lang.ProcessImpl |

### contrastsecurity-incident-observation-list

***
List Contrast Security incident Observations with provided filters.

#### Base Command

`contrastsecurity-incident-observation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Specify the ID of the Incident. | Required |
| page_size | Number of results to return per page. Maximum value is 200. Default is 10. | Optional |
| next_page_cursor | Cursor token to get the next page of Observations. Use the cursor returned in the previous response. | Optional |
| created_after | Filter the Observations detected at or after this time.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-17T14:05:44Z. | Optional |
| created_before | Filter the Observations detected at or before this time.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Oct 2026, 01 Oct 2026 04:45:33, 2026-10-17T14:05:44Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ContrastSecurity.Observation.observationId | String | The unique identifier of the observation. |
| ContrastSecurity.Observation.dataType | String | The data type of the observation \(e.g., ATTACK, VULNERABILITY, BEHAVIOR\). |
| ContrastSecurity.Observation.issueId | String | The ID of the issue associated with the observation. |
| ContrastSecurity.Observation.ruleId | String | The ID of the rule associated with the observation. |
| ContrastSecurity.Observation.ruleName | String | The name of the rule associated with the observation. |
| ContrastSecurity.Observation.severity | String | The severity of the observation. |
| ContrastSecurity.Observation.result | String | The result of the observation \(e.g., EXPLOITED, EXPOSED, SUSPICIOUS, BLOCKED, BLOCKED_AT_PERIMETER, PROBED\). |
| ContrastSecurity.Observation.sourceIp | String | The source IP address of the request. |
| ContrastSecurity.Observation.httpRoute | String | The HTTP route where the observation was detected. |
| ContrastSecurity.Observation.environment | String | The environment where the observation was detected \(e.g., DEVELOPMENT, QA, PRODUCTION\). |
| ContrastSecurity.Observation.language | String | The programming language of the application. |
| ContrastSecurity.Observation.application.id | String | The ID of the application where the observation was detected. |
| ContrastSecurity.Observation.application.name | String | The name of the application where the observation was detected. |
| ContrastSecurity.Observation.server.id | String | The ID of the server where the observation was detected. |
| ContrastSecurity.Observation.server.name | String | The name of the server where the observation was detected. |
| ContrastSecurity.Observation.attackPayload.url | String | The URL targeted by the attack. |
| ContrastSecurity.Observation.attackPayload.value | String | The attack payload value. |
| ContrastSecurity.Observation.detectedTime | Date | The time when the observation was detected. |
| ContrastSecurity.Observation.applicationId | String | The ID of the application where the observation was detected. |
| ContrastSecurity.Observation.organizationId | String | The ID of the organization the observation belongs to. |
| ContrastSecurity.Observation.target | String | The artifact type targeted by the detection \(e.g., CODE, LIBRARY\). |
| ContrastSecurity.Observation.technique | String | The technique used to detect the observation \(e.g., RUNTIME, STATIC\). |
| ContrastSecurity.Observation.mitreTactics.id | String | The ID of the MITRE ATT&CK tactic associated with the observation. |
| ContrastSecurity.Observation.mitreTactics.name | String | The name of the MITRE ATT&CK tactic associated with the observation. |
| ContrastSecurity.Observation.mitreTactics.url | String | The URL of the MITRE ATT&CK tactic page. |
| ContrastSecurity.Observation.observationLink | String | The direct link to the observation in the Contrast Security platform. |
| ContrastSecurity.Observation.issueLink | String | The direct link to the associated issue in the Contrast Security platform. |
| ContrastSecurity.Observation.applicationLink | String | The direct link to the application in the Contrast Security platform. |
| ContrastSecurity.PageToken.Observation.next_page_cursor | String | The cursor to retrieve the next page of observations. |
| ContrastSecurity.PageToken.Observation.name | String | The name of the command. |
| ContrastSecurity.PageToken.Observation.has_next_page | Boolean | Whether there is a next page of observations. |

#### Command example

```!contrastsecurity-incident-observation-list incident_id=INC-2026-1001 page_size=2```

#### Context Example

```json
{
    "ContrastSecurity": {
        "Observation": [
            {
                "observationId": "A-D-11111111-2222-3333-4444-555555555551-1234567890",
                "detectedTime": "2026-10-13T16:28:24.255Z",
                "application": {
                    "id": "12345678-1234-1234-1234-123456789abc",
                    "name": "sample-cargocats-frontgateservice"
                },
                "applicationId": "12345678-1234-1234-1234-123456789abc",
                "dataType": "ATTACK",
                "environment": "DEVELOPMENT",
                "httpRoute": "/login",
                "issueId": "ISS-2026-001",
                "language": "JAVA",
                "mitreTactics": [
                    {
                        "id": "TA0040",
                        "name": "Impact",
                        "url": "https://attack.mitre.org/tactics/TA0040"
                    },
                    {
                        "id": "TA0002",
                        "name": "Execution",
                        "url": "https://attack.mitre.org/tactics/TA0002"
                    }
                ],
                "organizationId": "abcdef12-3456-7890-abcd-ef1234567890",
                "result": "SUSPICIOUS",
                "ruleId": "cmd-injection",
                "ruleName": "Command Injection",
                "server": {
                    "id": "12345",
                    "name": "sample-cargocats-frontgateservice-agent"
                },
                "severity": "CRITICAL",
                "sourceIp": "192.168.0.10",
                "target": "CODE",
                "technique": "RUNTIME",
                "attackPayload": {
                    "url": "https://test-app.example.com/login",
                    "value": "/bin/sh -c : 10; id; whoami"
                },
                "observationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-11111111-2222-3333-4444-555555555551-1234567890",
                "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001",
                "applicationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=12345678-1234-1234-1234-123456789abc"
            },
            {
                "observationId": "A-D-66666666-7777-8888-9999-000000000000-1234567891",
                "detectedTime": "2026-10-13T16:17:57.651Z",
                "application": {
                    "id": "87654321-4321-4321-4321-cba987654321",
                    "name": "sample-cargocats-dataservice"
                },
                "applicationId": "87654321-4321-4321-4321-cba987654321",
                "dataType": "ATTACK",
                "environment": "PRODUCTION",
                "httpRoute": "/payments",
                "issueId": "ISS-2026-002",
                "language": "JAVA",
                "mitreTactics": [
                    {
                        "id": "TA0010",
                        "name": "Exfiltration",
                        "url": "https://attack.mitre.org/tactics/TA0010"
                    },
                    {
                        "id": "TA0009",
                        "name": "Collection",
                        "url": "https://attack.mitre.org/tactics/TA0009"
                    }
                ],
                "organizationId": "abcdef12-3456-7890-abcd-ef1234567890",
                "result": "EXPLOITED",
                "ruleId": "sql-injection",
                "ruleName": "SQL Injection",
                "server": {
                    "id": "67890",
                    "name": "sample-cargocats-dataservice-agent"
                },
                "severity": "HIGH",
                "sourceIp": "192.168.0.20",
                "target": "CODE",
                "technique": "RUNTIME",
                "attackPayload": {
                    "url": "https://test-app.example.com/payments",
                    "value": "' OR '1'='1"
                },
                "observationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-66666666-7777-8888-9999-000000000000-1234567891",
                "issueLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-002",
                "applicationLink": "https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=87654321-4321-4321-4321-cba987654321"
            }
        ],
        "PageToken": {
            "Observation": {
                "next_page_cursor": "test-next-page-cursor",
                "name": "contrastsecurity-incident-observation-list",
                "has_next_page": true
            }
        }
    }
}
```

#### Human Readable Output

>### Contrast Security Incident Observations
>
>|Observation ID|Severity|Source IP|Associated Issue ID|Rule|Application Name|Application ID|Server|Environment|Result|Data Type|URL|Attack Value|Detected|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| [A-D-11111111-2222-3333-4444-555555555551-1234567890](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-11111111-2222-3333-4444-555555555551-1234567890) | Critical | 192.168.0.10 | [ISS-2026-001](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-001) | Command Injection | [sample-cargocats-frontgateservice](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=12345678-1234-1234-1234-123456789abc) | 12345678\-1234\-1234\-1234\-123456789abc | sample\-cargocats\-frontgateservice\-agent | DEVELOPMENT | Suspicious | Attack | /login | /bin/sh \-c : 10; id; whoami | 2026\-10\-13T16:28:24.255Z |
>| [A-D-66666666-7777-8888-9999-000000000000-1234567891](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/observations/A-D-66666666-7777-8888-9999-000000000000-1234567891) | High | 192.168.0.20 | [ISS-2026-002](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/issues/ISS-2026-002) | SQL Injection | [sample-cargocats-dataservice](https://test.contrast.com/Contrast/cs/index.html#/test-org-id/explorer?applicationId=87654321-4321-4321-4321-cba987654321) | 87654321\-4321\-4321\-4321\-cba987654321 | sample\-cargocats\-dataservice\-agent | PRODUCTION | Exploited | Attack | /payments | ' OR '1'='1 | 2026\-10\-13T16:17:57.651Z |
>
>To retrieve the next set of results, run the command with the same filters and **next_page_cursor** = `test-next-page-cursor`.
