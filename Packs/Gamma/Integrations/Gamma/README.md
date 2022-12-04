Gamma Enterprise DLP provides 1-click automatic discovery and remediation of data loss instances
 across enterprise sanctioned SaaS applications (cloud and on-prem) such as: Slack, Github, GSuite (Gmail, GDrive), Atlassian Suite (Jira, Confluence), Microsoft Office 365 (Outlook, Teams, OneDrive), ServiceNow, ZenDesk and many more.

## Configure Gamma.AI Enterprise DLP on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Gamma.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| api_key | Gamma Discovery API Key | True |
| url | URL of the Gamma API | True |
| first_fetch | The violation ID (offset) to begin fetching from. The value must be a number equal to or greater than 1. If empty, the fetch will default to the first violation that exists. You can retrieve a list of violation IDs by running the gamma-get-violation-list command.  | False |
| max_fetch | Max results to return | False |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gamma-get-violation-list
***
Fetch DLP violations found across SaaS applications monitored by Gamma 

#### Base Command

`gamma-get-violation-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| minimum_violation | Violation ID to begin pulling from. Defaults to the earliest existing violation for your account. | Required |
| limit | Default is "10". | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GammaViolation.violation_id | Integer | Violation ID | 
| GammaViolation.file_labels_map | Array | File in reference to the DLP violation | 
| GammaViolation.violation_status | String | one of 'OPEN', 'RESOLVED', 'IGNORED' | 
| GammaViolation.violation_category | String | Category of the violation e.g. PII, Secrets, GDPR/CCPA, etc. | 
| GammaViolation.violation_event_timestamp | Integer | Timestamp of violation in epoch milliseconds | 
| GammaViolation.text_labels | Array | Data classification labels |
| GammaViolation.user | JSON Object | a JSON field containing optional information (based on what the app allows us to access) like email address, name, atlassian account id, AD id, github login, etc. All these fields are nullable. |
| GammaViolation.dashboard_url | String | Gamma dashboard URL |
| GammaViolation.app_name | String | Name of the application |

#### Command Example
```!gamma-get-violation-list minimum_violation=998 limit=1```

#### Context Example
```json
{
    "response": [
        {
            "violation_id": 999,
            "file_labels_map": {
                "svc-prod-account.json": [
                    "cloud_db_credential"
                ]
            },
            "violation_status": "OPEN",
            "violation_category": "secrets",
            "violation_event_timestamp": 1569550580,
            "text_labels": [],
            "user": {
                "name": null,
                "atlassian_account_id": null,
                "email_address": "foo@example.com",
                "active_directory_user_id": null,
                "atlassian_server_user_key": null,
                "slack_user_id": "USER9Aa2",
                "github_handle": "markzuck"
            },
            "dashboard_url": "https://prod-iab12.gamma.ai/dashboard/slack/monitor/violationId/999",
            "app_name": "slack"
        }]
}
```

### gamma-get-violation
***
Fetches a single DLP violation. This command is the same as gamma-get-violation-list except that this
 command only returns the DLP violation details of the given violation id.  

#### Base Command

`gamma-get-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| violation | Violation id | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GammaViolation.violation_id | Integer | Violation ID |
| GammaViolation.file_labels_map | Array | File in reference to the DLP violation |
| GammaViolation.violation_status | String | one of 'OPEN', 'RESOLVED', 'IGNORED' |
| GammaViolation.violation_category | String | Category of the violation e.g. PII, Secrets, GDPR/CCPA, etc. |
| GammaViolation.violation_event_timestamp | Integer | Timestamp of violation in epoch milliseconds |
| GammaViolation.text_labels | Array | Data classification labels |
| GammaViolation.user | JSON Object | a JSON field containing optional information (based on what the app allows us to access) like email address, name, atlassian account id, AD id, github login, etc. All these fields are nullable. |
| GammaViolation.dashboard_url | String | Gamma dashboard URL |
| GammaViolation.app_name | String | Name of the application |

#### Command Example
```!gamma-get-violation violation=998```

#### Context Example
```json
{
    "response": [
        {
            "violation_id": 999,
            "file_labels_map": {
                "svc-prod-account.json": [
                    "cloud_db_credential"
                ]
            },
            "violation_status": "OPEN",
            "violation_category": "secrets",
            "violation_event_timestamp": 1569550580,
            "text_labels": [],
            "user": {
                "name": null,
                "atlassian_account_id": null,
                "email_address": "foo@example.com",
                "active_directory_user_id": null,
                "atlassian_server_user_key": null,
                "slack_user_id": "USER9Aa2",
                "github_handle": "markzuck"
            },
            "dashboard_url": "https://prod-iab12.gamma.ai/dashboard/slack/monitor/violationId/999",
            "app_name": "slack"
        }]
}
```

### gamma-update-violation
***
Updates a DLP violation status in Gamma  

#### Base Command

`gamma-update-violation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| violation | Violation id | Required | 
| status | Status of violation | Required |
| notes | Notes for violation | Optional | 


#### Context Output
There is no context output for this command
