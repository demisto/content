This integration enables using Elastic Security for SIEM for security operations management and searching Elastic logs. This pack is to be used in combination with the Elasticsearch v2 integration.
## Configure Kibana in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | True |
| Elastic API Port | The default port for the Elastic API is 9200. | False |
| Kibana API Port | The default port for the Kibana API is 443. | False |
| Authorization type | Select the authentication type and enter the appropriate credentials:- Basic Auth: Enter Username and Password.- Bearer Auth: Enter Username and Password.- API Key Auth: Enter the API Key ID and API Key. | False |
| API key ID |  | False |
| API Key |  | False |
| Username | Provide Username \+ Password instead of API key \+ API ID | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Client type | In some hosted ElasticSearch environments, the standard ElasticSearch client is not supported. If you encounter any related client issues, please consider using the OpenSearch client type. | False |
| Request timeout (in seconds). |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### kibana-cases-find

***
Used to list cases in Kibana

#### Base Command

`kibana-cases-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the cases to retrieve. Possible values are: open, in-progress, closed. Default is open. | Optional | 
| severity | The status of the cases to retrieve. Possible values are: critical, high, medium, low. | Optional | 
| from_time | Earliest time to search from (i.e. 2025-10-02T00:27:58.162Z). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.Cases.Status | unknown | Status of the case in Kibana | 
| Kibana.Cases.Version | unknown | Version number of the case in Kibana | 
| Kibana.Cases.ID | unknown | ID number of the case in Kibana | 

### kibana-case-alerts-find

***
Returns information on the alerts of input case in Kibana.

#### Base Command

`kibana-case-alerts-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of case in Kibana. Locate with "kibana-find-cases". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.CaseAlerts.ID | unknown | ID of alerts tied to case in Kibana | 

### kibana-alert-status-update

***
Updates the status of an input alert.

#### Base Command

`kibana-alert-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update. Find with "kibana-list-detection-alerts". | Required | 
| status | Status to set the alert to. Possible values are: open, closed. | Required | 

#### Context Output

There is no context output for this command.
### kibana-case-status-update

***
Updates the status of an input case

#### Base Command

`kibana-case-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the case to update. Possible values are: open, in-progress, closed. | Required | 
| case_id | ID of case in Kibana. Locate with "kibana-find-cases". | Required | 
| version_id | Version ID of the case. Found with kibana-find-cases. This ID changes after each case update. | Required | 

#### Context Output

There is no context output for this command.
### kibana-user-spaces-find

***
Get list of user spaces in Kibana

#### Base Command

`kibana-user-spaces-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UserSpaces.description | unknown | Default user space description | 
| Kibana.UserSpaces.disabledFeatures | unknown | List of disabled Kibana features | 

### kibana-case-comments-find

***
Finds comments for an input case ID

#### Base Command

`kibana-case-comments-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to find comments for. Locate with "kibana-find-cases". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.CaseComments.version | unknown | Version number of the case comment in Kibana | 
| Kibana.CaseComments.id | unknown | ID number of the case comment in Kibana | 

### kibana-case-delete

***
Deletes a case in Kibana based on case ID

#### Base Command

`kibana-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to delete. Locate with "kibana-find-cases". | Required | 

#### Context Output

There is no context output for this command.
### kibana-rule-delete

***
Delete rule in Kibana based on input rule ID.

#### Base Command

`kibana-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to delete. Find with "kibana-search-rule-details". | Required | 

#### Context Output

There is no context output for this command.
### kibana-rule-details-search

***
Retrieve details about detection rule in Kibana based on input KQL filter.

#### Base Command

`kibana-rule-details-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kql_query | Example query: "alert.attributes.name: *Smith*". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.RuleDetails.enabled | unknown | Whether the rule is enabled in Kibana | 
| Kibana.RuleDetails.name | unknown | Name of the rule in Kibana | 
| Kibana.RuleDetails.id | unknown | ID of the rule in Kibana | 

### kibana-case-comment-add

***
Adds a comment to a case in Kibana. Get case ID/owner from kibana-find-cases.

#### Base Command

`kibana-case-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to add comment to. Locate with "kibana-find-cases". | Required | 
| case_owner | Owner of the case listed in kibana-find-cases output. Possible values are: cases, observability, securitySolution. | Required | 
| comment | The comment to add to the case in Kibana. | Required | 

#### Context Output

There is no context output for this command.
### kibana-user-list-get

***
Search for list of users in Kibana and return user's UID.

#### Base Command

`kibana-user-list-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UserList.username | unknown | Username of the user in Kibana | 
| Kibana.UserList.roles | unknown | Associated roles of the user in Kibana | 

### kibana-alert-assign

***
Used to assign an alert in Kibana to a user via user ID input

#### Base Command

`kibana-alert-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | UID of user to be assigned. Locate with 'kibana-get-user-list'. | Required | 
| alert_id | Alert ID to assign user to. Find with "kibana-list-detection-alerts". | Required | 

#### Context Output

There is no context output for this command.
### kibana-detection-alerts-list

***
Used to search for detection alerts in Kibana

#### Base Command

`kibana-detection-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_status | Status of the detection alert to search for. Possible values are: open, closed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.DetectionAlerts.bhe.windows.security_id | unknown | Username associated with the detection alert | 
| Kibana.DetectionAlerts.kibana.alert.original_data_stream.dataset | unknown | Dataset associated with the detection alert | 
| Kibana.DetectionAlerts.message | unknown | Raw log message of the detection alert | 
| Kibana.DetectionAlerts.kibana.alert.uuid | unknown | ID of the detection alert | 
| Kibana.DetectionAlerts.kibana.alert.rule.name | unknown | Rule name associated with the detection alert | 

### kibana-alert-note-add

***
Add note to an alert in Kibana.

#### Base Command

`kibana-alert-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update the note on. Find with "kibana-list-detection-alerts". | Required | 
| note | The note text to add to the alert. | Required | 

#### Context Output

There is no context output for this command.
### kibana-alerting-health-get

***
Get the health status of Kibana alerting framework

#### Base Command

`kibana-alerting-health-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.AlertingFrameworkHealth.alerting_framework_health.decryption_health.status | unknown | Whether Kibana can successfully decrypt encrypted alert data | 
| Kibana.AlertingFrameworkHealth.alerting_framework_health.execution_health.status | unknown | Identify if rules are running on time or failing | 
| Kibana.AlertingFrameworkHealth.alerting_framework_health.read_health.status | unknown | Ability to successfully retrieve rule configurations from internal Kibana indices | 

### kibana-alert-rule-disable

***
Disable a detection alerting rule. Clears associated alerts from active alerts page.

#### Base Command

`kibana-alert-rule-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to disable. Find rule ID with "kibana-search-rule-details". | Required | 

#### Context Output

There is no context output for this command.
### kibana-alert-rule-enable

***
Used to enable a rule used for detection alerting. 

#### Base Command

`kibana-alert-rule-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to enable. Find rule ID with "kibana-search-rule-details". | Required | 

#### Context Output

There is no context output for this command.
### kibana-exception-lists-get

***
Get a list of all exception list containers.

#### Base Command

`kibana-exception-lists-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.ExceptionLists.name | unknown | The name of the exception list | 
| Kibana.ExceptionLists.list_id | unknown | The list ID of the exception list | 
| Kibana.ExceptionLists.description | unknown | The description of the exception list | 

### kibana-value-list-create

***
Used to create a value list in Kibana

#### Base Command

`kibana-value-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Describes the value list. | Required | 
| name | Value list's name. | Required | 
| data_type | Elasticsearch data type the list container holds. Possible values are: keyword, ip, ip_range, text. | Required | 
| list_id | Value list's identifier. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-lists-get

***
Find all value lists in Kibana Detection Rules menu.

#### Base Command

`kibana-value-lists-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.ValueLists.name | unknown | The name of the Value List | 
| Kibana.ValueLists.id | unknown | The ID of the Value List | 
| Kibana.ValueLists.description | unknown | The description of the Value List | 

### kibana-value-list-items-import

***
Import value list items from a TXT or CSV file.

#### Base Command

`kibana-value-list-items-import`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to import values to. Find with "kibana-get-value-lists". | Required | 
| file_content | Entries of the IOC file to import to Kibana in python string format. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-list-item-create

***
Create a value list item and associate it with the specified value list.

#### Base Command

`kibana-value-list-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to update. Find with "kibana-get-value-lists". | Required | 
| new_value_list_item | Item to add to the specified value list. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-list-items-get

***
Used to display entries in an input value list.

#### Base Command

`kibana-value-list-items-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to retrieve values for. Find with "kibana-get-value-lists". | Required | 
| result_size | Size of results to return. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.ValueListItems.value | unknown | The value of the value list item | 
| Kibana.ValueListItems.id | unknown | The ID of the value list item | 
| Kibana.ValueListItems.list_id | unknown | The list ID of the value list | 

### kibana-value-list-item-delete

***
Used to delete a value list item given the item ID as input.

#### Base Command

`kibana-value-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Value list entry ID to delete. Find with "kibana-get-value-list-items". | Required | 
| list_id | Value list ID to delete value from. Find with "kibana-get-value-lists". | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-list-delete

***
Used to delete a value list given the list ID as input.

#### Base Command

`kibana-value-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to delete. Find with "kibana-get-value-lists". | Required | 

#### Context Output

There is no context output for this command.
### kibana-status-get

***
Check Kibana's operational status

#### Base Command

`kibana-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.OperationalStatus.core.elasticsearch.level | unknown | Connection health between Kibana and Elasticsearch | 
| Kibana.OperationalStatus.overall.level | unknown | Aggregated health status of the Kibana instance | 
| Kibana.OperationalStatus.core.savedObjects.level | unknown | Health status of the Saved Objects repository | 

### kibana-task-manager-health-get

***
Get the health status of the Kibana task manager.

#### Base Command

`kibana-task-manager-health-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.TaskManagerHealth.capacity_estimation.status | unknown | Kibana ability to handle scheduled tasks | 
| Kibana.TaskManagerHealth.configuration.status | unknown | Tracks configuration status of Kibana task manager | 
| Kibana.TaskManagerHealth.runtime.status | unknown | Tracks performance, drift, and load of Kibana task execution | 
| Kibana.TaskManagerHealth.workload.status | unknown | Status of tasks running to identify potential overload | 

### kibana-upgrade-readiness-status-get

***
Check the status of your cluster.

#### Base Command

`kibana-upgrade-readiness-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UpgradeReadinessStatus.details | unknown | Details for what is needed prior to Kibana upgrades | 
| Kibana.UpgradeReadinessStatus.readyForUpgrade | unknown | Whether Kibana is ready for upgrade or not | 

### kibana-case-comment-delete

***
Delete a case comment

#### Base Command

`kibana-case-comment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to delete comment on. Retrieve case IDs with "kibana-find-cases". | Required | 
| comment_id | Identifier for the comment. To retrieve comment IDs use kibana-find-case-comments. | Required | 

#### Context Output

There is no context output for this command.
### kibana-case-file-add

***
Attach a file to a case. 

#### Base Command

`kibana-case-file-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to attach the file to. Locate with "kibana-find-cases". | Required | 
| file_id | File entry ID from XSOAR context data to add to the case. | Required | 

#### Context Output

There is no context output for this command.
### kibana-user-by-email-get

***
Search for a single user's UID in Kibana by email address filter.

#### Base Command

`kibana-user-by-email-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_wildcard | Full or partial email address to search for user with. (i.e. william.smith@*). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UserData.profile_uid | unknown | User ID for tracking user activity and checking privileges | 
| Kibana.UserData.roles | unknown | Roles tied to the user account | 

### kibana-case-information-get

***
Retrieve information for a specific case in Kibana.

#### Base Command

`kibana-case-information-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to retrieve information for. View available case IDs with kibana-cases-find. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.CaseInfo.status | unknown | Whether the case is open, in-progress, or closed | 
| Kibana.CaseInfo.owner | unknown | The application that created the case | 
| Kibana.CaseInfo.version | unknown | When updating case settings, version is required | 
| Kibana.CaseInfo.id | unknown | Unique identifier for a case | 
