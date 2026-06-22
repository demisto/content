Use the Kibana integration to manage Elastic Security cases, detection alerts, rules, and value lists for security operations.
This integration was tested with Elasticsearch versions 6.6.2, 7.3, 8.4.1, and 9.3.1.

## Configure Kibana in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The Elasticsearch server to which the integration connects. Ensure that the URL includes the correct Elasticsearch port. The default port for Elasticsearch v7 and below is 9200. Use the Server URL for on-premises deployments. | True |
| Elastic API Port | The port for the Elastic API. | False |
| Kibana API Port | The port for the Kibana API. | False |
| Authorization type | The authentication type and credentials to use: Basic Auth \(Username and Password\), Bearer Auth \(Username and Password\), or API Key Auth \(API Key ID and API Key\). | False |
| API key ID |  | False |
| API Key |  | False |
| Username | The username and password to use instead of API key and API ID. | False |
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
Lists cases in Kibana.

#### Base Command

`kibana-cases-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the cases to retrieve. Possible values are: open, in-progress, closed. Default is open. | Optional | 
| severity | The severity of the cases to retrieve. Possible values are: critical, high, medium, low. | Optional | 
| from_time | The earliest time to search from (for example, 2025-10-02T00:27:58.162Z). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.Cases.Status | unknown | The status of the case in Kibana. | 
| Kibana.Cases.Version | unknown | The version number of the case in Kibana. | 
| Kibana.Cases.ID | unknown | The ID number of the case in Kibana. | 

### kibana-case-alerts-find

***
Returns information on the alerts of the input case in Kibana.

#### Base Command

`kibana-case-alerts-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the case in Kibana. Locate it with the "kibana-cases-find" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.CaseAlerts.ID | unknown | The ID of alerts tied to the case in Kibana. | 

### kibana-alert-status-update

***
Updates the status of an input alert.

#### Base Command

`kibana-alert-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to update. Find it with the "kibana-detection-alerts-list" command. | Required | 
| status | The status to set the alert to. Possible values are: open, closed. | Required | 

#### Context Output

There is no context output for this command.
### kibana-case-status-update

***
Updates the status of an input case.

#### Base Command

`kibana-case-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the case to update. Possible values are: open, in-progress, closed. | Required | 
| case_id | The ID of the case in Kibana. Locate it with the "kibana-cases-find" command. | Required | 
| version_id | The version ID of the case. Find it with the "kibana-cases-find" command. This ID changes after each case update. | Required | 

#### Context Output

There is no context output for this command.
### kibana-user-spaces-find

***
Gets the list of user spaces in Kibana.

#### Base Command

`kibana-user-spaces-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UserSpaces.description | unknown | The default user space description. | 
| Kibana.UserSpaces.disabledFeatures | unknown | The list of disabled Kibana features. | 

### kibana-case-comments-find

***
Finds comments for an input case ID.

#### Base Command

`kibana-case-comments-find`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to find comments for. Locate it with the "kibana-cases-find" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.CaseComments.version | unknown | The version number of the case comment in Kibana. | 
| Kibana.CaseComments.id | unknown | The ID number of the case comment in Kibana. | 

### kibana-case-delete

***
Deletes a case in Kibana based on case ID.

#### Base Command

`kibana-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to delete. Locate it with the "kibana-cases-find" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-rule-delete

***
Deletes a rule in Kibana based on the input rule ID.

#### Base Command

`kibana-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID to delete. Find it with the "kibana-rule-details-search" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-rule-details-search

***
Retrieves details about a detection rule in Kibana based on the input KQL filter.

#### Base Command

`kibana-rule-details-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kql_query | The KQL filter to search rules with. For example: "alert.attributes.name: *Smith*". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.RuleDetails.enabled | unknown | Whether the rule is enabled in Kibana. | 
| Kibana.RuleDetails.name | unknown | The name of the rule in Kibana. | 
| Kibana.RuleDetails.id | unknown | The ID of the rule in Kibana. | 

### kibana-case-comment-add

***
Adds a comment to a case in Kibana. The case ID and owner can be obtained from the "kibana-cases-find" command.

#### Base Command

`kibana-case-comment-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to add the comment to. Locate it with the "kibana-cases-find" command. | Required | 
| case_owner | The owner of the case, as listed in the "kibana-cases-find" command output. Possible values are: cases, observability, securitySolution. | Required | 
| comment | The comment to add to the case in Kibana. | Required | 

#### Context Output

There is no context output for this command.
### kibana-user-list-get

***
Searches for the list of users in Kibana and returns the users' UIDs.

#### Base Command

`kibana-user-list-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UserList.username | unknown | The username of the user in Kibana. | 
| Kibana.UserList.roles | unknown | The associated roles of the user in Kibana. | 

### kibana-alert-assign

***
Assigns an alert in Kibana to a user via user ID input.

#### Base Command

`kibana-alert-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The UID of the user to be assigned. Locate it with the "kibana-user-list-get" command. | Required | 
| alert_id | The alert ID to assign the user to. Find it with the "kibana-detection-alerts-list" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-detection-alerts-list

***
Searches for detection alerts in Kibana.

#### Base Command

`kibana-detection-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_status | The status of the detection alert to search for. Possible values are: open, closed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.DetectionAlerts.bhe.windows.security_id | unknown | The username associated with the detection alert. | 
| Kibana.DetectionAlerts.kibana.alert.original_data_stream.dataset | unknown | The dataset associated with the detection alert. | 
| Kibana.DetectionAlerts.message | unknown | The raw log message of the detection alert. | 
| Kibana.DetectionAlerts.kibana.alert.uuid | unknown | The ID of the detection alert. | 
| Kibana.DetectionAlerts.kibana.alert.rule.name | unknown | The rule name associated with the detection alert. | 

### kibana-alert-note-add

***
Adds a note to an alert in Kibana.

#### Base Command

`kibana-alert-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID to update the note on. Find it with the "kibana-detection-alerts-list" command. | Required | 
| note | The note text to add to the alert. | Required | 

#### Context Output

There is no context output for this command.
### kibana-alerting-health-get

***
Retrieves the health status of the Kibana alerting framework.

#### Base Command

`kibana-alerting-health-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.AlertingFrameworkHealth.alerting_framework_health.decryption_health.status | unknown | Whether Kibana can successfully decrypt encrypted alert data. | 
| Kibana.AlertingFrameworkHealth.alerting_framework_health.execution_health.status | unknown | Whether rules are running on time or failing. | 
| Kibana.AlertingFrameworkHealth.alerting_framework_health.read_health.status | unknown | Whether rule configurations can be successfully retrieved from internal Kibana indices. | 

### kibana-alert-rule-disable

***
Disables a detection alerting rule. Clears associated alerts from the active alerts page.

#### Base Command

`kibana-alert-rule-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID to disable. Find it with the "kibana-rule-details-search" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-alert-rule-enable

***
Enables a rule used for detection alerting.

#### Base Command

`kibana-alert-rule-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID to enable. Find it with the "kibana-rule-details-search" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-exception-lists-get

***
Retrieves a list of all exception list containers.

#### Base Command

`kibana-exception-lists-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.ExceptionLists.name | unknown | The name of the exception list. | 
| Kibana.ExceptionLists.list_id | unknown | The list ID of the exception list. | 
| Kibana.ExceptionLists.description | unknown | The description of the exception list. | 

### kibana-value-list-create

***
Creates a value list in Kibana.

#### Base Command

`kibana-value-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The description of the value list. | Required | 
| name | The name of the value list. | Required | 
| data_type | The Elasticsearch data type the list container holds. Possible values are: keyword, ip, ip_range, text. | Required | 
| list_id | The identifier of the value list. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-lists-get

***
Finds all value lists in the Kibana Detection Rules menu.

#### Base Command

`kibana-value-lists-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.ValueLists.name | unknown | The name of the value list. | 
| Kibana.ValueLists.id | unknown | The ID of the value list. | 
| Kibana.ValueLists.description | unknown | The description of the value list. | 

### kibana-value-list-items-import

***
Imports value list items from a TXT or CSV file.

#### Base Command

`kibana-value-list-items-import`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The value list ID to import values to. Find it with the "kibana-value-lists-get" command. | Required | 
| file_content | The IOC file entries to import to Kibana in Python string format. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-list-item-create

***
Creates a value list item and associates it with the specified value list.

#### Base Command

`kibana-value-list-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The value list ID to update. Find it with the "kibana-value-lists-get" command. | Required | 
| new_value_list_item | The item to add to the specified value list. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-list-items-get

***
Displays entries in an input value list.

#### Base Command

`kibana-value-list-items-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The value list ID to retrieve values for. Find it with the "kibana-value-lists-get" command. | Required | 
| result_size | The size of results to return. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.ValueListItems.value | unknown | The value of the value list item. | 
| Kibana.ValueListItems.id | unknown | The ID of the value list item. | 
| Kibana.ValueListItems.list_id | unknown | The list ID of the value list. | 

### kibana-value-list-item-delete

***
Deletes a value list item, given the item ID and list ID as input.

#### Base Command

`kibana-value-list-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | The value list entry ID to delete. Find it with the "kibana-value-list-items-get" command. | Required | 
| list_id | The value list ID to delete the value from. Find it with the "kibana-value-lists-get" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-value-list-delete

***
Deletes a value list given the list ID as input.

#### Base Command

`kibana-value-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The value list ID to delete. Find it with the "kibana-value-lists-get" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-status-get

***
Checks the Kibana operational status.

#### Base Command

`kibana-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.OperationalStatus.core.elasticsearch.level | unknown | The connection health between Kibana and Elasticsearch. | 
| Kibana.OperationalStatus.overall.level | unknown | The aggregated health status of the Kibana instance. | 
| Kibana.OperationalStatus.core.savedObjects.level | unknown | The health status of the Saved Objects repository. | 

### kibana-task-manager-health-get

***
Retrieves the health status of the Kibana task manager.

#### Base Command

`kibana-task-manager-health-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.TaskManagerHealth.capacity_estimation.status | unknown | The ability to handle scheduled tasks in Kibana. | 
| Kibana.TaskManagerHealth.configuration.status | unknown | The configuration status of the Kibana task manager. | 
| Kibana.TaskManagerHealth.runtime.status | unknown | The performance, drift, and load of Kibana task execution. | 
| Kibana.TaskManagerHealth.workload.status | unknown | The status of tasks running, to identify potential overload. | 

### kibana-upgrade-readiness-status-get

***
Checks the status of the cluster.

#### Base Command

`kibana-upgrade-readiness-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UpgradeReadinessStatus.details | unknown | The details for what is needed prior to Kibana upgrades. | 
| Kibana.UpgradeReadinessStatus.readyForUpgrade | unknown | Whether Kibana is ready for upgrade. | 

### kibana-case-comment-delete

***
Deletes a case comment.

#### Base Command

`kibana-case-comment-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to delete the comment on. Retrieve case IDs with the "kibana-cases-find" command. | Required | 
| comment_id | The identifier for the comment. Find comment IDs with the "kibana-case-comments-find" command. | Required | 

#### Context Output

There is no context output for this command.
### kibana-case-file-add

***
Attaches a file to a case.

#### Base Command

`kibana-case-file-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to attach the file to. Locate it with the "kibana-cases-find" command. | Required | 
| file_id | The file entry ID from Cortex XSOAR context data to add to the case. | Required | 

#### Context Output

There is no context output for this command.
### kibana-user-by-email-get

***
Searches for a single user's UID in Kibana by email address filter.

#### Base Command

`kibana-user-by-email-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_wildcard | The full or partial email address to search for the user with (for example, william.smith@*). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.UserData.profile_uid | unknown | The user ID for tracking user activity and checking privileges. | 
| Kibana.UserData.roles | unknown | The roles tied to the user account. | 

### kibana-case-information-get

***
Retrieves information for a specific case in Kibana.

#### Base Command

`kibana-case-information-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to retrieve information for. View available case IDs with the "kibana-cases-find" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.CaseInfo.status | unknown | Whether the case is open, in-progress, or closed. | 
| Kibana.CaseInfo.owner | unknown | The application that created the case. | 
| Kibana.CaseInfo.version | unknown | The version of the case being updated. | 
| Kibana.CaseInfo.id | unknown | The unique identifier for a case. | 
