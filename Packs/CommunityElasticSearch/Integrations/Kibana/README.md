Supports Elastic Security SIEM functionality for security operations. This pack is to be used in combination with the Elasticsearch v2 integration.

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

### kibana-find-cases

***
Used to list cases in Kibana

#### Base Command

`kibana-find-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the cases to retrieve. Possible values are: open, in-progress, closed. | Optional |
| severity | The status of the cases to retrieve. Possible values are: critical, high, medium, low. | Optional |
| from_time | Earliest time to search from (i.e. 2025-10-02T00:27:58.162Z). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kibana.Cases | unknown | Kibana Cases Search Result |

### kibana-find-alerts-for-case

***
Returns information on the alerts of a case in Kibana.

#### Base Command

`kibana-find-alerts-for-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | ID of case in Kibana. Locate with "kibana-find-cases". | Required |

#### Context Output

There is no context output for this command.

### kibana-update-alert-status

***
Updates the status of an input alert.

#### Base Command

`kibana-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update. Find with "kibana-list-detection-alerts". | Required |
| status | Status to set the alert to. Possible values are: open, closed. | Required |

#### Context Output

There is no context output for this command.

### kibana-update-case-status

***
Updates the status of an input case

#### Base Command

`kibana-update-case-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the case to update. Possible values are: open, in-progress, closed. | Required |
| case_id | ID of case in Kibana. Locate with "kibana-find-cases". | Required |
| version_id | Version ID of the case. Found with kibana-find-cases. This ID changes after each case update. | Required |

#### Context Output

There is no context output for this command.

### kibana-find-user-spaces

***
Get list of user spaces in Kibana

#### Base Command

`kibana-find-user-spaces`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-find-case-comments

***
Finds comments for an input case ID

#### Base Command

`kibana-find-case-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to find comments for. Locate with "kibana-find-cases". | Required |

#### Context Output

There is no context output for this command.

### kibana-delete-case

***
Deletes a case in Kibana based on case ID

#### Base Command

`kibana-delete-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to delete. Locate with "kibana-find-cases". | Required |

#### Context Output

There is no context output for this command.

### kibana-delete-rule

***
Delete rule in Kibana based on input rule ID.

#### Base Command

`kibana-delete-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to delete. Find with "kibana-search-rule-details". | Required |

#### Context Output

There is no context output for this command.

### kibana-search-rule-details

***
Retrieve details about detection rule in Kibana based on input KQL filter.

#### Base Command

`kibana-search-rule-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kql_query | Example query: "alert.attributes.name: *Smith*". | Optional |

#### Context Output

There is no context output for this command.

### kibana-add-case-comment

***
Adds a comment to a case in Kibana. Get case ID/owner from kibana-find-cases.

#### Base Command

`kibana-add-case-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to add comment to. Locate with "kibana-find-cases". | Required |
| case_owner | Owner of the case listed in kibana-find-cases output. Possible values are: cases, observability, securitySolution. | Required |
| comment | The comment to add to the case in Kibana. | Required |

#### Context Output

There is no context output for this command.

### kibana-get-user-list

***
Search for list of users in Kibana and return user's UID.

#### Base Command

`kibana-get-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-assign-alert

***
Used to assign an alert in Kibana to a user via user ID input

#### Base Command

`kibana-assign-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | UID of user to be assigned. Locate with 'kibana-get-user-list'. | Required |
| alert_id | Alert ID to assign user to. Find with "kibana-list-detection-alerts". | Required |

#### Context Output

There is no context output for this command.

### kibana-list-detection-alerts

***
Used to search for detection alerts in Kibana

#### Base Command

`kibana-list-detection-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_status | Status of the detection alert to search for. Possible values are: open, closed. | Required |

#### Context Output

There is no context output for this command.

### kibana-add-alert-note

***
Add note to an alert in Kibana.

#### Base Command

`kibana-add-alert-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update the note on. Find with "kibana-list-detection-alerts". | Required |
| note | The note text to add to the alert. | Required |

#### Context Output

There is no context output for this command.

### kibana-get-alerting-health

***
Get the health status of Kibana alerting framework

#### Base Command

`kibana-get-alerting-health`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-disable-alert-rule

***
Disable a detection alerting rule. Clears associated alerts from active alerts page.

#### Base Command

`kibana-disable-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to disable. Find rule ID with "kibana-search-rule-details". | Required |

#### Context Output

There is no context output for this command.

### kibana-enable-alert-rule

***
Used to enable a rule used for detection alerting.

#### Base Command

`kibana-enable-alert-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | Rule ID to enable. Find rule ID with "kibana-search-rule-details". | Required |

#### Context Output

There is no context output for this command.

### kibana-get-exception-lists

***
Get a list of all exception list containers.

#### Base Command

`kibana-get-exception-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-create-value-list

***
Used to create a value list in Kibana

#### Base Command

`kibana-create-value-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | Describes the value list. | Required |
| name | Value list's name. | Required |
| data_type | Elasticsearch data type the list container holds. Possible values are: keyword, ip, ip_range, text. | Required |
| list_id | Value list's identifier. | Required |

#### Context Output

There is no context output for this command.

### kibana-get-value-lists

***
Find all value lists in Kibana Detection Rules menu.

#### Base Command

`kibana-get-value-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-import-value-list-items

***
Import value list items from a TXT or CSV file.

#### Base Command

`kibana-import-value-list-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to import values to. Find with "kibana-get-value-lists". | Required |
| file_content | Entries of the IOC file to import to Kibana in python string format. | Required |

#### Context Output

There is no context output for this command.

### kibana-create-value-list-item

***
Create a value list item and associate it with the specified value list.

#### Base Command

`kibana-create-value-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to update. Find with "kibana-get-value-lists". | Required |
| new_value_list_item | Item to add to the specified value list. | Required |

#### Context Output

There is no context output for this command.

### kibana-get-value-list-items

***
Used to display entries in an input value list.

#### Base Command

`kibana-get-value-list-items`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to retrieve values for. Find with "kibana-get-value-lists". | Required |
| result_size | Size of results to return. Default is 100. | Optional |

#### Context Output

There is no context output for this command.

### kibana-delete-value-list-item

***
Used to delete a value list item given the item ID as input.

#### Base Command

`kibana-delete-value-list-item`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| item_id | Value list entry ID to delete. Find with "kibana-get-value-list-items". | Required |

#### Context Output

There is no context output for this command.

### kibana-delete-value-list

***
Used to delete a value list given the list ID as input.

#### Base Command

`kibana-delete-value-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | Value list ID to delete. Find with "kibana-get-value-lists". | Required |

#### Context Output

There is no context output for this command.

### kibana-get-status

***
Check Kibana's operational status

#### Base Command

`kibana-get-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-get-task-manager-health

***
Get the health status of the Kibana task manager.

#### Base Command

`kibana-get-task-manager-health`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-get-upgrade-readiness-status

***
Check the status of your cluster.

#### Base Command

`kibana-get-upgrade-readiness-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### kibana-delete-case-comment

***
Delete a case comment

#### Base Command

`kibana-delete-case-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to delete comment on. Retrieve case IDs with "kibana-find-cases". | Required |
| comment_id | Identifier for the comment. To retrieve comment IDs use kibana-find-case-comments. | Required |

#### Context Output

There is no context output for this command.

### kibana-add-file-to-case

***
Attach a file to a case.

#### Base Command

`kibana-add-file-to-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | Case ID to attach the file to. Locate with "kibana-find-cases". | Required |
| file_id | File entry ID from XSOAR context data to add to the case. | Required |

#### Context Output

There is no context output for this command.

### kibana-get-user-by-email

***
Search for a single user's UID in Kibana by email address filter.

#### Base Command

`kibana-get-user-by-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email_wildcard | Full or partial email address to search for user with. (i.e. william.smith@*). | Required |

#### Context Output

There is no context output for this command.

### kibana-get-case-information

***
Retrieve information for a specific case in Kibana.

#### Base Command

`kibana-get-case-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The case ID to retrieve information for. View available case IDs with kibana_find_cases. | Required |

#### Context Output

There is no context output for this command.
