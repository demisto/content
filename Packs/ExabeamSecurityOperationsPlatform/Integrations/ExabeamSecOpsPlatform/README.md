Exabeam Security Operations Platform offers a centralized and scalable platform for log management.
This integration was integrated and tested with version v1.0 of ExabeamSecOpsPlatform.

## Configure Exabeam Security Operations Platform in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  |
| Maximum Incidents Per Fetch |  |
| Fetch query |  |
| Fetch incidents |  |
| Incident type |  |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### exabeam-platform-event-search

***
Get events from Exabeam Security Operations Platform.

#### Base Command

`exabeam-platform-event-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The starting date for the search range. | Required | 
| end_time | The ending date for the search range. | Required | 
| query | Query, using Lucene syntax, filters log data for precise analysis, without escaping and with values unquoted. e.g., query="product: Correlation Rule AND rule_severity: High". | Optional | 
| fields | Comma-separated list of fields to be returned from the search. | Optional | 
| group_by | Comma-separated list of fields by which to group the results. | Optional | 
| limit | The maximal number of results to return. Maximum value is 3000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamPlatform.Event.id | String | The unique identifier associated with the event. | 
| ExabeamPlatform.Event.rawLogIds | String | The raw log identifiers associated with the event. | 
| ExabeamPlatform.Event.tier | String | The tier associated with the event. | 
| ExabeamPlatform.Event.parsed | String | Whether the event has been parsed. | 
| ExabeamPlatform.Event.rawLogs | String | The raw logs associated with the event. | 

#### Command example
```!exabeam-platform-event-search end_time="today" start_time="7 days ago" limit=2 query="product: Correlation Rule AND rule_severity: High"```
#### Context Example
```json
{
    "ExabeamPlatform": {
        "Event": [
            {
                "approxLogTime": 1715694190909000,
                "collector_timestamp": 1715694190909000,
                "customFieldsJSON": "{}",
                "id": "fake",
                "ingest_time": 1715694222815000,
                "metadataFieldsJSON": "{\"m_collector_id\":\"aae1627e-8637-4597-9f43-e49a703a6151\",\"m_collector_name\":\"exa-cribl-logs-sm_exa_ws\",\"m_collector_type\":\"cribl-logs\"}",
                "parsed": false,
                "rawLogIds": [
                    "log-fic"
                ],
                "rawLogs": [
                    "ANY rawLog"
                ],
                "raw_log_size": 9,
                "tier": "Tier 4"
            },
            {
                "approxLogTime": 1715694915916000,
                "collector_timestamp": 1715694915916000,
                "customFieldsJSON": "{}",
                "id": "fictive-id",
                "ingest_time": 1715694946775000,
                "metadataFieldsJSON": "{\"m_collector_id\":\"aae1627e-8637-4597-9f43-e49a703a6151\",\"m_collector_name\":\"exa-cribl-logs-sm_exa_ws\",\"m_collector_type\":\"cribl-logs\"}",
                "parsed": false,
                "rawLogIds": [
                    "rawLogId"
                ],
                "rawLogs": [
                    "CONNECT hotmail"
                ],
                "raw_log_size": 59,
                "tier": "Tier 4"
            }
        ]
    }
}
```

#### Human Readable Output

>### Logs
>|Id|Is Parsed|Raw Log Ids|Raw Logs|Tier|
>|---|---|---|---|---|
>| fake | false | log-fic | ANY rawLog | Tier 4 |
>| fictive-id | false | rawLogId | CONNECT hotmail  | Tier 4 |

### exabeam-platform-table-record-list

***
Retrieve the records for a specific context table.

#### Base Command

`exabeam-platform-table-record-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_id | ID of the table. Obtain this value by running `exabeam-platform-context-table-list`. | Required | 
| limit | The number of records to return. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.
### exabeam-platform-table-record-create

***
Add one or more context records directly to an existing table.

#### Base Command

`exabeam-platform-table-record-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_id | ID of the table. Obtain this value by running `exabeam-platform-context-table-list`. | Required | 
| attributes | A key-value map of record attributes. | Required | 
| operation | Options for how data should be uploaded to an existing table. Possible values are: append, replace. Default is append. | Optional | 
| interval_in_seconds | The interval in seconds between each poll. Default is 30. | Optional | 
| timeout | The timeout in seconds until polling ends. Default is 600. | Optional | 
| tracker_id | Specify the tracker ID from an upload request whose progress you want to track. | Optional | 
| hide_polling_output | Suppresses the output of polling operations to reduce clutter in logs. | Optional | 

#### Context Output

There is no context output for this command.
### exabeam-platform-alert-search

***
Search for alerts that match one or more search criteria.

#### Base Command

`exabeam-platform-alert-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Unique ID that identifies an alert. | Optional | 
| start_time | Timestamp to start the search. Default is 7 days ago. | Optional | 
| end_time | Timestamp to end the search. Default is today. | Optional | 
| query | Query, using Lucene syntax, filters log data for precise analysis. | Optional | 
| fields | List of fields to be returned from the search. | Optional | 
| order_by | Order results by a specified field in ASC or DESC order, such as "riskScore ASC" or "riskScore DESC". | Optional | 
| limit | Limit the number of results returned from the search request. Default is 50. | Optional | 
| all_results | If set to 'True', retrieves all available results, ignoring the limit parameter. Possible values are: True, False. Default is False. | Optional | 
| include_related_rules | If set to 'True', filters the context to include the "rules" array related to the cases in the results. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamPlatform.Alert.alertDescriptionRt | String | The description of the alert in real-time. | 
| ExabeamPlatform.Alert.alertId | String | The unique identifier of the alert. | 
| ExabeamPlatform.Alert.alertName | String | The name or title of the alert. | 
| ExabeamPlatform.Alert.approxLogTime | Date | The approximate log time of the alert. | 
| ExabeamPlatform.Alert.assignee | String | The person assigned to the alert. | 
| ExabeamPlatform.Alert.caseCreationTimestamp | Number | The timestamp when the case was created. | 
| ExabeamPlatform.Alert.caseId | String | The unique identifier of the case associated with the alert. | 
| ExabeamPlatform.Alert.creationBy | String | The user who created the alert. | 
| ExabeamPlatform.Alert.creationTimestamp | Date | The timestamp when the alert was created. | 
| ExabeamPlatform.Alert.destEndpoints | Unknown | The destination endpoints involved in the alert. | 
| ExabeamPlatform.Alert.destHosts | Unknown | The destination hosts involved in the alert. | 
| ExabeamPlatform.Alert.destIps | Unknown | The destination IP addresses involved in the alert. | 
| ExabeamPlatform.Alert.groupedbyKey | String | The key used for grouping the alert. | 
| ExabeamPlatform.Alert.groupedbyValue | String | The value used for grouping the alert. | 
| ExabeamPlatform.Alert.groupingRuleId | String | The ID of the rule used for grouping the alert. | 
| ExabeamPlatform.Alert.hasAttachments | Boolean | Indicates if the alert has attachments. | 
| ExabeamPlatform.Alert.ingestTimestamp | Date | The timestamp when the alert was ingested into the system. | 
| ExabeamPlatform.Alert.lastModifiedBy | String | The user who last modified the alert. | 
| ExabeamPlatform.Alert.lastModifiedTimestamp | Date | The timestamp when the alert was last modified. | 
| ExabeamPlatform.Alert.mitres.tactic | String | The MITRE tactic associated with the alert. | 
| ExabeamPlatform.Alert.mitres.tacticKey | String | The MITRE tactic key associated with the alert. | 
| ExabeamPlatform.Alert.mitres.technique | String | The MITRE technique associated with the alert. | 
| ExabeamPlatform.Alert.mitres.techniqueKey | String | The MITRE technique key associated with the alert. | 
| ExabeamPlatform.Alert.priority | String | The priority level of the alert. | 
| ExabeamPlatform.Alert.products | String | The products involved in the alert. | 
| ExabeamPlatform.Alert.queue | String | The queue in which the alert is placed. | 
| ExabeamPlatform.Alert.riskScore | Number | The risk score associated with the alert. | 
| ExabeamPlatform.Alert.srcEndpoints.ip | String | The IP addresses of the source endpoints involved in the alert. | 
| ExabeamPlatform.Alert.srcHosts | Unknown | The source hosts involved in the alert. | 
| ExabeamPlatform.Alert.srcIps | String | The source IP addresses involved in the alert. | 
| ExabeamPlatform.Alert.stage | String | The stage of the alert in the investigation process. | 
| ExabeamPlatform.Alert.status | String | The status of the alert. | 
| ExabeamPlatform.Alert.subscriptionCode | String | The subscription code associated with the alert. | 
| ExabeamPlatform.Alert.tags | Unknown | The tags associated with the alert. | 
| ExabeamPlatform.Alert.useCases | String | The use cases related to the alert. | 
| ExabeamPlatform.Alert.users | Unknown | The users involved in the alert. | 
| ExabeamPlatform.Alert.vendors | String | The vendors associated with the alert. | 

### exabeam-platform-context-table-delete

***
Delete a specific context table, including records and attributes.

#### Base Command

`exabeam-platform-context-table-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_id | Specify the ID of an existing context table. | Required | 
| delete_unused_custom_attributes | Delete any custom attributes in this table that are not used in another context table. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

There is no context output for this command.
### exabeam-platform-context-table-list

***
Retrieve metadata for all existing context tables, including source, operational status, and attribute mapping.

#### Base Command

`exabeam-platform-table-record-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| table_id | Specify the ID of an existing context table. | Optional | 
| limit | Limit the number of results returned from the request. Default is 50. | Optional | 
| include_attributes | If set to 'True', filters the context to include the "attributes" array related to the cases in the results. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamPlatform.ContextTable.attributeMapping | Unknown | The attribute mapping of the context table. | 
| ExabeamPlatform.ContextTable.attributes.displayName | String | The display name of the attribute. | 
| ExabeamPlatform.ContextTable.attributes.id | String | The unique identifier of the attribute. | 
| ExabeamPlatform.ContextTable.attributes.isKey | Boolean | Indicates if the attribute is a key attribute. | 
| ExabeamPlatform.ContextTable.attributes.type | String | The type of the attribute. | 
| ExabeamPlatform.ContextTable.contextType | String | The type of context the table represents. | 
| ExabeamPlatform.ContextTable.id | String | The unique identifier of the context table. | 
| ExabeamPlatform.ContextTable.lastUpdated | Number | The timestamp of the last update to the context table. | 
| ExabeamPlatform.ContextTable.name | String | The name of the context table. | 
| ExabeamPlatform.ContextTable.source | String | The source of the context table data. | 
| ExabeamPlatform.ContextTable.status | String | The status of the context table. | 
| ExabeamPlatform.ContextTable.totalItems | Number | The total number of items in the context table. | 

### exabeam-platform-case-search

***
Search for cases that match one or more search criteria. For example, you can search for cases that are associated with a specific caseId and that reference specific rules.

#### Base Command

`exabeam-platform-case-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | An optional case id parameter to get a specific case. | Optional | 
| start_time | Timestamp to start the search. Default is 7 days ago. | Optional | 
| end_time | Timestamp to end the search. Default is today. | Optional | 
| query | Query, using Lucene syntax, filters log data for precise analysis. | Optional | 
| fields | List of fields to be returned from the search. | Optional | 
| order_by | Order results by a specified field in ASC or DESC order, such as "riskScore ASC" or "riskScore DESC". | Optional | 
| limit | Limit the number of results returned from the search request. Default is 50. | Optional | 
| all_results | If set to 'True', retrieves all available results, ignoring the limit parameter. Possible values are: True, False. Default is False. | Optional | 
| include_related_rules | If set to 'True', filters the context to include the "rules" array related to the cases in the results. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamPlatform.Case.alertId | String | Unique identifier for the alert associated with the case. | 
| ExabeamPlatform.Case.alertName | String | Name of the alert associated with the case. | 
| ExabeamPlatform.Case.approxLogTime | Number | Approximate log time of the event that generated the case. | 
| ExabeamPlatform.Case.assignee | String | User assigned to the case. | 
| ExabeamPlatform.Case.caseCreationTimestamp | Number | Timestamp when the case was created. | 
| ExabeamPlatform.Case.caseId | String | Unique identifier for the case. | 
| ExabeamPlatform.Case.destHosts | Unknown | Destination hosts involved in the case. | 
| ExabeamPlatform.Case.destIps | Unknown | Destination IP addresses involved in the case. | 
| ExabeamPlatform.Case.groupedbyKey | String | Key by which the case was grouped. | 
| ExabeamPlatform.Case.groupedbyValue | String | Value by which the case was grouped. | 
| ExabeamPlatform.Case.hasAttachments | Boolean | Indicates if the case has attachments. | 
| ExabeamPlatform.Case.ingestTimestamp | Unknown | Timestamp when the case was ingested. | 
| ExabeamPlatform.Case.lastModifiedTimestamp | Unknown | Timestamp when the case was last modified. | 
| ExabeamPlatform.Case.mitres | Unknown | MITRE tactics and techniques associated with the case. | 
| ExabeamPlatform.Case.priority | String | Priority level of the case. | 
| ExabeamPlatform.Case.products | String | Products involved in the case. | 
| ExabeamPlatform.Case.queue | String | Queue to which the case is assigned. | 
| ExabeamPlatform.Case.riskScore | Number | Risk score of the case. | 
| ExabeamPlatform.Case.rules.approxLogTime | Number | Approximate log time of the rule that triggered the case. | 
| ExabeamPlatform.Case.rules.ruleId | String | Unique identifier for the rule. | 
| ExabeamPlatform.Case.rules.ruleName | String | Name of the rule that triggered the case. | 
| ExabeamPlatform.Case.rules.ruleReason | String | Reason for the rule triggering the case. | 
| ExabeamPlatform.Case.rules.ruleSeverity | String | Severity level of the rule. | 
| ExabeamPlatform.Case.rules.ruleSource | String | Source of the rule. | 
| ExabeamPlatform.Case.rules.ruleType | String | Type of the rule. | 
| ExabeamPlatform.Case.srcHosts | Unknown | Source hosts involved in the case. | 
| ExabeamPlatform.Case.srcIps | Unknown | Source IP addresses involved in the case. | 
| ExabeamPlatform.Case.stage | String | Current stage of the case. | 
| ExabeamPlatform.Case.subscriptionCode | String | Subscription code associated with the case. | 
| ExabeamPlatform.Case.tags | Unknown | Tags associated with the case. | 
| ExabeamPlatform.Case.useCases | Unknown | Use cases associated with the case. | 
| ExabeamPlatform.Case.users | Unknown | Users involved in the case. | 
| ExabeamPlatform.Case.vendors | String | Vendors involved in the case. | 
| ExabeamPlatform.Case.alertCreationTimestamp | Date | Timestamp when the alert was created. | 
| ExabeamPlatform.Case.alertDescriptionRt | String | Description of the alert. | 
| ExabeamPlatform.Case.creationBy | String | User who created the case. | 
| ExabeamPlatform.Case.creationTimestamp | Date | Timestamp when the case was created. | 
| ExabeamPlatform.Case.destEndpoints | Unknown | Destination endpoints involved in the case. | 
| ExabeamPlatform.Case.mitres.tacticKey | String | Key of the MITRE tactic associated with the case. | 
| ExabeamPlatform.Case.mitres.technique | String | MITRE technique associated with the case. | 
| ExabeamPlatform.Case.mitres.techniqueKey | String | Key of the MITRE technique associated with the case. | 
