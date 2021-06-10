This integration runs queries and receives alarms from McAfee Enterprise Security Manager (ESM). Supports version 10 and above.
This integration was integrated and tested with version xx of McAfee ESM v2_copy
## Configure McAfee ESM v2_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for McAfee ESM v2_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL (e.g. https://example.com) |  | True |
    | Username |  | True |
    | Version: (one of 10.0, 10.1, 10.2, 10.3, 11.1, 11.3) |  | True |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Fetch Types: cases, alarms, both (relevant only for fetch incident mode) |  | False |
    | Start fetch after ID: (relevant only for fetch incident mode) |  | False |
    | Fetch cases limit |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
    | Fetch alarms limit |  | False |
    | McAfee ESM Timezone in hours (e.g if ESM timezone is +0300 =&gt; then insert 3) |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incidents Fetch Interval |  | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### esm-fetch-fields
***
Returns all fields that can be used in query filters, including type information for each field.


#### Base Command

`esm-fetch-fields`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-search
***
Perform a query against McAfee ESM SIEM.


#### Base Command

`esm-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeRange | The time period for the search. Can be LAST_3_DAYS, LAST_2_DAYS, LAST_24_HOURS, PREVIOUS_DAY, CURRENT_DAY, LAST_HOUR, LAST_30_MINUTES, LAST_10_MINUTES, LAST_MINUTE, CUSTOM, PREVIOUS_YEAR, CURRENT_YEAR, PREVIOUS_QUARTER, CURRENT_QUARTER, PREVIOUS_MONTH, CURRENT_MONTH, PREVIOUS_WEEK, or CURRENT_WEEK. Possible values are: LAST_3_DAYS, LAST_2_DAYS, LAST_24_HOURS, PREVIOUS_DAY, CURRENT_DAY, LAST_HOUR, LAST_30_MINUTES, LAST_10_MINUTES, LAST_MINUTE, CUSTOM, PREVIOUS_YEAR, CURRENT_YEAR, PREVIOUS_QUARTER, CURRENT_QUARTER, PREVIOUS_MONTH, CURRENT_MONTH, PREVIOUS_WEEK, CURRENT_WEEK. | Optional | 
| filters | Filters the query results in a JSON string, using the format EsmFilter (see - https://&lt;esm-ip&gt;:&lt;esm-port&gt;/rs/esm/help/types/EsmFilter). | Required | 
| queryType | Type of query to run. Can be "EVENT", "FLOW", or "ASSETS". Default is "EVENT". Possible values are: EVENT, FLOW, ASSETS. | Optional | 
| timeOut | Maximum time to wait before timeout (in minutes). Default is 30. | Optional | 
| customStart | If the timeRange argument is set to CUSTOM, the start time for the time range. For example: 2017-06-01T12:48:16.734Z. | Optional | 
| customEnd | If the timeRange argument is set to CUSTOM, the end time for the time range. For example: 2017-06-01T12:48:16.734Z. | Optional | 
| fields | The fields that will be selected when this query is executed. | Optional | 
| limit | Query results can be limited to a maximum row count. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-fetch-alarms
***
Retrieves a list of triggered alarms.


#### Base Command

`esm-fetch-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| timeRange | The time period for the search. Can be LAST_3_DAYS, LAST_2_DAYS, LAST_24_HOURS, PREVIOUS_DAY, CURRENT_DAY, LAST_HOUR, LAST_30_MINUTES, LAST_10_MINUTES, LAST_MINUTE, CUSTOM, PREVIOUS_YEAR, CURRENT_YEAR, PREVIOUS_QUARTER, CURRENT_QUARTER, PREVIOUS_MONTH, CURRENT_MONTH, PREVIOUS_WEEK, or CURRENT_WEEK. Possible values are: LAST_3_DAYS, LAST_2_DAYS, LAST_24_HOURS, PREVIOUS_DAY, CURRENT_DAY, LAST_HOUR, LAST_30_MINUTES, LAST_10_MINUTES, LAST_MINUTE, CUSTOM, PREVIOUS_YEAR, CURRENT_YEAR, PREVIOUS_QUARTER, CURRENT_QUARTER, PREVIOUS_MONTH, CURRENT_MONTH, PREVIOUS_WEEK, CURRENT_WEEK. | Optional | 
| customStart | If the timeRange argument is set to CUSTOM, the start time for the time range. For example: 2017-06-01T12:48:16.734Z. | Optional | 
| customEnd | If the timeRange argument is set to CUSTOM, the end time for the time range. For example: 2017-06-01T12:48:16.734Z. | Optional | 
| assignedUser | User assigned to handle the triggered alarm. Use the 'ME' option to use the instance user, or use format EsmUser as given by https://&lt;esm-ip&gt;:&lt;esm-port&gt;/rs/esm/help/types/EsmUser. . Possible values are: ME, . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Alarm.ID | number | Alarm ID. | 
| McAfeeESM.Alarm.summary | string | Alarm summary. | 
| McAfeeESM.Alarm.assignee | string | Alarm assignee. | 
| McAfeeESM.Alarm.severity | number | Alarm severity. | 
| McAfeeESM.Alarm.triggeredDate | date | Alarm triggered date. | 
| McAfeeESM.Alarm.acknowledgedDate | date | Alarm acknowledged date. | 
| McAfeeESM.Alarm.acknowledgedUsername | string | Alarm acknowledged username. | 
| McAfeeESM.Alarm.alarmName | string | Alarm name. | 
| McAfeeESM.Alarm.conditionType | number | Alarm condition type. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-get-case-list
***
Returns a list of cases from McAfee ESM.


#### Base Command

`esm-get-case-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| since | Filters cases that were opened before this date. In the format "&lt;number&gt;&lt;timeunit&gt;". For example, 1 day,30 minutes,2 weeks,6 months,1 year. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | Case ID. | 
| McAfeeESM.Case.Summary | string | The summary of the case. | 
| McAfeeESM.Case.Status | string | The status of the case. | 
| McAfeeESM.Case.OpenTime | date | The date and time when the case was opened. | 
| McAfeeESM.Case.Severity | number | The severity of the case. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-add-case
***
Adds a case to the system.


#### Base Command

`esm-add-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| summary | The name of the case. | Required | 
| status | The status of the case. Run the esm-get-case-statuses command to view all statuses. Default is Open. Default is Open. | Optional | 
| assignee | The user assigned to the case. Default is me. | Optional | 
| severity | The severity of the case (1 - 100). Default is 1. Default is 1. | Optional | 
| organization | The organization assigned to the case. Run the esm-get-organization-list command to view all organizations. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | The ID of the case. | 
| McAfeeESM.Case.Summary | string | The summary of the case. | 
| McAfeeESM.Case.Status | string | The status of the case. | 
| McAfeeESM.Case.OpenTime | date | The open time of the case. | 
| McAfeeESM.Case.Severity | number | The severity of the case. | 
| McAfeeESM.Case.Assignee | string | The assignee of the case. | 
| McAfeeESM.Case.Organization | string | The organization of the case. | 
| McAfeeESM.Case.EventList | Unknown | List of the case's events. | 
| McAfeeESM.Case.Notes | Unknown | List of the case's notes. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-edit-case
***
Edit the details of an existing case.


#### Base Command

`esm-edit-case`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the case. | Required | 
| summary | The name of the case. | Optional | 
| severity | The new severity of the case (1 - 100). | Optional | 
| assignee | The user assigned to the case. | Optional | 
| status | The new status of the case. Run the esm-get-case-statuses command to view all statuses. | Optional | 
| organization | The organization assigned to the case. Run the esm-get-organization-list command to view all organizations. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | The ID of the case. | 
| McAfeeESM.Case.Summary | string | The summary of the case. | 
| McAfeeESM.Case.Status | string | The status of the case. | 
| McAfeeESM.Case.OpenTime | date | The open time of the case. | 
| McAfeeESM.Case.Severity | number | The severity of the case. | 
| McAfeeESM.Case.Assignee | string | The assignee of the case. | 
| McAfeeESM.Case.Organization | string | The organization of the case. | 
| McAfeeESM.Case.EventList | Unknown | List of the case's events. | 
| McAfeeESM.Case.Notes | Unknown | List of the case's notes. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-get-case-statuses
***
Returns a list of valid case statuses from the system.


#### Base Command

`esm-get-case-statuses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-edit-case-status
***
Edits the status of a case.


#### Base Command

`esm-edit-case-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| original_name | The name of the case status to edit. | Required | 
| new_name | The new name for the case status. | Required | 
| show_in_case_pane | Whether the status will display in the case pane. Can be "True" or "False". Default is "True". Possible values are: True, False. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-get-case-detail
***
Returns the details of an existing case.


#### Base Command

`esm-get-case-detail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the case. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Case.ID | number | The ID of the case. | 
| McAfeeESM.Case.Summary | string | The summary of the case. | 
| McAfeeESM.Case.Status | string | The status of the case. | 
| McAfeeESM.Case.OpenTime | date | The open time of the case. | 
| McAfeeESM.Case.Severity | number | The severity of the case. | 
| McAfeeESM.Case.Assignee | string | The assignee of the case. | 
| McAfeeESM.Case.Organization | string | The organization of the case. | 
| McAfeeESM.Case.EventList | Unknown | List of the case's events. | 
| McAfeeESM.Case.Notes | Unknown | List of the case's notes. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-get-case-event-list
***
Returns case event details.


#### Base Command

`esm-get-case-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | Comma-separated list of event IDs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.CaseEvent.ID | string | The ID of the event. | 
| McAfeeESM.CaseEvent.LastTime | date | The time the event was last updated. | 
| McAfeeESM.CaseEvent.Message | string | The message of the event. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-add-case-status
***
Adds a status to the specified case.


#### Base Command

`esm-add-case-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the case status. | Required | 
| show_in_case_pane | Whether the status will display in the case pane. Can be "True" or "False". Default is "True". Possible values are: True, False. Default is True. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-delete-case-status
***
Deletes the status of a case.


#### Base Command

`esm-delete-case-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the case status to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-get-organization-list
***
Returns a case organization.


#### Base Command

`esm-get-organization-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Organization.ID | number | The organization ID. | 
| McAfeeESM.Organization.Name | string | The name of the organization. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-get-user-list
***
Returns a list of all users.


#### Base Command

`esm-get-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.User.ID | number | The ID of the user. | 
| McAfeeESM.User.Name | string | The ESM user name. | 
| McAfeeESM.User.Email | string | The email address of the user. | 
| McAfeeESM.User.SMS | string | The SMS details of the user. | 
| McAfeeESM.User.IsMaster | boolean | Whether the user is a master user. | 
| McAfeeESM.User.IsAdmin | boolean | Whether the user is an admin. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-acknowledge-alarms
***
Marks triggered alarms, as acknowledged.


#### Base Command

`esm-acknowledge-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmIds | Comma-separated list of triggered alarm IDs to be marked as acknowledged. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-unacknowledge-alarms
***
Marks triggered alarms, as unacknowledged.


#### Base Command

`esm-unacknowledge-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmIds | Comma-separated list of triggered alarm IDs to be marked, as unacknowledged. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-delete-alarms
***
Deletes triggered alarms.


#### Base Command

`esm-delete-alarms`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmIds | Comma-separated list of triggered alarm IDs to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-get-alarm-event-details
***
Gets the details for the triggered alarm.


#### Base Command

`esm-get-alarm-event-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| eventId | The event for which to get the details. Run the esm-list-alarm-events command to get the ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.AlarmEvent.ID | string | The event ID. | 
| McAfeeESM.AlarmEvent.SubType | string | The type of event. | 
| McAfeeESM.AlarmEvent.Severity | number | The severity of the event. | 
| McAfeeESM.AlarmEvent.Message | string | The message of the event. | 
| McAfeeESM.AlarmEvent.LastTime | date | The time of the event. | 
| McAfeeESM.AlarmEvent.SrcIP | string | The source IP address of the event. | 
| McAfeeESM.AlarmEvent.DstIP | string | The destination IP address of the event. | 
| McAfeeESM.AlarmEvent.Cases | Unknown | A list of cases related to the event. | 
| McAfeeESM.AlarmEvent.Cases.ID | string | The case ID. | 
| McAfeeESM.AlarmEvent.Cases.OpenTime | date | The creation time of the case. | 
| McAfeeESM.AlarmEvent.Cases.Severity | number | The severity of the case. | 
| McAfeeESM.AlarmEvent.Cases.Status | string | The status of the case. | 
| McAfeeESM.AlarmEvent.Cases.Summary | string | The summary of the case. | 
| McAfeeESM.AlarmEvent.DstMac | string | The destination MAC address of the event. | 
| McAfeeESM.AlarmEvent.SrcMac | string | The source MAC address of the event. | 
| McAfeeESM.AlarmEvent.DstPort | string | The destination port of the event. | 
| McAfeeESM.AlarmEvent.SrcPort | string | The source port of the event. | 
| McAfeeESM.AlarmEvent.FirstTime | date | The first time for the event. | 
| McAfeeESM.AlarmEvent.NormalizedDescription | string | The normalized description of the event. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-list-alarm-events
***
Gets a list of events related to the alarm.


#### Base Command

`esm-list-alarm-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alarmId | The alarm for which to get the details. Run the esm-fetch-alarms command to get the ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.AlarmEvent.ID | string | The event ID. | 
| McAfeeESM.AlarmEvent.SubType | string | The type of event. | 
| McAfeeESM.AlarmEvent.Severity | number | The severity of the event. | 
| McAfeeESM.AlarmEvent.Message | string | The message of the event. | 
| McAfeeESM.AlarmEvent.LastTime | date | The time of the event. | 
| McAfeeESM.AlarmEvent.SrcIP | string | The source IP address of the event. | 
| McAfeeESM.AlarmEvent.DstIP | string | The destination IP address of the event. | 
| McAfeeESM.AlarmEvent.Cases | Unknown | A list of cases related to the event. | 
| McAfeeESM.AlarmEvent.Cases.ID | string | The case ID. | 
| McAfeeESM.AlarmEvent.Cases.OpenTime | date | The creation time of the case. | 
| McAfeeESM.AlarmEvent.Cases.Severity | number | The severity of the case. | 
| McAfeeESM.AlarmEvent.Cases.Status | string | The status of the case.. | 
| McAfeeESM.AlarmEvent.Cases.Summary | string | The summary of the case. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-get-watchlists
***
Returns a list of watchlists' names and IDs.


#### Base Command

`esm-get-watchlists`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hidden | Whether to include hidden watchlists. Can be true or false. Possible values are: true, false. Default is true. | Required | 
| dynamic | Whether to include dynamic watchlists. Can be true or false. Possible values are: true, false. Default is true. | Required | 
| write_only | Whether to include write only watchlists. Can be true or false. Possible values are: true, false. Default is false. | Required | 
| indexed_only | Whether to include indexed only watchlists. Can be true or false. Possible values are: true, false. Default is false. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Watchlist.name | string | The name of the watchlist. | 
| McAfeeESM.Watchlist.id | number | The ID of the watchlist. | 
| McAfeeESM.Watchlist.type | string | The type of the watchlist. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-create-watchlist
***
Creates a new watchlist.


#### Base Command

`esm-create-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The new watchlist name. | Required | 
| type | The type of the new watchlist. Can be "IPAddress", "Hash", "SHA1", "DSIDSigID", "Port" "MacAddress", "NormID", "AppID", "CommandID", "DomainID" "HostID", "ObjectID", "Filename", or "File_Hash". Possible values are: IPAddress, Hash, SHA1, DSIDSigID, Port, MacAddress, NormID, AppID, CommandID, DomainID, HostID, ObjectID, Filename, File_Hash. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Watchlist.name | string | The name of the watchlist. | 
| McAfeeESM.Watchlist.id | number | The ID of the watchlist. | 
| McAfeeESM.Watchlist.type | string | The type of the watchlist. | 


#### Command Example
``` ```

#### Human Readable Output



### esm-delete-watchlist
***
Deletes a watchlist.


#### Base Command

`esm-delete-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ids | The watchlist IDs to delete. | Optional | 
| names | The watchlist names to delete. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-watchlist-add-entry
***
Creates a new watchlist entry.


#### Base Command

`esm-watchlist-add-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The watchlist name. | Optional | 
| watchlist_id | The watchlist ID. | Optional | 
| values | A comma separated list of values to add to a watchlist. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-watchlist-delete-entry
***
Deletes a watchlist entry.


#### Base Command

`esm-watchlist-delete-entry`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The watchlist name. | Optional | 
| watchlist_id | The watchlist ID. | Optional | 
| values | A comma separated list of values to remove from the watchlist. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### esm-watchlist-list-entries
***
Returns a list of watchlist entries.


#### Base Command

`esm-watchlist-list-entries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_name | The watchlist name. | Optional | 
| watchlist_id | The watchlist ID. | Optional | 
| limit | The maximum value count. Default is 50. Default is 50. | Required | 
| offset | The page of the results to retrieve. Default is 0. Default is 0. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| McAfeeESM.Watchlist.data | Unknown | The data of the watchlist. | 
| McAfeeESM.Watchlist.name | string | The name of the watchlist. | 


#### Command Example
``` ```

#### Human Readable Output


