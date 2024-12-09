Fetch alerts and events from SEKOIA.IO XDR.
To use this integration, please create an API Key with the appropriate permissions.
This integration was integrated and tested with version 1.0 of Sekoia XDR.

## Configure Sekoia XDR in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API key |  | True |
| API Key |  | True |
| Server URL (i.e. <https://api.sekoia.io>) |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;sign + or -&gt;&lt;number&gt;&lt;time unit&gt;, e.g., -7d, -1h) |  | True |
| Maximum incidents to fetch per interval. | By default the max_fetch is set to 10 | True |
| Incidents Fetch Interval |  | False |
| Alerts status. | Filter alerts to fetch by status. You can write and press enter to insert new types. | False |
| Alerts types. | Filter alerts to fetch by types. You can write and press enter to insert new types. | False |
| Alerts urgency levels  ( "MINurgency,MAXurgency".  i.e: 80,100 ). | Filter alerts by their urgency levels. Use the format "MINurgency, MAXurgency" | False |
| Fetch mode | If there's no max_fetch it will fetch 10 incidents by default. | True |
| Replace "dots" in event field names with another character. | Replacing dots in events will make names look pretty good for users | True |
| Events fields to exclude from the events search result. | These are the names of the headers presented in the events table. If the header is not in the dropdown list write it and press enter. | False |
| Include assets information in the alerts when fetching. | When selected, it includes the assets information in the alert when fetched from Sekoia.<br/>And also If there's no max_fetch it will fetch 10 incidents by default. | False |
| Include kill chain information in the alerts when fetching. | When selected, it includes the kill chain information in the alert when fetched from Sekoia.<br/>And also If there's no max_fetch it will fetch 10 incidents by default. | False |
| Incident Mirroring Direction. | Choose the direction to mirror the incident: None\(Disable mirroring\), Incoming \(from Sekoia XDR  to Cortex XSOAR\) , Outgoing \(from Cortex XSOAR to Sekoia XDR\), or Incoming and Outgoing \(from/to Cortex XSOAR and Sekoia XDR\). | True |
| Include events in the mirroring of the alerts. | When selected, it includes the events in the mirrored alerts when an alert is updated in Sekoia. | False |
| Include kill chain information in the mirroring of the alerts. | When selected, it includes the kill chain information of the alert in the mirrored alerts when an alert is updated in Sekoia. | False |
| Reopen Mirrored Cortex XSOAR Incidents (Incoming Mirroring) | When selected, reopening the Sekoia XDR alert will reopen the Cortex XSOAR incident. | False |
| Close Mirrored Cortex XSOAR Incidents (Incoming Mirroring) | When selected, closing the Sekoia XDR alert with a "Closed" or "Reject" status will close the Cortex XSOAR incident. | False |
| Close notes. | Change the closing notes that will be added to the tickets closed automatically by the automation. | True |
| Timezone ( TZ format ) | This will be used to present dates in the appropiate timezones,  used for comment timestamps, etc. | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### sekoia-xdr-list-alerts

***
Command to retrieve a list of Alerts from Sekoia XDR.

#### Base Command

`sekoia-xdr-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of alerts to return. The allowed range is 1-100, default is 20. Default is 20. | Optional | 
| status | Match alerts by their status name (separated by commas). Possible values are: Pending, Acknowledged, Ongoing, Rejected, Closed. | Optional | 
| created_at | Filter alerts by their creation dates, starting date followed by ending date, i.e:  "-3d,now" , "-1w,now" or "2023-01-15,2023-01-17". | Optional | 
| updated_at | Filter alerts by their update dates starting date followed by ending date, i.e:  "-3d,now" , "-1w,now" or "2023-01-15,2023-01-17". | Optional | 
| urgency | Filter alerts by their urgencies range in the following format: "MINurgency,MAXurgency". i.e: 80,100. | Optional | 
| Alerts type | Match alerts by their categories (separated by commas). Possible values are: spam, ddos, outage, phishing, unauthorized-use-of-resources, unauthorised-information-access, appscan, scanner, brute-force, exploit. | Optional | 
| sort_by | Sort the alerts by any information. Possible values are: created_at, updated_at, target, urgency, status. Default is created_at. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.ListAlerts.updated_at | unknown | The time at which the alert was updated. | 
| SekoiaXDR.ListAlerts.updated_by | unknown | The user who last updated the alert. | 
| SekoiaXDR.ListAlerts.uuid | unknown | The unique identifier of the alert. | 
| SekoiaXDR.ListAlerts.title | unknown | The title of the alert. | 
| SekoiaXDR.ListAlerts.time_to_respond | unknown | The time it took to respond to the alert. | 
| SekoiaXDR.ListAlerts.short_id | unknown | The short identifier of the alert. | 
| SekoiaXDR.ListAlerts.community_uuid | unknown | The unique identifier of the community associated with the alert. | 
| SekoiaXDR.ListAlerts.kill_chain_short_id | unknown | The short identifier of the kill chain associated with the alert. | 
| SekoiaXDR.ListAlerts.number_of_unseen_comments | unknown | The number of unseen comments on the alert. | 
| SekoiaXDR.ListAlerts.updated_by_type | unknown | The type of user who last updated the alert. | 
| SekoiaXDR.ListAlerts.source | unknown | The source of the alert. | 
| SekoiaXDR.ListAlerts.alert_type.value | unknown | The type of the alert. | 
| SekoiaXDR.ListAlerts.alert_type.category | unknown | The category type of the alert. | 
| SekoiaXDR.ListAlerts.time_to_acknowledge | unknown | The time it took to acknowledge the alert. | 
| SekoiaXDR.ListAlerts.stix | unknown | The STIX data associated with the alert. | 
| SekoiaXDR.ListAlerts.first_seen_at | unknown | The time the alert was first seen. | 
| SekoiaXDR.ListAlerts.ttps.type | unknown | The type of the TTP associated with the alert. | 
| SekoiaXDR.ListAlerts.ttps.name | unknown | The name of the TTP associated with the alert. | 
| SekoiaXDR.ListAlerts.ttps.id | unknown | The unique identifier of the TTP associated with the alert. | 
| SekoiaXDR.ListAlerts.ttps.description | unknown | The description of the TTP associated with the alert. | 
| SekoiaXDR.ListAlerts.adversaries.type | unknown | The type of the adversary associated with the alert. | 
| SekoiaXDR.ListAlerts.adversaries.name | unknown | The name of the adversary associated with the alert. | 
| SekoiaXDR.ListAlerts.adversaries.id | unknown | The unique identifier of the adversary associated with the alert. | 
| SekoiaXDR.ListAlerts.adversaries.description | unknown | The description of the adversary associated with the alert. | 
| SekoiaXDR.ListAlerts.time_to_ingest | unknown | The time it took to ingest the alert. | 
| SekoiaXDR.ListAlerts.target | unknown | The target of the alert. | 
| SekoiaXDR.ListAlerts.time_to_resolve | unknown | The time it took to resolve the alert. | 
| SekoiaXDR.ListAlerts.created_at | unknown | The time at which the alert was created. | 
| SekoiaXDR.ListAlerts.last_seen_at | unknown | The time at which the alert was last seen. | 
| SekoiaXDR.ListAlerts.assets | unknown | The assets associated with the alert. | 
| SekoiaXDR.ListAlerts.rule.severity | unknown | The severity level of the rule that triggered the alert. | 
| SekoiaXDR.ListAlerts.rule.type | unknown | The type of rule that triggered the alert. | 
| SekoiaXDR.ListAlerts.rule.uuid | unknown | The unique identifier of the rule that triggered the alert. | 
| SekoiaXDR.ListAlerts.rule.name | unknown | The name of the rule that triggered the alert. | 
| SekoiaXDR.ListAlerts.rule.description | unknown | The description of the rule that triggered the alert. | 
| SekoiaXDR.ListAlerts.rule.pattern | unknown | The pattern of the rule that triggered the alert. | 
| SekoiaXDR.ListAlerts.similar | unknown | The number of similar alerts to this one. | 
| SekoiaXDR.ListAlerts.status.name | unknown | The name of the status of the alert. | 
| SekoiaXDR.ListAlerts.status.description | unknown | The description of the status of the alert. | 
| SekoiaXDR.ListAlerts.status.uuid | unknown | The unique identifier of the status of the alert. | 
| SekoiaXDR.ListAlerts.urgency.criticity | unknown | The level of criticity of the urgency of the alert. | 
| SekoiaXDR.ListAlerts.urgency.current_value | unknown | The current value of the urgency of the alert. | 
| SekoiaXDR.ListAlerts.urgency.severity | unknown | The severity level of the urgency of the alert. | 
| SekoiaXDR.ListAlerts.urgency.display | unknown | The display of the urgency of the alert. | 
| SekoiaXDR.ListAlerts.urgency.value | unknown | The value of the urgency of the alert. | 
| SekoiaXDR.ListAlerts.created_by | unknown | The user who created the alert. | 
| SekoiaXDR.ListAlerts.number_of_total_comments | unknown | The total number of comments on the alert. | 
| SekoiaXDR.ListAlerts.time_to_detect | unknown | The time it took to detect the alert. | 
| SekoiaXDR.ListAlerts.entity.name | unknown | The name of the entity associated with the alert. | 
| SekoiaXDR.ListAlerts.entity.uuid | unknown | The unique identifier of the entity associated with the alert. | 
| SekoiaXDR.ListAlerts.created_by_type | unknown | The type of user who created the alert. | 
| SekoiaXDR.ListAlerts.details | unknown | The details of the alert. | 

### sekoia-xdr-get-alert

***
Command to retrieve a specific alert by uuid or short_id from Sekoia XDR.

#### Base Command

`sekoia-xdr-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The uuid or short_id of the alert to retrieve from sekoia-xdr-list-alerts or from sekoia plateform. i.e: "f5dcb81c-8d81-4332-9f1e-f119a1b31217" or "ALUnyZCYZ9Ga". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Alert.short_id | string | Short ID of the alert. | 
| SekoiaXDR.Alert.title | string | Title of the alert. | 
| SekoiaXDR.Alert.urgency | string | urgency of the alert. | 

### sekoia-xdr-events-execute-query

***
Command to create an event search job on Sekoia XDR, after this execute "sekoia-xdr-status-events-query" to see the status of the query job and "sekoia-xdr-results-events-query" to retrieve the results..

#### Base Command

`sekoia-xdr-events-execute-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| earliest_time | Valid formats &lt;sign + or -&gt;&lt;number&gt;&lt;time unit&gt; or ISO 8601 e.g -3d, -2w, -7d, 2023-01-15T00:00:00Z. | Required | 
| lastest_time | Valid formats &lt;sign + or -&gt;&lt;number&gt;&lt;time unit&gt; or ISO 8601 e.g +3d, +2w, now, 2023-01-15T00:00:00Z. | Required | 
| query | The query to use, i.e: "alert_short_ids:ALUnyZCYZ9Ga". | Optional | 
| max_last_events | Maximum number of listed events. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Events.Query.uuid | unknown | The unique identifier for the event. | 
| SekoiaXDR.Events.Query.term | unknown | The search term associated with the event. | 
| SekoiaXDR.Events.Query.started_at | unknown | The time at which the event started. | 
| SekoiaXDR.Events.Query.short_histogram.cases | unknown | The number of cases associated with the event. | 
| SekoiaXDR.Events.Query.short_histogram.total | unknown | The total number of events associated with the search term. | 
| SekoiaXDR.Events.Query.short_histogram.alerts | unknown | The number of alerts associated with the event. | 
| SekoiaXDR.Events.Query.short_histogram.earliest_time | unknown | The earliest time associated with the event. | 
| SekoiaXDR.Events.Query.short_histogram.length | unknown | The length of the histogram for the event. | 
| SekoiaXDR.Events.Query.created_by | unknown | The user who created the event. | 
| SekoiaXDR.Events.Query.expired | unknown | A boolean indicating whether the event has expired. | 
| SekoiaXDR.Events.Query.latest_time | unknown | The latest time associated with the event. | 
| SekoiaXDR.Events.Query.expiration_date | unknown | The date on which the event will expire. | 
| SekoiaXDR.Events.Query.created_at | unknown | The time at which the event was created. | 
| SekoiaXDR.Events.Query.status | unknown | The status of the event. | 
| SekoiaXDR.Events.Query.view_uuid | unknown | The unique identifier for the view associated with the event. | 
| SekoiaXDR.Events.Query.canceled_at | unknown | The time at which the event was canceled. | 
| SekoiaXDR.Events.Query.only_eternal | unknown | A boolean indicating whether the event is only eternal. | 
| SekoiaXDR.Events.Query.results_ttl | unknown | The time-to-live for the event results. | 
| SekoiaXDR.Events.Query.canceled_by | unknown | The user who canceled the event. | 
| SekoiaXDR.Events.Query.term_lang | unknown | The language of the search term associated with the event. | 
| SekoiaXDR.Events.Query.ended_at | unknown | The time at which the event ended. | 
| SekoiaXDR.Events.Query.earliest_time | unknown | The earliest time associated with the event. | 
| SekoiaXDR.Events.Query.max_last_events | unknown | The maximum number of events to include in the results. | 
| SekoiaXDR.Events.Query.canceled_by_type | unknown | The type of the user who canceled the event. | 
| SekoiaXDR.Events.Query.total | unknown | The total number of events associated with the event. | 
| SekoiaXDR.Events.Query.created_by_type | unknown | The type of the user who created the event. | 
| SekoiaXDR.Events.Query.community_uuids | unknown | The list of community UUIDs associated with the event. | 
| SekoiaXDR.Events.Query.filters.field | unknown | The field associated with the filter. | 
| SekoiaXDR.Events.Query.filters.value | unknown | The value associated with the filter. | 
| SekoiaXDR.Events.Query.filters.operator | unknown | The operator used in the filter. | 
| SekoiaXDR.Events.Query.filters.excluded | unknown | Indicates whether the filter is excluded or not. | 
| SekoiaXDR.Events.Query.filters.disabled | unknown | Indicates whether the filter is disabled or not. | 

### sekoia-xdr-events-status-query

***
Command to query the status of the search job on Sekoia XDR.

#### Base Command

`sekoia-xdr-events-status-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the query executed previously with the "sekoia-xdr-query-events" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Events.Status.uuid | unknown | The unique identifier for the event. | 
| SekoiaXDR.Events.Status.term | unknown | The term associated with the event. | 
| SekoiaXDR.Events.Status.started_at | unknown | The time at which the event started. | 
| SekoiaXDR.Events.Status.short_histogram.cases | unknown | The number of cases associated with the event. | 
| SekoiaXDR.Events.Status.short_histogram.total | unknown | The total number of events associated with the event. | 
| SekoiaXDR.Events.Status.short_histogram.alerts | unknown | The number of alerts associated with the event. | 
| SekoiaXDR.Events.Status.short_histogram.earliest_time | unknown | The earliest time associated with the event. | 
| SekoiaXDR.Events.Status.short_histogram.length | unknown | The length associated with the event. | 
| SekoiaXDR.Events.Status.created_by | unknown | The user who created the event. | 
| SekoiaXDR.Events.Status.expired | unknown | Whether the event is expired. | 
| SekoiaXDR.Events.Status.latest_time | unknown | The latest time associated with the event. | 
| SekoiaXDR.Events.Status.expiration_date | unknown | The date when the event expires. | 
| SekoiaXDR.Events.Status.created_at | unknown | The time when the event was created. | 
| SekoiaXDR.Events.Status.status | unknown | The current status of the event. | 
| SekoiaXDR.Events.Status.view_uuid | unknown | The view associated with the event. | 
| SekoiaXDR.Events.Status.canceled_at | unknown | The time when the event was canceled. | 
| SekoiaXDR.Events.Status.only_eternal | unknown | Whether only eternal events are associated with the event. | 
| SekoiaXDR.Events.Status.results_ttl | unknown | The time-to-live for the event results. | 
| SekoiaXDR.Events.Status.canceled_by | unknown | The user who canceled the event. | 
| SekoiaXDR.Events.Status.term_lang | unknown | The language associated with the term for the event. | 
| SekoiaXDR.Events.Status.ended_at | unknown | The time when the event ended. | 
| SekoiaXDR.Events.Status.earliest_time | unknown | The earliest time associated with the event. | 
| SekoiaXDR.Events.Status.max_last_events | unknown | The maximum number of events to retrieve. | 
| SekoiaXDR.Events.Status.canceled_by_type | unknown | The type of user who canceled the event. | 
| SekoiaXDR.Events.Status.total | unknown | The total number of events associated with the event. | 
| SekoiaXDR.Events.Status.created_by_type | unknown | The type of user who created the event. | 
| SekoiaXDR.Events.Status.community_uuids[0] | unknown | The community associated with the event. | 
| SekoiaXDR.Events.Status.filters.field | unknown | The field used for filtering events. | 
| SekoiaXDR.Events.Status.filters.field | unknown | The field used in the filter. | 
| SekoiaXDR.Events.Status.filters.value | unknown | The value of the filter. | 
| SekoiaXDR.Events.Status.filters.operator | unknown | The operator used in the filter. | 
| SekoiaXDR.Events.Status.filters.excluded | unknown | A boolean indicating whether the filter is excluded or not. | 
| SekoiaXDR.Events.Status.filters.disabled | unknown | A boolean indicating whether the filter is disabled or not. | 

### sekoia-xdr-events-results-query

***
Command to retrieve the events from the search job "sekoia-xdr-execute-events-query" previously done on Sekoia XDR.

#### Base Command

`sekoia-xdr-events-results-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID from response of the query executed previously with the "sekoia-xdr-query-events" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Events.Results | unknown | The outputs are different for each event, they will be output inside SekoiaXDR.Events.Results. | 

### sekoia-xdr-search-events

***
Command to search and retrieve the events from an alert. This is a combination of 3 commands: sekoia-xdr-events-execute-query, sekoia-xdr-events-status-query and sekoia-xdr-events-results-query.

#### Base Command

`sekoia-xdr-search-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| earliest_time | Valid formats &lt;sign + or -&gt;&lt;number&gt;&lt;time unit&gt; or ISO 8601 e.g -3d, -2w, -7d, 2023-01-15T00:00:00Z. | Required | 
| lastest_time | Valid formats &lt;sign + or -&gt;&lt;number&gt;&lt;time unit&gt; or ISO 8601 e.g +3d, +2w, now, 2023-01-15T00:00:00Z. | Required | 
| query | The query to use, i.e: "alert_short_ids:ALUnyZCYZ9Ga". | Optional | 
| max_last_events | Maximum number of listed events. | Optional | 
| exclude_info | Indicate if there is any information you want to exclude from the results of the events.  i.e:  original.message, message,  agent.name, etc. These are the names of the headers presented in the table. If the header you want to exclude is not in the list write it and press enter. Possible values are: original.message, message, __event_id, agent.name, alert_short_ids, client.address, client.ip, client.user.id, customer.community_name, customer.community_uuid, customer.id, customer.intake_key, customer.intake_name, customer.intake_uuid, ecs.version, entity.id, entity.name, entity.uuid, event.created, event.dialect, event.dialect_uuid, event.id, event.outcome, http.request.method, http.request.referrer, related.ip, sekoiaio.activity.client.id, sekoiaio.activity.client.type, sekoiaio.customer.community_name, sekoiaio.customer.community_uuid, sekoiaio.customer.id, sekoiaio.entity.id, sekoiaio.entity.name, sekoiaio.entity.uuid, sekoiaio.intake.dialect, sekoiaio.intake.dialect_uuid, sekoiaio.intake.key, sekoiaio.intake.name, sekoiaio.intake.parsing_status, sekoiaio.intake.uuid, timestamp, url.domain, url.original, url.path, url.port, url.query, url.registered_domain, url.scheme, url.subdomain, url.top_level_domain, user_agent.original. | Optional | 
| job_uuid | The job UUID to retrieve query results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Events.Results | unknown | The outputs are different for each event, they will be output inside SekoiaXDR.Events.Results. | 

### sekoia-xdr-update-status-alert

***
Command to update the status of a specific Alert by uuid or short_id.

#### Base Command

`sekoia-xdr-update-status-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The uuid or short_id of the alert to retrieve from sekoia-xdr-list-alerts or from sekoia plateform. i.e: "f5dcb81c-8d81-4332-9f1e-f119a1b31217" or "ALUnyZCYZ9Ga". | Required | 
| status | The status you want to apply. (Acknowledged, Rejected, Ongoing, Closed)). Possible values are: Acknowledged, Rejected, Ongoing, Closed. | Required | 
| comment | Comment to describe why the alert status has changed. | Optional | 

#### Context Output

There is no context output for this command.

### sekoia-xdr-post-comment-alert

***
Command to post comments to alerts in Sekoia XDR.

#### Base Command

`sekoia-xdr-post-comment-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The uuid or short_id of the alert to retrieve from sekoia-xdr-list-alerts command. i.e: "f5dcb81c-8d81-4332-9f1e-f119a1b31217" or "ALUnyZCYZ9Ga". | Required | 
| comment | Content of the comment to be posted on the alert. | Required | 
| author | Author of the comment. | Optional | 

#### Context Output

There is no context output for this command.

### sekoia-xdr-get-comments

***
Command to get all the comments from an alert in Sekoia XDR.

#### Base Command

`sekoia-xdr-get-comments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The uuid or short_id of the alert to retrieve from sekoia-xdr-list-alerts command or from sekoia plateform. i.e: "f5dcb81c-8d81-4332-9f1e-f119a1b31217" or "ALUnyZCYZ9Ga". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Comments.total | unknown | The total number of items in the comments. | 
| SekoiaXDR.Comments.items.date | unknown | The date at which the comment was created. | 
| SekoiaXDR.Comments.items.created_by | unknown | The user who created the comment. | 
| SekoiaXDR.Comments.items.uuid | unknown | The unique identifier for the comment. | 
| SekoiaXDR.Comments.items.content | unknown | The content of the comment. | 
| SekoiaXDR.Comments.items.created_by_type | unknown | The type of the user who created the comment. | 
| SekoiaXDR.Comments.items.unseen | unknown | Indicates whether the comment has been seen by the user. | 
| SekoiaXDR.Comments.items.author | unknown | The author of the comment. | 

### sekoia-xdr-get-workflow-alert

***
Command to get the possible transitions of status on the alert.

#### Base Command

`sekoia-xdr-get-workflow-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The uuid or short_id of the alert to retrieve from sekoia-xdr-list-alerts command or from sekoia plateform. i.e: "f5dcb81c-8d81-4332-9f1e-f119a1b31217" or "ALUnyZCYZ9Ga". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.StatusTransitions.actions.name | unknown | The name of the action. | 
| SekoiaXDR.StatusTransitions.actions.description | unknown | The description of the action. | 
| SekoiaXDR.StatusTransitions.actions.id | unknown | The ID of the action. | 

### sekoia-xdr-get-cases-alert

***
Command to retrieve the cases related to an Alert from Sekoia XDR. If a case_id is given, returns the information about it, and if not it will give all cases in this alert.

#### Base Command

`sekoia-xdr-get-cases-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The uuid or short_id of the alert to retrieve from sekoia-xdr-list-alerts command or from sekoia plateform. i.e: "f5dcb81c-8d81-4332-9f1e-f119a1b31217" or "ALUnyZCYZ9Ga". | Required | 
| case_id | The short_id of the case to retrieve from sekoia plateform or from this command without case_is param i.e: "CAQNurTJM8q2". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Cases.updated_at | unknown | The time at which the case was updated. | 
| SekoiaXDR.Cases.updated_by | unknown | The user who updated the case. | 
| SekoiaXDR.Cases.uuid | unknown | The unique identifier of the case. | 
| SekoiaXDR.Cases.title | unknown | The title of the case. | 
| SekoiaXDR.Cases.priority | unknown | The priority level of the case. | 
| SekoiaXDR.Cases.short_id | unknown | The short ID of the case. | 
| SekoiaXDR.Cases.community_uuid | unknown | The unique identifier of the community to which the case belongs. | 
| SekoiaXDR.Cases.updated_by_type | unknown | The type of user who updated the case. | 
| SekoiaXDR.Cases.first_seen_at | unknown | The time at which the case was first seen. | 
| SekoiaXDR.Cases.number_of_comments | unknown | The number of comments on the case. | 
| SekoiaXDR.Cases.alerts.updated_at | unknown | The time at which the alert was updated. | 
| SekoiaXDR.Cases.alerts.updated_by | unknown | The user who updated the alert. | 
| SekoiaXDR.Cases.alerts.uuid | unknown | The unique identifier of the alert. | 
| SekoiaXDR.Cases.alerts.title | unknown | The title of the alert. | 
| SekoiaXDR.Cases.alerts.time_to_respond | unknown | The time it took to respond to the alert. | 
| SekoiaXDR.Cases.alerts.short_id | unknown | The short ID of the alert. | 
| SekoiaXDR.Cases.alerts.community_uuid | unknown | The unique identifier of the community to which the alert belongs. | 
| SekoiaXDR.Cases.alerts.kill_chain_short_id | unknown | The short ID of the kill chain. | 
| SekoiaXDR.Cases.alerts.number_of_unseen_comments | unknown | The number of unseen comments on the alert. | 
| SekoiaXDR.Cases.alerts.updated_by_type | unknown | The type of user who updated the alert. | 
| SekoiaXDR.Cases.alerts.source | unknown | The source of the alert. | 
| SekoiaXDR.Cases.alerts.alert_type.value | unknown | The type of the alert. | 
| SekoiaXDR.Cases.alerts.alert_type.category | unknown | The category type of the alert. | 
| SekoiaXDR.Cases.alerts.time_to_acknowledge | unknown | The time it took to acknowledge the alert. | 
| SekoiaXDR.Cases.alerts.stix | unknown | The STIX data of the alert. | 
| SekoiaXDR.Cases.alerts.first_seen_at | unknown | The time at which the alert was first seen. | 
| SekoiaXDR.Cases.alerts.ttps.type | unknown | The type of TTP associated with the alert. | 
| SekoiaXDR.Cases.alerts.ttps.name | unknown | The name of the TTP associated with the alert. | 
| SekoiaXDR.Cases.alerts.ttps.id | unknown | The ID of the TTP associated with the alert. | 
| SekoiaXDR.Cases.alerts.ttps.description | unknown | The description of the TTP associated with the alert. | 
| SekoiaXDR.Cases.alerts.adversaries.type | unknown | The type of adversary associated with the alert. | 
| SekoiaXDR.Cases.alerts.adversaries.name | unknown | The name of the adversary associated with the alert. | 
| SekoiaXDR.Cases.alerts.adversaries.id | unknown | The ID of the adversary associated with the alert. | 
| SekoiaXDR.Cases.alerts.adversaries.description | unknown | The description of the adversary associated with the alert. | 
| SekoiaXDR.Cases.alerts.time_to_ingest | unknown | The time it took to ingest the alert. | 
| SekoiaXDR.Cases.alerts.target | unknown | The target of the alert. | 
| SekoiaXDR.Cases.alerts.time_to_resolve | unknown | The time it took to resolve the alert. | 
| SekoiaXDR.Cases.alerts.created_at | unknown | The time at which the alert was created. | 
| SekoiaXDR.Cases.alerts.last_seen_at | unknown | The time at which the alert was last seen. | 
| SekoiaXDR.Cases.alerts.assets | unknown | The assets associated with the alert. | 
| SekoiaXDR.Cases.alerts.rule.severity | unknown | The severity level of the rule associated with the alert. | 
| SekoiaXDR.Cases.alerts.rule.type | unknown | The type of rule associated with the alert. | 
| SekoiaXDR.Cases.alerts.rule.uuid | unknown | The unique identifier of the rule associated with the alert. | 
| SekoiaXDR.Cases.alerts.rule.name | unknown | The name of the rule associated with the alert. | 
| SekoiaXDR.Cases.alerts.rule.description | unknown | The description of the rule associated with the alert. | 
| SekoiaXDR.Cases.alerts.rule.pattern | unknown | The pattern of the rule associated with the alert. | 
| SekoiaXDR.Cases.alerts.similar | unknown | The number of similar alerts. | 
| SekoiaXDR.Cases.alerts.status.name | unknown | The name of the status of the alert. | 
| SekoiaXDR.Cases.alerts.status.description | unknown | The description of the status of the alert. | 
| SekoiaXDR.Cases.alerts.status.uuid | unknown | The unique identifier of the status of the alert. | 
| SekoiaXDR.Cases.alerts.urgency.criticity | unknown | The level of criticality of the urgency of the alert. | 
| SekoiaXDR.Cases.alerts.urgency.current_value | unknown | The current value of the urgency of the alert. | 
| SekoiaXDR.Cases.alerts.urgency.severity | unknown | The severity level of the urgency of the alert. | 
| SekoiaXDR.Cases.alerts.urgency.display | unknown | The display value of the urgency of the alert. | 
| SekoiaXDR.Cases.alerts.urgency.value | unknown | The value of the urgency of the alert. | 
| SekoiaXDR.Cases.alerts.created_by | unknown | The user who created the alert. | 
| SekoiaXDR.Cases.alerts.number_of_total_comments | unknown | The total number of comments on the alert. | 
| SekoiaXDR.Cases.alerts.time_to_detect | unknown | The time it took to detect the alert. | 
| SekoiaXDR.Cases.alerts.entity.name | unknown | The name of the entity associated with the alert. | 
| SekoiaXDR.Cases.alerts.entity.uuid | unknown | The unique identifier of the entity associated with the alert. | 
| SekoiaXDR.Cases.alerts.created_by_type | unknown | The type of user who created the alert. | 
| SekoiaXDR.Cases.alerts.details | unknown | The details of the alert. | 
| SekoiaXDR.Cases.number_of_alerts | unknown | The number of alerts in the case. | 
| SekoiaXDR.Cases.created_at | unknown | The time at which the case was created. | 
| SekoiaXDR.Cases.last_seen_at | unknown | The time at which the case was last seen. | 
| SekoiaXDR.Cases.status | unknown | The status of the case. | 
| SekoiaXDR.Cases.description | unknown | The description of the case. | 
| SekoiaXDR.Cases.status_uuid | unknown | The unique identifier of the status of the case. | 
| SekoiaXDR.Cases.created_by | unknown | The user who created the case. | 
| SekoiaXDR.Cases.tags | unknown | The tags associated with the case. | 
| SekoiaXDR.Cases.created_by_type | unknown | The type of user who created the case. | 
| SekoiaXDR.Cases.subscribers.avatar_uuid | unknown | The unique identifier of the avatar of the subscriber. | 
| SekoiaXDR.Cases.subscribers.type | unknown | The type of subscriber. | 

### sekoia-xdr-get-asset

***
Get an asset by its UUID from Sekoia XDR.

#### Base Command

`sekoia-xdr-get-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_uuid | UUID of the asset to get, the UUID should appear with "sekoia-xdr-list-assets" if that alert have assets related, example: "d4cc3b05-a78d-4f29-b27c-c637d86fa03a". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Asset.owners | unknown | The owners of the asset. | 
| SekoiaXDR.Asset.category.types.description | unknown | The description of the category type of the asset. | 
| SekoiaXDR.Asset.category.types.name | unknown | The name of the category type of the asset. | 
| SekoiaXDR.Asset.category.types.uuid | unknown | The UUID of the category type of the asset. | 
| SekoiaXDR.Asset.category.description | unknown | The description of the category of the asset. | 
| SekoiaXDR.Asset.category.name | unknown | The name of the category of the asset. | 
| SekoiaXDR.Asset.category.uuid | unknown | The UUID of the category of the asset. | 
| SekoiaXDR.Asset.created_at | unknown | The time at which the asset was created. | 
| SekoiaXDR.Asset.keys.value | unknown | The value of the keys of the asset. | 
| SekoiaXDR.Asset.keys.name | unknown | The name of the keys of the asset. | 
| SekoiaXDR.Asset.keys.uuid | unknown | The UUID of the keys of the asset. | 
| SekoiaXDR.Asset.attributes.value | unknown | The value of the attributes of the asset. | 
| SekoiaXDR.Asset.attributes.name | unknown | The name of the attributes of the asset. | 
| SekoiaXDR.Asset.attributes.uuid | unknown | The UUID of the attributes of the asset. | 
| SekoiaXDR.Asset.updated_at | unknown | The time at which the asset was updated. | 
| SekoiaXDR.Asset.asset_type.description | unknown | The description of the asset type. | 
| SekoiaXDR.Asset.asset_type.name | unknown | The name of the asset type. | 
| SekoiaXDR.Asset.asset_type.uuid | unknown | The UUID of the asset type. | 
| SekoiaXDR.Asset.criticity.value | unknown | The criticality value of the asset. | 
| SekoiaXDR.Asset.criticity.display | unknown | The display value of the criticality of the asset. | 
| SekoiaXDR.Asset.description | unknown | The description of the asset. | 
| SekoiaXDR.Asset.community_uuid | unknown | The UUID of the community of the asset. | 
| SekoiaXDR.Asset.name | unknown | The name of the asset. | 
| SekoiaXDR.Asset.uuid | unknown | The UUID of the asset. | 

### get-remote-data

***
This command gets new information about the incidents in the remote system and updates existing incidents in Cortex XSOAR.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote alert ID. | Optional | 
| lastUpdate | ISO format date with timezone, e.g., 2023-03-01T16:41:30.589575+02:00. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
available from Cortex XSOAR version 6.1.0. This command queries for incidents that were modified since the last update.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | ISO format date with timezone, e.g., 2023-03-01T16:41:30.589575+02:00. The incident is only returned if it was modified after the last update time. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
This command pulls the remote schema for the different incident types, and their associated incident fields, from the remote system.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### sekoia-xdr-list-assets

***
Command to retrieve a list of Assets from Sekoia XDR.

#### Base Command

`sekoia-xdr-list-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit a number of items. Default is 10. | Optional | 
| assets_type | Type of assets to list (computer, network, etc). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.Assets.total | unknown | The total number of items in the response. | 
| SekoiaXDR.Assets.items.0.owners.0 | unknown | The ID of the owner of the asset. | 
| SekoiaXDR.Assets.items.0.category.types.0.description | unknown | The description of the type of the asset category. | 
| SekoiaXDR.Assets.items.0.category.types.0.name | unknown | The name of the type of the asset category. | 
| SekoiaXDR.Assets.items.0.category.types.0.uuid | unknown | The UUID of the type of the asset category. | 
| SekoiaXDR.Assets.items.0.category.description | unknown | The description of the asset category. | 
| SekoiaXDR.Assets.items.0.category.name | unknown | The name of the asset category. | 
| SekoiaXDR.Assets.items.0.category.uuid | unknown | The UUID of the asset category. | 
| SekoiaXDR.Assets.items.0.created_at | unknown | The time at which the asset was created. | 
| SekoiaXDR.Assets.items.0.keys.0.value | unknown | The value of the asset key. | 
| SekoiaXDR.Assets.items.0.keys.0.name | unknown | The name of the asset key. | 
| SekoiaXDR.Assets.items.0.keys.0.uuid | unknown | The UUID of the asset key. | 
| SekoiaXDR.Assets.items.0.attributes.0.value | unknown | The value of the asset attribute. | 
| SekoiaXDR.Assets.items.0.attributes.0.name | unknown | The name of the asset attribute. | 
| SekoiaXDR.Assets.items.0.attributes.0.uuid | unknown | The UUID of the asset attribute. | 
| SekoiaXDR.Assets.items.0.updated_at | unknown | The time at which the asset was last updated. | 
| SekoiaXDR.Assets.items.0.asset_type.description | unknown | The description of the asset type. | 
| SekoiaXDR.Assets.items.0.asset_type.name | unknown | The name of the asset type. | 
| SekoiaXDR.Assets.items.0.asset_type.uuid | unknown | The UUID of the asset type. | 
| SekoiaXDR.Assets.items.0.criticity.value | unknown | The numeric value of the asset criticality. | 
| SekoiaXDR.Assets.items.0.criticity.display | unknown | The display value of the asset criticality. | 
| SekoiaXDR.Assets.items.0.description | unknown | The description of the asset. | 
| SekoiaXDR.Assets.items.0.community_uuid | unknown | The UUID of the community to which the asset belongs. | 
| SekoiaXDR.Assets.items.0.name | unknown | The name of the asset. | 
| SekoiaXDR.Assets.items.0.uuid | unknown | The UUID of the asset. | 

### sekoia-xdr-get-user

***
Command to get information about a user in Sekoia XDR. Used also in the command !sekoia-xdr-get-comments to have the name of the persons who made the comments.

#### Base Command

`sekoia-xdr-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_uuid | UUID of the user, you get it from `sekoia-xdr-get-comments` for example. But make sure that `created_by_type` field is `user`. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.User.creator.description | unknown | The description of the creator. | 
| SekoiaXDR.User.creator.name | unknown | The name of the creator. | 
| SekoiaXDR.User.creator.uuid | unknown | The UUID of the creator. | 
| SekoiaXDR.User.updated_at | unknown | The time at which the object was last updated. | 
| SekoiaXDR.User.created_by | unknown | The UUID of the user who created the object. | 
| SekoiaXDR.User.total_members | unknown | The total number of members in the community. | 
| SekoiaXDR.User.subcommunities | unknown | The UUIDs of the subcommunities. | 
| SekoiaXDR.User.parent_community_uuid | unknown | The UUID of the parent community. | 
| SekoiaXDR.User.applications.description | unknown | The description of the application. | 
| SekoiaXDR.User.applications.name | unknown | The name of the application. | 
| SekoiaXDR.User.applications.uuid | unknown | The UUID of the application. | 
| SekoiaXDR.User.is_parent | unknown | Whether the community is a parent community. | 
| SekoiaXDR.User.name | unknown | The name of the community. | 
| SekoiaXDR.User.members.uuid | unknown | The UUID of the member. | 
| SekoiaXDR.User.members.created_at | unknown | The time at which the member was created. | 
| SekoiaXDR.User.members.user.firstname | unknown | The first name of the user associated with the member. | 
| SekoiaXDR.User.members.user.mfa_enabled | unknown | Whether multi-factor authentication is enabled for the user associated with the member. | 
| SekoiaXDR.User.members.user.uuid | unknown | The UUID of the user associated with the member. | 
| SekoiaXDR.User.members.user.company_name | unknown | The company name of the user associated with the member. | 
| SekoiaXDR.User.members.user.lastname | unknown | The last name of the user associated with the member. | 
| SekoiaXDR.User.members.user.created_at | unknown | The time at which the user associated with the member was created. | 
| SekoiaXDR.User.members.user.picture_mode | unknown | The picture mode of the user associated with the member. | 
| SekoiaXDR.User.members.user.last_activity | unknown | The last activity time of the user associated with the member. | 
| SekoiaXDR.User.members.user.updated_at | unknown | The time at which the user associated with the member was last updated. | 
| SekoiaXDR.User.members.user.auth_provider | unknown | The authentication provider of the user associated with the member. | 
| SekoiaXDR.User.members.user.email | unknown | The email address of the user associated with the member. | 
| SekoiaXDR.User.members.user.invitation_v2.email | unknown | The email address for the invitation associated with the user associated with the member. | 
| SekoiaXDR.User.members.name | unknown | The name of the member. | 
| SekoiaXDR.User.members.updated_at | unknown | The time at which the member was last updated. | 
| SekoiaXDR.User.members.status_changed_at | unknown | The time at which the status of the member was last changed. | 
| SekoiaXDR.User.members.status | unknown | The status of the member. | 
| SekoiaXDR.User.session_timeout | unknown | The session timeout for the community. | 
| SekoiaXDR.User.is_mfa_enforced | unknown | Whether multi-factor authentication is enforced for the community. | 
| SekoiaXDR.User.uuid | unknown | The UUID of the community. | 
| SekoiaXDR.User.created_at | unknown | The time at which the community was created. | 
| SekoiaXDR.User.picture_mode | unknown | The picture mode for the community. | 
| SekoiaXDR.User.homepage_url | unknown | The homepage URL for the community. | 
| SekoiaXDR.User.created_by_type | unknown | The type of the user who created the community. | 
| SekoiaXDR.User.disable_inactive_avatars | unknown | Whether inactive avatars are disabled for the community. | 
| SekoiaXDR.User.description | unknown | The description of the community. | 

### sekoia-xdr-add-attributes-asset

***
Command to add attributes to an asset in Sekoia XDR.

#### Base Command

`sekoia-xdr-add-attributes-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_uuid | UUID of the asset to get, the UUID should appear with "sekoia-xdr-list-assets" if that alert have assets related, example: "d4cc3b05-a78d-4f29-b27c-c637d86fa03a". | Required | 
| name | The name of attributes. | Required | 
| value | The value of attributes. | Required | 

#### Context Output

There is no context output for this command.

### sekoia-xdr-add-keys-asset

***
Command to add keys to an asset in Sekoia XDR.

#### Base Command

`sekoia-xdr-add-keys-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_uuid | UUID of the asset to get, the UUID should appear with "sekoia-xdr-list-assets" if that alert have assets related, example: "d4cc3b05-a78d-4f29-b27c-c637d86fa03a". | Required | 
| name | The name of the key to be added. | Required | 
| value | The value of the key to be added. | Required | 

#### Context Output

There is no context output for this command.

### sekoia-xdr-get-kill-chain

***
Command to retrieve the definition of a Cyber Kill Chain Step.

#### Base Command

`sekoia-xdr-get-kill-chain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kill_chain_uuid | UUID or short_id of the kill chain the UUID should appear with "sekoia-xdr-list-alerts". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SekoiaXDR.KillChain.stix_name | unknown | The name of the STIX object. | 
| SekoiaXDR.KillChain.description | unknown | The description of the STIX object. | 
| SekoiaXDR.KillChain.name | unknown | The common name of the STIX object. | 
| SekoiaXDR.KillChain.uuid | unknown | The unique identifier of the STIX object. | 
| SekoiaXDR.KillChain.short_id | unknown | The short identifier of the STIX object. | 
| SekoiaXDR.KillChain.order_id | unknown | The order identifier of the STIX object. | 

### sekoia-xdr-remove-attribute-asset

***
Command to remove an attribute from an asset in Sekoia XDR. Note: use !sekoia-xdr-get-asset to find the attribute_uuid to delete.

#### Base Command

`sekoia-xdr-remove-attribute-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_uuid | UUID of the asset, the UUID should appear with "sekoia-xdr-list-assets" if that alert have assets related, example: "d4cc3b05-a78d-4f29-b27c-c637d86fa03a". | Required | 
| attribute_uuid | UUID of the attribute to delete. Note: use !sekoia-xdr-get-asset to find the attribute_uuid to delete. | Required | 

#### Context Output

There is no context output for this command.

### sekoia-xdr-remove-key-asset

***
Command to remove a key from an asset in Sekoia XDR. Note: use !sekoia-xdr-get-asset to find the key_uuid to delete.

#### Base Command

`sekoia-xdr-remove-key-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_uuid | UUID of the asset, the UUID should appear with "sekoia-xdr-list-assets" if that alert have assets related, example: "d4cc3b05-a78d-4f29-b27c-c637d86fa03a". | Required | 
| key_uuid | UUID of the key to remove. Note: use !sekoia-xdr-get-asset to find the key_uuid to delete. | Required | 

#### Context Output

There is no context output for this command.

### sekoia-xdr-http-request

***
Command that performs a HTTP request to Sekoia using the integration authentication configured.

#### Base Command

`sekoia-xdr-http-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | Method to use with the http request (GET,POST,etc). Default is GET. | Required | 
| url_sufix | The URL suffix after <https://api.sekoia.io>, i.e. /v1/sic/alerts/ or /v1/asset-management/assets/. | Required | 
| parameters | Query parameters, i.e. limit -&gt; 10 , match['status_name'] -&gt; Ongoing. | Optional | 

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Sekoia XDR corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Sekoia XDR events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Sekoia XDR events (outgoing mirrored fields). |
    | Incoming and Outgoing | Changes made in Sekoia will be reflected in Cortex, and vice versa, ensuring status updates are synchronized between both systems. |

3. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in Sekoia XDR.

4. Optional: Check the Reopen Mirrored Cortex XSOAR Incidents integration parameter to reopen the Cortex XSOAR incident when the matching Sekoia XDR alert is reopened.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Sekoia XDR.

## Troubleshooting

To troubleshoot possible issues with the SEKOIA XDR integration, consider the following steps:

- **Debug Mode**: 
    - In your integration instance, enable the Debug option.
    - Navigate to `Settings > About > Troubleshooting > Download logs` to download the logs. Analyzing these logs can provide valuable insights into any issues.

- **Mirror Values**: 
  - To diagnose mirroring issues beyond what debug mode offers, you can inspect specific fields in the context data. Check if the following dbot fields are set:
    - **dbotMirrorInstance**: Indicates the instance managing the mirroring.
    - **dbotMirrorDirection**: Shows the direction of mirroring.
    - **dbotMirrorId**: The unique identifier for the mirroring process.
  - If these fields are not set, review the mappers to ensure that they are configured correctly.

- **dbotMirrorLastSync Field**:
  - The `dbotMirrorLastSync` field in the context data will update when the mirroring process updates an incident. 
  - You can observe these updates in the **War Room** as well, which will provide a log of the mirroring activity.

By following these troubleshooting steps, you can effectively diagnose and resolve issues within the SEKOIA XDR integration.

## Best Practices

To make the most out of your SEKOIA XDR integration, consider the following best practices:

- **Mirroring Changes**: When mirroring is enabled, please allow at least 1 minute for changes to be reflected. The mirroring process runs every 1 minute, ensuring that data between SEKOIA and Cortex is kept in sync.

- **Handling Reopened Incidents**: If you have enabled the reopening option, the Cortex incident will be reopened under two specific conditions:
  - **Reopened Alert in SEKOIA**: If an alert is reopened in SEKOIA, the corresponding incident in Cortex will also be reopened. This ensures that the incident tracking is consistent across both platforms.
  - **Reopened Incident in Cortex**: If you reopen an incident directly in Cortex, you need to be cautious. After reopening the incident in Cortex, you should promptly change the status of the SEKOIA alert. Failing to do so might lead to the incident being automatically closed by the mirroring process.

By adhering to these best practices, you can ensure a smoother and more effective synchronization between SEKOIA and your incident management platform.

## Additional documentation

The following documentation can be useful to understand the integration:

| Information | Description |
| --- | --- |
| [Mirroring](https://xsoar.pan.dev/docs/integrations/mirroring_integration) | Adittional information for mirroring |
| [Post process scripts](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.5/Cortex-XSOAR-Administrator-Guide/Post-Processing-for-Incidents) | Adittional information for post process scripts |
| [Sekoia XDR documentation](https://docs.sekoia.io/xdr/) | Sekoia XDR Documentation |
| [Rest API Documentation](https://docs.sekoia.io/xdr/develop/rest_api/alert/) | Sekoia XDR API Documentation |
