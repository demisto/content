<!-- HTML_DOC -->
<p>IronDefense gives users the ability to rate alerts, update alert statuses, add comments to alerts, and to report observed bad activity.</p>
<p> </p>
<h2>Configure IronDefense on XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for IronDefense.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>IronAPI Host/IP</strong></li>
<li><strong>IronAPI Port</strong></li>
<li><strong>Username</strong></li>
<li><strong>Request Timeout (Sec)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#irondefense-rate-alert" target="_self">Rate an alert: irondefense-rate-alert</a></li>
<li><a href="#irondefense-comment-alert" target="_self">Add a comment to an alert: irondefense-comment-alert</a></li>
<li><a href="#irondefense-set-alert-status" target="_self">Set the status of an alert: irondefense-set-alert-status</a></li>
<li><a href="#irondefense-report-observed-bad-activity" target="_self">Submit an observed bad endpoint to create Threat Intelligence Rules (TIR): irondefense-report-observed-bad-activity</a></li>
</ol>
<h3 id="irondefense-rate-alert">1. Rate an alert</h3>
<hr>
<p>Rates an IronDefense alert.</p>
<h5>Base Command</h5>
<p><code>irondefense-rate-alert</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 231.667px;"><strong>Argument Name</strong></th>
<th style="width: 412.333px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 231.667px;">alert_id</td>
<td style="width: 412.333px;">The ID of the IronDefense alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">severity</td>
<td style="width: 412.333px;">The severity rating of the alert. Can be: "Undecided", "Benign", "Suspicious", "Malicious".</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">expectation</td>
<td style="width: 412.333px;">Determines whether the rating was expected. Can be: "Unknown", "Expected", "Unexpected". Use "Unknown" if the rating is undecided.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">comments</td>
<td style="width: 412.333px;">Explains the rating of the alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">share_comment_with_irondome</td>
<td style="width: 412.333px;">Whether to share the comment with IronDome.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<h3 id="irondefense-comment-alert">2. Add a comment to an alert</h3>
<hr>
<p>Adds a comment to an IronDefense alert.</p>
<h5>Base Command</h5>
<p><code>irondefense-comment-alert</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 260.667px;"><strong>Argument Name</strong></th>
<th style="width: 372.333px;"><strong>Description</strong></th>
<th style="width: 84px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260.667px;">alert_id</td>
<td style="width: 372.333px;">The ID of the IronDefense alert.</td>
<td style="width: 84px;">Required</td>
</tr>
<tr>
<td style="width: 260.667px;">comment</td>
<td style="width: 372.333px;">Explains the rating of the alert.</td>
<td style="width: 84px;">Required</td>
</tr>
<tr>
<td style="width: 260.667px;">share_comment_with_irondome</td>
<td style="width: 372.333px;">Whether to share the comment with IronDome.</td>
<td style="width: 84px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<h3 id="irondefense-set-alert-status">3. Set the status of an alert</h3>
<hr>
<p>Sets the status of an IronDefense alert.</p>
<h5>Base Command</h5>
<p><code>irondefense-set-alert-status</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 238.667px;"><strong>Argument Name</strong></th>
<th style="width: 405.333px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 238.667px;">alert_id</td>
<td style="width: 405.333px;">The ID of the IronDefense alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 238.667px;">status</td>
<td style="width: 405.333px;">The alert status to set. Can be: "Awaiting Review", "Under Review", "Closed".</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 238.667px;">comments</td>
<td style="width: 405.333px;">Explains the status of the alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 238.667px;">share_comment_with_irondome</td>
<td style="width: 405.333px;">Whether to share the comment with IronDome.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<h3 id="irondefense-report-observed-bad-activity">4. Submit an observed bad endpoint to create Threat Intelligence Rules (TIR)</h3>
<hr>
<p>Submits an observed bad endpoint to IronDefense to create Threat Intelligence Rules (TIR).</p>
<h5>Base Command</h5>
<p><code>irondefense-report-observed-bad-activity</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 160.333px;"><strong>Argument Name</strong></th>
<th style="width: 473.667px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160.333px;">name</td>
<td style="width: 473.667px;">The name of the Threat Intelligence Rule (TIR) to be created.</td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 160.333px;">description</td>
<td style="width: 473.667px;">A description of the observed bad endpoint.</td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 160.333px;">ip</td>
<td style="width: 473.667px;">The IP address of the observed bad endpoint.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 160.333px;">domain</td>
<td style="width: 473.667px;">The domain name of the observed bad endpoint.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 160.333px;">activity_start_time</td>
<td style="width: 473.667px;">The start time of the observed bad activity in RFC 3339 format.</td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 160.333px;">activity_end_time</td>
<td style="width: 473.667px;">The end time of the observed bad activity in RFC 3339 format.</td>
<td style="width: 81px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> <span style="font-size: 1.5em;"> </span></p>

### irondefense-get-event

***
Retrieves an IronDefense event.

#### Base Command

`irondefense-get-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The ID of the IronDefense event. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IronDefense.Event.id | String | The event ID. | 
| IronDefense.Event.alert_id | String | The associated alert ID. | 
| IronDefense.Event.category | String | The event category. | 
| IronDefense.Event.sub_category | String | The event sub category. | 
| IronDefense.Event.severity | Number | The event severity \(0-1000\). | 
| IronDefense.Event.confidence | Number | The event confidence \(real number between 0-1\). | 
| IronDefense.Event.created | Date | Time the event was created. | 
| IronDefense.Event.updated | Date | Time the event was last updated. | 
| IronDefense.Event.start_time | Date | The start time of this event's activity. | 
| IronDefense.Event.end_time | Date | The end time of this event's activity. | 
| IronDefense.Event.iron_dome_shared_time | Date | The time when the event was sent to IronDome - not present if not shared with irondome. | 
| IronDefense.Event.is_whitelisted | Boolean | True if the event activity was whitelisted, false otherwise. | 
| IronDefense.Event.is_blacklisted | Boolean | True if the event activity was blacklisted, false otherwise. | 
| IronDefense.Event.src_ip | String | The source IP associated with this event. | 
| IronDefense.Event.dst_ip | String | The destination IP associated with this event. | 
| IronDefense.Event.dst_port | Number | The destination port associated with this event. | 
| IronDefense.Event.ppp_domains | String | Any domains associated with this event. | 
| IronDefense.Event.primary_app_protocol | String | The primary application protocol associated with this event. | 
| IronDefense.Event.secondary_app_protocol | String | The secondary application protocol associated with this event. | 
| IronDefense.Event.bytes_in | Number | The byte count of incoming traffic for this event. | 
| IronDefense.Event.bytes_out | Number | The byte count of outgoing traffic for this event. | 
| IronDefense.Event.total_bytes | Number | The byte count of the total traffic \(in either direction\) for this event. | 
| IronDefense.Event.url | String | The related URL for this event, if applicable. | 
| IronDefense.Event.raw_data_formats | String | The list of distinct raw data formats for this event. | 
| IronDefense.Event.src_entity_attribute | String | The source entity attribute related to this event, if one could be determined. | 
| IronDefense.Event.src_entity_attribute_type | String | The source entity attribute type related to this event, if one could be determined. | 
| IronDefense.Event.dst_entity_attribute | String | The destination entity attribute related to this event, if one could be determined. | 
| IronDefense.Event.dst_entity_attribute_type | String | The destination entity attribute type related to this event, if one could be determined. | 
| IronDefense.Event.vue_url | String | The url for displaying the event within IronVUE. | 
| IronDefense.Event.Context.name | String | The name of the context table. | 
| IronDefense.Event.Context.columns | String | Column values for the context table. | 
### irondefense-get-alerts

***
Pulls Alerts from IronDefense.

#### Base Command

`irondefense-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The list of Alert IDs to filter by. | Optional | 
| category | The list of Alert categories to filter by. Possible values are: C2, Action, Access, Recon, Other. | Optional | 
| sub_category | The list of Alert sub categories to filter by. | Optional | 
| status | The list of Alert status to filter by. Possible values are: Awaiting Review, Under Review, Closed. | Optional | 
| analyst_severity | The list of Alert analyst severity to filter by. Possible values are: Undecided, Benign, Suspicious, Malicious. | Optional | 
| analyst_expectation | The list of Alert analyst expectation to filter by. Possible values are: Unknown, Expected, Unexpected. | Optional | 
| min_severity | The minimum Alert severity to filter by. (0-1000). | Optional | 
| max_severity | The maximum Alert severity to filter by. (0-1000). | Optional | 
| min_created | The minimum Alert created date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| max_created | The maximum Alert created date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| min_updated | The minimum Alert updated date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| max_updated | The maximum Alert updated date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| min_first_event_created | The minimum Alert first event created date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| max_first_event_created | The maximum Alert first event created date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| min_last_event_created | The minimum Alert last event created date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| max_last_event_created | The maximum Alert last event created date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| min_first_event_start_time | The minimum Alert first event start date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| max_first_event_start_time | The maximum Alert first event start date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| min_last_event_end_time | The minimum Alert last event end date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| max_last_event_end_time | The maximum Alert last event end date to filter by in RFC 3339 format (E.g. 2017-10-13T07:20:50.52Z). | Optional | 
| analytic_version | The list of Alert analytic versions to filter by. | Optional | 
| limit | The limit on the number of Alerts to be returned. | Optional | 
| offset | The number of results to skip - used for paging the results. | Optional | 
| sort | The list of Alert fields to sort by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IronDefense.Alert.id | string | The ID of the alert. | 
| IronDefense.Alert.category | string | The category of the alert. | 
| IronDefense.Alert.sub_category | string | The subcategory of the alert. | 
| IronDefense.Alert.severity | Number | The severity score of the alert. \(0-1000\) | 
| IronDefense.Alert.status | String | The status of the alert. | 
| IronDefense.Alert.analyst_severity | String | The analyst severity of the alert. | 
| IronDefense.Alert.analyst_expectation | String | The analyst expectation of the alert. | 
| IronDefense.Alert.created | Date | Time the alert was created in IronDefense. | 
| IronDefense.Alert.updated | Date | Time the alert was last updated in IronDefense. | 
| IronDefense.Alert.event_count | Number | The number of non-whitelisted events associated with this alert. | 
| IronDefense.Alert.FirstEventCreated | String | The earliest created date of any associated event on this alert. | 
| IronDefense.Alert.last_event_created | String | The last created date of any associated event on this alert. | 
| IronDefense.Alert.raw_data_format | String | List of distinct raw data formats for this event. | 
| IronDefense.Alert.aggregation_criteria | String | Criteria used to build alert, specific to the event context fields. | 
| IronDefense.Alert.vue_url | String | The url for displaying the alert within IronVUE. | 
| IronDefense.Query.GetAlerts.limit | Number | The maximum number of results that were requested to be returned. | 
| IronDefense.Query.GetAlerts.offset | Number | The number of results that were skipped - used for paging the results. | 
| IronDefense.Query.GetAlerts.total | Number | The total number of results possible from the query. | 
### irondefense-get-alert-irondome-information

***
Retrieves IronDome information for an IronDefense alert.

#### Base Command

`irondefense-get-alert-irondome-information`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the IronDefense alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IronDome.Correlations.alert_id | String | The alert ID the correlations are associated with. | 
| IronDome.Correlations.dome_tag | String | The IronDome tag. | 
| IronDome.Correlations.correlation.correlations.ip | String | The IP correlated on \(if an IP correlation\). | 
| IronDome.Correlations.correlation.correlations.domain | String | The Domain correlated on \(if a Domain correlation\). | 
| IronDome.Correlations.correlation.correlations.behavior | Boolean | True if the correlation was behavior-based. | 
| IronDome.Correlations.correlation.correlations.enterprise_correlations | Number | The number of enterprise correlations. | 
| IronDome.Correlations.correlation.correlations.community_correlations | Number | The number of community correlations. | 
| IronDome.CorrelationParticipation.alert_id | String | The alert ID the correlation participants are associated with. | 
| IronDome.CorrelationParticipation.correlation_participation.dome_tag | String | The IronDome tag. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.malicious_count | Number | Count of malicious ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.suspicious_count | Number | Count of suspicious ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.benign_count | Number | Count of benign ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.whitelisted_count | Number | Count of whitelisted ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.comments_count | Number | Count of comments made. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.activity_count | Number | Count of activity. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.resource_owner | Boolean | True if the caller is the resource owner. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.first_seen | Date | The time the activity was first seen. | 
| IronDome.CorrelationParticipation.correlation_participation.behavior.last_seen | Date | The time the activity was last seen. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.malicious_count | Number | Count of malicious ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.suspicious_count | Number | Count of suspicious ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.benign_count | Number | Count of benign ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.whitelisted_count | Number | Count of whitelisted ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.comments_count | Number | Count of comments made. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.activity_count | Number | Count of activity. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.resource_owner | Boolean | True if the caller is the resource owner. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.first_seen | Date | The time the activity was first seen. | 
| IronDome.CorrelationParticipation.correlation_participation.domain.last_seen | Date | The time the activity was last seen. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.malicious_count | Number | Count of malicious ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.suspicious_count | Number | Count of suspicious ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.benign_count | Number | Count of benign ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.whitelisted_count | Number | Count of whitelisted ratings. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.comments_count | Number | Count of comments made. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.activity_count | Number | Count of activity. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.resource_owner | Boolean | True if the caller is the resource owner. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.first_seen | Date | The time the activity was first seen. | 
| IronDome.CorrelationParticipation.correlation_participation.ip.last_seen | Date | The time the activity was last seen. | 
| IronDome.CommunityComments.alert_id | String | The alert ID associated with the community comments. | 
| IronDome.CommunityComments.community_comments.created | Date | The time that the comment was created. | 
| IronDome.CommunityComments.community_comments.comment | String | The comment text. | 
| IronDome.CommunityComments.community_comments.dome_tags | String | The IronDome tags related to the comment. | 
| IronDome.CommunityComments.community_comments.enterprise | Boolean | True if enterprise. | 
| IronDome.CommunityComments.community_comments.self | Boolean | True if the comment was made by the caller. | 
| IronDome.CognitiveSystemScore.alert_id | String | The alert ID associated with the cognitive system score. | 
| IronDome.CognitiveSystemScore.cognitive_system_score | Number | The cognitive system score of the alert. | 
| IronDome.Notification.alert_id | String | The alert ID associated with the IronDome notification. | 
| IronDome.Notification.dome_notification.id | String | The unique ID of the notification. | 
| IronDome.Notification.dome_notification.category | String | The category of Dome notification. | 
| IronDome.Notification.dome_notification.created | Date | The category of Dome notification. | 
| IronDome.Notification.dome_notification.dome_tags | String | The IronDome tags related to this notification. | 
| IronDome.Notification.dome_notification.alert_ids | String | The IDs of the alerts related to this notification. | 
| IronDome.Notification.dome_notification.mismatch_details.enterprise_severities.analyst_severity | String | The mismatched severity across correlated alerts within the enterprise. | 
| IronDome.Notification.dome_notification.mismatch_details.enterprise_severities.count | Number | The count of mismatched severity with this analyst rating. | 
| IronDome.Notification.dome_notification.mismatch_details.community_severities.analyst_severity | String | The mismatched severity across correlated alerts within the community. | 
| IronDome.Notification.dome_notification.mismatch_details.community_severities.count | Number | The count of mismatched severity with this analyst rating. | 
| IronDome.Notification.dome_notification.severity_details.analyst_severity | String | The analyst severity of the alert. | 
| IronDome.Notification.dome_notification.comment_details.comment | String | The comment text in the notification. | 
| IronDome.Notification.dome_notification.severity_suspicious_details.domains | String | The list of domains correlated on a suspicious alert. | 
| IronDome.Notification.dome_notification.severity_suspicious_details.ips | String | The list of IPs correlated on a suspicious alert. | 
| IronDome.Notification.dome_notification.severity_suspicious_details.comments | String | The comments about this suspicious alert correlation. | 
| IronDome.Notification.dome_notification.severity_malicious_details.domains | String | The list of domains correlated on a malicious alert. | 
| IronDome.Notification.dome_notification.severity_malicious_details.ips | String | The list of IPs correlated on a malicious alert. | 
| IronDome.Notification.dome_notification.severity_malicious_details.comments | String | The comments about this malicious alert correlation. | 
| IronDome.Notification.dome_notification.severity_malicious_details.generated_threat_intel_rules.ip | String | The IP of a Threat Intelligence rule that was automatically created based on an IronDome correlation. | 
| IronDome.Notification.dome_notification.severity_malicious_details.generated_threat_intel_rules.domain | String | The domain of a Threat Intelligence rule that was automatically created based on an IronDome correlation. | 
| IronDome.Notification.dome_notification.severity_malicious_details.generated_threat_intel_rules.rule_id | String | The rule ID of a Threat Intelligence rule that was automatically created based on an IronDome correlation. | 
| IronDome.Notification.dome_notification.severity_malicious_details.generated_threat_intel_rules.vue_url | String | The IronVUE URL of a Threat Intelligence rule that was automatically created based on an IronDome correlation. | 
| IronDome.Notification.dome_notification.high_cognitive_system_score_details.enterprise_alert_score | Number | The alert score for the enterprise. | 
| IronDome.Notification.dome_notification.high_cognitive_system_score_details.cognitive_system_score | Number | The cognitive system score. | 
### irondefense-get-events-from-alert

***
Retrieves IronDefense Events for a given Alert ID.

#### Base Command

`irondefense-get-events-from-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the IronDefense alert to retrieve events for. | Required | 
| limit | The limit on the number of Events to be returned. | Optional | 
| offset | The number of results to skip - used for paging the results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IronDefense.Event.id | String | The event ID. | 
| IronDefense.Event.alert_id | String | The associated alert ID. | 
| IronDefense.Event.category | String | The event category. | 
| IronDefense.Event.sub_category | String | The event sub category. | 
| IronDefense.Event.severity | Number | The event severity \(0-1000\). | 
| IronDefense.Event.confidence | Number | The event confidence \(real number between 0-1\). | 
| IronDefense.Event.created | Date | Time the event was created. | 
| IronDefense.Event.updated | Date | Time the event was last updated. | 
| IronDefense.Event.start_time | Date | The start time of this event's activity. | 
| IronDefense.Event.end_time | Date | The end time of this event's activity. | 
| IronDefense.Event.iron_dome_shared_time | Date | The time when the event was sent to IronDome - not present if not shared with irondome. | 
| IronDefense.Event.is_whitelisted | Boolean | True if the event activity was whitelisted, false otherwise. | 
| IronDefense.Event.is_blacklisted | Boolean | True if the event activity was blacklisted, false otherwise. | 
| IronDefense.Event.src_ip | String | The source IP associated with this event. | 
| IronDefense.Event.dst_ip | String | The destination IP associated with this event. | 
| IronDefense.Event.dst_port | Number | The destination port associated with this event. | 
| IronDefense.Event.app_domains | String | Any domains associated with this event. | 
| IronDefense.Event.primary_app_protocol | String | The primary application protocol associated with this event. | 
| IronDefense.Event.secondary_app_protocol | String | The secondary application protocol associated with this event. | 
| IronDefense.Event.bytes_in | Number | The byte count of incoming traffic for this event. | 
| IronDefense.Event.bytes_out | Number | The byte count of outgoing traffic for this event. | 
| IronDefense.Event.total_bytes | Number | The byte count of the total traffic \(in either direction\) for this event. | 
| IronDefense.Event.url | String | The related URL for this event, if applicable. | 
| IronDefense.Event.raw_data_formats | String | The list of distinct raw data formats for this event. | 
| IronDefense.Event.src_entity_attribute | String | The source entity attribute related to this event, if one could be determined. | 
| IronDefense.Event.src_entity_attribute_type | String | The source entity attribute type related to this event, if one could be determined. | 
| IronDefense.Event.dst_entity_attribute | String | The destination entity attribute related to this event, if one could be determined. | 
| IronDefense.Event.dst_entity_attribute_type | String | The destination entity attribute type related to this event, if one could be determined. | 
| IronDefense.Event.vue_url | String | The url for displaying the event within IronVUE. | 
| IronDefense.Query.GetEvents.limit | Number | The maximum number of results that were requested to be returned. | 
| IronDefense.Query.GetEvents.offset | Number | The number of results that were skipped - used for paging the results. | 
| IronDefense.Query.GetEvents.total | Number | The total number of results possible from the query. | 
