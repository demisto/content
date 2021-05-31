<!-- HTML_DOC -->
<p>Use the PagerDuty integration to manage schedules and on-call users. This integration was integrated and tested with PagerDuty API v2.</p>
<p> </p>
<h2>Configure PagerDuty on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for PagerDuty.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>API Key</strong></li>
<li><strong>Service Key (for triggering events only)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Fetched Incidents Data</h2>
<p>By default, the integration will import PagerDuty incidents data as Demisto incidents. All incidents created in the minute prior to the configuration of Fetch Incidents and up to current time will be imported.</p>
<p> </p>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_73841401041542871564295">Get all schedules: PagerDuty-get-all-schedules</a></li>
<li><a href="#h_626992915791542871568883">Get information for on-call users by time or schedule: PagerDuty-get-users-on-call</a></li>
<li><a href="#h_4809571811531542871574076">Get information for current on-call users: PagerDuty-get-users-on-call-now</a></li>
<li><a href="#h_4580568372261542871578413">Get incidents: PagerDuty-incidents</a></li>
<li><a href="#h_4808113662991542871583078">Create a new event/incident: PagerDuty-submit-event</a></li>
<li><a href="#h_5162125903701542871587221">Get the contact methods of a user: PagerDuty-get-contact-methods</a></li>
<li><a href="#h_9489540204401542871592653">Get a user's notification rules: PagerDuty-get-users-notification</a></li>
<li><a href="#h_956187916621543922011652">Resolve an event: PagerDuty-resolve-event</a></li>
<li><a href="#h_63914822271543922018179">Acknowledge an event: PagerDuty-acknowledge-event</a></li>
<li><a href="#pagerduty-get-incident-data" target="_self">Get incident information: PagerDuty-get-incident-data</a></li>
<li><a href="#pagerduty-get-service-keys" target="_self">Get service keys for each configured service: PagerDuty-get-service-keys</a></li>
</ol>
<h3 id="h_73841401041542871564295">1. Get all schedules</h3>
<hr>
<p>Retrieves all schedules from PagerDuty.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-get-all-schedules</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">query</td>
<td style="width: 499px;">Returns schedules that match the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">limit</td>
<td style="width: 499px;">The maximum number of schedules to retrieve. Default = 25, Maximum = 100.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 381px;"><strong>Path</strong></th>
<th style="width: 101px;"><strong>Type</strong></th>
<th style="width: 226px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 381px;">PagerDuty.Schedules.id</td>
<td style="width: 101px;">string</td>
<td style="width: 226px;">The Schedule ID.</td>
</tr>
<tr>
<td style="width: 381px;">PagerDuty.Schedules.name</td>
<td style="width: 101px;">string</td>
<td style="width: 226px;">The name of the schedule.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-get-all-schedules</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44710670-582dd000-aab5-11e8-8636-e23eb9863878.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44710670-582dd000-aab5-11e8-8636-e23eb9863878.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44710683-60860b00-aab5-11e8-885c-fc1c0b161e54.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44710683-60860b00-aab5-11e8-885c-fc1c0b161e54.png" alt="image" width="750" height="196"></a></p>
<h3 id="h_626992915791542871568883">2. Get information for on-call users by time or schedule</h3>
<hr>
<p>Returns the names and details of on-call users at a certain time or according to a specific schedule.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-get-users-on-call</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 505px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">scheduleID</td>
<td style="width: 505px;">The unique identifier of the schedule (default).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 132px;">since</td>
<td style="width: 505px;">Start date and time in ISO 8601 format (2011-05-06T17:00Z).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">until</td>
<td style="width: 505px;">End date and time in ISO 8601 format (2011-07-06T17:00Z).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">PagerDutyUser.id</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The ID of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.Emails</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The email address of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.Username</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The user's username.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.DisplayName</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The display name of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.Role</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The display role of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.TimeZone</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The time zone of the user.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-get-users-on-call scheduleID=PFE1I5O</pre>
<h5>Context Example</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/46350080-75c5fa80-c65c-11e8-957c-864440474a2c.png" alt="image"></p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/46350104-8b3b2480-c65c-11e8-9bb9-a4ebc36a589d.png" alt="image" width="753" height="183"></p>
<h3 id="h_4809571811531542871574076">3. Get information for current on-call users</h3>
<hr>
<p>Returns the names and details of all personnel currently on-call.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-get-users-on-call-now</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 475px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">limit</td>
<td style="width: 475px;">The maximum number of users to retrieve. Default = 25, Maximum = 100.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">escalation_policy_ids</td>
<td style="width: 475px;">Filters results by the specified escalation policy. If the value is null, permanent on-call users are included due to direct user escalation policy targets.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">schedule_ids</td>
<td style="width: 475px;">Filters the results by on-call users for the specified schedule IDs. If the value is null, permanent on-call users are included due to direct user escalation policy targets.</td>
<td style="width: 71px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">PagerDutyUser.ID</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The ID of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.Email</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The email address of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.Username</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The user's username.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.DisplayName</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The display name of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.Role</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The display role of the user.</td>
</tr>
<tr>
<td style="width: 304px;">PagerDutyUser.TimeZone</td>
<td style="width: 74px;">string</td>
<td style="width: 330px;">The time zone of the user.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-get-users-on-call-now</pre>
<h5>Context Example</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/46350175-b7ef3c00-c65c-11e8-8a94-27fc99984e56.png" alt="image"></p>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/46350152-a9a12000-c65c-11e8-855e-b4076e91b3d3.png" alt="image" width="754" height="160"></p>
<h3 id="h_4580568372261542871578413">4. Get incidents</h3>
<hr>
<p>Shows incidents in PagerDuty.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-incidents</code></p>
<h5>Input</h5>
<table style="width: 712px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 289px;"><strong>Argument Name</strong></th>
<th style="width: 751px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 289px;">status</td>
<td style="width: 751px;">Returns only the incidents currently in the passed status(es). Valid status options are <em>triggered</em>, <em>acknowledged</em>, and <em>resolved</em>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 289px;">since</td>
<td style="width: 751px;">Start date and time in ISO 8601 format (2011-05-06T17:00Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 289px;">sortBy</td>
<td style="width: 751px;">Used to specify both the field you want to sort the results by, and the direction of the results (ascending/descending). See the <a href="https://developer.pagerduty.com/documentation/rest/incidents/list">PagerDuty documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 289px;">until</td>
<td style="width: 751px;">End date and time in ISO 8601 format (2011-05-06T17:00Z).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 372px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 277px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.ID</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The ID of the Incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.Title</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The title of the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.Status</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The status of the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.created_at</td>
<td style="width: 59px;">date</td>
<td style="width: 277px;">The time the incident was created.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.urgency</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The incident urgency.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.assignee</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The user assigned to the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.service_id</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The ID of the impacted service.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.service_name</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The name of the impacted service.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.escalation_policy</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The escalation policy.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.last_status_change_at</td>
<td style="width: 59px;">date</td>
<td style="width: 277px;">The time of the last status change.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.last_status_change_by</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The Name of the user who performed the last status change</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.number_of_escalations</td>
<td style="width: 59px;">number</td>
<td style="width: 277px;">Number of escalations that took place</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.resolved_by</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">Name of the user who resolved the incident</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.resolve_reason</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The reason the issue was resolved.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The description of the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.teams.ID</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The ID of the team assigned to the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.teams.ID</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">Name of the team assigned to the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.assignment.time</td>
<td style="width: 59px;">date</td>
<td style="width: 277px;">Time of the assignment to the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.assignment.assignee</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">Name of the user assigned to the incident.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.acknowledgement.time</td>
<td style="width: 59px;">date</td>
<td style="width: 277px;">The time the incident was  acknowledged.</td>
</tr>
<tr>
<td style="width: 372px;">PagerDuty.Incidents.acknowledgement.acknowledger</td>
<td style="width: 59px;">string</td>
<td style="width: 277px;">The name of the user that acknowledged the incident.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-incidents</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/48852863-f8df1380-edb6-11e8-9395-c01ed6612507.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/48852863-f8df1380-edb6-11e8-9395-c01ed6612507.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/48852914-0c8a7a00-edb7-11e8-8ff0-eb37b2fd5d1a.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/48852914-0c8a7a00-edb7-11e8-8ff0-eb37b2fd5d1a.png" alt="image" width="751" height="196"></a></p>
<p> </p>
<h3 id="h_4808113662991542871583078">5. Create an event/incident</h3>
<hr>
<p>Creates a new event or incident in PagerDuty.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-submit-event</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 489px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">source</td>
<td style="width: 489px;">Specific human-readable unique identifier, such as a hostname, for the system with the problem.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">summary</td>
<td style="width: 489px;">A high-level, text summary message of the event. Will be used to construct an alert's description.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">severity</td>
<td style="width: 489px;">The severity of the event</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">action</td>
<td style="width: 489px;">The action to be executed</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 148px;">description</td>
<td style="width: 489px;">A short description of the problem</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">group</td>
<td style="width: 489px;">A cluster or grouping of sources. For example, sources “prod-datapipe-02” and “prod-datapipe-03” might both be part of “prod-datapipe”. Example: "prod-datapipe" "www"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">event_class</td>
<td style="width: 489px;">The class/type of the event. Example: "High CPU" "Latency"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">component</td>
<td style="width: 489px;">The part or component of the affected system that is broken. Example: "keepalive" "webping"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">incident_key</td>
<td style="width: 489px;">Incident key, used to acknowledge/resolve specific event</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 303px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 339px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 303px;">PagerDuty.Event.Status</td>
<td style="width: 66px;">string</td>
<td style="width: 339px;">Status of the action on the event</td>
</tr>
<tr>
<td style="width: 303px;">PagerDuty.Event.incident_key</td>
<td style="width: 66px;">string</td>
<td style="width: 339px;">Incident key</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-submit-event action=resolve severity=info source=rony summary=testing incident_key=1de3b86c5fd8484ca011839c4cf33923</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/46350496-96db1b00-c65d-11e8-83f5-b4f7d8309c68.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/46350496-96db1b00-c65d-11e8-83f5-b4f7d8309c68.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/46350460-8460e180-c65d-11e8-83c7-131302e26fc2.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/46350460-8460e180-c65d-11e8-83c7-131302e26fc2.png" alt="image" width="755" height="137"></a></p>
<h3 id="h_5162125903701542871587221">6. Get the contact methods of a user</h3>
<hr>
<p>Gets the contact methods of the specified user.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-get-contact-methods</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 295.667px;"><strong>Argument Name</strong></th>
<th style="width: 237.333px;"><strong>Description</strong></th>
<th style="width: 174px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 295.667px;">UserID</td>
<td style="width: 237.333px;">ID of the user</td>
<td style="width: 174px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 358.667px;"><strong>Path</strong></th>
<th style="width: 63.3333px;"><strong>Type</strong></th>
<th style="width: 286px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 358.667px;">PagerDuty.Contact_methods.address</td>
<td style="width: 63.3333px;">string</td>
<td style="width: 286px;">The address of the user</td>
</tr>
<tr>
<td style="width: 358.667px;">PagerDuty.Contact_methods.id</td>
<td style="width: 63.3333px;">string</td>
<td style="width: 286px;">ID of the contact method</td>
</tr>
<tr>
<td style="width: 358.667px;">PagerDuty.Contact_methods.type</td>
<td style="width: 63.3333px;">string</td>
<td style="width: 286px;">Current contact method type</td>
</tr>
<tr>
<td style="width: 358.667px;">PagerDuty.Contact_methods.email</td>
<td style="width: 63.3333px;">string</td>
<td style="width: 286px;">User email</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-get-contact-methods UserID=PKVY389</pre>
<h5>Context Example</h5>
<p><img src="https://user-images.githubusercontent.com/37589583/46350747-3d272080-c65e-11e8-9d31-eac4289f1d85.png" alt="image"></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44711476-21f15000-aab7-11e8-9331-d20cedc0f118.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44711476-21f15000-aab7-11e8-9331-d20cedc0f118.png" alt="image" width="748" height="199"></a></p>
<h3 id="h_9489540204401542871592653">7. Get a user's notification rules</h3>
<hr>
<p>Get the users notification rules</p>
<h5>Base Command</h5>
<p><code>PagerDuty-get-users-notification</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 296.667px;"><strong>Argument Name</strong></th>
<th style="width: 236.333px;"><strong>Description</strong></th>
<th style="width: 174px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296.667px;">UserID</td>
<td style="width: 236.333px;">ID of the user</td>
<td style="width: 174px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 387.333px;"><strong>Path</strong></th>
<th style="width: 46.6667px;"><strong>Type</strong></th>
<th style="width: 274px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 387.333px;">PagerDuty.Notification_rules.start_delay_in_minutes</td>
<td style="width: 46.6667px;">string</td>
<td style="width: 274px;">The delay time for notifying the user</td>
</tr>
<tr>
<td style="width: 387.333px;">PagerDuty.Notification_rules.urgency</td>
<td style="width: 46.6667px;">string</td>
<td style="width: 274px;">The urgency of the notification</td>
</tr>
<tr>
<td style="width: 387.333px;">PagerDuty.Notification_rules.id</td>
<td style="width: 46.6667px;">string</td>
<td style="width: 274px;">Notification rule ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-get-users-notification UserID="PKVY389"</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44710594-24eb4100-aab5-11e8-8deb-2477c74aeeaf.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44710594-24eb4100-aab5-11e8-8deb-2477c74aeeaf.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44710615-2ddc1280-aab5-11e8-9d86-eecdae83671b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44710615-2ddc1280-aab5-11e8-9d86-eecdae83671b.png" alt="image" width="750" height="233"></a></p>
<h3 id="h_956187916621543922011652">8. Resolve an event</h3>
<hr>
<p>Resolves an existing event in PagerDuty.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-resolve-event</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 216px;"><strong>Argument Name</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">incident_key</td>
<td style="width: 366px;">Incident key</td>
<td style="width: 126px;">Required</td>
</tr>
<tr>
<td style="width: 216px;">serviceKey</td>
<td style="width: 366px;">Service key for the integration</td>
<td style="width: 126px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 301px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 339px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">PagerDuty.Event.Status</td>
<td style="width: 68px;">string</td>
<td style="width: 339px;">Status of the action on the event</td>
</tr>
<tr>
<td style="width: 301px;">PagerDuty.Event.incident_key</td>
<td style="width: 68px;">string</td>
<td style="width: 339px;">Incident key</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-resolve-event incident_key=84d6f9baaca346658f5d85d12b4156e6 serviceKey=XXXXXXXXXXXXXX</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/49224215-7cb58300-f3e9-11e8-8622-688d448585cb.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/49224215-7cb58300-f3e9-11e8-8622-688d448585cb.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/49224233-8b039f00-f3e9-11e8-86f5-5898eeab6798.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/49224233-8b039f00-f3e9-11e8-86f5-5898eeab6798.png" alt="image"></a></p>
<h3 id="h_63914822271543922018179">9. Acknowledge an event</h3>
<hr>
<p>Acknowledges an existing event in PagerDuty.</p>
<h5>Base Command</h5>
<p><code>PagerDuty-acknowledge-event</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 217px;"><strong>Argument Name</strong></th>
<th style="width: 365px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 217px;">incident_key</td>
<td style="width: 365px;">The incident key.</td>
<td style="width: 126px;">Required</td>
</tr>
<tr>
<td style="width: 217px;">serviceKey</td>
<td style="width: 365px;">The service key for the integration.</td>
<td style="width: 126px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 301px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 339px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">PagerDuty.Event.Status</td>
<td style="width: 68px;">string</td>
<td style="width: 339px;">Status of the action on the event</td>
</tr>
<tr>
<td style="width: 301px;">PagerDuty.Event.incident_key</td>
<td style="width: 68px;">string</td>
<td style="width: 339px;">Incident key</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!PagerDuty-acknowledge-event incident_key=84d6f9baaca346658f5d85d12b4156e6 serviceKey=XXXXXXXXXXXXXX</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/49224215-7cb58300-f3e9-11e8-8622-688d448585cb.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/49224215-7cb58300-f3e9-11e8-8622-688d448585cb.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/49224261-a1a9f600-f3e9-11e8-9153-b3f1a73a3da8.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/49224261-a1a9f600-f3e9-11e8-9153-b3f1a73a3da8.png" alt="image"></a></p>
<div class="cl-preview-section">
<h3 id="pagerduty-get-incident-data">10. Get incident data</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets data from PagerDuty about an incident.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>PagerDuty-get-incident-data</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 187px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">incident_id</td>
<td style="width: 453px;">ID of the incident for which to get information.</td>
<td style="width: 100px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 383px;"><strong>Path</strong></th>
<th style="width: 50px;"><strong>Type</strong></th>
<th style="width: 307px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.ID</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">Incident ID</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.Title</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The incident title.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.Status</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The incident status.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.created_at</td>
<td style="width: 50px;">date</td>
<td style="width: 307px;">Time that the incident was created.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.urgency</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The incident urgency.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.assignee</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The incident assignee.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.service_id</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The ID of the impacted service.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.service_name</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The name of the impacted service.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.escalation_policy</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The escalation policy.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.last_status_change_at</td>
<td style="width: 50px;">date</td>
<td style="width: 307px;">Time when the last status change occurred.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.last_status_change_by</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">Name of the user who preformed the last status change.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.number_of_escalations</td>
<td style="width: 50px;">number</td>
<td style="width: 307px;">Number of escalations that occurred.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.resolved_by</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">Name of the user who resolved the incident.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.resolve_reason</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The reason for resolving the issue.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.Description</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The description of the incident.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.teams.ID</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The ID of the team assigned to the incident.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.teams.ID</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The name of the team assigned to the incident.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.assignment.time</td>
<td style="width: 50px;">date</td>
<td style="width: 307px;">The time that the incident was assigned.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.assignment.assignee</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The name of the incident assignee.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.acknowledgement.time</td>
<td style="width: 50px;">date</td>
<td style="width: 307px;">The time the incident was acknowledged.</td>
</tr>
<tr>
<td style="width: 383px;">PagerDuty.Incidents.acknowledgement.acknowledger</td>
<td style="width: 50px;">string</td>
<td style="width: 307px;">The name of the incident acknowledger.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!PagerDuty-get-incident-data incident_id=PW159UV</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
  "PagerDuty.Incidents": [
    {
      "Description": "",
      "ID": "PW159UV",
      "Status": "resolved",
      "Title": "[#98] test",
      "acknowledgement": {},
      "assignee": "-",
      "assignment": {},
      "created_at": "2019-03-30T00:07:37Z",
      "escalation_policy": "Default",
      "last_status_change_at": "2019-03-30T04:07:37Z",
      "last_status_change_by": "API Service",
      "number_of_escalations": null,
      "resolve_reason": null,
      "resolved_by": "-",
      "service_id": "P6UX4CI",
      "service_name": "API Service",
      "teams": [],
      "urgency": "high"
    }
  ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37589583/56862805-81419000-69b7-11e9-9acd-478027d6e83f.png" alt="image"></p>
</div>
<div class="cl-preview-section">
<h3 id="pagerduty-get-service-keys">11. Get service keys for each configured service</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets service keys for each of the services configured in the PagerDuty instance.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>PagerDuty-get-service-keys</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 252px;"><strong>Path</strong></th>
<th style="width: 49px;"><strong>Type</strong></th>
<th style="width: 439px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 252px;">PagerDuty.Service.ID</td>
<td style="width: 49px;">string</td>
<td style="width: 439px;">The ID of the service connected to PagerDuty.</td>
</tr>
<tr>
<td style="width: 252px;">PagerDuty.Service.Name</td>
<td style="width: 49px;">string</td>
<td style="width: 439px;">The name of the service connected to PagerDuty.</td>
</tr>
<tr>
<td style="width: 252px;">PagerDuty.Service.Status</td>
<td style="width: 49px;">string</td>
<td style="width: 439px;">The status of the service connected to PagerDuty.</td>
</tr>
<tr>
<td style="width: 252px;">PagerDuty.Service.CreatedAt</td>
<td style="width: 49px;">date</td>
<td style="width: 439px;">The date when the service connected to PagerDuty was created.</td>
</tr>
<tr>
<td style="width: 252px;">PagerDuty.Service.Integration.Name</td>
<td style="width: 49px;">string</td>
<td style="width: 439px;">The name of the integration used with the service.</td>
</tr>
<tr>
<td style="width: 252px;">PagerDuty.Service.Integration.Key</td>
<td style="width: 49px;">string</td>
<td style="width: 439px;">The key used to control events with the integration.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!PagerDuty-get-service-keys</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
  "PagerDuty.Service": [
    {
      "CreatedAt": "2016-03-20T14:00:55+02:00",
      "ID": "P6UX4CI",
      "Integration": [
        {
          "Key": "e18b825980164e03a85964679dcb4b2c",
          "Name": "API Service",
          "Vendor": "Missing Vendor information"
        }
      ],
      "Name": "API Service",
      "Status": "active"
    }
  ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37589583/56862849-f01ee900-69b7-11e9-933a-c59d0929d733.png" alt="image"></p>
</div>