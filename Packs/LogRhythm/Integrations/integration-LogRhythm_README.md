<!-- HTML_DOC -->
<p>Use the LogRhythm integration to manage your alarm systems.</p>
<p>This integration was integrated and tested with LogRhythm v7.3.2 / UI 18.5.1.</p>
<h2>Use Cases</h2>
<ul>
<li>Get alarms.</li>
<li>Update alarm data.</li>
<li>Get incidents from one day ago until the current time.</li>
</ul>
<h2>Prerequisites</h2>
<p>Contact <strong>LogRhythm support</strong> for information about retrieving an API token. You can refer to the following LogRhythm documentation.</p>
<ul>
<li>LogRhythm-SOAP-API-InstallationGuide</li>
<li>LogRhythm-SOAP-API-WindowsAuthenticationGuide</li>
</ul>
<h2>Configure LogRhythm on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for LogRhythm.</li>
<li>Click <strong>Add instance</strong><span class="wysiwyg-color-black"> to create and configure a new integration instance.</span>
<ul>
<li>
<strong>Name:</strong> a textual name for the integration instance</li>
<li>
<strong>Hostname</strong> or <strong>IP address</strong>
</li>
<li>Do not validate server certificate (not secure)</li>
<li>Use system proxy settings</li>
<li><strong>Fetch incidents</strong></li>
<li>Default page size for alarm queries (for example: 2000)</li>
<li>Timezone offset in minutes of the LogRhythm server machine</li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_1135894461529417647474">Add an alarm comment: lr-add-alarm-comments</a></li>
<li><a href="#h_464591753421529417654366">Get information for an alarm: lr-get-alarm-by-id</a></li>
<li><a href="#h_62843225771529417661728">Get information for events: lr-get-alarm-events-by-id</a></li>
<li><a href="#h_1215003921101529417669830">Get the history of an alarm: lr-get-alarm-history-by-id</a></li>
<li><a href="#h_5782120891431529417680262">Update the status of an alarm: lr-update-alarm-status</a></li>
<li><a href="#h_2938800481741529417687894">Get information for multiple alarms: lr-get-alarms</a></li>
</ol>
<h3 id="h_1135894461529417647474">1. Add an alarm comment</h3>
<hr>
<p>Adds a comment to an alarm.</p>
<h5>Basic Command</h5>
<p><code>lr-add-alarm-comments</code></p>
<h5>Input</h5>
<table style="height: 80px;" width="750">
<thead>
<tr>
<td style="width: 299px;"><strong>Argument Name</strong></td>
<td style="width: 300px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">alarm-id</td>
<td style="width: 300px;">Unique ID of the alarm</td>
</tr>
<tr>
<td style="width: 299px;">comments</td>
<td style="width: 300px;">Alarm comments</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!lr-add-alarm-comments alarm-id=18 comments="test comment" raw-response=true</code></p>
<h5>Context Output</h5>
<pre>{  
   "DataID":"18",
   "Errors":"",
   "Key":"0",
   "Succeeded":"true",
   "Warnings":{  
      "-a":"http://schemas.microsoft.com/2003/10/Serialization/Arrays"
   }
}
</pre>
<h3 id="h_464591753421529417654366">2. Get information for an alarm</h3>
<hr>
<p>Returns information of an alarm.</p>
<h5>Basic Command</h5>
<p><code>lr-get-alarm-by-id</code></p>
<h5>Input</h5>
<table style="height: 80px; width: 749px;">
<thead>
<tr>
<td style="width: 296px;"><strong>Argument Name</strong></td>
<td style="width: 303px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">alarm-id</td>
<td style="width: 303px;">Unique ID of the alarm</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!lr-get-alarm-by-id alarm-id=18 raw-response=true</code></p>
<h5>Context Output</h5>
<pre>{  
   "AlarmDate":"2018-03-27T09:18:04.41",
   "AlarmID":"18",
   "AlarmRuleID":"677",
   "AlarmRuleName":"LogRhythm AI Comm Manager Heartbeat Missed",
   "AlarmStatus":"New",
   "DateInserted":"2018-03-27T09:18:04.72",
   "DateUpdated":"2018-04-09T08:50:47.027",
   "EntityID":"1",
   "EntityName":"Primary Site",
   "EventCount":"1",
   "EventDateFirst":"2018-03-27T09:18:02.873",
   "EventDateLast":"2018-03-27T09:18:02.873",
   "LastUpdatedID":"3",
   "LastUpdatedName":"api, lrapi",
   "RBPAvg":"67",
   "RBPMax":"67"
}
</pre>
<h3 id="h_62843225771529417661728">3. Get information for events</h3>
<hr>
<p>Get alarm events.</p>
<h5>Basic Command</h5>
<p><code>lr-get-alarm-events-by-id</code></p>
<h5>Input</h5>
<table style="height: 80px; width: 749px;">
<thead>
<tr>
<td style="width: 295px;"><strong>Argument Name</strong></td>
<td style="width: 304px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 295px;">alarm-id</td>
<td style="width: 304px;">Unique ID of the alarm</td>
</tr>
<tr>
<td style="width: 295px;">include-raw-log</td>
<td style="width: 304px;">Include raw log</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!lr-get-alarm-events-by-id alarm-id=5 raw-response=true</code></p>
<h5>Context Output</h5>
<pre>"Command":"",
"CommonEventID":"-1100001",
"CommonEventName":"LogRhythm Mediator Heartbeat Missed",
"Count":"1",
"DateInserted":"0001-01-01T00:00:00",
"Direction":"Local",
"DirectionName":"Local",
"Domain":"",
"Duration":"NaN",
"EntityID":"0",
"EntityName":{  
   "-nil":"true"
},
"Group":"",
"ImpactedEntityID":"1",
"ImpactedEntityName":"Primary Site",
"ImpactedHostID":"1",
"ImpactedHostName":"WIN-JSBOL5ERCQA",
"ImpactedIP":"",
...
</pre>
<h3 id="h_1215003921101529417669830">4. Get the history of an alarm</h3>
<hr>
<p>Returns the history of an alarm.</p>
<h5>Basic Command</h5>
<p><code>lr-get-alarm-history-by-id</code></p>
<h5>Input</h5>
<table style="height: 80px; width: 749px;">
<thead>
<tr>
<td style="width: 291px;"><strong>Argument Name</strong></td>
<td style="width: 308px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">alarm-id</td>
<td style="width: 308px;">Unique ID of the alarm</td>
</tr>
<tr>
<td style="width: 291px;">include-notifications</td>
<td style="width: 308px;">Include notification history</td>
</tr>
<tr>
<td style="width: 291px;">include-comments</td>
<td style="width: 308px;">Include comments history</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p>!lr-get-alarm-history-by-id alarm-id=5 raw-response=true include-comments=true</p>
<h5>Context Output</h5>
<pre>"AlarmID":"18",
"Comments":{  
   "AlarmCommentDataModel":[  
      {  
         "Comment":"Comment: test comment",
         "DateInserted":"2018-04-09T08:50:47.027",
         "ID":"11",
         "PersonID":"3",
         "PersonName":"api, lrapi"
      },
      {  
         "Comment":"Changed status to: New\r\nComment:",
         "DateInserted":"2018-04-08T15:34:51",
         "ID":"10",
         "PersonID":"3",
         "PersonName":"api, lrapi"
      },
      {  
         "Comment":"Comment: test 2",
         "DateInserted":"2018-04-08T15:34:07.91",
         "ID":"9",
         "PersonID":"3",
</pre>
<h3 id="h_5782120891431529417680262">5. Update the status of an alarm</h3>
<hr>
<p>Updates the status of an alarm.</p>
<h5>Basic Command</h5>
<p><code>lr-update-alarm-status</code></p>
<h5>Input</h5>
<table style="height: 80px; width: 749px;">
<thead>
<tr>
<td style="width: 296px;"><strong>Argument Name</strong></td>
<td style="width: 303px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">alarm-id</td>
<td style="width: 303px;">Unique ID of the alarm</td>
</tr>
<tr>
<td style="width: 296px;">status</td>
<td style="width: 303px;">Enumeration status of the alarm</td>
</tr>
<tr>
<td style="width: 296px;">comments</td>
<td style="width: 303px;">Alarm comments</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command example</h5>
<p><code>!lr-update-alarm-status alarm-id=5 status=New raw-response=true</code></p>
<h5>Context Output</h5>
<pre>"DataID":"5",
"Errors":"",
"Key":"0",
"Succeeded":"true",
"Warnings":{  
   "-a":"http://schemas.microsoft.com/2003/10/Serialization/Arrays"
}
</pre>
<h3 id="h_2938800481741529417687894">6. Get information for multiple alarms</h3>
<hr>
<p>Returns information for multiple alarms.</p>
<h5>Basic Command</h5>
<p><code>lr-get-alarms</code></p>
<h5>Input</h5>
<table style="height: 80px; width: 749px;">
<thead>
<tr>
<td style="width: 294px;"><strong>Argument Name</strong></td>
<td style="width: 305px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 294px;">start-date</td>
<td style="width: 305px;">Start date for the data query. For example: start-date="2018-03-27"</td>
</tr>
<tr>
<td style="width: 294px;">end-date</td>
<td style="width: 305px;">End date for the data query. For example: end-date="2018-04-08"</td>
</tr>
<tr>
<td style="width: 294px;">all-users</td>
<td style="width: 305px;">Alarms for all users</td>
</tr>
<tr>
<td style="width: 294px;">count</td>
<td style="width: 305px;">
<p>Number of alerts to retrieve,</p>
<p>Defaults: 1000</p>
</td>
</tr>
<tr>
<td style="width: 294px;">status</td>
<td style="width: 305px;">Enumeration status of the alarm</td>
</tr>
<tr>
<td style="width: 294px;">time_frame</td>
<td style="width: 305px;">Time frame to retrieve alerts for ("Today", "Last2Days", "LastWeek", "LastMonth", and "Custom". If "Custom", you need to specify the <em>start-date</em> and <em>end-date</em> arguments, otherwise the command ignores the <em>time_frame</em> argument.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!lr-get-alarms start-date="2018-03-27" end-date="2018-04-01" status=New all-users=true raw-response=true</code></p>
<h5>Context Output</h5>
<pre>{  
   "AlarmDate":"2018-03-27T08:23:33.55",
   "AlarmID":"13",
   "AlarmRuleID":"102",
   "AlarmRuleName":"LogRhythm Mediator Heartbeat Missed",
   "AlarmStatus":"New",
   "DateInserted":"2018-03-27T08:23:33.987",
   "DateUpdated":"2018-03-27T08:23:34.053",
   "EntityID":"1",
   "EntityName":"Primary Site",
   "EventCount":"1",
   "EventDateFirst":"2018-03-27T08:23:31.517",
   "EventDateLast":"2018-03-27T08:23:31.517",
   "LastUpdatedID":"0",
   "LastUpdatedName":{  
      "-nil":"true"
   },
   "RBPAvg":"67",
   "RBPMax":"67"
}...
</pre>