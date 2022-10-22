<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Deprecated. No available replacement.</p>
<p>Use the Preempt integration to eliminate security breaches and internal threats. Preempt is an Adaptive Threat Prevention platform based on identity, behavior, and risk.</p>
<p>This integration was integrated and tested with Preempt v2.3.1086.</p>
<hr>
<h2>Use Cases</h2>
<ul>
<li>Enable multi-factor authentication (MFA)</li>
<li>Retrieve user activities and the endpoints used by users</li>
<li>Retrieve alerts from the Preempt platform.</li>
</ul>
<hr>
<h2>Prerequisites</h2>
<p>You need to obtain the following Preempt information.</p>
<ul>
<li><font style="vertical-align: inherit;">Server address</font></li>
<li>API key</li>
</ul>
<h3>Get Your Preempt API Key</h3>
<ol>
<li>Log in to the Preempt platform.</li>
<li>Navigate to <strong>Administration</strong> &gt; <strong>System</strong> &gt; <strong>Settings</strong> &gt; <strong>API Keys</strong>.</li>
<li>Enable the <strong>API Token</strong> option.</li>
<li>Create a token for Cortex XSOAR if one was not already created.</li>
<li>Click the link icon on the row for the token.<br> The API key is copied to your clipboard. You will paste this when configuring the integration in Cortex XSOAR.</li>
</ol>
<hr>
<h2>Configure the Preempt Integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Preempt.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong><font style="vertical-align: inherit;">Preempt server address</font></strong><font style="vertical-align: inherit;">: for example, https://192.168.0.1</font>
</li>
<li>
<strong>API key</strong>: paste the token that you copied.</li>
<li><strong>Days to look back</strong></li>
<li><strong>Client Secret</strong></li>
<li><strong>Refresh Token</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<li><a href="#h_57680759771526892358096">Add an account to the watch list: preempt-add-to-watch-list</a></li>
<li><a href="#h_326567481411526892365995">Remove an account from the watch list: preempt-remove-from-watch-list</a></li>
<li><a href="#h_558909914741526892373370">Retrieve User Activities: preempt-get-activities</a></li>
<li><a href="#h_2086129511101526892381603">Retrieve User Endpoints: preempt-get-user-endpoints</a></li>
<li><a href="#h_6710437861441526892387471">Retrieve User Alerts: preempt-get-alerts</a></li>
</ul>
<hr>
<h3 id="h_57680759771526892358096">Add an account to the watch list: preempt-add-to-watch-list</h3>
<p>Add a user account to the Preempt watch list.</p>
<h4>Input</h4>
<p> accountObjectGuid: preempt-get-activities</p>
<h4>Ouput</h4>
<p>There is no output for this command.</p>
<hr>
<h3 id="h_326567481411526892365995">Remove an account from the watch list: preempt-add-to-watch-list</h3>
<p>Remove a user account from the Preempt watch list.</p>
<h4>Input</h4>
<p> accountObjectGuid: preempt-get-activities</p>
<h4>Ouput</h4>
<p>There is no output for this command.</p>
<hr>
<h3 id="h_558909914741526892373370">Retrieve User Activities: preempt-get-activities</h3>
<p>Retrieve the activities and the activity data for a specific user.</p>
<h4>Command Example</h4>
<p><code>!preempt-get-activities sourceUserId="<em>userID</em>" types="LOGIN" numOfHours="48"</code></p>
<h4>Input</h4>
<table style="height: 137px; width: 656px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 190px;"><strong>Parameter</strong></td>
<td style="width: 461px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 190px;">sourceUserId</td>
<td style="width: 461px;">ID of user that you want to retrieve the activities for</td>
</tr>
<tr>
<td style="width: 190px;">types</td>
<td style="width: 461px;">List of specific incident types (comma delimited)</td>
</tr>
<tr>
<td style="width: 190px;">endTime</td>
<td style="width: 461px;">For example: 2012-03-04 12:08:12.354</td>
</tr>
<tr>
<td style="width: 190px;">numOfHours</td>
<td style="width: 461px;">Number of hours to search back (from the endTime)</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Context Output</h4>
<table style="height: 117px; width: 655px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 192px;"><strong>Parameter</strong></td>
<td style="width: 459px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Activities.EndpointHostName</td>
<td style="width: 459px;">Hostname of the activity's endpoint</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Activities.EventType</td>
<td style="width: 459px;">Activity type</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Activities.AuthenticationType</td>
<td style="width: 459px;">Authentication type</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Activities.Timestamp</td>
<td style="width: 459px;">Activity's date and time</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Activities.Cursor</td>
<td style="width: 459px;">Cursor of last retrieved activity for pagination</td>
</tr>
</tbody>
</table>
<p> </p>
<h4>Human Readable Output</h4>
<p><img src="https://user-images.githubusercontent.com/37335599/40068766-0c22749e-5872-11e8-89a2-2327746f3c40.png" width="648" height="250"></p>
<p> </p>
<h4>Raw Output</h4>
<pre>{  
   "Preeempt":{  
      "Activities":[  
         {  
            "AuthenticationType":"DOMAIN_LOGIN",
            "EndpointHostName":"xxxxxx.xxxxx.xxx",
            "EventType":"SUCCESSFUL_AUTHENTICATION",
            "Timestamp":"2018-03-11T12:41:00.000Z"
         }
      ]
   }
}</pre>
<hr>
<h3 id="h_2086129511101526892381603">Retrieve User Endpoints: preempt-get-user-endpoints</h3>
<p>Retrieve the endpoints used by a spefic user.</p>
<h4>Input</h4>
<table style="height: 137px; width: 656px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 190px;"><strong>Parameter</strong></td>
<td style="width: 461px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 190px;">sourceUserId</td>
<td style="width: 461px;">ID of user that you want to retrieve the endpoints for</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Context Output</h4>
<table style="height: 117px; width: 655px;" border="2" cellpadding="6">
<tbody>
<tr style="height: 21px;">
<td style="width: 192px; height: 21px;"><strong>Parameter</strong></td>
<td style="width: 459px; height: 21px;"><strong>Description</strong></td>
</tr>
<tr style="height: 21px;">
<td style="width: 192px; height: 21px;">Endpoint.Hostname</td>
<td style="width: 459px; height: 21px;">Hostname of the endpoint</td>
</tr>
<tr style="height: 21px;">
<td style="width: 192px; height: 21px;">Endpoint.ID</td>
<td style="width: 459px; height: 21px;">Object GUID of the computer account</td>
</tr>
<tr style="height: 19.5313px;">
<td style="width: 192px; height: 19.5313px;">Endpoint.PrimaryDisplayName</td>
<td style="width: 459px; height: 19.5313px;">Computer's display name in Active Directory (AD)</td>
</tr>
<tr style="height: 21px;">
<td style="width: 192px; height: 21px;">Endpoint.IsOwnedByUser</td>
<td style="width: 459px; height: 21px;">Indicates if the user owns this endpoint (boolean)</td>
</tr>
<tr style="height: 21px;">
<td style="width: 192px; height: 21px;">Endpoint.IPAddress</td>
<td style="width: 459px; height: 21px;">Last IP address associated with the endpoint, detected by the system</td>
</tr>
<tr style="height: 21px;">
<td style="width: 192px; height: 21px;">Endpoint.StaticIpAddresses</td>
<td style="width: 459px; height: 21px;">Static IP address that has been associated with the endpoint</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Raw Output</h4>
<pre>{  
   "Preempt":{  
      "Endpoint":[  
         {  
            "HostName":"xxxxxx.xx.xxx",
            "Id":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxx",
            "IsOwnedByUser":T/F,
            "LastIpAddress":"xxx.xxx.xxx.xxx",
            "PrimaryDisplayName":"xxx-xxxx",
            "StaticIpAddresses":[  
               "xxx.xxx.x.xxx"
            ]
         }</pre>
<hr>
<h3 id="h_6710437861441526892387471">Retrieve User Alerts: preempt-get-alerts</h3>
<p>Retrieve the alerts for a specific user.</p>
<h4>Command Example</h4>
<p><code>!preempt-get-alerts sourceUserId="<em>userID</em>" numOfHours="48"</code></p>
<h4>Input</h4>
<table style="height: 137px; width: 656px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 190px;"><strong>Parameter</strong></td>
<td style="width: 461px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 190px;">sourceUserId</td>
<td style="width: 461px;">ID of user that you want to retrieve the activities for</td>
</tr>
<tr>
<td style="width: 190px;">endTime</td>
<td style="width: 461px;">For example: 2012-03-04 12:08:12.354</td>
</tr>
<tr>
<td style="width: 190px;">numOfHours</td>
<td style="width: 461px;">Number of hours to search back (from the endTime)</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Context Output</h4>
<table style="height: 117px; width: 655px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 192px;"><strong>Parameter</strong></td>
<td style="width: 459px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Alerts.AlertType</td>
<td style="width: 459px;">Alert type</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Alerts.Timestamp</td>
<td style="width: 459px;">Alert's date and time</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Alerts.startTime</td>
<td style="width: 459px;">Date and time the alert started</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Alerts.EndTime</td>
<td style="width: 459px;">Date and time the alert ended</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Alerts.eventLabel</td>
<td style="width: 459px;">Alert label</td>
</tr>
<tr>
<td style="width: 192px;">Preempt.Alerts.Cursor</td>
<td style="width: 459px;">Cursor of the last retrieved activity for pagination</td>
</tr>
</tbody>
</table>
<p> </p>
<h4>Human Readable Output</h4>
<p><img src="https://user-images.githubusercontent.com/37335599/40178946-a3180b50-59eb-11e8-84b8-0b2bbf220da1.png" width="665" height="286"></p>
<p> </p>
<h4>Raw Output</h4>
<pre>{  
   "Alerts":[  
      {  
         "alertType":"AbnormalServiceAccessAlert",
         "cursor":"xxxxxxxxxx",
         "endTime":"2018-03-27T19:43:00.000Z",
         "endpointEntity":{  
            "_id":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
            "hostName":null
         },
         "eventId":"xxxxxx",
         "eventLabel":"Unusual Access to Service",
         "incident":{  
            "_id":"INC-43",
            "severity":"INFO",
            "state":{  
               "lifeCycleStage":"NEW"
            }
         },
         "relatedEvents":[  
            {  
               "eventType":"SERVICE_ACCESS",
               "geoLocation":null,
               "ipAddress":"xxx.xxx.xxx.xxx",
               "timestamp":"2018-03-27T19:43:00.000Z"
            }
         ]
      }</pre>
<hr>
<h3>Demisto-Preempt Demo</h3>
<p><iframe src="https://www.youtube.com/embed/YSB8OBY8jx4?rel=0" width="560" height="315" frameborder="0" allowfullscreen=""></iframe></p>