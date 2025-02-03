<!-- HTML_DOC -->
<p>ArcSight Logger delivers a universal log management solution that unifies searching, reporting, alerting, and analysis across any type of enterprise machine data.</p>
<p>The Cortex XSOAR-ArcSight Logger integration allows you to run a search session, refine or limit the search and retrieve a list of events detected in the search.</p>
<p>To set up Arcsight Logger to work with Cortex XSOAR:</p>
<ul>
<li>Make sure you have the Arcsight Logger server url.</li>
<li>Make sure you have credentials for Arcsight Logger.</li>
</ul>
<h3>To set up the integration on Cortex XSOAR:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate ‘ArcSight Logger’ by searching for it using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:<br><strong>Name</strong>: A textual name for the integration instance.<br><strong>Server URL and Port</strong>: The API server URL and port number.<br><strong>Credentials and Password</strong>: User and password used to access ArcSight Logger.<br>
<div class="field">
<div class="demisto-checkbox ui checkbox ">
<label class="checkbox-label" title="Import events as incidents"><label class="checkbox-label" title="Import events as incidents"><strong>Import events as incidents</strong> - Mark </label></label><label class="checkbox-label" title="Import events as incidents">to automatically create Cortex XSOAR incidents from ArcSight Logger events. <br><strong>Incident type</strong>: Choose the incident type from the drop-down list. This incident type will be triggered when an event is received from the integration.  <br><strong>Events query</strong> - The events query received from the integration.  </label>
</div>
<div class="demisto-checkbox ui checkbox "><label class="checkbox-label" title="Do not validate server certificate (insecure)"><strong>Do not validate server certificate (insecure)</strong> - Select to avoid server certification validation. You may want to do this in case Cortex XSOAR cannot validate the integration server certificate (due to missing CA certificate).</label></div>
<div class="demisto-checkbox ui checkbox ">
<strong>Use system proxy settings</strong>: Select whether to communicate via the system proxy server or not.<br><strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the server.<br>Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.<br>For more information on Cortex XSOAR engines see:<br><a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Engines">Cortex XSOAR 6.13 - Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines">Cortex XSOAR 8 Cloud- Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engines">Cortex XSOAR 8.7 On-prem - Engines</a><br><strong>Require users to enter additional password:</strong> Select whether you’d like an additional step where users are required to authenticate themselves with a password.</div>
</div>
</li>
<li>Press the ‘Test’ button to validate connection.
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Fetched incidents data:</h3>
<p>The integration imports events as incidents. All events from 24 hours prior to the instance configuration and up to the current time will be fetched.</p>
<p>Top Use-case:</p>
<p>Arcsight Logger integration can be used to run a search session, refine or limit the search, and retrieve a list of events detected in the search.</p>
<p>This can be achieved in two possible ways:</p>
<ul>
<li>Use ‘as-search-events’ for the complete flow of the use case to be executed.<br>‘as-search-events’ starts a new search session, waits until the search status is complete or reaches the required number of hits, and then returns the list of detected events.</li>
</ul>
<ul>
<li>Alternatively, the explicit commands can be used to ‘breakdown’ the search-events process. A possible flow of commands can be:
<ul>
<li>Use ‘as-search’ to start a new search session and receive the session ID and search session ID to be used in the following commands.</li>
<li>Use ‘as-drilldown’ to narrow-down the search results to the specified time range.</li>
<li>Use ‘as-status’ to inquire if the search session is complete or still running, view the number of scanned events and hits.</li>
<li>Use ‘as-events’ to get a list of all events detected in the search.</li>
<li>Use ‘as-close’ to stop the execution of the search and clear the session data from the server.</li>
</ul>
</li>
</ul>
<p>Commands:</p>
<ul>
<li style="font-family: courier;"><strong>as-search-events<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>query, discover_fields, endTime, startTime, summary_fields, field_summary, local_search, timeout, lastDays, offset, length, dir, fields</p>
<p>for example:</p>
<ul>
<li>
<em>!as-search-events<br></em>query=”deviceVendor= Arcsight AND name CONTAINS \”CPU\””  <br>length=10</li>
</ul>
<ul>
<li>
<em>!as-search-events<br></em>offset=15<br>length=10<br>fields=name,deviceVendor</li>
</ul>
<p>       Find more query examples at <a href="https://wikis.uit.tufts.edu/confluence/display/exchange2010/ArcSight+Logger+-+Commonly+Used+Event+Fields">wikis/ArcsightLogger</a>.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{</p>
<p>    "ArcSightLogger": {</p>
<p>        "Events": [</p>
<p>            {</p>
<p>                "destinationAddress": ##.##.##.##,</p>
<p>                "agentSeverity": "1",</p>
<p>                "Version": "0",</p>
<p>                "Logger": "Local",</p>
<p>                "ReceiptTime": 1513249919185,</p>
<p>                "deviceCustomNumber1Label": "Percent Usage",</p>
<p>                "deviceCustomNumber1": 2,</p>
<p>                "deviceAddress":  ##.##.##.##,</p>
<p>                "deviceCustomString2Label": "timeframe",</p>
<p>                "deviceVendor": "ArcSight",</p>
<p>                "Device": "Logger",</p>
<p>                "deviceProduct": "Logger",</p>
<p>                "EventTime": 1513249440017,</p>
<p>                "baseEventCount": 1,</p>
<p>                "deviceReceiptTime": 1513249440017,</p>
<p>                "startTime": 1513249440017,</p>
<p>                "deviceEventClassId": "cpu:100",</p>
<p>                "deviceCustomString2": "CurrentValue",</p>
<p>                "name": "CPU Usage",</p>
<p>                "deviceEventCategory": "/Monitor/CPU/Usage",</p>
<p>                "rowId": "347259-26@Local",</p>
<p>                "endTime": 1513249440017,</p>
<p>                "deviceVersion": "6.2.0.7633.0"</p>
<p>            }, </p>
<p>…</p>
<p>       ]</p>
<p>   }</p>
<p>}</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>[</p>
<p>   {</p>
<p>Device:Logger</p>
<p>EventTime:1513249693332</p>
<p>Logger:Local</p>
<p>ReceiptTime:1513249693838</p>
<p>Version:0</p>
<p>agentSeverity:3</p>
<p>baseEventCount:1</p>
<p>cn1label:Session</p>
<p>destinationAddress: ##.##.##.##,</p>
<p>destinationUserId:1</p>
<p>destinationUserName:admin</p>
<p>deviceCustomNumber1: 741618068</p>
<p>deviceEventCategory:/Platform/Authentication/Login</p>
<p>deviceEventClassId:platform:230</p>
<p>deviceProduct:Logger</p>
<p>deviceVendor:ArcSight</p>
<p>deviceVersion:L7633</p>
<p>name:Successful login</p>
<p>rowId:347186-0@Local</p>
<p>sourceAddress: ##.##.##.##,</p>
<p>               },</p>
<p>                     …</p>
<p>]</p>
<p> </p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>as-search<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>query, discover_fields, endTime, startTime, summary_fields, field_summary, local_search, timeout, lastDays</p>
<p>for example:</p>
<ul>
<li>
<p><em>!as-search</em></p>
<p>startTime=2017-12-21T06:30:00.000Z</p>
<p>endTime=2017-12-21T07:30:00.000Z</p>
<p>local_search=false</p>
</li>
<li>
<p> </p>
<p><em>!as-search</em></p>
<p>lastDays=1</p>
</li>
</ul>
<p>       Find more query examples at <a href="https://wikis.uit.tufts.edu/confluence/display/exchange2010/ArcSight+Logger+-+Commonly+Used+Event+Fields">wikis/ArcsightLogger</a>.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{</p>
<p>"ArcSightLogger": {</p>
<p>"Search": {</p>
<p>"SearchSessionId": 1513260595933,</p>
<p>"SessionId": "3dxITLyDE9FyRiflQD7UFG_hSsUPq4uCTM4B6Y5D3p4."</p>
<p>}</p>
<p>}</p>
<p>}</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>{</p>
<p>searchSessionId:1513260595933</p>
<p>sessionId:3dxITLyDE9FyRiflQD7UFG_hSsUPq4uCTM4B6Y5D3p4.</p>
<p>}</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>as-drilldown<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>searchSessionId, sessionId, startTime, endTime, lastDays</p>
<p>for example:</p>
<ul>
<li>
<p><em>!as-drilldown </em></p>
<p><em>lastDays=1 <br></em><em>searchSessionId="1513875662638"<br></em><em>sessionId="18t2-5sQ4h1LcTqFwEUJj0XIatasCpM8l0T8NZlhxEg."</em></p>
</li>
<li>
<p> <em>!as-drilldown<br></em><em>startTime=2017-12-21T06:30:00.000Z<br></em><em>endTime=2017-12-21T07:30:00.000Z<br></em><em>searchSessionId="1513875662638" sessionId="18t25sQ4h1LcTqFwEUJj0XIatasCpM8l0T8NZlhxEg."</em></p>
</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p> The command has no context.</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>The command has no raw output.</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>as-status<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>searchSessionId, sessionId </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{</p>
<p>"ArcSightLogger": {</p>
<p>"Status": {</p>
<p>"Status": "complete",</p>
<p>"Hit": 2462,</p>
<p>"Elapsed": "00:00:00.290",</p>
<p>"ResultType": "histogram",</p>
<p>"Scanned": 2520,</p>
<p>"SearchSessionId": "1513272858387",</p>
<p>"Message": []</p>
<p>} </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>{</p>
<p>elapsed: 00:00:00.290</p>
<p>hit:2462</p>
<p>message: []</p>
<p>result_type: histogram</p>
<p>scanned: 2520</p>
<p>status: complete</p>
<p>}</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>as-events<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>searchSessionId, sessionId, length, dir, offset, fields</p>
<p><strong>Command use example</strong></p>
<ul>
<li>
<em>!as-events<br></em>searchSessionId="1513875662638" sessionId="18t25sQ4h1LcTqFwEUJj0XIatasCpM8l0T8NZlhxEg."<br>length=10<br>fields=name,deviceAddress,deviceVendor,EventTime</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>{</p>
<p>"ArcSightLogger": {</p>
<p>"Events": [</p>
<p>{</p>
<p>"destinationAddress": ##.##.##.##,</p>
<p>"agentSeverity": "1",</p>
<p>"Version": "0",</p>
<p>"Logger": "Local",</p>
<p>"ReceiptTime": 1513249919185,</p>
<p>"deviceCustomNumber1Label": "Percent Usage",</p>
<p>"deviceCustomNumber1": 2,</p>
<p>"deviceAddress":  ##.##.##.##,</p>
<p>"deviceCustomString2Label": "timeframe",</p>
<p>"deviceVendor": "ArcSight",</p>
<p>"Device": "Logger",</p>
<p>"deviceProduct": "Logger",</p>
<p>"EventTime": 1513249440017,</p>
<p>"baseEventCount": 1,</p>
<p>"deviceReceiptTime": 1513249440017,</p>
<p>"startTime": 1513249440017,</p>
<p>"deviceEventClassId": "cpu:100",</p>
<p>"deviceCustomString2": "CurrentValue",</p>
<p>"name": "CPU Usage",</p>
<p>"deviceEventCategory": "/Monitor/CPU/Usage",</p>
<p>"rowId": "347259-26@Local",</p>
<p>"endTime": 1513249440017,</p>
<p>"deviceVersion": "6.2.0.7633.0"</p>
<p>}, </p>
<p>…</p>
<p>]</p>
<p>}</p>
<p>}</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>[</p>
<p>{</p>
<p>Device:Logger</p>
<p>EventTime:1513249693332</p>
<p>Logger:Local</p>
<p>ReceiptTime:1513249693838</p>
<p>Version:0</p>
<p>agentSeverity:3</p>
<p>baseEventCount:1</p>
<p>cn1label:Session</p>
<p>destinationAddress: ##.##.##.##,</p>
<p>destinationUserId:1</p>
<p>destinationUserName:admin</p>
<p>deviceCustomNumber1: 741618068</p>
<p>deviceEventCategory:/Platform/Authentication/Login</p>
<p>deviceEventClassId:platform:230</p>
<p>deviceProduct:Logger</p>
<p>deviceVendor:ArcSight</p>
<p>deviceVersion:L7633</p>
<p>name:Successful login</p>
<p>rowId:347186-0@Local</p>
<p>sourceAddress: ##.##.##.##,</p>
<p>},</p>
<p>…</p>
<p>]</p>
<p> </p>
<p>{</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>as-stop<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>searchSessionId, sessionId </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>The command has no context. </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>The command has no raw output.</p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>as-close<br></strong></li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>searchSessionId, sessionId </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td>
<p>The command has no context. </p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output (example):</p>
<table style="margin-left: 70px; width: 681.556px;">
<tbody>
<tr>
<td style="width: 678.556px;">
<p>The command has no raw output.</p>
</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>Additional info:         </h3>
<ul>
<li>
<strong>Search time range:</strong> When no time limitations are applied on a search session, Arcsight Logger will use its default time limitation and will search events in time range of the last 2 hours.<br>To set the search time range:<br>
<ul>
<li>
<strong>When starting a new search session, using ‘as-search’</strong>: pass both startTime and endTime parameters to set the time range for the search. Alternatively, you can use the lastDays parameter.</li>
<li>
<strong>When in an active search session:</strong> use ‘as-drilldown’ to narrow-down the search results to a specified time range.</li>
<li>
<strong>When starting a new search, using ‘as-search-events’:</strong> pass both startTime and endTime parameters to set the time range for the search. Alternatively, use lastDays parameter.</li>
</ul>
</li>
<li>
<strong>Date/time format: </strong>Use the compliant date/time format when passing startTime and endTime parameters.</li>
<li>
<strong>Expected date/time format</strong>: yyyy-MM-dd’T’HH:mm:ss.SSSXXX.<br>For example, May 26 2014 at 21:49:46 PM could have a format like one of the following:<br>
<ul>
<li>Format in PDT: 2014-05-26T21:49:46.000-07:00</li>
<li>Format in UTC: 2014-05-26T21:49:46.000Z</li>
</ul>
</li>
<li>
<strong>Events list default limitation: </strong>The default events list length is 100. To set a new length specify the path length parameter in the relevant commands.</li>
<li>
<strong>Local/global search: </strong>In ‘as-search’ and ‘as-search-events’ you can optionally pass the  ‘local_search’ parameter, to Indicate whether the search is local only, and does not include peers. <strong>Please note</strong> that local search is the default option for a search session.</li>
</ul>
<h3>Known Limitations</h3>
<ul>
<li>
<strong>Session limitations: </strong>Arcsight Logger has default limitations for running maximum sessions simultaneously, and for inactive sessions. <br>To change the default limitation for both, use administrator credentials to login to Archsight Logger UI, navigate to ‘System Admin’-&gt;’Users/Groups’-&gt;’Authentication’ and set new limitations for ‘Max Simultaneous Logins/User’ and ‘Logout Inactive Session After’.</li>
</ul>
<h3>Troubleshooting</h3>
<ul>
<li>
<strong>Reoccurring ‘timeout’ error</strong> <strong>when using commands ‘as-search-events’ or ‘as-events’:</strong>
</li>
</ul>
<p class="wysiwyg-indent4">This may indicate that a large amount of data returned from Arcsight Logger. To resolve this error, try to limit the search time range or the events list length.  See additional ways to set the search time range in ‘Additional info’ above.<br><strong>DBot error snap-shot<br></strong> <img src="../../doc_files/ArcsightLogger_mceclip0.png"><strong><br></strong></p>
<p class="wysiwyg-indent4"> </p>
<ul>
<li><strong>Reoccurring ‘Login failed’ error when using ‘as-search’ or ‘as-search-events’:</strong></li>
</ul>
<p class="wysiwyg-indent4">First eliminate the case of wrong credentials configured in the Arcsight Logger instance.</p>
<p class="wysiwyg-indent4">If this error still araises, it may indicate that Arcsight Logger is failing to generate a new search session. New sessions cannot be generated by Arcsight Logger when the maximum allowed number of simultaneous sessions was reached.</p>
<p class="wysiwyg-indent4">To resolve this problem, use administrator credentials to login to Archsight Logger UI and set a new limitation for maximum simultaneous sessions. <br>See ’Known Limitations’ above for more information.</p>
<p class="wysiwyg-indent4">If administrator credentials are not available for you, use ‘as-close’ to close the running sessions.</p>
<p class="wysiwyg-indent4"> <strong>DBot error snap-shot<br></strong> <img src="../../doc_files/ArcsightLogger_mceclip1.png"><strong><br></strong></p>
<p> </p>
<ul>
<li><strong>Reoccurring ‘User session id is not valid’ error:</strong></li>
</ul>
<p class="wysiwyg-indent4">The search session timed out.</p>
<p class="wysiwyg-indent4">Search session timeout can be caused by the followings:<br>- Low ‘timeout’ passed to ‘as-search’. This can be resolved by passing a higher ‘timeout’      value to ‘as-search’.<br>- Arcsight Logger limitation on inactive sessions - Inactive sessions are automatically terminated after a defined period of time determined by Arcsight Logger, even if the ‘timeout’ argument is changed to ‘as-search’.</p>
<p class="wysiwyg-indent4">To resolve this problem, use administrator credentials to login to Archsight Logger UI and set a new limitation for inactive sessions. See ’Known Limitations’ above for more information. </p>
<p class="wysiwyg-indent4"><strong>DBot error snap-shot</strong></p>
<p class="wysiwyg-indent4"><img src="../../doc_files/ArcsightLogger_mceclip2.png"></p>