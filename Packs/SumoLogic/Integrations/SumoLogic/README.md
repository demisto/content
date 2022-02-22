<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the SumoLogic integration to search for and return SumoLogic records.</p>
<h2>Configure SumoLogic on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for SumoLogic_copy.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>SumoLogic URL, in the format<span> </span><a href="https://api.us2.sumologic.com/api/" rel="nofollow">https://api.us2.sumologic.com/api/</a>. This is region specific.</strong></li>
<li><strong>API Version</strong></li>
<li><strong>The access ID - can be created under "Settings"</strong></li>
<li><strong>The access key - can be created under "Settings"</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Escape URLs</strong> (add a \\ prefix to = chars when the value queried is a URL. Default is false.)</li>
<li><strong>Seconds to sleep between checking for results</strong></li>
<li><strong>Default limit for the number of records to retrieve</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Run this query to fetch new events as incidents</strong></li>
<li><strong>Timeframe for first fetch (in seconds)</strong></li>
<li><strong><span>Time between fetches (in seconds). The actual time will be the maximum between the selected value and the server configuration.</span></strong></li>
<li><strong>Default max total wait for results</strong></li>
<li><strong>Time Zone</strong></li>
<li><strong><span>Fetch aggregate records (instead of messages)</span></strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>

Note: in versions preceding 1.1.0, URL escaping was performed as default. The `Escape URLs` param allows disabling the escaping when necessary by setting it to `true`. 

<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_13217748-cde2-4873-9928-dbcf2992e581" target="_self">Search for SumoLogic records: search</a></li>
</ol>
<h3 id="h_13217748-cde2-4873-9928-dbcf2992e581">1. Search for SumoLogic Records</h3>
<hr>
<p>Search SumoLogic for records that match the specified query.</p>
<h5>Base Command</h5>
<p><code>search</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 187px;"><strong>Argument Name</strong></th>
<th style="width: 482px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">query</td>
<td style="width: 482px;">The search query to execute</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 187px;">from</td>
<td style="width: 482px;">The ISO 8601 date of the time range to start the search (example - 2016-08-28T12:00:00). Can also be milliseconds since epoch.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 187px;">to</td>
<td style="width: 482px;">The ISO 8601 date of the time range to end the search (example - 2016-08-28T12:00:00). Can also be milliseconds since epoch.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 187px;">limit</td>
<td style="width: 482px;">Maximum number of results to return from query. Default is 100. The value specified overrides the default set in the limit parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 187px;">offset</td>
<td style="width: 482px;">Return results starting at this offset. should be int - by default is 0</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 187px;">timezone</td>
<td style="width: 482px;">The time zone if from/to is not in milliseconds, default is UTC, See this (<a href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones" rel="nofollow">https://en.wikipedia.org/wiki/List_of_tz_database_time_zones</a>) article for a list of time zone codes.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 187px;">maxTimeToWaitForResults</td>
<td style="width: 482px;">Max amount of minutes to wait for search to end, default is 10 minutes</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 187px;">headers</td>
<td style="width: 482px;">A comma separated list of table headers that are displayed in order. For example, _blockid,_collector,_format.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 187px;">byReceiptTime</td>
<td style="width: 482px;">Define as "true" to run the search using receipt time. By default, searches do not run by receipt time.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 215px;"><strong>Path</strong></th>
<th style="width: 109px;"><strong>Type</strong></th>
<th style="width: 416px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 215px;">Search.Messages</td>
<td style="width: 109px;">unknown</td>
<td style="width: 416px;">The array of raw message objects</td>
</tr>
<tr>
<td style="width: 215px;">Search.Records</td>
<td style="width: 109px;">unknown</td>
<td style="width: 416px;">The array of aggregate records</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!search query=_sourceCategory=macos/system from=2019-07-02T12:00:00 to=2019-07-04T16:00:00 using=SumoLogic_copy_instance_1 byReceiptTime=false limit=5</pre>
<h5>Context Example</h5>
<pre>{
    "Search": {
        "Messages": [
            {
                "_messageid": "-9223372036854375794", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745796", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255587000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:53:07 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.", 
                "_size": "142", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "2", 
                "_receipttime": "1562244826549", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854375795", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745797", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255551000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:52:31 TLVMAC30YCJG5H syslogd[46]: ASL Sender Statistics", 
                "_size": "65", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "1", 
                "_receipttime": "1562244789356", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854375796", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745798", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255501000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:51:41 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.", 
                "_size": "142", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "0", 
                "_receipttime": "1562244754298", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854425618", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854750767", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255066000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:44:26 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.apple.quicklook[57770]): Endpoint has been activated through legacy launch(3) APIs. Please switch to XPC or bootstrap_check_in(): com.apple.quicklook", 
                "_size": "210", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "2", 
                "_receipttime": "1562244306570", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854375797", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745799", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562254946000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:42:26 TLVMAC30YCJG5H syslogd[46]: ASL Sender Statistics", 
                "_size": "65", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "1", 
                "_receipttime": "1562244217085", 
                "_view": ""
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>SumoLogic Search Messages</h3>
<table>
<thead>
<tr>
<th>blockid</th>
<th>collector</th>
<th>collectorid</th>
<th>format</th>
<th>messagecount</th>
<th>messageid</th>
<th>messagetime</th>
<th>raw</th>
<th>receipttime</th>
<th>size</th>
<th>source</th>
<th>sourcecategory</th>
<th>sourcehost</th>
<th>sourceid</th>
<th>sourcename</th>
<th>view</th>
</tr>
</thead>
<tbody>
<tr>
<td>-9223372036854745796</td>
<td>TLVMAC30YCJG5H</td>
<td>162683374</td>
<td>t:cache:0:l:15:p:MMM dd HH:mm:ss</td>
<td>2</td>
<td>-9223372036854375794</td>
<td>1562255587000</td>
<td>Jul 4 15:53:07 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.</td>
<td>1562244826549</td>
<td>142</td>
<td>macOS System</td>
<td>macos/system</td>
<td>TLVMAC30YCJG5H</td>
<td>753908607</td>
<td>/private/var/log/system.log</td>
<td> </td>
</tr>
<tr>
<td>-9223372036854745797</td>
<td>TLVMAC30YCJG5H</td>
<td>162683374</td>
<td>t:cache:0:l:15:p:MMM dd HH:mm:ss</td>
<td>1</td>
<td>-9223372036854375795</td>
<td>1562255551000</td>
<td>Jul 4 15:52:31 TLVMAC30YCJG5H syslogd[46]: ASL Sender Statistics</td>
<td>1562244789356</td>
<td>65</td>
<td>macOS System</td>
<td>macos/system</td>
<td>TLVMAC30YCJG5H</td>
<td>753908607</td>
<td>/private/var/log/system.log</td>
<td> </td>
</tr>
<tr>
<td>-9223372036854745798</td>
<td>TLVMAC30YCJG5H</td>
<td>162683374</td>
<td>t:cache:0:l:15:p:MMM dd HH:mm:ss</td>
<td>0</td>
<td>-9223372036854375796</td>
<td>1562255501000</td>
<td>Jul 4 15:51:41 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.</td>
<td>1562244754298</td>
<td>142</td>
<td>macOS System</td>
<td>macos/system</td>
<td>TLVMAC30YCJG5H</td>
<td>753908607</td>
<td>/private/var/log/system.log</td>
<td> </td>
</tr>
<tr>
<td>-9223372036854750767</td>
<td>TLVMAC30YCJG5H</td>
<td>162683374</td>
<td>t:cache:0:l:15:p:MMM dd HH:mm:ss</td>
<td>2</td>
<td>-9223372036854425618</td>
<td>1562255066000</td>
<td>Jul 4 15:44:26 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.apple.quicklook[57770]): Endpoint has been activated through legacy launch(3) APIs. Please switch to XPC or bootstrap_check_in():<span> </span>
</td>
</tr>
</tbody>
</table>
</div>