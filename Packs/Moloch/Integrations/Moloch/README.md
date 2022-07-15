<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Moloch integration to store and index network traffic in standard PCAP format.</p>
<p>This integration was integrated and tested with Moloch v1.5.1.</p>
<p> </p>
<h2>Configure Moloch on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Moloch.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br>After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_69960582341534849781507">Retrieve connections data in JSON: moloch_connections_json</a></li>
<li><a href="#h_904296321891534849786929">Retrieve connections data in CSV: moloch_connections_csv</a></li>
<li><a href="#h_5776399291731534849792667">Return a list of files: moloch_files_json</a></li>
<li><a href="#h_2349818532561534849799003">Retrieve session data in JSON: moloch_sessions_json</a></li>
<li><a href="#h_8715631133381534849806087">Retrieve session data in CSV: moloch_sessions_csv</a></li>
<li><a href="#h_9944458354201534849812715">Retrieve session data in PCAP: moloch_sessions_pcap</a></li>
<li><a href="#h_6574066535021534849825151">Retrieve Spigraph data in JSON: moloch_spigraph_json</a></li>
<li><a href="#h_7273295005831534849837430">Retrieve Spiview data in JSON: moloch_spiview_json</a></li>
<li><a href="#h_5058951916611534849845170">Retrieve unique data for a field in JSON: moloch_unique_json</a></li>
</ol>
<p> </p>
<h3 id="h_69960582341534849781507">1. Retrieve connections data in JSON</h3>
<hr>
<p>Retrieve the connections data in JSON format.</p>
<h5>Base Command</h5>
<p><code>moloch_connections_json</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 152px;"><strong>Argument Name</strong></th>
<th style="width: 485px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">date</td>
<td style="width: 485px;">The number of hours to return data for (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">dstField</td>
<td style="width: 485px;">The source database field name (Default: a2)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">expression</td>
<td style="width: 485px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">iDisplayLength</td>
<td style="width: 485px;">Number of items to return (Default: 5000, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">iDisplayStart</td>
<td style="width: 485px;">The entry to start from (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">length</td>
<td style="width: 485px;">The number of items to return (Default: 5000, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">srcField</td>
<td style="width: 485px;">The source database field name (Default: a1)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">start</td>
<td style="width: 485px;">The entry to start from (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">startTime</td>
<td style="width: 485px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">stopTime</td>
<td style="width: 485px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">strictly</td>
<td style="width: 485px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">view</td>
<td style="width: 485px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_connections_json startTime="2014/02/26 10:27:57"
</code></p>
<h5>Human Readable Output</h5>
<pre>{
    "health": {
        "_timeStamp": 1534839251551,
        "active_primary_shards": 380,
        "active_shards": 380,
        "active_shards_percent_as_number": 100,
        "cluster_name": "Moloch",
        "delayed_unassigned_shards": 0,
        "initializing_shards": 0,
        "molochDbVersion": 51,
        "number_of_data_nodes": 1,
        "number_of_in_flight_fetch": 0,
        "number_of_nodes": 1,
        "number_of_pending_tasks": 0,
        "relocating_shards": 0,
        "status": "green",
        "task_max_waiting_in_queue_millis": 0,
        "timed_out": false,
        "unassigned_shards": 0,
        "version": "5.6.4"
    },
    "links": [
        {
            "by": 136284,
            "db": 121356,
            "node": {
                "demo": 1
            },
            "pa": 1866,
            "source": 0,
            "target": 1,
            "value": 4
        },
        {
            "by": 8999,
            "db": 8231,
            "node": {
                "demo": 1,
                "ip-10-97-23-168": 1
            },
            "pa": 96,
            "source": 2,
            "target": 3,
            "value": 4
        }
    ],
    "nodes": [
        {
            "by": 136284,
            "cnt": 1,
            "db": 121356,
            "id": "1.1.1.1",
            "pa": 1866,
            "pos": 0,
            "sessions": 4,
            "type": 1
        },
        {
            "by": 136284,
            "cnt": 1,
            "db": 121356,
            "id": "2.2.2.2",
            "pa": 1866,
            "pos": 1,
            "sessions": 4,
            "type": 2
        }
    ],
    "recordsFiltered": 145724
}
</pre>
<h3> </h3>
<h3 id="h_904296321891534849786929">2. Retrieve connections data in CSV: moloch_connections_csv</h3>
<hr>
<p>Retrieve the connections data in CSV format.</p>
<h5>Base Command</h5>
<p><code>moloch_connections_csv</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">date</td>
<td style="width: 506px;">The number of hours to return data for (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">dstField</td>
<td style="width: 506px;">The source database field name (Default: a2)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">expression</td>
<td style="width: 506px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">iDisplayLength</td>
<td style="width: 506px;">The number of items to return (Default: 5000, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">iDisplayStart</td>
<td style="width: 506px;">The entry to start from (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">length</td>
<td style="width: 506px;">The number of items to return (Default: 5000, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">srcField</td>
<td style="width: 506px;">The source database field name (Default: a1)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">start</td>
<td style="width: 506px;">The entry to start at (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">startTime</td>
<td style="width: 506px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">stopTime</td>
<td style="width: 506px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">strictly</td>
<td style="width: 506px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">view</td>
<td style="width: 506px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_connections_csv date="-1"
</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44390423-e6dea200-a535-11e8-9c05-2758da9b568b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44390423-e6dea200-a535-11e8-9c05-2758da9b568b.png" alt="screen shot 2018-08-21 at 11 32 06" width="749" height="77"></a></p>
<h3> </h3>
<h3 id="h_5776399291731534849792667">3. Return a list of files</h3>
<hr>
<p>Return a list of files in the Moloch database.</p>
<h5>Base Command</h5>
<p><code>moloch_files_json</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>iDisplayLength</td>
<td>The number of items to return (Default: 500, Max: 10000)</td>
<td>Optional</td>
</tr>
<tr>
<td>iDisplayStart</td>
<td>The entry to start from (Default: 0)</td>
<td>Optional</td>
</tr>
<tr>
<td>length</td>
<td>The number of items to return (Default: 500, Max: 10000)</td>
<td>Optional</td>
</tr>
<tr>
<td>start</td>
<td>The entry to start at (Default: 0)</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_files_json length="10"
</code></p>
<h5>Human Readable Output</h5>
<pre>{
    "data": [
        {
            "filesize": 15819,
            "first": 1273057060,
            "id": "demo-1",
            "locked": 1,
            "name": "/moloch/1filtered.cap",
            "node": "demo",
            "num": 1
        },
        {
            "filesize": 2514,
            "first": 1249662076,
            "id": "demo-2",
            "locked": 1,
            "name": "/moloch/20090807_portal_prod_io0_01.cap",
            "node": "demo",
            "num": 2
        }
    ],
    "recordsFiltered": 434,
    "recordsTotal": 434
}
</pre>
<h3> </h3>
<h3 id="h_2349818532561534849799003">4. Retrieve session data in JSON</h3>
<hr>
<p>Retrieve the session data in JSON format.</p>
<h5>Base Command</h5>
<p><code>moloch_sessions_json</code></p>
<h5>Input</h5>
<table style="width: 738px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">date</td>
<td style="width: 500px;">The number of hours to return data for (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">expression</td>
<td style="width: 500px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">facets</td>
<td style="width: 500px;">Also include the aggregation information for maps and time graphs</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">iDisplayLength</td>
<td style="width: 500px;">The number of items to return (Default: 100, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">iDisplayStart</td>
<td style="width: 500px;">The entry to start from (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">length</td>
<td style="width: 500px;">The number of items to return (Default: 100, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">start</td>
<td style="width: 500px;">The entry to start at (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">startTime</td>
<td style="width: 500px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">stopTime</td>
<td style="width: 500px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">strictly</td>
<td style="width: 500px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">view</td>
<td style="width: 500px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_sessions_json stopTime="2014/02/26 11:27:57"
</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44390893-1215c100-a537-11e8-9b55-387330049a5e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44390893-1215c100-a537-11e8-9b55-387330049a5e.png" alt="image" width="747" height="313"></a></p>
<h3> </h3>
<h3 id="h_8715631133381534849806087">5. Retrieve session data in CSV</h3>
<hr>
<p>Retrieve the session data in CSV format.</p>
<h5>Base Command</h5>
<p><code>moloch_sessions_csv</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 503px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">date</td>
<td style="width: 503px;">The number of hours to return data for (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">expression</td>
<td style="width: 503px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">facets</td>
<td style="width: 503px;">Also include the aggregation information for maps and time graphs</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">iDisplayLength</td>
<td style="width: 503px;">The number of items to return (Default: 100, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">iDisplayStart</td>
<td style="width: 503px;">The entry to start from (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">length</td>
<td style="width: 503px;">the number of items to return (Default: 100, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">start</td>
<td style="width: 503px;">The entry to start at (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">startTime</td>
<td style="width: 503px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">stopTime</td>
<td style="width: 503px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">strictly</td>
<td style="width: 503px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">view</td>
<td style="width: 503px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_sessions_csv
</code></p>
<h5> </h5>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44390942-35d90700-a537-11e8-8599-91969b2e8afd.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44390942-35d90700-a537-11e8-8599-91969b2e8afd.png" alt="image" width="748" height="70"></a></p>
<h3> </h3>
<h3 id="h_9944458354201534849812715">6. Retrieve raw session data in PCAP</h3>
<hr>
<p>Retrieve the raw session data in PCAP format.</p>
<h5>Base Command</h5>
<p><code>moloch_sessions_pcap</code></p>
<h5>Input</h5>
<table style="width: 740px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">date</td>
<td style="width: 504px;">The number of hours to return data for (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">expression</td>
<td style="width: 504px;">The expression string, used if ids not set</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">ids</td>
<td style="width: 504px;">The list of ids to return</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">iDisplayLength</td>
<td style="width: 504px;">The number of items to return (Default: 100, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">iDisplayStart</td>
<td style="width: 504px;">The entry to start from (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">length</td>
<td style="width: 504px;">The number of items to return (Default: 100, Max: 2000000)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">segments</td>
<td style="width: 504px;">When set return linked segments</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">start</td>
<td style="width: 504px;">The entry to start at (Default: 0)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">startTime</td>
<td style="width: 504px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">stopTime</td>
<td style="width: 504px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">strictly</td>
<td style="width: 504px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">view</td>
<td style="width: 504px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!moloch_sessions_pcap startTime="1520542248" stopTime="1533329500"
</code></p>
<h5> </h5>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44391036-76388500-a537-11e8-93c7-746d9a00a6b1.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44391036-76388500-a537-11e8-93c7-746d9a00a6b1.png" alt="image" width="752" height="66"></a></p>
<h3> </h3>
<h3 id="h_6574066535021534849825151">7. Retrieve Spigraph data in JSON</h3>
<hr>
<p>Retrieve the Spigraph data in JSON format.</p>
<h5>Base Command</h5>
<p><code>moloch_spigraph_json</code></p>
<h5>Input</h5>
<table style="width: 740px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">date</td>
<td style="width: 499px;">The number of hours to return data for (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">expression</td>
<td style="width: 499px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">field</td>
<td style="width: 499px;">The database field name to spigraph on</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">size</td>
<td style="width: 499px;">The number of unique values to return</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">startTime</td>
<td style="width: 499px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">stopTime</td>
<td style="width: 499px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">strictly</td>
<td style="width: 499px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">view</td>
<td style="width: 499px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!moloch_spigraph_json startTime=1520542248 stopTime=1533329500
</code></p>
<h5> </h5>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44391124-b435a900-a537-11e8-9ff7-8ed23760e886.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44391124-b435a900-a537-11e8-9ff7-8ed23760e886.png" alt="image" width="752" height="63"></a><br><a href="https://user-images.githubusercontent.com/37589583/44391182-d92a1c00-a537-11e8-835f-ad2df937caf3.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44391182-d92a1c00-a537-11e8-835f-ad2df937caf3.png" alt="image"></a></p>
<h3> </h3>
<h3 id="h_7273295005831534849837430">8. Retrieve Spiview data in JSON</h3>
<hr>
<p>Retrieve the Spiview data in JSON format.</p>
<h5>Base Command</h5>
<p><code>moloch_spiview_json</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 503px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">date</td>
<td style="width: 503px;">The number of hours of data to return (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">expression</td>
<td style="width: 503px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">spi</td>
<td style="width: 503px;">A comma-separated list of fields to return data for</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">startTime</td>
<td style="width: 503px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">stopTime</td>
<td style="width: 503px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">strictly</td>
<td style="width: 503px;">When this argument is used, the entire session must be within the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">view</td>
<td style="width: 503px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_spiview_json startTime=1520542248 stopTime=1533329500
</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37589583/44391263-04147000-a538-11e8-92e1-da62736c0494.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37589583/44391263-04147000-a538-11e8-92e1-da62736c0494.png" alt="image" width="751" height="129"></a></p>
<h3> </h3>
<h3 id="h_5058951916611534849845170">9. Retrieve unique data for a field in JSON</h3>
<hr>
<p>Retrieve unique data for a specified field in JSON format.</p>
<h5>Base Command</h5>
<p><code>moloch_unique_json</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">date</td>
<td style="width: 495px;">The number of hours of data to return (-1 returns all data)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">expression</td>
<td style="width: 495px;">The expression string</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">field</td>
<td style="width: 495px;">The database field name to unique on</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">startTime</td>
<td style="width: 495px;">If the date parameter is not set, this is the start time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">stopTime</td>
<td style="width: 495px;">If the date parameter is not set, this is the stop time of the date to return. If an integer is used (the number of seconds since Unix EPOC), otherwise parsed using JavaScript Date parser. Usage example: <code>!moloch_sessions_json startTime="2014/02/26 10:27:57"</code>. For more  examples see <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/parse" target="_blank" rel="noopener">here</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">strictly</td>
<td style="width: 495px;">When set the entire session must be inside the date range to be observed, otherwise if it overlaps it is displayed</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">view</td>
<td style="width: 495px;">The view name to apply before the expression</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!moloch_unique_json date="-1" field="https.status"</code></p>