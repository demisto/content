<!-- HTML_DOC -->
<p>Use the SplunkPy integration to fetch events (logs) from within Demisto, push events from Demisto to SplunkPy, and fetch SplunkPy ES notable events as Demisto incidents.</p>
<p>This integration was integrated and tested with Splunk v6.5.</p>
<h2>Use Cases</h2>
<ul>
<li>Query Splunk for events</li>
<li>Create a new event in Splunk</li>
<li>Get results of a search that was executed in Splunk</li>
</ul>
<h2>Prerequisites</h2>
<p>Make sure you satisfy the following requirements on SplunkPy before you configure SplunkPy on Demisto.</p>
<ul>
<li>Splunk username and password.</li>
<li>To use a Splunk Cloud instance, contact Splunk support to request API access. Use the non-SAML authentication. Use the following host: input-${deployment-name}.cloud.splunk.com.</li>
<li>If you encounter certificate validation problems, open a configuration file: /etc/python/cert-verification.cfg, find "verify=enable" and change it to disable.</li>
</ul>
<h2>Configure SplunkPy on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for SplunkPy.</li>
<li>Click ‘Add instance’ to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Host IP</strong>: The hostname or IP address of your Splunk instance.</li>
<li><strong>Username and Password</strong></li>
<li>
<strong>Port</strong>: The appliance port, usually 8089. This is not the same as the web user interface port.</li>
<li>
<strong>Fetch notable events ES query</strong>: This query is used to fetch notable events, relevant only to Splunk Enterprise Security.</li>
<li>
<strong>Fetch incidents</strong>: Select if to automatically create Demisto incidents from this integration instance.</li>
<li>
<strong>Fetch limit</strong>: The maximum number of results to return (max. 50).</li>
<li>
<strong>Incident type</strong>: Select the incident type to trigger.</li>
<li>
<strong>Proxy:</strong> in format: 127.0.0.1:8080. If you use a proxy to reach SplunkPy from your environment, add it here. The proxy IP and port format:127.0.0.1:8080.</li>
<li>
<strong>Timezone of Splunk server:</strong> If the Demisto server and SplunkPy server are on different time zones, and you want to fetch notable events in real time (Splunk ES only), specify the time gap in minutes (for example, for gmt +3 set +180).</li>
<li><strong>Parse Raw part of notable events</strong></li>
<li>
<strong>Extract Fields:</strong> A comma-separated list of fields that will be parsed out of raw notable events.</li>
<li><strong>Use Splunk Clock Time for Fetch</strong></li>
<li>
<strong>Earliest time to fetch</strong>: T<span>he name of the Splunk field whose value defines the query's earliest time to fetch</span>
</li>
<li>
<strong>Latest time to fetch</strong>: T<span>he name of the Splunk field whose value defines the query's latest time to fetch.</span>
</li>
<li><span><strong>App</strong>: The app context of the namespace.</span></li>
<li>
<strong>Demisto engine</strong>: If relevant, select the engine that acts as a proxy to the server.<br> Demisto uses engines to access remote segments, when network devices (like proxies and firewalls) prevent the Demisto server from accessing these remote networks.<br> For more information on Demisto engines see:<br> <a href="https://support.demisto.com/hc/en-us/articles/226274727-Settings-Integrations-Engines">https://demisto.zendesk.com/hc/en-us/articles/226274727-Settings-Integrations-Engines</a>
</li>
<li>
<strong>Require users to enter an additional password</strong>: Select if you want to require users to authenticate themselves with a password as an additional step.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate URLs and connection.</li>
</ol>
<h2>Configure Splunk to Produce Alerts for SplunkPy</h2>
<p>We recommend that you configure Splunk to produce basic alerts that the SplunkPy integration can ingest, by creating a summary index in which alerts are stored. The SplunkPy integration can then query that index for incident ingestion. We do not recommend using the Demisto App for Splunk for routine event consumption because this method is not monitorable nor scalable.</p>
<ol>
<li>Create a summary index in Splunk. For more information, see the <a href="https://docs.splunk.com/Documentation/Splunk/7.3.0/Indexer/Setupmultipleindexes#Create_events_indexes_2" target="_blank" rel="noopener">Splunk documentation</a>.</li>
<li>Build a query to return relevant alerts.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Query_Example.png" alt="SplunkPy_-_Query_Example.png">
</li>
<li>Identify the Fields list from the Splunk query and save it to a local file.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Fields_List.png" alt="SplunkPy_-_Fields_List.png">
</li>
<li>Define a search macro to capture the Fields list that you saved locally. For more information, see the <a href="https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros" target="_blank" rel="noopener">Splunk documentation</a>.<br>Use the following naming convention: (demisto_fields_{type}).<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Macro.png" alt="SplunkPy_-_Macro.png"><br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Macros2.png" alt="SplunkPy_-_Macros2.png">
</li>
<li>Define a scheduled search, the results of which are stored in the summary index. For more information about scheduling searches, see the <a href="https://docs.splunk.com/Documentation/Splunk/7.3.0/Alert/Definescheduledalerts" target="_blank" rel="noopener">Splunk documentation</a>.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Scheduled_Search_1.png" alt="SplunkPy_-_Scheduled_Search_1.png">
</li>
<li>In the Summary indexing section, select the summary index, and enter the {key:value} pair for Demisto classification.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Scheduled_Search_2.png" alt="SplunkPy_-_Scheduled_Search_2.png">
</li>
<li>Configure the incident type in Demisto by navigating to <strong>Settings &gt; Advanced &gt; Incident Types</strong>.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Define_Incident_Type.png" alt="SplunkPy_-_Define_Incident_Type.png">
</li>
<li>Navigate to <strong>Settings &gt; Integrations &gt; Classification &amp; Mapping</strong>, and drag the value to the appropriate incident type.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Mapping_and_Classification.png" alt="SplunkPy_-_Mapping_and_Classification.png">
</li>
<li>Click the <strong>Edit mapping</strong> link to map the Splunk fields to Demisto.<br><img src="https://raw.githubusercontent.com/demisto/content/a2c287c5ab0bf88b6aece7bcf70c45b0500ca572/docs/images/Integrations/SplunkPy_SplunkPy_-_Mapping_and_Classification_2.png" alt="SplunkPy_-_Mapping_and_Classification_2.png">
</li>
<li>(optional) Create custom fields.</li>
<li>Build a playbook and assign it as the default for this incident type.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<ol>
<li><a href="#h_38658307461530020654003">Search SplunkPy: splunk-search</a></li>
<li><a href="#h_578742137491530020662320">Create a job: splunk-job-create</a></li>
<li><a href="#h_369548850901530020680044">Get the results of a previous search: splunk-results</a></li>
<li><a href="#h_4126493431301530020689487">Create a new event: splunk-submit-event</a></li>
<li><a href="#h_1819590401711530020699266">Get index: splunk-get-indexes</a></li>
<li><a href="#h_3454070742101530020710886">Edit a notable event: splunk-notable-event-edit</a></li>
</ol>
<h3 id="h_38658307461530020654003">1. Search SplunkPy</h3>
<hr>
<p>Search SplunkPy for a specific text.</p>
<p>You can search for notable events using the <em><strong>notable</strong></em> macro. For example: <code>query="`notable` | head 3</code>.</p>
<h5>Base Command</h5>
<p><code>splunk-search</code></p>
<h5>Input:</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 158px;"><strong>Argument Name</strong></td>
<td style="width: 571px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">Query</td>
<td style="width: 571px;">String. Required. Text to search for.</td>
</tr>
<tr>
<td style="width: 158px;">Earliest_time</td>
<td style="width: 571px;">
<p>Specifies start time for search range.</p>
<p>The time string can be a UTC time (with fractional seconds), a relative time specifier (relative to now), or a formatted time string.</p>
<p>It is also possible to use this time format: 2014-06-19T12:00:00.000-07:00.</p>
<p>Default is 1 week ago, in this format "-7d".</p>
</td>
</tr>
<tr>
<td style="width: 158px;">event_limit</td>
<td style="width: 571px;">
<p>Limits the amount of events to return.</p>
<p>Zero equals unlimited. </p>
<p>Default is 100.</p>
</td>
</tr>
<tr>
<td style="width: 158px;">Latest_time</td>
<td style="width: 571px;">
<p>Specifies end time for search range.</p>
<p>The time string can be a UTC time (with fractional seconds), a relative time specifier (relative to now), or a formatted time string, for example "2014-06-19T12:00:00.000-07:00" or "-3d" (for time 3 days before now).</p>
<p>Default is one week from start time.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!splunk-search query="* | head 3"</code></p>
<h5>Context Output</h5>
<pre>[  
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:337",
      "_indextime":"1511162543",
      "_raw":"test",
      "_serial":"0",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T07:22:23.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   },
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:336",
      "_indextime":"1511141352",
      "_raw":"test",
      "_serial":"1",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T01:29:12.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   },
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:335",
      "_indextime":"1511141044",
      "_raw":"test",
      "_serial":"2",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T01:24:04.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   }
]
</pre>
<p> </p>
<h5>War Room Output</h5>
<p>The War Room output is raw JSON, because the data from SplunkPy logs can differ across datasets.</p>
<pre>[  
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:337",
      "_indextime":"1511162543",
      "_raw":"test",
      "_serial":"0",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T07:22:23.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   },
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:336",
      "_indextime":"1511141352",
      "_raw":"test",
      "_serial":"1",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T01:29:12.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   },
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:335",
      "_indextime":"1511141044",
      "_raw":"test",
      "_serial":"2",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T01:24:04.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   }
]
</pre>
<p> </p>
<h3 id="h_578742137491530020662320">2. Create a Job</h3>
<hr>
<p>Creates a job.</p>
<h5>Basic Command</h5>
<p><code>splunk-job-create</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>Query</td>
<td>String. Required. Text to search for</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<p><code>Splunk.Job=1511167689.39984</code></p>
<h5>War Room Output</h5>
<p><code>Splunk Job created with SID: 1511167689.39984 </code></p>
<h3 id="h_369548850901530020680044">3. Get the results of a previous search</h3>
<hr>
<p>Gets the results of a search previously executed in SplunkPy.</p>
<h5>Base Command</h5>
<p><code>splunk-results</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<td style="width: 348px;"><strong>Argument Name</strong></td>
<td style="width: 381px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 348px;">SID</td>
<td style="width: 381px;">Search ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example:</h5>
<p><code>!splunk-results sid=1506542235.419700</code></p>
<h5>War Room Output</h5>
<pre>[  
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:337",
      "_indextime":"1511162543",
      "_raw":"test",
      "_serial":"0",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T07:22:23.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   },
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:336",
      "_indextime":"1511141352",
      "_raw":"test",
      "_serial":"1",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T01:29:12.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   },
   {  
      "_bkt":"main~6~20D04CCE-0394-423E-984A-7CD0719C07C1",
      "_cd":"6:335",
      "_indextime":"1511141044",
      "_raw":"test",
      "_serial":"2",
      "_si":[  
         "ip-172-31-16-62",
         "main"
      ],
      "_sourcetype":"demisto-ci",
      "_time":"2017-11-20T01:24:04.000+00:00",
      "host":"localhost",
      "index":"main",
      "linecount":"1",
      "source":"http-simple",
      "sourcetype":"demisto-ci",
      "splunk_server":"ip-172-31-16-62"
   }
]
</pre>
<h3 id="h_4126493431301530020689487">4. Create a new event</h3>
<hr>
<p>Creates a new event in Splunk.</p>
<h5>Base Command</h5>
<p><code>splunk-submit-event</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>index</td>
<td>
<p>Required. The SplunkPy index to push data to.</p>
<p>Run <code>splunk-get-indexes</code> to get all indexes.</p>
</td>
</tr>
<tr>
<td>Data</td>
<td>
<p>Required. The new event data to push.</p>
<p>Can be any string.</p>
</td>
</tr>
<tr>
<td>Sourcetype</td>
<td>Required. The Event source-type.</td>
</tr>
<tr>
<td>Host</td>
<td>
<p>Required. The Event host.</p>
<p>Can be local or '120.0.0.1'.</p>
</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example:</h5>
<p><code>!splunk-submit-event data="event data" host=127.0.0.1 index=main sourcetype=src</code></p>
<h5>Context Output</h5>
<p>There is no context output.</p>
<h5>War Room Output</h5>
<p><code>Event was created in Splunk index: main</code></p>
<h3 id="h_1819590401711530020699266">5. Get Indexes</h3>
<hr>
<p>Returns all indexes.</p>
<h5>Base Command</h5>
<p><code>splunk-get-indexes</code></p>
<h5>Input</h5>
<p>This command does not require any parameters.</p>
<h5>Context Output</h5>
<p>There is no context output.</p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "count":"764852",
      "name":"_audit"
   },
   {  
      "count":"5278037",
      "name":"_internal"
   },
   {  
      "count":"5210675",
      "name":"_introspection"
   },
   {  
      "count":"0",
      "name":"_thefishbucket"
   },
   {  
      "count":"0",
      "name":"history"
   },
   {  
      "count":"17543",
      "name":"main"
   },
   {  
      "count":"0",
      "name":"splunklogger"
   },
   {  
      "count":"0",
      "name":"summary"
   }
]
</pre>
<p> </p>
<h5>War Room Output</h5>
<pre>count | name
-- | --
764852 | _audit
5277911 | _internal
5210660 | _introspection
0 | _thefishbucket
0 | history
17543 | main
0 | splunklogger
0 | summary
</pre>
<h3 id="h_3454070742101530020710886">6. Edit a notable event</h3>
<hr>
<p>Modifies a notable event.</p>
<h5>Base Command</h5>
<p><code>splunk-notable-event-edit</code></p>
<h5>Input</h5>
<table style="width: 750px;">
<thead>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>EventIDs</td>
<td>Required. Comma-sepperated list of event-IDs, pertaining to notable events.</td>
</tr>
<tr>
<td>Comment</td>
<td>Required. Comment to add to the notable event</td>
</tr>
<tr>
<td>Owner</td>
<td>Splunk-user to assign to the notable event</td>
</tr>
<tr>
<td>Urgency</td>
<td>Notable event urgency</td>
</tr>
<tr>
<td>Status</td>
<td>
<p>Notable event status:</p>
<ul>
<li>0 for Unassigned</li>
<li>1 for Assigned</li>
<li>2 for In Progress</li>
<li>3 for pending</li>
<li>4 for Resolved</li>
<li>5 for Closed</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output.</p>
