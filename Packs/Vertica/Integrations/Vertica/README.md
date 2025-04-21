<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>This integration was integrated and tested with Vertica v4.1.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-vertica-on-xsoar">Configure Vertica on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Vertica.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Host (myhost.example.com)</strong></li>
<li><strong>Database</strong></li>
<li><strong>Username</strong></li>
<li><strong>Port</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#query-the-vertica-database" target="_self">Query the Vertica database: vertica-query</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="query-the-vertica-database">1. Query the Vertica database</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Executes a query on the Vertica database.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vertica-query</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 183px;"><strong>Argument Name</strong></th>
<th style="width: 460px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183px;">query</td>
<td style="width: 460px;">A SQL query to perform on the Vertica database.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 183px;">limit</td>
<td style="width: 460px;">The maximum number of results to return.</td>
<td style="width: 97px;">Optional</td>
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
<th style="width: 239px;"><strong>Path</strong></th>
<th style="width: 122px;"><strong>Type</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 239px;">Vertica.Query</td>
<td style="width: 122px;">string</td>
<td style="width: 379px;">The original query.</td>
</tr>
<tr>
<td style="width: 239px;">Vertica.Row</td>
<td style="width: 122px;">string</td>
<td style="width: 379px;">The content of rows.</td>
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
<pre>!vertica-query query="SELECT * FROM system_tables ORDER BY table_schema, table_name LIMIT 5;" limit="50"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>Vertica:{} 2 items
Query:SELECT * FROM system_tables ORDER BY table_schema, table_name LIMIT 5;
Row:[] 5 items
0:{} 8 items
IsAccessibleDuringLockdown:false
IsMonitorable:true
IsSuperuserOnly:true
TableDescription:Access Policy information
TableId:95400
TableName:access_policy
TableSchema:v_catalog
TableSchemaId:8301
1:{} 8 items
IsAccessibleDuringLockdown:false
IsMonitorable:true
IsSuperuserOnly:false
TableDescription:A complete listing of all tables and views
TableId:10206
TableName:all_tables
TableSchema:v_catalog
TableSchemaId:8301
2:{} 8 items
IsAccessibleDuringLockdown:false
IsMonitorable:true
IsSuperuserOnly:false
TableDescription:Audit table for Managing_Users_And_Privileges category
TableId:10338
TableName:audit_managing_users_privileges
TableSchema:v_catalog
TableSchemaId:8301
3:{} 8 items
IsAccessibleDuringLockdown:false
IsMonitorable:true
IsSuperuserOnly:true
TableDescription:List of available branches
TableId:10800
TableName:branches
TableSchema:v_catalog
TableSchemaId:8301
4:{} 8 items
IsAccessibleDuringLockdown:false
IsMonitorable:true
IsSuperuserOnly:true
TableDescription:Current status of existing branches
TableId:117200
TableName:branches_status
TableSchema:v_catalog
TableSchemaId:8301</pre>
</div>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/55957498-2eee3880-5c6f-11e9-9566-6e4dcfcea39b.png"></p>