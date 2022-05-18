<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Snowflake integration to query and update your Snowflake database.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-snowflake-on-demisto">Configure Snowflake on Cortex XSOAR</h2>
<p>Several parameters are explained in greater detail in the <a href="#detailed-description" target="_self">Detailed Instructions</a> section.</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Snowflake.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Username</strong></li>
<li><strong>Account - See Detailed Description section.</strong></li>
<li><strong>Region (only if you are not US West)</strong></li>
<li><strong>Authenticator - See Detailed Description section.</strong></li>
<li><strong>Default warehouse to use</strong></li>
<li><strong>Default database to use</strong></li>
<li><strong>Default schema to use</strong></li>
<li><strong>Default role to use</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust server certificate (insecure)</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Fetch query to retrieve new incidents. This field is mandatory when ‘Fetches incidents’ is set to true.</strong></li>
<li><strong>First fetch timestamp ( <time>, e.g., 12 hours, 7 days)</time></strong></li>
<li><strong>The name of the field/column that contains the datetime object or timestamp for the data being fetched (case sensitive). This field is mandatory when ‘Fetches incidents’ is set to true.</strong></li>
<li><strong>The name of the field/column in the fetched data from which the name for the Cortex XSOAR incident will be assigned (case sensitive)</strong></li>
<li><strong>The maximum number of rows to be returned by a fetch</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="detailed-description">Detailed Instructions</h2>
</div>
<div class="cl-preview-section">
<p>Additional information for configuring the integration instance.</p>
</div>
<div class="cl-preview-section">
<h3 id="integration-parameters">Integration Parameters</h3>
</div>
<div class="cl-preview-section">
<ul>
<li>
<p><strong>Account</strong><br> The name of the Snowflake account to connect to without the domain name: snowflakecomputing.com. For example, mycompany.snowflakecomputing.com, enter “mycompany”. For more information, see the <a href="https://docs.snowflake.net/manuals/user-guide/python-connector-api.html#label-account-format-info">Snowflake Computing documentation</a>.</p>
</li>
<li>
<p><strong>Authenticator</strong><br> (Optional) Use this parameter to log in to your Snowflake account using Okta. For the ‘Username’ parameter, enter your ‘&lt;okta_login_name&gt;’. For the ‘Password’ parameter, enter your ‘&lt;okta_password&gt;’. The value entered here should be ‘https://&lt;okta_account_name&gt;.okta.com/’ where all the values between the less than and greater than symbols are replaced with the actual information specific to your Okta account.</p>
</li>
<li>
<p><strong>Credentials</strong><br> To use Key Pair authentication, follow these instructions:</p>
<ol>
<li>Follow steps 1-4 in the instructions detailed in the <a href="https://docs.snowflake.net/manuals/user-guide/python-connector-example.html#using-key-pair-authentication">Snowflake Computing documentation</a>.</li>
<li>Follow the instructions under the section titled <strong>Configure Cortex XSOAR Credentials</strong> at this <a href="https://xsoar.pan.dev/docs/reference/articles/managing-credentials">link</a>.</li>
<li>Use the credentials you configured. Refer to the two images at the bottom of the section titled <strong>Configure an External Credentials Vault</strong>.</li>
</ol>
</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#run-a-query-in-snowflake" target="_self">Run a query in Snowflake: snowflake-query</a></li>
<li><a href="#make-a-dml-change-in-the-database" target="_self">Make a DML change in the database: snowflake-update</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="run-a-query-in-snowflake">1. Run a query in Snowflake</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Executes a SELECT query and retrieve the data.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>snowflake-query</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 527px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">query</td>
<td style="width: 527px;">The query to execute.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">warehouse</td>
<td style="width: 527px;">The warehouse to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">database</td>
<td style="width: 527px;">The database to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">schema</td>
<td style="width: 527px;">The schema to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">role</td>
<td style="width: 527px;">The role to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">limit</td>
<td style="width: 527px;">The number of rows to retrieve.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">columns</td>
<td style="width: 527px;">A CSV list of columns to display in the specified order, for example: “Name, ID, Timestamp”</td>
<td style="width: 71px;">Optional</td>
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
<th style="width: 179px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 467px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">Snowflake.Query</td>
<td style="width: 94px;">String</td>
<td style="width: 467px;">The query used to fetch results from the database.</td>
</tr>
<tr>
<td style="width: 179px;">Snowflake.Result</td>
<td style="width: 94px;">Unknown</td>
<td style="width: 467px;">Results from querying the database.</td>
</tr>
<tr>
<td style="width: 179px;">Snowflake.Database</td>
<td style="width: 94px;">String</td>
<td style="width: 467px;">The name of the database object.</td>
</tr>
<tr>
<td style="width: 179px;">Snowflake.Schema</td>
<td style="width: 94px;">String</td>
<td style="width: 467px;">The name of the schema object.</td>
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
<pre>snowflake-query warehouse=demo_wh database=demo_db schema=public query="select * from test"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Snowflake": {
        "Query": "select * from test", 
        "Schema": "public", 
        "Result": [
            {
                "TS": "2018-09-11 00:00:00.000000", 
                "ID": 1, 
                "NAME": "b"
            }, 
            {
                "TS": "2018-10-12 00:00:00.000000", 
                "ID": 2, 
                "NAME": "kuku"
            }, 
            {
                "TS": "2018-10-12 00:00:00.000000", 
                "ID": 3, 
                "NAME": "kiki"
            }, 
            {
                "TS": "2018-10-12 00:00:00.000000", 
                "ID": 4, 
                "NAME": "kaka"
            }, 
            {
                "TS": "2018-10-12 00:00:00.000000", 
                "ID": 5, 
                "NAME": "kuku"
            }, 
            {
                "TS": "2019-03-26 11:14:18.574000", 
                "ID": 8, 
                "NAME": "blah"
            }, 
            {
                "TS": "2019-03-26 11:16:16.773000", 
                "ID": 8, 
                "NAME": "new"
            }, 
            {
                "TS": "2019-03-26 11:30:42.479000", 
                "ID": 9, 
                "NAME": "nBw4QhFcGJ"
            }, 
            {
                "TS": "2019-03-14 00:00:00.000000", 
                "ID": 10, 
                "NAME": "UPDATing"
            }, 
            {
                "TS": "2019-03-19 00:00:00.000000", 
                "ID": 11, 
                "NAME": "TESTING IT OUT again"
            }, 
            {
                "TS": "2019-03-28 05:32:13.355000", 
                "ID": 13, 
                "NAME": "New Alert"
            }, 
            {
                "TS": "2019-03-28 06:09:26.153000", 
                "ID": 14, 
                "NAME": "SHOULD FETCH THIS NEW"
            }, 
            {
                "TS": "2019-03-28 08:46:50.311000", 
                "ID": 15, 
                "NAME": "Perth"
            }, 
            {
                "TS": "2019-03-28 06:19:06.271000", 
                "ID": 16, 
                "NAME": "Edinburgh"
            }, 
            {
                "TS": "2019-03-28 06:19:14.059000", 
                "ID": 17, 
                "NAME": "York"
            }, 
            {
                "TS": "2019-03-28 06:20:27.126000", 
                "ID": 18, 
                "NAME": "Persimmon"
            }, 
            {
                "TS": "2019-03-28 06:28:31.001000", 
                "ID": 19, 
                "NAME": "Langdon"
            }, 
            {
                "TS": "2019-03-28 11:53:41.416000", 
                "ID": 20, 
                "NAME": "London"
            }
        ], 
        "Database": "demo_db"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="select--from-test">select * from test</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 433px;" border="2">
<thead>
<tr>
<th style="width: 35px;">ID</th>
<th style="width: 174px;">NAME</th>
<th style="width: 214px;">TS</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 35px;">1</td>
<td style="width: 174px;">b</td>
<td style="width: 214px;">2018-09-11 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">2</td>
<td style="width: 174px;">kuku</td>
<td style="width: 214px;">2018-10-12 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">3</td>
<td style="width: 174px;">kiki</td>
<td style="width: 214px;">2018-10-12 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">4</td>
<td style="width: 174px;">kaka</td>
<td style="width: 214px;">2018-10-12 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">5</td>
<td style="width: 174px;">kuku</td>
<td style="width: 214px;">2018-10-12 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">8</td>
<td style="width: 174px;">blah</td>
<td style="width: 214px;">2019-03-26 11:14:18.574000</td>
</tr>
<tr>
<td style="width: 35px;">8</td>
<td style="width: 174px;">new</td>
<td style="width: 214px;">2019-03-26 11:16:16.773000</td>
</tr>
<tr>
<td style="width: 35px;">9</td>
<td style="width: 174px;">nBw4QhFcGJ</td>
<td style="width: 214px;">2019-03-26 11:30:42.479000</td>
</tr>
<tr>
<td style="width: 35px;">10</td>
<td style="width: 174px;">UPDATing</td>
<td style="width: 214px;">2019-03-14 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">11</td>
<td style="width: 174px;">TESTING IT OUT again</td>
<td style="width: 214px;">2019-03-19 00:00:00.000000</td>
</tr>
<tr>
<td style="width: 35px;">13</td>
<td style="width: 174px;">New Alert</td>
<td style="width: 214px;">2019-03-28 05:32:13.355000</td>
</tr>
<tr>
<td style="width: 35px;">14</td>
<td style="width: 174px;">SHOULD FETCH THIS NEW</td>
<td style="width: 214px;">2019-03-28 06:09:26.153000</td>
</tr>
<tr>
<td style="width: 35px;">15</td>
<td style="width: 174px;">Perth</td>
<td style="width: 214px;">2019-03-28 08:46:50.311000</td>
</tr>
<tr>
<td style="width: 35px;">16</td>
<td style="width: 174px;">Edinburgh</td>
<td style="width: 214px;">2019-03-28 06:19:06.271000</td>
</tr>
<tr>
<td style="width: 35px;">17</td>
<td style="width: 174px;">York</td>
<td style="width: 214px;">2019-03-28 06:19:14.059000</td>
</tr>
<tr>
<td style="width: 35px;">18</td>
<td style="width: 174px;">Persimmon</td>
<td style="width: 214px;">2019-03-28 06:20:27.126000</td>
</tr>
<tr>
<td style="width: 35px;">19</td>
<td style="width: 174px;">Langdon</td>
<td style="width: 214px;">2019-03-28 06:28:31.001000</td>
</tr>
<tr>
<td style="width: 35px;">20</td>
<td style="width: 174px;">London</td>
<td style="width: 214px;">2019-03-28 11:53:41.416000</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="make-a-dml-change-in-the-database">2. Make a DML change in the database</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Makes a DML change in the database.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>snowflake-update</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">db_operation</td>
<td style="width: 496px;">The command to execute.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 173px;">warehouse</td>
<td style="width: 496px;">The warehouse to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173px;">database</td>
<td style="width: 496px;">The database to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173px;">schema</td>
<td style="width: 496px;">The schema to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173px;">role</td>
<td style="width: 496px;">The role to use for the query. If not specified, the default will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>snowflake-update warehouse=demo_wh database=demo_db schema=public db_operation="update test set NAME='Persimmon' where ID=18"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Operation executed successfully.</p>
</div>