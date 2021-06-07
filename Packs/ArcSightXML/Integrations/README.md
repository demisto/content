<!-- HTML_DOC -->
<section class="article-info">
        <div class="article-content">
          <div class="article-body"><h2>Overview</h2>
<hr>
<p>Use the ArcSight XML integration to fetch cases from ArcSight and create incidents Cortex XSOAR using XML files. ArcSight exports cases and security events as XML to a specified folder and Cortex XSOAR fetches the emails from the folder and creates an incident in Cortex XSOAR for each case.</p>
<p><strong>Important: </strong> The integration should be executed in native Python, not Docker, because the program must have direct access to the folder, otherwise will not be fetched. You can use an engine, but make sure the engine does not use Docker. If the folder is on the Cortex XSOAR server then you can use <code>python.executable=python</code>.</p>
<h2>Configure ArcSight XML on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for ArcSight XML.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li><strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Directory from which to get XML files and create incidents.</strong></li>
<li><strong>Directory to which put command XML files.</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Fetched Incidents Data</h2>
<hr>
<p>The integration polls the specified folder every minute. When there is an XML file in the folder, the integration loads that file, parses the Security Events/Cases, and converts the cases to incidents in Cortex XSOAR. The integration will delete those XML files.</p>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li>Update a case: arcsight-update-case</li>
</ol>
<h3>1. Update a case</h3>
<hr>
<p>Creates an XML file to update a case.</p>
<h5>Base Command</h5>
<pre><code>arcsight-update-case</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 251px;"><strong>Argument Name</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
<th style="width: 147px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 251px;">caseId</td>
<td style="width: 310px;">ID of the case</td>
<td style="width: 147px;">Required</td>
</tr>
<tr>
<td style="width: 251px;">name</td>
<td style="width: 310px;">Name of the case</td>
<td style="width: 147px;">Required</td>
</tr>
<tr>
<td style="width: 251px;">stage</td>
<td style="width: 310px;">The stage of the case</td>
<td style="width: 147px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre><code>!arcsight-update-case stage=CLOSED caseId=7-XAMnF8BABDCGttHdj30lA==</code></pre>
<h5>Human Readable Output</h5>
<p><code>Modified stage to CLOSED in case 7-XAMnF8BABDCGttHdj30lA==</code></p>
<h2> </h2>
<h2>Export XML to a Folder in ArcSight</h2>
<hr>
<ol>
<li>In the navigator pane, (left bar) select rules in the resources.</li>
<li>Double click the rule that you want to initiate the export.</li>
<li>In the right pane, (Inspect/Edit) click the <strong>Actions</strong> tab.</li>
<li>Right-click the relevant type, for example <em>on every event</em>, <em>first event</em>, and so on.</li>
<li>Select <strong>Add</strong> &gt; <strong>Execute to External System</strong>.</li>
<li>Click <strong>Save</strong>.</li>
</ol>
<p>An XML file will is generated in the ArcSight server under <code>/opt/arcsight/manager/archive/exports</code>.</p></div></div></section>
