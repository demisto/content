<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Check Point Firewall integration to identify and control applications by user and scan content to stop threats.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-check-point-on-demisto">Configure Check Point on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Check Point.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g., https://192.168.0.1)</strong></li>
<li><strong>Port</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#get-items-in-an-access-rulebase" target="_self">Get items in an access rulebase: checkpoint-show-access-rule-base</a></li>
<li><a href="#set-attributes-of-an-access-rule-object" target="_self">Set attributes of an access rule object: checkpoint-set-rule</a></li>
<li><a href="#get-the-status-of-a-check-point-task" target="_self">Get the status of a Check Point task: checkpoint-task-status</a></li>
<li><a href="#get-all-host-objects" target="_self">Get all host objects: checkpoint-show-hosts</a></li>
<li><a href="#block-an-ip-address" target="_self">Block an IP address: checkpoint-block-ip</a></li>
<li><a href="#use-the-check-point-management-api" target="_self">Use the Check Point Management API: checkpoint</a></li>
<li><a href="#delete-a-rule" target="_self">Delete a rule: checkpoint-delete-rule</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-items-in-an-access-rulebase">1. Get items in an access rulebase</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Show items in an access rulebase configured in Check Point Firewall.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint-show-access-rule-base</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 164px;"><strong>Argument Name</strong></th>
<th style="width: 481px;"><strong>Description</strong></th>
<th style="width: 95px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">name</td>
<td style="width: 481px;">The object name. Should be unique in the domain.</td>
<td style="width: 95px;">Required</td>
</tr>
<tr>
<td style="width: 164px;">uid</td>
<td style="width: 481px;">The unique identifier of the object.</td>
<td style="width: 95px;">Optional</td>
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
<th style="width: 274px;"><strong>Path</strong></th>
<th style="width: 47px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 274px;">CheckpointFWRule.Name</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.UID</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Type</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The object type.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Action</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The level of detail returned depends on the “details-level” field of the request (Accept, Drop, Apply Layer, Ask, Info). This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.ActionSetting</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">Action settings.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.CustomFields</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">Custom fields.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Data</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Data.Name</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.UID</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Type</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The object type.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Data.Domain</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.DataDirection</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The direction the file types processing is applied to.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.DataNegate</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">“True” if negate is set for data.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Destination</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">Collection of network objects identified by the name or UID. The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.DestinationNegate</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">“True” if negate is set for the destination.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Domain</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Domain.Name</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Domain.UID</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Domain.Type</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The domain type.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Enabled</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">Whether the rule is enabled or disabled.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Hits</td>
<td style="width: 47px;">number</td>
<td style="width: 419px;">The hits count object.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Hits.FirstDate</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The first date of hits.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Hits.LastDate</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The last date of hits.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Hits.Level</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The level of hits.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Hits.Percentage</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The percentage of hits.</td>
</tr>
<tr>
<td style="width: 274px;">CheckpointFWRule.Hits.Value</td>
<td style="width: 47px;">string</td>
<td style="width: 419px;">The value of hits.</td>
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
<pre>!checkpoint-show-access-rule-base name="Network"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/52956734-b5d21380-3398-11e9-84d4-fb6eb40d9cbc.png" alt="screen shot 2019-02-18 at 16 15 48"></p>
</div>
<div class="cl-preview-section">
<h3 id="set-attributes-of-an-access-rule-object">2. Set attributes of an access rule object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Sets attributes of an access rule object configured in Check Point Firewall.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint-set-rule</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">uid</td>
<td style="width: 506px;">The unique identifier of the object.</td>
<td style="width: 80px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">name</td>
<td style="width: 506px;">The object name.</td>
<td style="width: 80px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">rule_number</td>
<td style="width: 506px;">The rule number.</td>
<td style="width: 80px;">Optional</td>
</tr>
<tr>
<td style="width: 154px;">layer</td>
<td style="width: 506px;">The layer that the rule belongs to, identified by the name or UID.</td>
<td style="width: 80px;">Required</td>
</tr>
<tr>
<td style="width: 154px;">enabled</td>
<td style="width: 506px;">If “true”, the rule will be enabled. If “false”, the rule will be disabled.</td>
<td style="width: 80px;">Optional</td>
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
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 262px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 262px;">CheckpointFWRule.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.UID</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The object type.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Action</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The level of detail returned depends on the “details-level” field of the request (Accept, Drop, Apply Layer, Ask, Info). This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.ActionSetting</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Action settings.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.CustomFields</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Custom fields.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Data</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Data.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.UID</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The object type.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Data.Domain</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.DataDirection</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The direction the file types processing is applied to.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.DataNegate</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">“True” if negate is set for data.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Destination</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Collection of network objects identified by the name or UID. The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.DestinationNegate</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">“True” if negate is set for the destination.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Domain</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Domain.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Object name. Should be unique in domain</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Domain.UID</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Domain.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Domain type.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Enabled</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">Whether the rule is enabled or disabled.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Hits</td>
<td style="width: 59px;">number</td>
<td style="width: 419px;">The hits count object.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Hits.FirstDate</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The first date of hits.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Hits.LastDate</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The last date of hits.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Hits.Level</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The level of hits.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Hits.Percentage</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The percentage of hits.</td>
</tr>
<tr>
<td style="width: 262px;">CheckpointFWRule.Hits.Value</td>
<td style="width: 59px;">string</td>
<td style="width: 419px;">The value of hits.</td>
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
<pre>!checkpoint-set-rule name="bar-from-6.6.6.5" layer="8a5e96fb-c793-457f-b78f-c667074223a5"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/52952045-1444c500-338c-11e9-941a-53a7cea3363a.png" alt="screen shot 2019-02-18 at 13 55 04"></p>
</div>
<div class="cl-preview-section">
<h3 id="get-the-status-of-a-check-point-task">3. Get the status of a Check Point task</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Shows status of a Check Point task, by task UUID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint-task-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 199px;"><strong>Argument Name</strong></th>
<th style="width: 424px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 199px;">task_id</td>
<td style="width: 424px;">A CSV list of task unique identifiers.</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 316px;"><strong>Path</strong></th>
<th style="width: 45px;"><strong>Type</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 316px;">CheckpointFWTask.Name</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.UID</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Type</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object type.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Domain</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Domain.Name</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Domain.UID</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Domain.Type</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">Domain type.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.LastUpdateTime</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The last update date and time (in international ISO 8601 format).</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.MetaInfo.CreationTime</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object creation time.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.MetaInfo.Creator</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object creator.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.MetaInfo.LastModifier</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The last modifier of object.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.MetaInfo.LastModifyTime</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object last modification time.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.MetaInfo.LockStatus</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object lock state. Editing objects locked by other sessions is not supported.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.MetaInfo.ValidationStatus</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object validation state (ok, info, warning, error).</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.ProgressPercentage</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The object progress percentage.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.ReadOnly</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">Read only.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.StartTime</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The start time date and time (in international ISO 8601 format).</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Status</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The task status.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Suppressed</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">Is suppressed.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Tags</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">A collection of tag objects identified by the name or UID. The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.Details</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The task details. The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.ID</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The asynchronous unique identifier of the task.</td>
</tr>
<tr>
<td style="width: 316px;">CheckpointFWTask.TaskName</td>
<td style="width: 45px;">string</td>
<td style="width: 379px;">The task name.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-all-host-objects">4. Get all host objects</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Shows all host objects configured in Check Point Firewall.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint-show-hosts</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">limit</td>
<td style="width: 506px;">The maximum number of results to return.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">offset</td>
<td style="width: 506px;">The number of results to skip before starting to return them.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">order</td>
<td style="width: 506px;">Sorts results by the given field. The default is the random order.</td>
<td style="width: 81px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 205px;"><strong>Path</strong></th>
<th style="width: 46px;"><strong>Type</strong></th>
<th style="width: 489px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 205px;">Endpoint.Hostname</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">Object name. Should be unique in domain</td>
</tr>
<tr>
<td style="width: 205px;">Endpoint.UID</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 205px;">Endpoint.Type</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">The object type.</td>
</tr>
<tr>
<td style="width: 205px;">Endpoint.Domain</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 205px;">Endpoint.Domain.Name</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 205px;">Endpoint.Domain.UID</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">Object unique identifier</td>
</tr>
<tr>
<td style="width: 205px;">Endpoint.Domain.Type</td>
<td style="width: 46px;">string</td>
<td style="width: 489px;">Type of the object</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!checkpoint-show-hosts</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/52951911-c039e080-338b-11e9-9918-c4986fdd4e19.png" alt="screen shot 2019-02-18 at 14 26 54"></p>
</div>
<div class="cl-preview-section">
<h3 id="block-an-ip-address">5. Block an IP address</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Block one or more IP addresses using Checkpoint Firewall</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint-block-ip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 531px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">ip</td>
<td style="width: 531px;">A CSV list of IP addresses to block.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">direction</td>
<td style="width: 531px;">Whether to block traffic “to” or “from” the IPs, or “both”. Default is “both”.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">rulename</td>
<td style="width: 531px;">The base name for added rules inside Check Point DB.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 270px;"><strong>Path</strong></th>
<th style="width: 56px;"><strong>Type</strong></th>
<th style="width: 414px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 270px;">CheckpointFWRule.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.UID</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Type</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">Type of the object</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Action</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The level of detail returned depends on the "details-level" field of the request (Accept, Drop, Apply Layer, Ask, Info). This table shows the level of detail shown when 'details-level" is set to standard.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.ActionSetting</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">Action settings.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.CustomFields</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">Custom fields.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Data</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when “details-level” is set to standard.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Data.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.UID</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The unique identifier of the object.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Type</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The object type.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Data.Domain</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.DataDirection</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The direction the file types processing is applied to.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.DataNegate</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">"True" if negate is set for data.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Destination</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">A collection of network objects identified by the name or UID. The level of detail returned depends on the “details-level” field of the request. This table shows the level of detail shown when details-level is set to standard.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.DestinationNegate</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">“True” if negate is set for the destination.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Domain</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">Information about the domain that the object belongs to.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Domain.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The object name. Should be unique in the domain.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Domain.UID</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The unique identifer of the object.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Domain.Type</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The domain type.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Enabled</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">Whether the rule is enabled or disabled.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Hits</td>
<td style="width: 56px;">number</td>
<td style="width: 414px;">Hits count object</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Hits.FirstDate</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">First of hits</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Hits.LastDate</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The last date of hits.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Hits.Level</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The level of hits.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Hits.Percentage</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The percentage of hits.</td>
</tr>
<tr>
<td style="width: 270px;">CheckpointFWRule.Hits.Value</td>
<td style="width: 56px;">string</td>
<td style="width: 414px;">The value of hits.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="use-the-check-point-management-api">6. Use the Check Point Management API</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Enables you to use the Check Point Management API. When using this command, the required format is: ‘command’=.<br> This command requires management server R80 or later.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no inputs for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h3 id="delete-a-rule">7. Delete a rule</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a rule from Check Point Firewall.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>checkpoint-delete-rule</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 216px;"><strong>Argument Name</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
<th style="width: 124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">uid</td>
<td style="width: 400px;">The UID of the rule.</td>
<td style="width: 124px;">Optional</td>
</tr>
<tr>
<td style="width: 216px;">name</td>
<td style="width: 400px;">The name of the rule.</td>
<td style="width: 124px;">Optional</td>
</tr>
<tr>
<td style="width: 216px;">layer</td>
<td style="width: 400px;">The layer, for example: Network</td>
<td style="width: 124px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
<h2>Troubleshooting</h2>
<p>If you receive the following 400 Bad Request error when running the <a href="#block-an-ip-address" target="_self">checkpoint-block-ip</a> command, you need to disconnect (clear) all other sessions in the SmartConsole, even if they appear to be disconnected. In SmartConsole, navigate to <strong>Manage &amp; Settings &gt; Sessions &gt; View Sessions</strong>.</p>
<blockquote>400 Bad Request - Runtime error: An object is locked by another session </blockquote>
</div>