<!-- HTML_DOC -->
<p>IronDefense gives users the ability to rate alerts, update alert statuses, add comments to alerts, and to report observed bad activity.</p>
<p> </p>
<h2>Configure IronDefense on XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for IronDefense.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>IronAPI Host/IP</strong></li>
<li><strong>IronAPI Port</strong></li>
<li><strong>Username</strong></li>
<li><strong>Request Timeout (Sec)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#irondefense-rate-alert" target="_self">Rate an alert: irondefense-rate-alert</a></li>
<li><a href="#irondefense-comment-alert" target="_self">Add a comment to an alert: irondefense-comment-alert</a></li>
<li><a href="#irondefense-set-alert-status" target="_self">Set the status of an alert: irondefense-set-alert-status</a></li>
<li><a href="#irondefense-report-observed-bad-activity" target="_self">Submit an observed bad endpoint to create Threat Intelligence Rules (TIR): irondefense-report-observed-bad-activity</a></li>
</ol>
<h3 id="irondefense-rate-alert">1. Rate an alert</h3>
<hr>
<p>Rates an IronDefense alert.</p>
<h5>Base Command</h5>
<p><code>irondefense-rate-alert</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 231.667px;"><strong>Argument Name</strong></th>
<th style="width: 412.333px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 231.667px;">alert_id</td>
<td style="width: 412.333px;">The ID of the IronDefense alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">severity</td>
<td style="width: 412.333px;">The severity rating of the alert. Can be: "Undecided", "Benign", "Suspicious", "Malicious".</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">expectation</td>
<td style="width: 412.333px;">Determines whether the rating was expected. Can be: "Unknown", "Expected", "Unexpected". Use "Unknown" if the rating is undecided.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">comments</td>
<td style="width: 412.333px;">Explains the rating of the alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 231.667px;">share_comment_with_irondome</td>
<td style="width: 412.333px;">Whether to share the comment with IronDome.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> <!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="irondefense-comment-alert">2. Add a comment to an alert</h3>
<hr>
<p>Adds a comment to an IronDefense alert.</p>
<h5>Base Command</h5>
<p><code>irondefense-comment-alert</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 260.667px;"><strong>Argument Name</strong></th>
<th style="width: 372.333px;"><strong>Description</strong></th>
<th style="width: 84px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260.667px;">alert_id</td>
<td style="width: 372.333px;">The ID of the IronDefense alert.</td>
<td style="width: 84px;">Required</td>
</tr>
<tr>
<td style="width: 260.667px;">comment</td>
<td style="width: 372.333px;">Explains the rating of the alert.</td>
<td style="width: 84px;">Required</td>
</tr>
<tr>
<td style="width: 260.667px;">share_comment_with_irondome</td>
<td style="width: 372.333px;">Whether to share the comment with IronDome.</td>
<td style="width: 84px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="irondefense-set-alert-status">3. Set the status of an alert</h3>
<hr>
<p>Sets the status of an IronDefense alert.</p>
<h5>Base Command</h5>
<p><code>irondefense-set-alert-status</code></p>
<h5>Input</h5>
<table style="width: 749px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 238.667px;"><strong>Argument Name</strong></th>
<th style="width: 405.333px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 238.667px;">alert_id</td>
<td style="width: 405.333px;">The ID of the IronDefense alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 238.667px;">status</td>
<td style="width: 405.333px;">The alert status to set. Can be: "Awaiting Review", "Under Review", "Closed".</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 238.667px;">comments</td>
<td style="width: 405.333px;">Explains the status of the alert.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 238.667px;">share_comment_with_irondome</td>
<td style="width: 405.333px;">Whether to share the comment with IronDome.</td>
<td style="width: 73px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> <!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="irondefense-report-observed-bad-activity">4. Submit an observed bad endpoint to create Threat Intelligence Rules (TIR)</h3>
<hr>
<p>Submits an observed bad endpoint to IronDefense to create Threat Intelligence Rules (TIR).</p>
<h5>Base Command</h5>
<p><code>irondefense-report-observed-bad-activity</code></p>
<h5>Input</h5>
<table style="width: 747px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 160.333px;"><strong>Argument Name</strong></th>
<th style="width: 473.667px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160.333px;">name</td>
<td style="width: 473.667px;">The name of the Threat Intelligence Rule (TIR) to be created.</td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 160.333px;">description</td>
<td style="width: 473.667px;">A description of the observed bad endpoint.</td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 160.333px;">ip</td>
<td style="width: 473.667px;">The IP address of the observed bad endpoint.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 160.333px;">domain</td>
<td style="width: 473.667px;">The domain name of the observed bad endpoint.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 160.333px;">activity_start_time</td>
<td style="width: 473.667px;">The start time of the observed bad activity in RFC 3339 format.</td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 160.333px;">activity_end_time</td>
<td style="width: 473.667px;">The end time of the observed bad activity in RFC 3339 format.</td>
<td style="width: 81px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> <span style="font-size: 1.5em;"> </span></p>