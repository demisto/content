<!-- HTML_DOC -->
<p>Use the  Prisma Cloud (RedLock) Threat Defense integration to manage alerts from Microsoft Azure, Google Cloud Platform, and AWS.</p>
<h2>Configure the Prisma Cloud (RedLock) Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Prisma Cloud (RedLock).</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: URL of RedLlock server.</li>
<li><strong>Username</strong></li>
<li><strong>Password</strong></li>
<li><strong>Customer name</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Fetch only incidents matching this rule name</strong></li>
<li><strong>Fetch only incidents with this severity</strong></li>
<li><strong>Fetch Incidents</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_95612196841530795631871">Search RedLock alerts: redlock-search-alerts</a></li>
<li><a href="#h_696049476181530796105219">Get RedLock alert details: redlock-get-alert-details</a></li>
<li><a href="#h_256874257371530796584869">Dismiss RedLock alerts: redlock-dismiss-alerts</a></li>
<li><a href="#h_321535839611530796763100">Reopen RedLock alerts: redlock-reopen-alerts</a></li>
<li><a href="#h_463885917901530796933580">List all Redlock alerts: redlock-list-alert-filters</a></li>
</ol>
<hr>
<h3 id="h_95612196841530795631871">1. Search RedLock alerts</h3>
<p>Searches RedLock for all alerts.</p>
<h5>Base Command</h5>
<p><code>redlock-search-alerts</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 744px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Input Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">time-range-date-from</td>
<td style="width: 535px;">Search start time (MM/DD/YYYY)</td>
</tr>
<tr>
<td style="width: 210px;">time-range-date-to</td>
<td style="width: 535px;">Search end time (MM/DD/YYYY)</td>
</tr>
<tr>
<td style="width: 210px;">time-range-value</td>
<td style="width: 535px;">Amount of units to go back in time</td>
</tr>
<tr>
<td style="width: 210px;">time-range-unit</td>
<td style="width: 535px;">The search unit. The types <em>login</em> and <em>epoch</em> are only available if <em>timeRangeValue</em> is blank.</td>
</tr>
<tr>
<td style="width: 210px;">policy-name</td>
<td style="width: 535px;">Policy name</td>
</tr>
<tr>
<td style="width: 210px;">policy-label</td>
<td style="width: 535px;">Policy label</td>
</tr>
<tr>
<td style="width: 210px;">policy-compliance-standard</td>
<td style="width: 535px;">Policy compliance standard</td>
</tr>
<tr>
<td style="width: 210px;">cloud-account</td>
<td style="width: 535px;">Cloud account</td>
</tr>
<tr>
<td style="width: 210px;">cloud-region</td>
<td style="width: 535px;">Cloud region</td>
</tr>
<tr>
<td style="width: 210px;">alert-rule-name</td>
<td style="width: 535px;">Name of the alert rule</td>
</tr>
<tr>
<td style="width: 210px;">resource-id</td>
<td style="width: 535px;">Resource ID</td>
</tr>
<tr>
<td style="width: 210px;">resource-name</td>
<td style="width: 535px;">Resource name</td>
</tr>
<tr>
<td style="width: 210px;">resource-type</td>
<td style="width: 535px;">Resource type</td>
</tr>
<tr>
<td style="width: 210px;">alert-status</td>
<td style="width: 535px;">Alert status</td>
</tr>
<tr>
<td style="width: 210px;">alert-id</td>
<td style="width: 535px;">Alert ID</td>
</tr>
<tr>
<td style="width: 210px;">cloud-type</td>
<td style="width: 535px;">Cloud type</td>
</tr>
<tr>
<td style="width: 210px;">risk-grade</td>
<td style="width: 535px;">Risk grade</td>
</tr>
<tr>
<td style="width: 210px;">policy-type</td>
<td style="width: 535px;">Policy type</td>
</tr>
<tr>
<td style="width: 210px;">policy-severity</td>
<td style="width: 535px;">Policy severity</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.ID</td>
<td style="width: 565px;">ID of returned alert</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Status</td>
<td style="width: 565px;">Status of returned alert</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.AlertTime</td>
<td style="width: 565px;">Time of alert</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.ID</td>
<td style="width: 565px;">Policy ID</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Name</td>
<td style="width: 565px;">Policy name</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Type</td>
<td style="width: 565px;">Policy type</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Severity</td>
<td style="width: 565px;">Policy severity</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Remediable</td>
<td style="width: 565px;">Whether or not the policy is remediable</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.RiskDetail.Rating</td>
<td style="width: 565px;">Risk rating</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.RiskDetail.Score</td>
<td style="width: 565px;">Risk score</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Metadata.CountOfAlerts</td>
<td style="width: 565px;">Number of alerts found</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!redlock-search-alerts time-range-date-from="05/19/2018" time-range-date-to="06/26/2018"</code></p>
<h5>Raw Output</h5>
<pre>[
	{
		"AlertTime": 1527208131469,
		"ID": "P-120",
		"Policy": {
			"ID": "c2b84f89-7ec8-473e-a6af-404feeeb96c5",
			"Name": "CloudTrail logs are not encrypted using Customer Master Keys (CMKs)",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "arn:aws:cloudtrail:us-west-1:961855366482:trail/Logs",
			"Name": "Logs"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 20
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208131954,
		"ID": "P-151",
		"Policy": {
			"ID": "b82f90ce-ed8b-4b49-970c-2268b0a6c2e5",
			"Name": "Security Groups allow internet traffic from internet to RDP port (3389)",
			"Remediable": true,
			"Severity": "high",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "sg-00c2402879388152c",
			"Name": "launch-wizard-1"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 80
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527283805892,
		"ID": "P-206",
		"Policy": {
			"ID": "cd94c83e-6f84-4a37-a116-13ccba78a615",
			"Name": "Internet connectivity via tcp over insecure port",
			"Remediable": false,
			"Severity": "high",
			"Type": "network"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "i-0798ff02acd2cd1cf",
			"Name": "i-0798ff02acd2cd1cf"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 80
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527283805839,
		"ID": "P-204",
		"Policy": {
			"ID": "9c7af8a8-5743-420f-a879-8f0f73d678ea",
			"Name": "Internet exposed instances",
			"Remediable": false,
			"Severity": "high",
			"Type": "network"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "i-0798ff02acd2cd1cf",
			"Name": "i-0798ff02acd2cd1cf"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 80
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527202810000,
		"ID": "P-195",
		"Policy": {
			"ID": "e12e210c-3018-11e7-93ae-92361f002671",
			"Name": "Excessive login failures",
			"Remediable": false,
			"Severity": "high",
			"Type": "anomaly"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "akaylor",
			"Name": "akaylor"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 40
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527209282788,
		"ID": "P-192",
		"Policy": {
			"ID": "50af1c0a-ab70-44dd-b6f6-3529e795131f",
			"Name": "MFA not enabled for IAM users",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "akaylor",
			"Name": "akaylor"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 20
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527209282796,
		"ID": "P-193",
		"Policy": {
			"ID": "6a34af3f-21ae-8008-0850-229761d01081",
			"Name": "IAM user has both Console access and Access Keys",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "akaylor",
			"Name": "akaylor"
		},
		"RiskDetail": {
			"Rating": "C",
			"Score": 20
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208132072,
		"ID": "P-164",
		"Policy": {
			"ID": "d9b86448-11a2-f9d4-74a5-f6fc590caeef",
			"Name": "IAM policy allow full administrative privileges",
			"Remediable": false,
			"Severity": "low",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "arn:aws:iam::aws:policy/AdministratorAccess",
			"Name": "AdministratorAccess"
		},
		"RiskDetail": {
			"Rating": "B",
			"Score": 1
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208132065,
		"ID": "P-163",
		"Policy": {
			"ID": "7913fcbf-b679-5aac-d979-1b6817becb22",
			"Name": "S3 buckets do not have server side encryption",
			"Remediable": false,
			"Severity": "low",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "tax-returns-and-bitcoin-wallets",
			"Name": "tax-returns-and-bitcoin-wallets"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 51
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208131969,
		"ID": "P-152",
		"Policy": {
			"ID": "630d3779-d932-4fbf-9cce-6e8d793c6916",
			"Name": "S3 buckets are accessible to public",
			"Remediable": true,
			"Severity": "high",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "tax-returns-and-bitcoin-wallets",
			"Name": "tax-returns-and-bitcoin-wallets"
		},
		"RiskDetail": {
			"Rating": "F",
			"Score": 51
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208132057,
		"ID": "P-162",
		"Policy": {
			"ID": "7913fcbf-b679-5aac-d979-1b6817becb22",
			"Name": "S3 buckets do not have server side encryption",
			"Remediable": false,
			"Severity": "low",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "someprivatestuff",
			"Name": "someprivatestuff"
		},
		"RiskDetail": {
			"Rating": "B",
			"Score": 11
		},
		"Status": "open"
	},
	{
		"AlertTime": 1527208131434,
		"ID": "P-118",
		"Policy": {
			"ID": "4daa435b-fa46-457a-9359-6a4b4a43a442",
			"Name": "Access logging not enabled on S3 buckets",
			"Remediable": false,
			"Severity": "medium",
			"Type": "config"
		},
		"Resource": {
			"Account": "Adrians AWS account",
			"AccountID": "961855366482",
			"ID": "lotsologs",
			"Name": "lotsologs"
		},
		"RiskDetail": {
			"Rating": "B",
			"Score": 11
		},
		"Status": "open"
	}
]
</pre>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/39116813/42449980-5bcee498-838b-11e8-81a7-34c2d4650b03.jpg" alt="playground - war room 2018-07-09 15-11-24" width="749" height="341"></p>
<hr>
<h3 id="h_696049476181530796105219">2. Get RedLock alert details</h3>
<p>Get details for RedLock alerts.</p>
<h5>Base Command</h5>
<p><code>redlock-get-alert-details</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 744px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Input Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">alert-id</td>
<td style="width: 535px;">Alert ID</td>
</tr>
<tr>
<td style="width: 210px;">detailed</td>
<td style="width: 535px;">Enables retrieving the entire or trimmed alert model</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.ID</td>
<td style="width: 565px;">ID of returned alert</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Status</td>
<td style="width: 565px;">Status of returned alert</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.AlertTime</td>
<td style="width: 565px;">Time of alert</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.ID</td>
<td style="width: 565px;">Policy ID</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Name</td>
<td style="width: 565px;">Policy name</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Type</td>
<td style="width: 565px;">Policy type</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Severity</td>
<td style="width: 565px;">Policy severity</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.Policy.Remediable</td>
<td style="width: 565px;">Whether or not the policy is remediable</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.RiskDetail.Rating</td>
<td style="width: 565px;">Risk rating</td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.RiskDetail.Score</td>
<td style="width: 565px;">Risk score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!redlock-get-alert-details alert-id="P-120"</code></p>
<h5>Raw Output</h5>
<pre>{
	"AlertTime": 1527208131469,
	"ID": "P-120",
	"Policy": {
		"ID": "c2b84f89-7ec8-473e-a6af-404feeeb96c5",
		"Name": null,
		"Remediable": false,
		"Severity": null,
		"Type": "config"
	},
	"Resource": {
		"Account": "Adrians AWS account",
		"AccountID": "961855366482",
		"ID": "arn:aws:cloudtrail:us-west-1:961855366482:trail/Logs",
		"Name": "Logs"
	},
	"RiskDetail": {
		"Rating": "C",
		"Score": 20
	},
	"Status": "dismissed"
}
</pre>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/39116813/42450437-c86ac6d4-838c-11e8-95bb-3358f3ba33e5.jpg" alt="playground - artifact viewer 2018-07-09 15-28-04" width="750" height="1299"></p>
<hr>
<h3 id="h_256874257371530796584869">3. Dismiss RedLock alerts</h3>
<p>Dismisses the specified RedLock alerts.</p>
<h5>Base Command</h5>
<p><code>redlock-dismiss-alerts</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 744px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Input Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">alert-id</td>
<td style="width: 535px;">Alert ID</td>
</tr>
<tr>
<td style="width: 210px;">dismissal-note</td>
<td style="width: 535px;">Reason for dismissal</td>
</tr>
<tr>
<td style="width: 210px;">time-range-date-from</td>
<td style="width: 535px;">Search start time (MM/DD/YYYY)</td>
</tr>
<tr>
<td style="width: 210px;">time-range-date-to</td>
<td style="width: 535px;">Search end time (MM/DD/YYYY)</td>
</tr>
<tr>
<td style="width: 210px;">time-range-value</td>
<td style="width: 535px;">Amount of units to go back in time</td>
</tr>
<tr>
<td style="width: 210px;">time-range-unit</td>
<td style="width: 535px;">The search unit. The types <em>login</em> and <em>epoch</em> are only available if <em>timeRangeValue</em> is blank.</td>
</tr>
<tr>
<td style="width: 210px;">policy-name</td>
<td style="width: 535px;">Policy name</td>
</tr>
<tr>
<td style="width: 210px;">policy-label</td>
<td style="width: 535px;">Policy label</td>
</tr>
<tr>
<td style="width: 210px;">policy-compliance-standard</td>
<td style="width: 535px;">Policy compliance standard</td>
</tr>
<tr>
<td style="width: 210px;">cloud-account</td>
<td style="width: 535px;">Cloud account</td>
</tr>
<tr>
<td style="width: 210px;">cloud-region</td>
<td style="width: 535px;">Cloud region</td>
</tr>
<tr>
<td style="width: 210px;">alert-rule-name</td>
<td style="width: 535px;">Name of the alert rule</td>
</tr>
<tr>
<td style="width: 210px;">resource-id</td>
<td style="width: 535px;">Resource ID</td>
</tr>
<tr>
<td style="width: 210px;">resource-name</td>
<td style="width: 535px;">Resource name</td>
</tr>
<tr>
<td style="width: 210px;">resource-type</td>
<td style="width: 535px;">Resource type</td>
</tr>
<tr>
<td style="width: 210px;">alert-status</td>
<td style="width: 535px;">Alert status</td>
</tr>
<tr>
<td style="width: 210px;">cloud-type</td>
<td style="width: 535px;">Cloud type</td>
</tr>
<tr>
<td style="width: 210px;">risk-grade</td>
<td style="width: 535px;">Risk grade</td>
</tr>
<tr>
<td style="width: 210px;">policy-type</td>
<td style="width: 535px;">Policy type</td>
</tr>
<tr>
<td style="width: 210px;">policy-severity</td>
<td style="width: 535px;">Policy severity</td>
</tr>
<tr>
<td style="width: 210px;">policy-id</td>
<td style="width: 535px;">Policy IDs (comma-separated string)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.ID</td>
<td style="width: 565px;">ID of the dismissed alerts</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!redlock-dismiss-alerts alert-id="P-120" dismissal-note="Dismiss"</code></p>
<h5>Raw Output</h5>
<pre>[
	"P-120"
]
</pre>
<h5>War Room Output</h5>
<pre>Alerts dismissed successfully. Dismissal Note: Dismiss.</pre>
<hr>
<h3 id="h_321535839611530796763100">4. Reopen RedLock alerts: redlock-reopen-alerts</h3>
<p>Reopens dismissed alerts.</p>
<h5>Base Command</h5>
<p><code>redlock-dismiss-alerts</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 744px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Input Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">alert-id</td>
<td style="width: 535px;">Alert ID</td>
</tr>
<tr>
<td style="width: 210px;">time-range-date-from</td>
<td style="width: 535px;">Search start time (MM/DD/YYYY)</td>
</tr>
<tr>
<td style="width: 210px;">time-range-date-to</td>
<td style="width: 535px;">Search end time (MM/DD/YYYY)</td>
</tr>
<tr>
<td style="width: 210px;">time-range-value</td>
<td style="width: 535px;">Amount of units to go back in time</td>
</tr>
<tr>
<td style="width: 210px;">time-range-unit</td>
<td style="width: 535px;">The search unit. The types <em>login</em> and <em>epoch</em> are only available if <em>timeRangeValue</em> is blank.</td>
</tr>
<tr>
<td style="width: 210px;">policy-name</td>
<td style="width: 535px;">Policy name</td>
</tr>
<tr>
<td style="width: 210px;">policy-label</td>
<td style="width: 535px;">Policy label</td>
</tr>
<tr>
<td style="width: 210px;">policy-compliance-standard</td>
<td style="width: 535px;">Policy compliance standard</td>
</tr>
<tr>
<td style="width: 210px;">cloud-account</td>
<td style="width: 535px;">Cloud account</td>
</tr>
<tr>
<td style="width: 210px;">cloud-region</td>
<td style="width: 535px;">Cloud region</td>
</tr>
<tr>
<td style="width: 210px;">alert-rule-name</td>
<td style="width: 535px;">Name of the alert rule</td>
</tr>
<tr>
<td style="width: 210px;">resource-id</td>
<td style="width: 535px;">Resource ID</td>
</tr>
<tr>
<td style="width: 210px;">resource-name</td>
<td style="width: 535px;">Resource name</td>
</tr>
<tr>
<td style="width: 210px;">resource-type</td>
<td style="width: 535px;">Resource type</td>
</tr>
<tr>
<td style="width: 210px;">alert-status</td>
<td style="width: 535px;">Alert status</td>
</tr>
<tr>
<td style="width: 210px;">cloud-type</td>
<td style="width: 535px;">Cloud type</td>
</tr>
<tr>
<td style="width: 210px;">risk-grade</td>
<td style="width: 535px;">Risk grade</td>
</tr>
<tr>
<td style="width: 210px;">policy-type</td>
<td style="width: 535px;">Policy type</td>
</tr>
<tr>
<td style="width: 210px;">policy-severity</td>
<td style="width: 535px;">Policy severity</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">Redlock.Alert.ID</td>
<td style="width: 565px;">ID of the reopened alerts</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!redlock-reopen-alerts alert-id="P-120"</code></p>
<h5>Raw Output</h5>
<pre>[
	"P-120"
]
</pre>
<h5>War Room Output</h5>
<pre>Alerts re-opened successfully.</pre>
<hr>
<h3 id="h_463885917901530796933580">5. List all RedLock alerts</h3>
<p>Lists all RedLock alerts.</p>
<h5>Base Command</h5>
<p><code>redlock-list-alert-filters</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>War Room Output</h5>
<p><img src="https://user-images.githubusercontent.com/39116813/42451747-c934f072-8390-11e8-948d-a6ed094f5b04.jpg" alt="playground - artifact viewer 2018-07-09 15-54-29" width="749" height="366"></p>