<!-- HTML_DOC -->
<p>Fidelis Elevate provides a terrain-based defense that shines a light on the blind spots in your environment and calculates your vulnerable attack surface.</p>
<div class="cl-preview-section">
<h2 id="configure-fidelis-elevate-network-on-demisto">Configure Fidelis Elevate Network on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Fidelis Elevate Network.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL</strong></li>
<li><strong>Credentials</strong></li>
<li><strong>Trust any certificate (unsecure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>First fetch timestamp ( <time>, e.g., 12 hours, 7 days, 3 months, 1 year)</time></strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#get-alert-details" target="_self">Get alert details: fidelis-get-alert</a></li>
<li><a href="#delete-an-alert" target="_self">Delete an alert: fidelis-delete-alert</a></li>
<li><a href="#export-alert-details" target="_self">Export alert details: fidelis-export-alert</a></li>
<li><a href="#get-malware-data-for-a-malware-alert" target="_self">Get malware data for a Malware alert: fidelis-get-malware-data</a></li>
<li><a href="#download-an-alert-report" target="_self">Download an alert report: fidelis-get-alert-report</a></li>
<li><a href="#upload-a-file-or-url-for-sanbox-analysis" target="_self">Upload a file or URL for sanbox analysis: fidelis-sandbox-upload</a></li>
<li><a href="#list-all-open-alerts" target="_self">List all open alerts: fidelis-list-alerts</a></li>
<li><a href="#upload-a-pcap-file-for-analysis" target="_self">Upload a PCAP file for analysis: fidelis-upload-pcap</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-alert-details">1. Get alert details</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns alert details from Fidelis Elevate.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-get-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 335px;"><strong>Argument Name</strong></th>
<th style="width: 222px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 335px;">alert_id</td>
<td style="width: 222px;">The alert ID.</td>
<td style="width: 183px;">Required</td>
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
<th style="width: 289px;"><strong>Path</strong></th>
<th style="width: 79px;"><strong>Type</strong></th>
<th style="width: 372px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 289px;"><a href="http://fidelis.alert.id/">Fidelis.Alert.ID</a></td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The alert ID.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.ThreatScore</td>
<td style="width: 79px;">number</td>
<td style="width: 372px;">The alert threat score.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.Time</td>
<td style="width: 79px;">date</td>
<td style="width: 372px;">The alert time.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.RuleID</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The ID of the related rule.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.RuleName</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The name of the related rule.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.Summary</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The alert summary.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.PolicyName</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The name of the related policy.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.Severity</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The severity of the alert.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.Protocol</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The protocol involved in the alert.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.Type</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The alert type.</td>
</tr>
<tr>
<td style="width: 289px;">Fidelis.Alert.AssignedUser</td>
<td style="width: 79px;">string</td>
<td style="width: 372px;">The ID of the assigned user.</td>
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
<p><code>fidelis-get-alert alert_id="35"</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Fidelis.Alert": {
        "PolicyName": "UPLOAD", 
        "Protocol": "HTTP", 
        "AssignedUser": 0, 
        "RuleID": 214, 
        "Time": "2019-01-10 08:50:45", 
        "ThreatScore": 90, 
        "Summary": "UPLOAD", 
        "RuleName": "UPLOAD", 
        "Type": "FILE_UPLOAD", 
        "ID": 35, 
        "Severity": "Low"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="alert-35">Alert 35</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Policy Name</th>
<th>Severity</th>
<th>Rule ID</th>
<th>Threat Score</th>
<th>Summary</th>
<th>Time</th>
<th>Type</th>
<th>ID</th>
<th>Assigned User</th>
<th>Protocol</th>
<th>Rule Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>UPLOAD</td>
<td>Low</td>
<td>214</td>
<td>90</td>
<td>UPLOAD</td>
<td>2019-01-10 08:50:45</td>
<td>FILE_UPLOAD</td>
<td>35</td>
<td>0</td>
<td>HTTP</td>
<td>UPLOAD</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="delete-an-alert">2. Delete an alert</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes an alert from Fidelis Elevate.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-delete-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 336px;"><strong>Argument Name</strong></th>
<th style="width: 221px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 336px;">alert_id</td>
<td style="width: 221px;">The alert ID.</td>
<td style="width: 183px;">Required</td>
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
<th style="width: 235px;"><strong>Path</strong></th>
<th style="width: 85px;"><strong>Type</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 235px;"><a href="http://fidelis.alert.id/">Fidelis.Alert.ID</a></td>
<td style="width: 85px;">string</td>
<td style="width: 420px;">The ID of the deleted alert.</td>
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
<p><code>fidelis-delete-alert alert_id="8"</code></p>
</div>
<div class="cl-preview-section">
<h3 id="export-alert-details">3. Export alert details</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Exports alert details to PDF.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-export-alert</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 339px;"><strong>Argument Name</strong></th>
<th style="width: 218px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 339px;">alert_id</td>
<td style="width: 218px;">The alert ID.</td>
<td style="width: 183px;">Required</td>
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
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h3 id="get-malware-data-for-a-malware-alert">4. Get malware data for a Malware alert</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves malware data related to a “Malware” type alert</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-get-malware-data</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 338px;"><strong>Argument Name</strong></th>
<th style="width: 219px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 338px;">alert_id</td>
<td style="width: 219px;">The alert ID.</td>
<td style="width: 183px;">Required</td>
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
<th style="width: 282px;"><strong>Path</strong></th>
<th style="width: 55px;"><strong>Type</strong></th>
<th style="width: 403px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 282px;">Fidelis.Alert.ID</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The alert ID.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.Name</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware name.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.Type</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware type.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.Behavior</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware behavior.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.Platform</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware platform.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.DetailName</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware detail name from Fidelis Elevate.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.Variant</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware variant.</td>
</tr>
<tr>
<td style="width: 282px;">Fidelis.Alert.Malware.Description</td>
<td style="width: 55px;">string</td>
<td style="width: 403px;">The malware description from Fidelis Elevate.</td>
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
<p><code>fidelis-get-malware-data alert_id=30</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Fidelis.Alert": {
        "Malware": {
            "Description": "This type of Trojan modifies data on the victim computer so that the victim can no longer use the data, or it prevents the computer from running correctly. Once the data has been \"taken hostage\" (blocked or encrypted), the user will receive a ransom demand.\n\nThe ransom demand tells the victim to send the malicious user money; on receipt of this, the cyber criminal will send a program to the victim to restore the data or restore the computer's performance.", 
            "Variant": "fss1", 
            "Platform": "Win", 
            "DetailName": "Cryptowall", 
            "Behavior": "Trojan-Ransom", 
            "Type": "C2", 
            "Name": "Trojan-Ransom.Win.Cryptowall.fss1"
        }, 
        "ID": "30"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="alert-30-malware">Alert 30 Malware:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table class="" border="2">
<thead>
<tr>
<th>Malware Description</th>
<th>Malware Variant</th>
<th>Malware Name</th>
<th>Malware Type</th>
<th>Malware Behavior</th>
<th>Malware Detail Name</th>
<th>Malware Platform</th>
</tr>
</thead>
<tbody>
<tr>
<td>This type of Trojan modifies data on the victim computer so that the victim can no longer use the data, or it prevents the computer from running correctly. Once the data has been “taken hostage” (blocked or encrypted), the user will receive a ransom demand.<br> <br> The ransom demand tells the victim to send the malicious user money; on receipt of this, the cyber criminal will send a program to the victim to restore the data or restore the computer’s performance.</td>
<td>fss1</td>
<td>Trojan-Ransom.Win.Cryptowall.fss1</td>
<td>C2</td>
<td>Trojan-Ransom</td>
<td>Cryptowall</td>
<td>Win</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section"> </div>
<div class="cl-preview-section">
<p> </p>
</div>
<div class="cl-preview-section">
<h3 id="download-an-alert-report">5. Download an alert report</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Downloads a PDF report for a specified alert.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-get-alert-report</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 336px;"><strong>Argument Name</strong></th>
<th style="width: 221px;"><strong>Description</strong></th>
<th style="width: 183px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 336px;">alert_id</td>
<td style="width: 221px;">The alert ID.</td>
<td style="width: 183px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h3 id="upload-a-file-or-url-for-sanbox-analysis">6. Upload a file or URL for sanbox analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Uploads a file or a URL for a sandbox analysis in Fidelis Elevate.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-sandbox-upload</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 262px;"><strong>Argument Name</strong></th>
<th style="width: 338px;"><strong>Description</strong></th>
<th style="width: 140px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 262px;">upload_item</td>
<td style="width: 338px;">The file or URL to upload.</td>
<td style="width: 140px;">Required</td>
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
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 187px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">Fidelis.Alert.ID</td>
<td style="width: 66px;">string</td>
<td style="width: 487px;">The alert ID generated from the upload.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="list-all-open-alerts">7. List all open alerts</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Lists all open alerts from Fidelis Elevate.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-list-alerts</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">time_frame</td>
<td style="width: 526px;">Filter by time frame, for example: “Last 48 Hours”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">start_time</td>
<td style="width: 526px;">If time_frame is Custom, specify the start time for the time range (e.g. 2017-06-01T12:48:16.734Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">end_time</td>
<td style="width: 526px;">If time_frame is Custom, specify the end time for the time range (e.g. 2017-06-01T12:48:16.734Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">severity</td>
<td style="width: 526px;">Filter by alert severity</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">type</td>
<td style="width: 526px;">Filter by alert type</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">threat_score</td>
<td style="width: 526px;">Filter by alert Threat Score Threshold (higher than)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">ioc</td>
<td style="width: 526px;">Filter alerts that are related to a specified IOC</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 335px;"><strong>Path</strong></th>
<th style="width: 123px;"><strong>Type</strong></th>
<th style="width: 282px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 335px;">Fidelis.Alert.ID</td>
<td style="width: 123px;">string</td>
<td style="width: 282px;">The alert ID.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-list-alerts time_frame="Custom" start_time="2018-12-17T07:50:48Z" end_time="2018-12-20T09:50:48Z"</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Fidelis.Alert": [
        {
            "Time": "2018-12-19 08:42:23", 
            "Summary": "Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to runlove.us", 
            "Type": "Malware", 
            "ID": "31", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-19 08:42:23", 
            "Summary": "Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to comarksecurity.com", 
            "Type": "Malware", 
            "ID": "32", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-19 08:42:17", 
            "Summary": "Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to runlove.us", 
            "Type": "Malware", 
            "ID": "29", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-19 08:42:17", 
            "Summary": "Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to comarksecurity.com", 
            "Type": "Malware", 
            "ID": "30", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-19 08:42:14", 
            "Summary": "Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to comarksecurity.com", 
            "Type": "Malware", 
            "ID": "28", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-19 08:42:11", 
            "Summary": "Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to runlove.us", 
            "Type": "Malware", 
            "ID": "27", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-19 08:42:05", 
            "Summary": "Malware Exploit.JS.Agent.bro of Type TROJAN Detected from va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in to 192.168.138.158", 
            "Type": "Malware", 
            "ID": "26", 
            "Severity": "Critical"
        }, 
        {
            "Time": "2018-12-18 12:18:08", 
            "Summary": "UPLOAD", 
            "Type": "File Upload", 
            "ID": "25", 
            "Severity": "Low"
        }, 
        {
            "Time": "2018-12-18 12:17:21", 
            "Summary": "UPLOAD", 
            "Type": "File Upload", 
            "ID": "24", 
            "Severity": "Low"
        }, 
        {
            "Time": "2018-12-18 12:16:45", 
            "Summary": "UPLOAD", 
            "Type": "File Upload", 
            "ID": "23", 
            "Severity": "Low"
        }, 
        {
            "Time": "2018-12-17 15:01:21", 
            "Summary": "UPLOAD", 
            "Type": "File Upload", 
            "ID": "22", 
            "Severity": "Low"
        }, 
        {
            "Time": "2018-12-17 14:54:44", 
            "Summary": "Malware EICAR-Test-File of Type VIRWARE Detected from 0.0.0.0 to 0.0.0.0", 
            "Type": "Malware", 
            "ID": "20", 
            "Severity": "Critical"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="found-12-alerts">Found 12 Alerts:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Type</th>
<th>Summary</th>
<th>Severity</th>
<th>ID</th>
<th>Time</th>
</tr>
</thead>
<tbody>
<tr>
<td>Malware</td>
<td>Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to <a href="http://runlove.us/">runlove.us</a>
</td>
<td>Critical</td>
<td>31</td>
<td>2018-12-19 08:42:23</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to <a href="http://comarksecurity.com/">comarksecurity.com</a>
</td>
<td>Critical</td>
<td>32</td>
<td>2018-12-19 08:42:23</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to <a href="http://runlove.us/">runlove.us</a>
</td>
<td>Critical</td>
<td>29</td>
<td>2018-12-19 08:42:17</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to <a href="http://comarksecurity.com/">comarksecurity.com</a>
</td>
<td>Critical</td>
<td>30</td>
<td>2018-12-19 08:42:17</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to <a href="http://comarksecurity.com/">comarksecurity.com</a>
</td>
<td>Critical</td>
<td>28</td>
<td>2018-12-19 08:42:14</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware Trojan-Ransom.Win.Cryptowall.fss1 of Type C2 Detected from 192.168.138.158 to <a href="http://runlove.us/">runlove.us</a>
</td>
<td>Critical</td>
<td>27</td>
<td>2018-12-19 08:42:11</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware Exploit.JS.Agent.bro of Type TROJAN Detected from <a href="http://va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in/">va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in</a>to 192.168.138.158</td>
<td>Critical</td>
<td>26</td>
<td>2018-12-19 08:42:05</td>
</tr>
<tr>
<td>File Upload</td>
<td>UPLOAD</td>
<td>Low</td>
<td>25</td>
<td>2018-12-18 12:18:08</td>
</tr>
<tr>
<td>File Upload</td>
<td>UPLOAD</td>
<td>Low</td>
<td>24</td>
<td>2018-12-18 12:17:21</td>
</tr>
<tr>
<td>File Upload</td>
<td>UPLOAD</td>
<td>Low</td>
<td>23</td>
<td>2018-12-18 12:16:45</td>
</tr>
<tr>
<td>File Upload</td>
<td>UPLOAD</td>
<td>Low</td>
<td>22</td>
<td>2018-12-17 15:01:21</td>
</tr>
<tr>
<td>Malware</td>
<td>Malware EICAR-Test-File of Type VIRWARE Detected from 0.0.0.0 to 0.0.0.0</td>
<td>Critical</td>
<td>20</td>
<td>2018-12-17 14:54:44</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="upload-a-pcap-file-for-analysis">8. Upload a PCAP file for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Uploads a PCAP file for analysis in Fidelis Elevate.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fidelis-upload-pcap</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">Fidelis.Alert.ID</td>
<td style="width: 71px;">string</td>
<td style="width: 510px;">The alert ID generated from the PCAP upload.</td>
</tr>
</tbody>
</table>
<!-- <h3 class="code-line" data-line-start="0" data-line-end="1">11. fidelis-get-alert-by-uuid</h3>
    <hr>
    <p class="has-line-data" data-line-start="2" data-line-end="3">Returns an alert, by UUID.</p>
    <h5 class="code-line" data-line-start="3" data-line-end="4">
      <a id="Base_Command_3"></a>Base Command
    </h5>
    <p class="has-line-data" data-line-start="5" data-line-end="6">
      <code>fidelis-get-alert-by-uuid</code>
    </p>
    <h5 class="code-line" data-line-start="6" data-line-end="7">
      <a id="Input_6"></a>Input
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:271px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:319px">
            <strong>Description</strong>
          </th>
          <th style="width:150px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:271px">alert_uuid</td>
          <td style="width:319px">The UUID of the alert.</td>
          <td style="width:150px">Required</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="13" data-line-end="14">
      <a id="Context_Output_13"></a>Context Output
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:364px">
            <strong>Path</strong>
          </th>
          <th style="width:124px">
            <strong>Type</strong>
          </th>
          <th style="width:252px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:364px">Fidelis.Alert.ID</td>
          <td style="width:124px">Number</td>
          <td style="width:252px">Alert ID.</td>
        </tr>
        <tr>
          <td style="width:364px">Fidelis.Alert.Severity</td>
          <td style="width:124px">String</td>
          <td style="width:252px">Alert severity.</td>
        </tr>
        <tr>
          <td style="width:364px">Fidelis.Alert.Summary</td>
          <td style="width:124px">String</td>
          <td style="width:252px">Alert summary.</td>
        </tr>
        <tr>
          <td style="width:364px">Fidelis.Alert.Time</td>
          <td style="width:124px">Date</td>
          <td style="width:252px">Alert time.</td>
        </tr>
        <tr>
          <td style="width:364px">Fidelis.Alert.Type</td>
          <td style="width:124px">String</td>
          <td style="width:252px">Alert type.</td>
        </tr>
        <tr>
          <td style="width:364px">Fidelis.Alert.UUID</td>
          <td style="width:124px">String</td>
          <td style="width:252px">Alert UUID.</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="25" data-line-end="26">
      <a id="Command_Example_25"></a>Command Example
    </h5>
    <pre>!fidelis-get-alert-by-uuid alert_uuid=2d189aef-a7bd-11e9-8c7d-0e2fc66832d6</pre>
    <h5 class="code-line" data-line-start="28" data-line-end="29">
      <a id="Context_Example_28"></a>Context Example
    </h5>
    <pre>{
    "Fidelis.Alert": [
        {
            "Time": "2019-07-16 11:30:55", 
            "Summary": "ET CNC Ransomware Tracker Reported CnC Server group 87 from 10.12.16.101 to 37.235.50.29", 
            "Type": "DPI", 
            "ID": "10", 
            "Severity": "High"
        }
    ]
}
</pre>
    <h5 class="code-line" data-line-start="43" data-line-end="44">
      <a id="Human_Readable_Output_43"></a>Human Readable Output
    </h5>
    <h3 class="code-line" data-line-start="44" data-line-end="45">
      <a id="Found_1_Alerts_44"></a>Found 1 Alerts:
    </h3>
    <table class="table table-striped table-bordered" border="2">
      <thead>
        <tr>
          <th>ID</th>
          <th>Severity</th>
          <th>Summary</th>
          <th>Time</th>
          <th>Type</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>10</td>
          <td>High</td>
          <td>
            ET CNC Ransomware Tracker Reported CnC Server group 87 from
            10.12.16.101 to 37.235.50.29
          </td>
          <td>2019-07-16 11:30:55</td>
          <td>DPI</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h3 class="code-line" data-line-start="50" data-line-end="51">
      <a id="12_fidelislistmetadata_50"></a>12. fidelis-list-metadata
    </h3>
    <hr>
    <p class="has-line-data" data-line-start="52" data-line-end="53">Returns a metadata list.</p>
    <h5 class="code-line" data-line-start="53" data-line-end="54">
      <a id="Base_Command_53"></a>Base Command
    </h5>
    <p class="has-line-data" data-line-start="55" data-line-end="56">
      <code>fidelis-list-metadata</code>
    </p>
    <h5 class="code-line" data-line-start="56" data-line-end="57">
      <a id="Input_56"></a>Input
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:173px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:496px">
            <strong>Description</strong>
          </th>
          <th style="width:71px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:173px">time_frame</td>
          <td style="width:496px">Filter alerts by time frame, for example, Last 48 Hours.</td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:173px">start_time</td>
          <td style="width:496px">
            If the time_frame value is Custom, specify the start time
            for the time range, for example, 2017-06-01T12:48:16.734.
          </td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:173px">end_time</td>
          <td style="width:496px">
            If the time_frame value is Custom, specify the end time for
            the time range, for example,2017-06-01T12:48:16.734.
          </td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:173px">client_ip</td>
          <td style="width:496px">Filter alerts by client IP.</td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:173px">server_ip</td>
          <td style="width:496px">Filter alerts by server IP address.</td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:173px">request_direction</td>
          <td style="width:496px">
            Direction of the request. Can be “s2c” (server to client)
            or “c2s” (client to server).
          </td>
          <td style="width:71px">Optional</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="68" data-line-end="69">
      <a id="Context_Output_68"></a>Context Output
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:313px">
            <strong>Path</strong>
          </th>
          <th style="width:68px">
            <strong>Type</strong>
          </th>
          <th style="width:359px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:313px">Fidelis.Metadata.MalwareName</td>
          <td style="width:68px">String</td>
          <td style="width:359px">Malware name.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.ServerPort</td>
          <td style="width:68px">Number</td>
          <td style="width:359px">Server port number.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.SHA256</td>
          <td style="width:68px">String</td>
          <td style="width:359px">SHA256 hash of the file.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.FileName</td>
          <td style="width:68px">String</td>
          <td style="width:359px">File name.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.PcapFilename</td>
          <td style="width:68px">String</td>
          <td style="width:359px">PCAP file name.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.SessionDuration</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The event session duration.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.ServerIP</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The server IP address.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.ClientCountry</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The client country.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.ClientPort</td>
          <td style="width:68px">Number</td>
          <td style="width:359px">The client port number.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.SessionStart</td>
          <td style="width:68px">Date</td>
          <td style="width:359px">The date/time that the session started.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.MalwareType</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The malware type.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.URL</td>
          <td style="width:68px">String</td>
          <td style="width:359px">Request URL.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.RequestDirection</td>
          <td style="width:68px">String</td>
          <td style="width:359px">Request direction (s2c or c2s).</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.MalwareSeverity</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The severity of the malware.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.ClientIP</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The client IP address.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.ServerCountry</td>
          <td style="width:68px">String</td>
          <td style="width:359px">The country of the server.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.PcapTimestamp</td>
          <td style="width:68px">Date</td>
          <td style="width:359px">PCAP timestamp.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.SensorUUID</td>
          <td style="width:68px">String</td>
          <td style="width:359px">Sensor UUID.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.Timestamp</td>
          <td style="width:68px">Date</td>
          <td style="width:359px">Timestamp of the event.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.FileType</td>
          <td style="width:68px">String</td>
          <td style="width:359px">File type.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.Protocol</td>
          <td style="width:68px">String</td>
          <td style="width:359px">Event protocol.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.UserAgent</td>
          <td style="width:68px">String</td>
          <td style="width:359px">User agent of the request.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.Type</td>
          <td style="width:68px">String</td>
          <td style="width:359px">Type of the event.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.FileSize</td>
          <td style="width:68px">Number</td>
          <td style="width:359px">The size of the file.</td>
        </tr>
        <tr>
          <td style="width:313px">Fidelis.Metadata.MD5</td>
          <td style="width:68px">String</td>
          <td style="width:359px">MD5 hash of the file.</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="99" data-line-end="100">
      <a id="Command_Example_99"></a>Command Example
    </h5>
    <pre>!fidelis-list-metadata</pre>
    <h5 class="code-line" data-line-start="102" data-line-end="103">
      <a id="Context_Example_102"></a>Context Example
    </h5>
    <pre>{
    "Fidelis.Metadata": [
        {
            "SensorUUID": "43cd4175-7dfa-11e8-8173-12de490879d6", 
            "ClientPort": "49317", 
            "FileName": null, 
            "MalwareName": "", 
            "SHA256": "", 
            "SessionStart": "2019-07-16 11:41:32", 
            "SessionDuration": null, 
            "Timestamp": "2019-07-16 11:41:33", 
            "ServerCountry": "United States", 
            "ServerIP": "104.27.188.52", 
            "RequestDirection": null, 
            "PcapFilename": null, 
            "ServerPort": "80", 
            "UserAgent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", 
            "ClientIP": "10.3.23.103", 
            "FileSize": null, 
            "MalwareType": "", 
            "URL": "quantum.binaryguru.biz/?transaction_id=1026b2a2b8ea4e4a1e62268472a224&amp;offer_id=52&amp;affiliate_id=1318", 
            "FileType": null, 
            "ClientCountry": "UNKNOWN", 
            "MD5": "", 
            "Type": "", 
            "Protocol": "HTTP", 
            "MalwareSeverity": "", 
            "PcapTimestamp": null
        }, 
        {
            "SensorUUID": "43cd4175-7dfa-11e8-8173-12de490879d6", 
            "ClientPort": "49317", 
            "FileName": null, 
            "MalwareName": "", 
            "SHA256": "f3c32c25c87f2f0b742fba09d4f4006a118df393b7d99c590144b7f7704ccc04", 
            "SessionStart": "2019-07-16 11:41:32", 
            "SessionDuration": null, 
            "Timestamp": "2019-07-16 11:41:33", 
            "ServerCountry": "United States", 
            "ServerIP": "104.27.188.52", 
            "RequestDirection": null, 
            "PcapFilename": null, 
            "ServerPort": "80", 
            "UserAgent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", 
            "ClientIP": "10.3.23.103", 
            "FileSize": null, 
            "MalwareType": "", 
            "URL": "quantum.binaryguru.biz/?transaction_id=1026b2a2b8ea4e4a1e62268472a224&amp;offer_id=52&amp;affiliate_id=1318", 
            "FileType": null, 
            "ClientCountry": "UNKNOWN", 
            "MD5": "db25ea398ea1c0c746810836d2bc2d52", 
            "Type": "", 
            "Protocol": "HTTP", 
            "MalwareSeverity": "", 
            "PcapTimestamp": null
        }, <br>... 
</pre>
    <h5 class="code-line" data-line-start="2675" data-line-end="2676">
      <a id="Human_Readable_Output_2675"></a>Human Readable Output
    </h5>
    <h3 class="code-line" data-line-start="2676" data-line-end="2677">
      <a id="Found_95_Metadata_2676"></a>Found 95 Metadata:
    </h3>
    <table class="table table-striped table-bordered" border="2">
      <thead>
        <tr>
          <th>ClientIP</th>
          <th>ClientPort</th>
          <th>ServerIP</th>
          <th>ServerPort</th>
          <th>Timestamp</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>10.3.23.103</td>
          <td>49317</td>
          <td>104.27.188.52</td>
          <td>80</td>
          <td>2019-07-16 11:41:33</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49317</td>
          <td>104.27.188.52</td>
          <td>80</td>
          <td>2019-07-16 11:41:33</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49317</td>
          <td>104.27.188.52</td>
          <td>80</td>
          <td>2019-07-16 11:41:33</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49316</td>
          <td>52.52.210.187</td>
          <td>80</td>
          <td>2019-07-16 11:41:32</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49316</td>
          <td>52.52.210.187</td>
          <td>80</td>
          <td>2019-07-16 11:41:32</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49314</td>
          <td>52.9.23.208</td>
          <td>80</td>
          <td>2019-07-16 11:41:32</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49314</td>
          <td>52.9.23.208</td>
          <td>80</td>
          <td>2019-07-16 11:41:32</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49311</td>
          <td>192.254.233.44</td>
          <td>80</td>
          <td>2019-07-16 11:41:30</td>
        </tr>
        <tr>
          <td>10.3.23.103</td>
          <td>49311</td>
          <td>192.254.233.44</td>
          <td>80</td>
          <td>2019-07-16 11:41:30</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:48</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>172.22.5.119</td>
          <td>54637</td>
          <td>8.8.8.8</td>
          <td>53</td>
          <td>2019-07-16 11:36:47</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49165</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:33:42</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49165</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:33:42</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:32:57</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:32:57</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49165</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:32:54</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49165</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:32:54</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:32:09</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:32:09</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:31:48</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:31:48</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:31:46</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:31:46</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:31:45</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:31:45</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49159</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:31:42</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49159</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:31:42</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:30:58</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49160</td>
          <td>37.235.50.29</td>
          <td>80</td>
          <td>2019-07-16 11:30:58</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49159</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:30:55</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49159</td>
          <td>176.121.14.95</td>
          <td>80</td>
          <td>2019-07-16 11:30:55</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49158</td>
          <td>190.105.238.43</td>
          <td>80</td>
          <td>2019-07-16 11:29:58</td>
        </tr>
        <tr>
          <td>10.12.16.101</td>
          <td>49158</td>
          <td>190.105.238.43</td>
          <td>80</td>
          <td>2019-07-16 11:29:58</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h3 class="code-line" data-line-start="2776" data-line-end="2777">
      <a id="13_fidelislistalertsbyip_2776"></a>13. fidelis-list-alerts-by-ip
    </h3>
    <hr>
    <p class="has-line-data" data-line-start="2778" data-line-end="2779">
      Returns a list of alerts, by source IP address or destination IP address.
    </p>
    <h5 class="code-line" data-line-start="2779" data-line-end="2780">
      <a id="Base_Command_2779"></a>Base Command
    </h5>
    <p class="has-line-data" data-line-start="2781" data-line-end="2782">
      <code>fidelis-list-alerts-by-ip</code>
    </p>
    <h5 class="code-line" data-line-start="2782" data-line-end="2783">
      <a id="Input_2782"></a>Input
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:141px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:528px">
            <strong>Description</strong>
          </th>
          <th style="width:71px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:141px">time_frame</td>
          <td style="width:528px">
            Today, Yesterday, Last 7 Days, Last Hour, Last 24 Hours,
            Last 48 Hours, Last 30 Days, Custom.
          </td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:141px">start_time</td>
          <td style="width:528px">
            If the time_frame value is Custom, specify the start time
            for the time range, for example, 2017-06-01T12:48:16.734.
          </td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:141px">end_time</td>
          <td style="width:528px">
            If the time_frame value is Custom, specify the start time
            for the time range, for example, 2017-06-01T12:48:16.734.
          </td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:141px">src_ip</td>
          <td style="width:528px">Filter alerts by the source IP.</td>
          <td style="width:71px">Optional</td>
        </tr>
        <tr>
          <td style="width:141px">dest_ip</td>
          <td style="width:528px">Filter alerts by the destination IP address.</td>
          <td style="width:71px">Optional</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="2793" data-line-end="2794">
      <a id="Context_Output_2793"></a>Context Output
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:331px">
            <strong>Path</strong>
          </th>
          <th style="width:75px">
            <strong>Type</strong>
          </th>
          <th style="width:334px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:331px">Fidelis.Alert.SourceIP</td>
          <td style="width:75px">String</td>
          <td style="width:334px">The alert source IP address.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.UserRating</td>
          <td style="width:75px">String</td>
          <td style="width:334px">User rating.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.DestinationCountry</td>
          <td style="width:75px">String</td>
          <td style="width:334px">Destination country of the alert.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.AssetID</td>
          <td style="width:75px">Number</td>
          <td style="width:334px">The ID of the asset.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.Time</td>
          <td style="width:75px">Date</td>
          <td style="width:334px">Date/time that the alert started.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.HostIP</td>
          <td style="width:75px">String</td>
          <td style="width:334px">The host IP address of the alert.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.DistributedAlertID</td>
          <td style="width:75px">String</td>
          <td style="width:334px">Alert distributed ID.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.DestinationIP</td>
          <td style="width:75px">String</td>
          <td style="width:334px">Alert destination IP address.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.AlertUUID</td>
          <td style="width:75px">String</td>
          <td style="width:334px">The alert UUID.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.Type</td>
          <td style="width:75px">String</td>
          <td style="width:334px">The alert type.</td>
        </tr>
        <tr>
          <td style="width:331px">
            <a href="http://fidelis.alert.id/">Fidelis.Alert.ID</a>
          </td>
          <td style="width:75px">Number</td>
          <td style="width:334px">Alert ID.</td>
        </tr>
        <tr>
          <td style="width:331px">Fidelis.Alert.SourceCountry</td>
          <td style="width:75px">String</td>
          <td style="width:334px">Alert source country</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="2811" data-line-end="2812">
      <a id="Command_Example_2811"></a>Command Example
    </h5>
    <pre>!fidelis-list-alerts-by-ip src_ip=10.12.16.101</pre>
    <h5 class="code-line" data-line-start="2814" data-line-end="2815">
      <a id="Context_Example_2814"></a>Context Example
    </h5>
    <pre>{
    "Fidelis.Alert": [
        {
            "Type": "DPI", 
            "DestinationIP": "37.235.50.29", 
            "DistributedAlertID": "Console-10", 
            "AssetID": "0", 
            "SourceIP": "10.12.16.101", 
            "Time": "2019-07-16 11:30:55", 
            "AlertUUID": "2d189aef-a7bd-11e9-8c7d-0e2fc66832d6", 
            "UserRating": "No Rating", 
            "SourceCountry": "unknown", 
            "HostIP": "10.12.16.101", 
            "DestinationCountry": "Switzerland", 
            "ID": "10"
        }, 
        {
            "Type": "DPI", 
            "DestinationIP": "176.121.14.95", 
            "DistributedAlertID": "Console-8", 
            "AssetID": "0", 
            "SourceIP": "10.12.16.101", 
            "Time": "2019-07-16 11:29:58", 
            "AlertUUID": "2c1ccf8d-a7bd-11e9-8c7d-0e2fc66832d6", 
            "UserRating": "No Rating", 
            "SourceCountry": "unknown", 
            "HostIP": "10.12.16.101", 
            "DestinationCountry": "Ukraine", 
            "ID": "8"
        }
    ]
}
</pre>
    <h5 class="code-line" data-line-start="2850" data-line-end="2851">
      <a id="Human_Readable_Output_2850"></a>Human Readable Output
    </h5>
    <h3 class="code-line" data-line-start="2851" data-line-end="2852">
      <a id="Found_2_Alerts_2851"></a>Found 2 Alerts:
    </h3>
    <table class="table table-striped table-bordered" border="2">
      <thead>
        <tr>
          <th>Time</th>
          <th>AlertUUID</th>
          <th>ID</th>
          <th>DistributedAlertID</th>
          <th>UserRating</th>
          <th>HostIP</th>
          <th>AssetID</th>
          <th>Type</th>
          <th>DestinationCountry</th>
          <th>SourceCountry</th>
          <th>DestinationIP</th>
          <th>SourceIP</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>2019-07-16 11:30:55</td>
          <td>2d189aef-a7bd-11e9-8c7d-0e2fc66832d6</td>
          <td>10</td>
          <td>Console-10</td>
          <td>No Rating</td>
          <td>10.12.16.101</td>
          <td>0</td>
          <td>DPI</td>
          <td>Switzerland</td>
          <td>unknown</td>
          <td>37.235.50.29</td>
          <td>10.12.16.101</td>
        </tr>
        <tr>
          <td>2019-07-16 11:29:58</td>
          <td>2c1ccf8d-a7bd-11e9-8c7d-0e2fc66832d6</td>
          <td>8</td>
          <td>Console-8</td>
          <td>No Rating</td>
          <td>10.12.16.101</td>
          <td>0</td>
          <td>DPI</td>
          <td>Ukraine</td>
          <td>unknown</td>
          <td>176.121.14.95</td>
          <td>10.12.16.101</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h3 class="code-line" data-line-start="2858" data-line-end="2859">
      <a id="14_fidelisdownloadmalwarefile_2858"></a>14. fidelis-download-malware-file
    </h3>
    <hr>
    <p class="has-line-data" data-line-start="2860" data-line-end="2861">Downloads a malware file from a specified alert.</p>
    <h5 class="code-line" data-line-start="2861" data-line-end="2862">
      <a id="Base_Command_2861"></a>Base Command
    </h5>
    <p class="has-line-data" data-line-start="2863" data-line-end="2864">
      <code>fidelis-download-malware-file</code>
    </p>
    <h5 class="code-line" data-line-start="2864" data-line-end="2865">
      <a id="Input_2864"></a>Input
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:174px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:466px">
            <strong>Description</strong>
          </th>
          <th style="width:100px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:174px">alert_id</td>
          <td style="width:466px">ID of the alert from which to download the file.</td>
          <td style="width:100px">Required</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="2871" data-line-end="2872">
      <a id="Context_Output_2871"></a>Context Output
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:219px">
            <strong>Path</strong>
          </th>
          <th style="width:117px">
            <strong>Type</strong>
          </th>
          <th style="width:404px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:219px">File.Size</td>
          <td style="width:117px">Number</td>
          <td style="width:404px">The size of the file.</td>
        </tr>
        <tr>
          <td style="width:219px">File.Extension</td>
          <td style="width:117px">String</td>
          <td style="width:404px">The file extension.</td>
        </tr>
        <tr>
          <td style="width:219px">File.Info</td>
          <td style="width:117px">String</td>
          <td style="width:404px">Information about the file.</td>
        </tr>
        <tr>
          <td style="width:219px">File.Name</td>
          <td style="width:117px">String</td>
          <td style="width:404px">The name of the file.</td>
        </tr>
        <tr>
          <td style="width:219px">File.SHA1</td>
          <td style="width:117px">String</td>
          <td style="width:404px">SHA1 hash of the file.</td>
        </tr>
        <tr>
          <td style="width:219px">File.Type</td>
          <td style="width:117px">String</td>
          <td style="width:404px">The file type.</td>
        </tr>
        <tr>
          <td style="width:219px">File.SHA256</td>
          <td style="width:117px">String</td>
          <td style="width:404px">SHA256 hash of the file.</td>
        </tr>
        <tr>
          <td style="width:219px">File.SSDeep</td>
          <td style="width:117px">String</td>
          <td style="width:404px">SSDeep hash of the file.</td>
        </tr>
        <tr>
          <td style="width:219px">File.EntryID</td>
          <td style="width:117px">String</td>
          <td style="width:404px">File entry ID.</td>
        </tr>
        <tr>
          <td style="width:219px">File.MD5</td>
          <td style="width:117px">String</td>
          <td style="width:404px">MD5 hash of the file.</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="2887" data-line-end="2888">
      <a id="Command_Example_2887"></a>Command Example
    </h5>
    <pre>!fidelis-download-malware-file alert_id=3</pre>
    <h5 class="code-line" data-line-start="2890" data-line-end="2891">
      <a id="Human_Readable_Output_2890"></a>Human Readable Output
    </h5>
    <ul>
      <li class="has-line-data" data-line-start="2891" data-line-end="2893">Will return the file to download</li>
    </ul>
    <h3 class="code-line" data-line-start="2893" data-line-end="2894">
      <a id="15_fidelisdownloadpcapfile_2893"></a>15. fidelis-download-pcap-file
    </h3>
    <hr>
    <p class="has-line-data" data-line-start="2895" data-line-end="2896">Downloads the PCAP file from a specified alert.</p>
    <h5 class="code-line" data-line-start="2896" data-line-end="2897">
      <a id="Base_Command_2896"></a>Base Command
    </h5>
    <p class="has-line-data" data-line-start="2898" data-line-end="2899">
      <code>fidelis-download-pcap-file</code>
    </p>
    <h5 class="code-line" data-line-start="2899" data-line-end="2900">
      <a id="Input_2899"></a>Input
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:175px">
            <strong>Argument Name</strong>
          </th>
          <th style="width:471px">
            <strong>Description</strong>
          </th>
          <th style="width:94px">
            <strong>Required</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:175px">alert_id</td>
          <td style="width:471px">The ID of the alert from which to download the file.</td>
          <td style="width:94px">Required</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="2906" data-line-end="2907">
      <a id="Context_Output_2906"></a>Context Output
    </h5>
    <table class="table table-striped table-bordered" style="width:749px">
      <thead>
        <tr>
          <th style="width:208px">
            <strong>Path</strong>
          </th>
          <th style="width:128px">
            <strong>Type</strong>
          </th>
          <th style="width:404px">
            <strong>Description</strong>
          </th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td style="width:208px">File.EntryID</td>
          <td style="width:128px">String</td>
          <td style="width:404px">The entry ID of the file.</td>
        </tr>
        <tr>
          <td style="width:208px">File.Info</td>
          <td style="width:128px">String</td>
          <td style="width:404px">File information.</td>
        </tr>
        <tr>
          <td style="width:208px">File.Name</td>
          <td style="width:128px">String</td>
          <td style="width:404px">Name of the file.</td>
        </tr>
        <tr>
          <td style="width:208px">File.Size</td>
          <td style="width:128px">Number</td>
          <td style="width:404px">File size.</td>
        </tr>
        <tr>
          <td style="width:208px">File.Type</td>
          <td style="width:128px">String</td>
          <td style="width:404px">File type.</td>
        </tr>
        <tr>
          <td style="width:208px">File.SHA1</td>
          <td style="width:128px">String</td>
          <td style="width:404px">SHA1 hash of the file.</td>
        </tr>
        <tr>
          <td style="width:208px">File.SHA256</td>
          <td style="width:128px">String</td>
          <td style="width:404px">SHA256 hash of the file.</td>
        </tr>
        <tr>
          <td style="width:208px">File.SSDeep</td>
          <td style="width:128px">String</td>
          <td style="width:404px">SSDeep hash of the file.</td>
        </tr>
        <tr>
          <td style="width:208px">File.MD5</td>
          <td style="width:128px">String</td>
          <td style="width:404px">MD5 hash of the file.</td>
        </tr>
      </tbody>
    </table>
    <p> </p>
    <h5 class="code-line" data-line-start="2921" data-line-end="2922">
      <a id="Command_Example_2921"></a>Command Example
    </h5>
    <pre>!fidelis-download-pcap-file alert_id=12</pre>
    <h5 class="code-line" data-line-start="2924" data-line-end="2925">
      <a id="Human_Readable_Output_2924"></a>Human Readable Output
    </h5>
    <ul>
      <li class="has-line-data" data-line-start="2925" data-line-end="2926">Will return the file to download</li>
    </ul>
  </div>
</div> -->
</div>
</div>