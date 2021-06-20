<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Closing the gap on traditional solutions, training, and talent with next-generation anti-phishing platform powered by AI &amp; Computer Vision.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-phish.ai-on-demisto">Configure Phish.AI on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Phish.AI.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Private API Key (Optional)</strong> get it from My Profile on your Phish.AI Web URL</li>
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
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#scan-a-url" target="_self">Scan a URL: phish-ai-scan-url</a></li>
<li><a href="#check-a-url-status" target="_self">Check a URL status: phish-ai-check-status</a></li>
<li><a href="#dispute-a-scan-result" target="_self">Dispute a scan result: phish-ai-dispute-url</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="scan-a-url">1. Scan a URL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Checks if a URL is phishing, and returns details about the brand that is being phished.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>phish-ai-scan-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 223px;"><strong>Argument Name</strong></th>
<th style="width: 486px;"><strong>Description</strong></th>
<th style="width: 31px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 223px;">url</td>
<td style="width: 486px;">The URL to check.</td>
<td style="width: 31px;">Required</td>
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
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 222px;"><strong>Path</strong></th>
<th style="width: 10px;"><strong>Type</strong></th>
<th style="width: 508px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 222px;">URL.Data</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The URL address.</td>
</tr>
<tr>
<td style="width: 222px;">URL.Malicious.Vendor</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 222px;">URL.Malicious.Description</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 222px;">DBotScore.Indicator</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 222px;">DBotScore.Type</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 222px;">DBotScore.Vendor</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 222px;">DBotScore.Score</td>
<td style="width: 10px;">number</td>
<td style="width: 508px;">The actual score.</td>
</tr>
<tr>
<td style="width: 222px;">IP.Address</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The IP address of the URL.</td>
</tr>
<tr>
<td style="width: 222px;">IP.Geo.Country</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The geo-location of the URL.</td>
</tr>
<tr>
<td style="width: 222px;">PhishAI.ScanID</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The Phish AI scan ID.</td>
</tr>
<tr>
<td style="width: 222px;">PhishAI.Status</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The status of the scan.</td>
</tr>
<tr>
<td style="width: 222px;">PhishAI.URL</td>
<td style="width: 10px;">string</td>
<td style="width: 508px;">The URL address.</td>
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
<pre>!phish-ai-scan url=www.demisto.com</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/53904776-86393180-404f-11e9-91b0-bb572f709568.png" alt="phishaiscan" width="1080"></div>
<div class="cl-preview-section">
<h3 id="check-a-url-status">2. Check a URL status</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Checks the status of a URL, for example, “completed” or “in progress”.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>phish-ai-check-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 236px;"><strong>Argument Name</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
<th style="width: 36px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 236px;">scan_id</td>
<td style="width: 468px;">The scan ID of the URL to check the status of. You must replace the <em>url</em> argument with the <em>scan_id</em> argument in automations and playbooks. Backward compatibility is not supported.</td>
<td style="width: 36px;">Required</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 272px;"><strong>Path</strong></th>
<th style="width: 49px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 272px;">URL.Data</td>
<td style="width: 49px;">string</td>
<td style="width: 419px;">The IP address of the URL.</td>
</tr>
<tr>
<td style="width: 272px;">PhishAI.Status</td>
<td style="width: 49px;">string</td>
<td style="width: 419px;">That status of the scan.</td>
</tr>
<tr>
<td style="width: 272px;">PhishAI.ScanID</td>
<td style="width: 49px;">string</td>
<td style="width: 419px;">The Phish.AI scan ID.</td>
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
<pre>!phish-ai-check-status scan_id="{CsFCgZ494mmW2JMI4hkK}"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/53904907-d6b08f00-404f-11e9-9cce-14c2e2092783.png" alt="phishaicheck" width="1094"></div>
<div class="cl-preview-section">
<h3 id="dispute-a-scan-result">3. Dispute a scan result</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Disputes the result of a scan.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>phish-ai-dispute-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 221px;"><strong>Argument Name</strong></th>
<th style="width: 471px;"><strong>Description</strong></th>
<th style="width: 48px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 221px;">scan_id</td>
<td style="width: 471px;">The scan ID of the URL to dispute.</td>
<td style="width: 48px;">Required</td>
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
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!phish-ai-dispute-url scan_id="CsFCgZ494mmW2JMI4hkK"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/53904858-b8e32a00-404f-11e9-8976-b74d63b9deeb.png" alt="phishaidispute" width="1097"></div>