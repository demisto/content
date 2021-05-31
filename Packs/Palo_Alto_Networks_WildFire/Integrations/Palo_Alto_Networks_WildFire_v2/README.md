<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Palo Alto Networks Wildfire integration to automatically identify unknown threats and stop attackers in their tracks.</p>
</div>
<div class="cl-preview-section">
<h2 id="palo-alto-networks-wildfire-v2-playbook">Palo Alto Networks WildFire v2 Playbooks</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>WildFire - Detonate File</li>
<li>Detonate URL - WildFire-v2</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Send a File sample to WildFire.</li>
<li>Upload a file hosted on a website to WildFire.</li>
<li>Submit a webpage to WildFire.</li>
<li>Get a report regarding the sent samples using file hash.</li>
<li>Get sample file from WildFire.</li>
<li>Get verdict regarding multiple hashes(up to 500) using the wildfire-get-verdicts command.</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-palo-alto-networks-wildfire-v2-on-demisto">Configure Palo Alto Networks WildFire v2 on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Palo Alto Networks WildFire v2.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span>https://192.168.0.1/publicapi)</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Return warning entry for unsupported file types</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Get results for a file hash: file</li>
<li>Upload a file for analysis: wildfire-upload</li>
<li>Upload the URL of a remote file for analysis: wildfire-upload-file-url</li>
<li>Get results of a file hash analysis wildfire-report</li>
<li>Get the verdict of a file hash: wildfire-get-verdict</li>
<li>Get the verdicts for multiple file hashes: wildfire-get-verdicts</li>
<li>Upload a URL for analysis: wildfire-upload-url</li>
<li>Get a sample: wildfire-get-sample</li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-results-for-a-file-hash">1. Get results for a file hash</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves results for a file hash using WildFire.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>file</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 256px;"><strong>Argument Name</strong></th>
<th style="width: 338px;"><strong>Description</strong></th>
<th style="width: 146px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">file</td>
<td style="width: 338px;">File hash to check.</td>
<td style="width: 146px;">Optional</td>
</tr>
<tr>
<td style="width: 256px;">md5</td>
<td style="width: 338px;">MD5 hash to check.</td>
<td style="width: 146px;">Optional</td>
</tr>
<tr>
<td style="width: 256px;">sha256</td>
<td style="width: 338px;">SHA256 hash to check.</td>
<td style="width: 146px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 210px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 458px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 210px;">File.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">Name of the file.</td>
</tr>
<tr>
<td style="width: 210px;">File.Type</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">File type, for example: “PE”.</td>
</tr>
<tr>
<td style="width: 210px;">File.Size</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">Size of the file.</td>
</tr>
<tr>
<td style="width: 210px;">File.MD5</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 210px;">File.SHA1</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 210px;">File.SHA256</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 210px;">File.Malicious.Vendor</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Indicator</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Type</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Vendor</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 210px;">DBotScore.Score</td>
<td style="width: 72px;">number</td>
<td style="width: 458px;">The actual score.</td>
</tr>
<tr>
<td style="width: 210px;">WildFire.Report.Status</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">The status of the submission.</td>
</tr>
<tr>
<td style="width: 210px;">WildFire.Report.SHA256</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">SHA256 hash of the submission.</td>
</tr>
<tr>
<td style="width: 210px;">InfoFile.EntryID</td>
<td style="width: 72px;">Unknown</td>
<td style="width: 458px;">The EntryID of the report file.</td>
</tr>
<tr>
<td style="width: 210px;">InfoFile.Extension</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">Extension of the report file.</td>
</tr>
<tr>
<td style="width: 210px;">InfoFile.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">Name of the report file.</td>
</tr>
<tr>
<td style="width: 210px;">InfoFile.Info</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">Details of the report file.</td>
</tr>
<tr>
<td style="width: 210px;">InfoFile.Size</td>
<td style="width: 72px;">number</td>
<td style="width: 458px;">Size of the report file.</td>
</tr>
<tr>
<td style="width: 210px;">InfoFile.Type</td>
<td style="width: 72px;">string</td>
<td style="width: 458px;">The report file type.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!file file=1d457069cb511af47a587287d59817148d404a2a7f39e1032d16094811f648e3</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57465993-6bba4900-7288-11e9-945b-d7da8540789e.png" alt="Screen Shot 2019-05-09 at 18 29 10" width="700"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="upload-a-file-for-analysis">2. Upload a file for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Uploads a file to WildFire for analysis.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-upload</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 195px;"><strong>Argument Name</strong></th>
<th style="width: 440px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 195px;">upload</td>
<td style="width: 440px;">ID of the entry containing the file to upload</td>
<td style="width: 105px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 263px;"><strong>Path</strong></th>
<th style="width: 104px;"><strong>Type</strong></th>
<th style="width: 373px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 263px;">WildFire.Report.MD5</td>
<td style="width: 104px;">string</td>
<td style="width: 373px;">MD5 hash of the submission.</td>
</tr>
<tr>
<td style="width: 263px;">WildFire.Report.SHA256</td>
<td style="width: 104px;">string</td>
<td style="width: 373px;">SHA256 hash of the submission.</td>
</tr>
<tr>
<td style="width: 263px;">WildFire.Report.FileType</td>
<td style="width: 104px;">string</td>
<td style="width: 373px;">The submission type.</td>
</tr>
<tr>
<td style="width: 263px;">WildFire.Report.Size</td>
<td style="width: 104px;">number</td>
<td style="width: 373px;">The size of the submission.</td>
</tr>
<tr>
<td style="width: 263px;">WildFire.Report.Status</td>
<td style="width: 104px;">string</td>
<td style="width: 373px;">The status of the submission.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-upload upload="1740@24"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57465419-3e20d000-7287-11e9-8c5d-46f4484d73cc.png" alt="Screen Shot 2019-05-09 at 18 20 53" width="1261"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="upload-the-url-of-a-remote-file-for-analysis">3. Upload the URL of a remote file for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Uploads the URL of a remote file to WildFire for analysis.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-upload-file-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 227px;"><strong>Argument Name</strong></th>
<th style="width: 389px;"><strong>Description</strong></th>
<th style="width: 124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 227px;">upload</td>
<td style="width: 389px;">URL of the remote file to upload.</td>
<td style="width: 124px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 294px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 385px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 294px;">WildFire.Report.MD5</td>
<td style="width: 61px;">string</td>
<td style="width: 385px;">MD5 hash of the submission.</td>
</tr>
<tr>
<td style="width: 294px;">WildFire.Report.SHA256</td>
<td style="width: 61px;">string</td>
<td style="width: 385px;">SHA256 hash of the submission.</td>
</tr>
<tr>
<td style="width: 294px;">WildFire.Report.Status</td>
<td style="width: 61px;">string</td>
<td style="width: 385px;">The status of the submission.</td>
</tr>
<tr>
<td style="width: 294px;">WildFire.Report.URL</td>
<td style="width: 61px;">string</td>
<td style="width: 385px;">URL of the submission.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-upload-file-url upload="http://www.pdf995.com/samples/pdf.pdf"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57465358-20536b00-7287-11e9-84c4-50d1c37bf943.png" alt="Screen Shot 2019-05-09 at 18 19 31" width="1309"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="get-results-of-a-file-hash-analysis">4. Get results of a file hash analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves results for a file hash using WildFire.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-report</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 185px;"><strong>Argument Name</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">md5</td>
<td style="width: 457px;">MD5 hash to check.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">sha256</td>
<td style="width: 457px;">SHA256 hash to check</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">hash</td>
<td style="width: 457px;">Deprecated - Use the sha256 argument instead.</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">format</td>
<td style="width: 457px;">Request a structured report (XML PDF).</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">verbose</td>
<td style="width: 457px;">Receive extended information from WildFire.</td>
<td style="width: 98px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 285px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 285px;">File.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Name of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">File type, for example: “PE”</td>
</tr>
<tr>
<td style="width: 285px;">File.Size</td>
<td style="width: 59px;">number</td>
<td style="width: 396px;">Size of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.MD5</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.SHA1</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.SHA256</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.Malicious.Vendor</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 285px;">DBotScore.Indicator</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 285px;">DBotScore.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 285px;">DBotScore.Vendor</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 285px;">DBotScore.Score</td>
<td style="width: 59px;">number</td>
<td style="width: 396px;">The actual score.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Status</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The status of the submission.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.SHA256</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">SHA256 hash of the submission.</td>
</tr>
<tr>
<td style="width: 285px;">InfoFile.EntryID</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The EntryID of the report file.</td>
</tr>
<tr>
<td style="width: 285px;">InfoFile.Extension</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The extension of the report file.</td>
</tr>
<tr>
<td style="width: 285px;">InfoFile.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The name of the report file.</td>
</tr>
<tr>
<td style="width: 285px;">InfoFile.Info</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Details of the report file.</td>
</tr>
<tr>
<td style="width: 285px;">InfoFile.Size</td>
<td style="width: 59px;">number</td>
<td style="width: 396px;">The size of the report file.</td>
</tr>
<tr>
<td style="width: 285px;">InfoFile.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">The report file type.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Network.UDP.IP</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission related IPs, in UDP protocol.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Network.UDP.Port</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission related ports, in UDP protocol.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Network.TCP.IP</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission related IPs, in TCP protocol.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Network.TCP.Port</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission related ports, in TCP protocol.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Network.DNS.Query</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission DNS queries.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Network.DNS.Response</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission DNS responses.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Evidence.md5</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission evidence MD5 hash.</td>
</tr>
<tr>
<td style="width: 285px;">WildFire.Report.Evidence.Text</td>
<td style="width: 59px;">string</td>
<td style="width: 396px;">Submission evidence text.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-report hash="ebb031c3945e884e695dbc63c52a5efcd075375046c49729980073585ee13c52"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57465509-70cac880-7287-11e9-8bd3-3808be763ce8.png" alt="Screen Shot 2019-05-09 at 18 21 41" width="1058"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="get-the-verdict-of-a-file-hash">5. Get the verdict of a file hash</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a verdict for a hash.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-get-verdict</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 250px;"><strong>Argument Name</strong></th>
<th style="width: 353px;"><strong>Description</strong></th>
<th style="width: 137px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 250px;">hash</td>
<td style="width: 353px;">Hash to get the verdict for.</td>
<td style="width: 137px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 329px;"><strong>Path</strong></th>
<th style="width: 79px;"><strong>Type</strong></th>
<th style="width: 332px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 329px;">WildFire.Verdicts.MD5</td>
<td style="width: 79px;">string</td>
<td style="width: 332px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 329px;">WildFire.Verdicts.SHA256</td>
<td style="width: 79px;">string</td>
<td style="width: 332px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 329px;">WildFire.Verdicts.Verdict</td>
<td style="width: 79px;">number</td>
<td style="width: 332px;">Verdict of the file.</td>
</tr>
<tr>
<td style="width: 329px;">WildFire.Verdicts.VerdictDescription</td>
<td style="width: 79px;">string</td>
<td style="width: 332px;">Description of the file verdict.</td>
</tr>
<tr>
<td style="width: 329px;">DBotScore.Indicator</td>
<td style="width: 79px;">string</td>
<td style="width: 332px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 329px;">DBotScore.Type</td>
<td style="width: 79px;">string</td>
<td style="width: 332px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 329px;">DBotScore.Vendor</td>
<td style="width: 79px;">string</td>
<td style="width: 332px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 329px;">DBotScore.Score</td>
<td style="width: 79px;">number</td>
<td style="width: 332px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-get-verdict hash="afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57465590-9a83ef80-7287-11e9-964c-7c28c539ffb9.png" alt="Screen Shot 2019-05-09 at 18 23 30" width="1274"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="get-the-verdicts-for-multiple-file-hashes">6. Get the verdicts for multiple file hashes</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a verdict regarding multiple hashes, stored in a TXT file or given as list. The maximum number of verdicts is 500, and can be given as an EntryID of a file in the specified format, or in the hash_list argument. For more information, see the <a href="https://docs.paloaltonetworks.com/wildfire/7-1/wildfire-api/get-wildfire-information-through-the-wildfire-api/get-multiple-wildfire-verdicts-wildfire-api.html" target="_blank" rel="noopener">WildFire documentation</a>.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-get-verdicts</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">EntryID</td>
<td style="width: 530px;">EntryID of the text file that contains multiple hashes. Limit is 500 hashes.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">hash_list</td>
<td style="width: 530px;">A list of hashes to get verdicts for.</td>
<td style="width: 73px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 338px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 332px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 338px;">WildFire.Verdicts.MD5</td>
<td style="width: 70px;">string</td>
<td style="width: 332px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 338px;">WildFire.Verdicts.SHA256</td>
<td style="width: 70px;">string</td>
<td style="width: 332px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 338px;">WildFire.Verdicts.Verdict</td>
<td style="width: 70px;">number</td>
<td style="width: 332px;">Verdict of the file.</td>
</tr>
<tr>
<td style="width: 338px;">WildFire.Verdicts.VerdictDescription</td>
<td style="width: 70px;">string</td>
<td style="width: 332px;">Description of the file verdict.</td>
</tr>
<tr>
<td style="width: 338px;">DBotScore.Indicator</td>
<td style="width: 70px;">string</td>
<td style="width: 332px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 338px;">DBotScore.Type</td>
<td style="width: 70px;">string</td>
<td style="width: 332px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 338px;">DBotScore.Vendor</td>
<td style="width: 70px;">string</td>
<td style="width: 332px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 338px;">DBotScore.Score</td>
<td style="width: 70px;">number</td>
<td style="width: 332px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-get-verdicts EntryID="1770@24"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57465676-c69f7080-7287-11e9-9910-4a97a4d5cd92.png" alt="Screen Shot 2019-05-09 at 18 24 31" width="1277"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="upload-the-url-of-a-webpage-for-analysis">7. Upload a URL for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Uploads a URL to WildFire for analysis. </p>
<p><strong>Note</strong>: Only malicious URLs will be included and displayed in the report. There will be no record of non-malicious URLs.</p>
<p> </p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-upload-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 245px;"><strong>Argument Name</strong></th>
<th style="width: 357px;"><strong>Description</strong></th>
<th style="width: 138px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 245px;">upload</td>
<td style="width: 357px;">URL to submit to WildFire.</td>
<td style="width: 138px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 293px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 367px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293px;">WildFire.Report.MD5</td>
<td style="width: 80px;">string</td>
<td style="width: 367px;">MD5 of the submission.</td>
</tr>
<tr>
<td style="width: 293px;">WildFire.Report.SHA256</td>
<td style="width: 80px;">string</td>
<td style="width: 367px;">SHA256 of the submission.</td>
</tr>
<tr>
<td style="width: 293px;">WildFire.Report.Status</td>
<td style="width: 80px;">string</td>
<td style="width: 367px;">The status of the submission.</td>
</tr>
<tr>
<td style="width: 293px;">WildFire.Report.URL</td>
<td style="width: 80px;">string</td>
<td style="width: 367px;">URL of the submission.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-upload-url upload=https://moviepropit.com/eas/chase/home/</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57466328-10d52180-7289-11e9-9057-04884f531366.png" alt="Screen Shot 2019-05-09 at 18 33 44" width="1315"></div>
<div class="cl-preview-section"></div>
<div class="cl-preview-section">
<h3 id="get-a-sample">8. Get a sample</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a sample. Malicious files are saved indefinitely. Non-malicious files are saved for 14 days.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>wildfire-get-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 246px;"><strong>Argument Name</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
<th style="width: 133px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 246px;">md5</td>
<td style="width: 361px;">MD5 hash of the sample.</td>
<td style="width: 133px;">Optional</td>
</tr>
<tr>
<td style="width: 246px;">sha256</td>
<td style="width: 361px;">SHA256 hash of the sample.</td>
<td style="width: 133px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!wildfire-get-sample md5=5af84a3db5883627bfdff909e210634e</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section"><img src="https://user-images.githubusercontent.com/37335599/57466126-b045e480-7288-11e9-983c-8910a76a8d00.png" alt="Screen Shot 2019-05-09 at 18 30 35" width="1300"></div>