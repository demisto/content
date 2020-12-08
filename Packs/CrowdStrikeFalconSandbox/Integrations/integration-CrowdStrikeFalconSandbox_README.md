<!-- HTML_DOC -->
<p>Use the CrowdStrike Falcon Sandbox integration to submit and analyze files and URLs.</p>
<p>The maximum file upload size is 100 MB.</p>
<p>Supported File Types:</p>
<ul>
<li>PE (.exe, .scr, .pif, .dll, .com, .cpl, and so on)</li>
<li>Microsoft Word (.doc, .docx, .ppt, .pps, .pptx, .ppsx, .xls, .xlsx, .rtf, .pub)</li>
<li>PDF</li>
<li>APK</li>
<li>JAR executables</li>
<li>Windows Script Component (.sct)</li>
<li>Windows Shortcut (.lnk)</li>
<li>Windows Help (.chm)</li>
<li>HTML Application (.hta)</li>
<li>Windows Script File (*.wsf)</li>
<li>Javascript (.js)</li>
<li>Visual Basic (*.vbs, *.vbe)</li>
<li>Shockwave Flash (.swf)</li>
<li>Perl (.pl)</li>
<li>PowerShell (.ps1, .psd1, .psm1)</li>
<li>Scalable Vector Graphics (.svg)</li>
<li>Python scripts (.py)</li>
<li>Perl scripts (.pl)</li>
<li>Linux ELF executables</li>
<li>MIME RFC 822 (*.eml)</li>
<li>Outlook (*.msg files)</li>
</ul>
<h2>Prerequisites</h2>
<p>Make sure you have the following CrowdStrike Falcon Sandbox information.</p>
<ul>
<li>API key</li>
<li>Secret key (applicable for v1)</li>
<li>API version (v1 or v2)</li>
</ul>
<p>Each API key has an associated authorization level, which determines the available endpoints. By default, all free, non-vetted accounts can issue restricted keys. You can upgrade to full default keys, enabling file submissions and downloads.</p>
<p>Authorization levels:</p>
<ul>
<li>Restricted</li>
<li>Default</li>
<li>Elevated</li>
<li>Super</li>
</ul>
<p> </p>
<div class="cl-preview-section">
<h2 id="configure-crowdstrike-falcon-sandbox-on-demisto">Configure CrowdStrike Falcon Sandbox on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for VxStream.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g., https://216.3.128.82)</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Secret Key (applicable only for v1)</strong></li>
<li><strong>API Version (v1,v2)</strong></li>
<li><strong>Trust any certificate (<span>not secure</span>)</strong></li>
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
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#deprecated-get-summary-information-for-a-file-hash" target="_self">(Deprecated) Get summary information for a file hash: vx-scan</a></li>
<li><a href="#get-hash-scan-results" target="_self">Get hash scan results: crowdstrike-scan</a></li>
<li><a href="#deprecated-get-a-list-of-all-environments" target="_self">(Deprecated) Get a list of all environments: vx-get-environments</a></li>
<li><a href="#get-a-list-of-all-environments" target="_self">Get a list of all environments: crowdstrike-get-environments</a></li>
<li><a href="#deprecated-submit-a-file-sample-for-analysis" target="_self">(Deprecated) Submit a file sample for analysis: vx-submit-sample</a></li>
<li><a href="#submit-a-file-sample-for-analysis" target="_self">Submit a file sample for analysis: crowdstrike-submit-sample</a></li>
<li><a href="#deprecated-query-the-database" target="_self">(Deprecated) Query the database: vx-search</a></li>
<li><a href="#query-the-database" target="_self">Query the database: crowdstrike-search</a></li>
<li><a href="#deprecated-get-result-data-for-a-file" target="_self">(Deprecated) Get result data for a file: vx-result</a></li>
<li><a href="#get-result-data-for-a-file" target="_self">Get result data for a file: crowdstrike-result</a></li>
<li><a href="#deprecated-detonate-a-file" target="_self">(Deprecated) Detonate a file: vx-detonate-file</a></li>
<li><a href="#deprecated-detonate-a-file-1" target="_self">(Deprecated) Detonate a file: crowdstrike-detonate-file</a></li>
<li><a href="#submit-a-url-for-analysis" target="_self">Submit a URL for analysis: crowdstrike-submit-url</a></li>
<li><a href="#get-screenshots-from-a-report" target="_self">Get screenshots from a report: crowdstrike-get-screenshots</a></li>
<li><a href="#deprecated-detonate-a-url" target="_self">(Depecrated) Detonate a URL: crowdstrike-detonate-url</a></li>
<li><a href="#submit-a-file-for-analysis-by-url" target="_self">Submit a file for analysis (by URL): crowdstrike-submit-file-by-url</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="deprecated-get-summary-information-for-a-file-hash">1. (Deprecated) Get summary information for a file hash</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Get summary information for a given MD5 hash, SHA-1 hash, or SHA-256 hash, and all the reports generated for any environment ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vx-scan</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 192px;"><strong>Argument Name</strong></th>
<th style="width: 440px;"><strong>Description</strong></th>
<th style="width: 108px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 192px;">file</td>
<td style="width: 440px;">The file hash (MD5, SHA-1, or SHA-256).</td>
<td style="width: 108px;">Required</td>
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
<th style="width: 223px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 223px;">File.SHA256</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">The SHA-256 hash of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.SHA1</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">SHA1 of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.MD5</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.environmentId</td>
<td style="width: 60px;">number</td>
<td style="width: 457px;">The environment ID of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.analysis_start_time</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">The analysis start time of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.submitname</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">The submission name of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.classification_tags</td>
<td style="width: 60px;">unknown</td>
<td style="width: 457px;">The list of classification tags of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.vxfamily</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">The family classification of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.total_network_connections</td>
<td style="width: 60px;">number</td>
<td style="width: 457px;">The total network connections of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.total_processes</td>
<td style="width: 60px;">number</td>
<td style="width: 457px;">The total processes count of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.total_signatures</td>
<td style="width: 60px;">number</td>
<td style="width: 457px;">The total signatures count of the file.</td>
</tr>
<tr>
<td style="width: 223px;">File.hosts</td>
<td style="width: 60px;">unknown</td>
<td style="width: 457px;">The list of the file’s hosts.</td>
</tr>
<tr>
<td style="width: 223px;">File.isinteresting</td>
<td style="width: 60px;">boolean</td>
<td style="width: 457px;">Whether the server found this file interesting.</td>
</tr>
<tr>
<td style="width: 223px;">File.domains</td>
<td style="width: 60px;">unknown</td>
<td style="width: 457px;">A list of the file’s related domains.</td>
</tr>
<tr>
<td style="width: 223px;">File.isurlanalysis</td>
<td style="width: 60px;">boolean</td>
<td style="width: 457px;">If file analyzed by url.</td>
</tr>
<tr>
<td style="width: 223px;">File.Malicious.Vendor</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 223px;">File.Malicious.Description</td>
<td style="width: 60px;">string</td>
<td style="width: 457px;">For malicious files, the reason that the vendor made the decision.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-hash-scan-results">2. Get hash scan results</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns summary information for a given MD5 hash, SHA-1 hash, or SHA-256 hash, and all the reports generated for any environment ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-scan</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 191px;"><strong>Argument Name</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
<th style="width: 108px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 191px;">file</td>
<td style="width: 441px;">The file hash (MD5, SHA-1, or SHA-256).</td>
<td style="width: 108px;">Required</td>
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
<th style="width: 226px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">File.SHA256</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The SHA-256 hash of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.SHA1</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The SHA-1 hash of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.MD5</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.environmentId</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The environment ID of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.analysis_start_time</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The analysis start time of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.submitname</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The submission name of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.classification_tags</td>
<td style="width: 57px;">unknown</td>
<td style="width: 457px;">A list of classification tags of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.vxfamily</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The family classification of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.total_network_connections</td>
<td style="width: 57px;">number</td>
<td style="width: 457px;">The total network connections of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.total_processes</td>
<td style="width: 57px;">number</td>
<td style="width: 457px;">The total processes count of the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.total_signatures</td>
<td style="width: 57px;">number</td>
<td style="width: 457px;">The total signatures count if the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.hosts</td>
<td style="width: 57px;">unknown</td>
<td style="width: 457px;">A list of the file’s hosts.</td>
</tr>
<tr>
<td style="width: 226px;">File.isinteresting</td>
<td style="width: 57px;">boolean</td>
<td style="width: 457px;">If the server found this file interesting.</td>
</tr>
<tr>
<td style="width: 226px;">File.domains</td>
<td style="width: 57px;">unknown</td>
<td style="width: 457px;">A list of the file’s related domains.</td>
</tr>
<tr>
<td style="width: 226px;">File.isurlanalysis</td>
<td style="width: 57px;">boolean</td>
<td style="width: 457px;">Whether the file was analyzed by URL.</td>
</tr>
<tr>
<td style="width: 226px;">File.Malicious.Vendor</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">or malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 226px;">File.Malicious.Description</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">For malicious files, the reason for the vendor to make the decision.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Indicator</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Type</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Vendor</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Score</td>
<td style="width: 57px;">number</td>
<td style="width: 457px;">The actual score.</td>
</tr>
<tr>
<td style="width: 226px;">File.hash</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The hash used to query the file.</td>
</tr>
<tr>
<td style="width: 226px;">File.state</td>
<td style="width: 57px;">string</td>
<td style="width: 457px;">The state of the file test.</td>
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
<pre>crowdstrike-scan file=59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "DBotScore": {
        "Vendor": "CrowdStrike Falcon Sandbox", 
        "Indicator": "59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355", 
        "Score": 3, 
        "Type": "hash"
    }, 
    "File": [
        {
            "compromised_hosts": [], 
            "vxfamily": "Trojan.Generic", 
            "environmentId": 100, 
            "JobID": "5ae5ae527ca3e1156459b9f3", 
            "classification_tags": [], 
            "total_processes": 1, 
            "SHA256": "59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355", 
            "size": 38400, 
            "submitname": "Keygen.exe", 
            "threat_level": 2, 
            "target_url": null, 
            "error_type": null, 
            "state": "SUCCESS", 
            "mitre_attcks": [], 
            "certificates": [], 
            "verdict": "malicious", 
            "sha512": "d771eb56097a771b9faab47b3d32007a8a5c2c06c3fa2c590d48d7000bf120f69d41340490d61564cab7f2e9135e3f9465a62b69f8e922602f946cff4a76fc13", 
            "extracted_files": [], 
            "isurlanalysis": false, 
            "environmentDescription": "Windows 7 32 bit", 
            "SHA1": "f0fe4ae74cfb7be57c99551b75f00d66915e6900", 
            "hash": "59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355", 
            "analysis_start_time": "2018-04-29T13:42:28+00:00", 
            "tags": [], 
            "imphash": "610be5e05d19476fe9370d6dd1347f2a", 
            "total_network_connections": 0, 
            "av_detect": 48, 
            "threatscore": 100, 
            "total_signatures": 18, 
            "error_origin": null, 
            "ssdeep": "768:IXD4nBg7xSUrIzAx9BNVk3aEKmICkm2oxAlGrPbKjol0qcDg2p9LjLJvN:I6W8yIzAx9r+UkzaG6Y0qcz9nVvN", 
            "MD5": "6ba83f1bf6617dab7990c495cd67dcf6", 
            "processes": [], 
            "type": "PE32 executable (GUI) Intel 80386, for MS Windows, UPX compressed", 
            "file_metadata": null, 
            "hosts": [], 
            "isinteresting": false, 
            "domains": [], 
            "type_short": [
                "peexe", 
                "executable"
            ]
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="scan-results">Scan Results:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Analysis start time</th>
<th>AvDetect</th>
<th>Certificates</th>
<th>Classification tags</th>
<th>CompromisedHosts</th>
<th>Domains</th>
<th>EnvironmentDescription</th>
<th>EnvironmentId</th>
<th>ErrorOrigin</th>
<th>ErrorType</th>
<th>ExtractedFiles</th>
<th>FileMetadata</th>
<th>Hosts</th>
<th>Imphash</th>
<th>Interesting</th>
<th>JobId</th>
<th>Md5</th>
<th>MitreAttcks</th>
<th>Processes</th>
<th>Sha1</th>
<th>Sha256</th>
<th>Sha512</th>
<th>Size</th>
<th>Ssdeep</th>
<th>State</th>
<th>SubmitName</th>
<th>Tags</th>
<th>TargetUrl</th>
<th>ThreatLevel</th>
<th>ThreatScore</th>
<th>Total network connections</th>
<th>Total processes</th>
<th>Total signatures</th>
<th>Type</th>
<th>TypeShort</th>
<th>UrlAnalysis</th>
<th>Verdict</th>
<th>VxFamily</th>
</tr>
</thead>
<tbody>
<tr>
<td>2018-04-29T13:42:28+00:00</td>
<td>48</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>Windows 7 32 bit</td>
<td>100</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>610be5e05d19476fe9370d6dd1347f2a</td>
<td>false</td>
<td>5ae5ae527ca3e1156459b9f3</td>
<td>6ba83f1bf6617dab7990c495cd67dcf6</td>
<td> </td>
<td> </td>
<td>f0fe4ae74cfb7be57c99551b75f00d66915e6900</td>
<td>59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355</td>
<td>d771eb56097a771b9faab47b3d32007a8a5c2c06c3fa2c590d48d7000bf120f69d41340490d61564cab7f2e9135e3f9465a62b69f8e922602f946cff4a76fc13</td>
<td>38400</td>
<td>768:IXD4nBg7xSUrIzAx9BNVk3aEKmICkm2oxAlGrPbKjol0qcDg2p9LjLJvN:I6W8yIzAx9r+UkzaG6Y0qcz9nVvN</td>
<td>SUCCESS</td>
<td>Keygen.exe</td>
<td> </td>
<td> </td>
<td>2</td>
<td>100</td>
<td>0</td>
<td>1</td>
<td>18</td>
<td>PE32 executable (GUI) Intel 80386, for MS Windows, UPX compressed</td>
<td>peexe,executable</td>
<td>false</td>
<td>malicious</td>
<td>Trojan.Generic</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="deprecated-get-a-list-of-all-environments">3. (Deprecated) Get a list of all environments</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all available environments. Deprecated, use the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command instead.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vx-get-environments</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 292px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 364px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 292px;">VX.Environment.ID</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">Environment ID.</td>
</tr>
<tr>
<td style="width: 292px;">VX.Environment.description</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">The environment description.</td>
</tr>
<tr>
<td style="width: 292px;">VX.Environment.architecture</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">Environment architecture.</td>
</tr>
<tr>
<td style="width: 292px;">VX.Environment.VMs_total</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">Total virtual machines in the environment.</td>
</tr>
<tr>
<td style="width: 292px;">VX.Environment.VMs_busy</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">Busy virtual machines in the environment.</td>
</tr>
<tr>
<td style="width: 292px;">VX.Environment.analysisMode</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">Analysis mode of environment.</td>
</tr>
<tr>
<td style="width: 292px;">VX.Environment.groupicon</td>
<td style="width: 84px;">unknown</td>
<td style="width: 364px;">Icon of environment.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-environments">4. Get a list of all environments</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all available environments.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-get-environments</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 368px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.ID</td>
<td style="width: 68px;">number</td>
<td style="width: 368px;">The environment ID.</td>
</tr>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.description</td>
<td style="width: 68px;">string</td>
<td style="width: 368px;">The environment description.</td>
</tr>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.architecture</td>
<td style="width: 68px;">string</td>
<td style="width: 368px;">The environment architecture.</td>
</tr>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.VMs_total</td>
<td style="width: 68px;">number</td>
<td style="width: 368px;">The total virtual machines in the environment.</td>
</tr>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.VMs_busy</td>
<td style="width: 68px;">number</td>
<td style="width: 368px;">The busy virtual machines in the environment.</td>
</tr>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.analysisMode</td>
<td style="width: 68px;">string</td>
<td style="width: 368px;">The analysis mode of the environment.</td>
</tr>
<tr>
<td style="width: 304px;">CrowdStrike.Environment.groupicon</td>
<td style="width: 68px;">string</td>
<td style="width: 368px;">The icon of the environment.</td>
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
<pre>crowdstrike-get-environments</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "VX.Environment": [
        {
            "VMs_total": 78, 
            "description": "Windows 7 32 bit", 
            "VMs_invalid": 3, 
            "groupicon": "windows", 
            "architecture": "WINDOWS", 
            "ID": 100, 
            "VMs_busy": 3, 
            "analysisMode": "KERNELMODE"
        }, 
        {
            "VMs_total": 77, 
            "description": "Windows 7 32 bit (HWP Support)", 
            "VMs_invalid": 3, 
            "groupicon": "windows", 
            "architecture": "WINDOWS", 
            "ID": 110, 
            "VMs_busy": 3, 
            "analysisMode": "KERNELMODE"
        }, 
        {
            "VMs_total": 86, 
            "description": "Windows 7 64 bit", 
            "VMs_invalid": 0, 
            "groupicon": "windows", 
            "architecture": "WINDOWS", 
            "ID": 120, 
            "VMs_busy": 4, 
            "analysisMode": "KERNELMODE"
        }, 
        {
            "VMs_total": 18, 
            "description": "Linux (Ubuntu 16.04, 64 bit)", 
            "VMs_invalid": 0, 
            "groupicon": "linux", 
            "architecture": "WINDOWS", 
            "ID": 300, 
            "VMs_busy": 0, 
            "analysisMode": "USERMODE"
        }, 
        {
            "VMs_total": 0, 
            "description": "Android Static Analysis", 
            "VMs_invalid": 0, 
            "groupicon": "android", 
            "architecture": "ANDROID", 
            "ID": 200, 
            "VMs_busy": 0, 
            "analysisMode": "USERMODE"
        }
    ], 
    "CrowdStrike.Environment": [
        {
            "VMs_total": 78, 
            "description": "Windows 7 32 bit", 
            "VMs_invalid": 3, 
            "groupicon": "windows", 
            "architecture": "WINDOWS", 
            "ID": 100, 
            "VMs_busy": 3, 
            "analysisMode": "KERNELMODE"
        }, 
        {
            "VMs_total": 77, 
            "description": "Windows 7 32 bit (HWP Support)", 
            "VMs_invalid": 3, 
            "groupicon": "windows", 
            "architecture": "WINDOWS", 
            "ID": 110, 
            "VMs_busy": 3, 
            "analysisMode": "KERNELMODE"
        }, 
        {
            "VMs_total": 86, 
            "description": "Windows 7 64 bit", 
            "VMs_invalid": 0, 
            "groupicon": "windows", 
            "architecture": "WINDOWS", 
            "ID": 120, 
            "VMs_busy": 4, 
            "analysisMode": "KERNELMODE"
        }, 
        {
            "VMs_total": 18, 
            "description": "Linux (Ubuntu 16.04, 64 bit)", 
            "VMs_invalid": 0, 
            "groupicon": "linux", 
            "architecture": "WINDOWS", 
            "ID": 300, 
            "VMs_busy": 0, 
            "analysisMode": "USERMODE"
        }, 
        {
            "VMs_total": 0, 
            "description": "Android Static Analysis", 
            "VMs_invalid": 0, 
            "groupicon": "android", 
            "architecture": "ANDROID", 
            "ID": 200, 
            "VMs_busy": 0, 
            "analysisMode": "USERMODE"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-environments">All Environments:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>_ID</th>
<th>Description</th>
<th>Architecture</th>
<th>Total VMS</th>
<th>Busy VMS</th>
<th>Analysis mode</th>
<th>Group icon</th>
</tr>
</thead>
<tbody>
<tr>
<td>100</td>
<td>Windows 7 32 bit</td>
<td>WINDOWS</td>
<td>78</td>
<td>3</td>
<td>KERNELMODE</td>
<td>windows</td>
</tr>
<tr>
<td>110</td>
<td>Windows 7 32 bit (HWP Support)</td>
<td>WINDOWS</td>
<td>77</td>
<td>3</td>
<td>KERNELMODE</td>
<td>windows</td>
</tr>
<tr>
<td>120</td>
<td>Windows 7 64 bit</td>
<td>WINDOWS</td>
<td>86</td>
<td>4</td>
<td>KERNELMODE</td>
<td>windows</td>
</tr>
<tr>
<td>300</td>
<td>Linux (Ubuntu 16.04, 64 bit)</td>
<td>WINDOWS</td>
<td>18</td>
<td>0</td>
<td>USERMODE</td>
<td>linux</td>
</tr>
<tr>
<td>200</td>
<td>Android Static Analysis</td>
<td>ANDROID</td>
<td>0</td>
<td>0</td>
<td>USERMODE</td>
<td>android</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="deprecated-submit-a-file-sample-for-analysis">5. (Deprecated) Submit a file sample for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Submits a file from the investigation for analysis. Deprecated, use the <a href="#submit-a-file-sample-for-analysis" target="_self"><code>crowdstrike-submit-sample</code></a> command instead.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vx-submit-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 535px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">entryId</td>
<td style="width: 535px;">The War Room entry ID of the sample file.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 134px;">environmentId</td>
<td style="width: 535px;">The ID of the environment to submit the file to. To get all IDs, run the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command.</td>
<td style="width: 71px;">Optional</td>
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
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h3 id="submit-a-file-sample-for-analysis">6. Submit a file sample for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Submits a file from the investigation for analysis.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-submit-sample</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">entryId</td>
<td style="width: 518px;">The War Room entry ID of the sample file.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">environmentID</td>
<td style="width: 518px;">The ID of the environment to submit the file to. To get all IDs, run the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command.</td>
<td style="width: 71px;">Required</td>
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
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 285px;"><strong>Path</strong></th>
<th style="width: 89px;"><strong>Type</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 285px;">File.SHA256</td>
<td style="width: 89px;">string</td>
<td style="width: 366px;">The SHA-256 hash of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.MD5</td>
<td style="width: 89px;">string</td>
<td style="width: 366px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 285px;">File.SHA1</td>
<td style="width: 89px;">string</td>
<td style="width: 366px;">The SHA-1 hash of the file.</td>
</tr>
<tr>
<td style="width: 285px;">CrowdStrike.JobID</td>
<td style="width: 89px;">string</td>
<td style="width: 366px;">The job ID of the sample.</td>
</tr>
<tr>
<td style="width: 285px;">CrowdStrike.EnvironmentID</td>
<td style="width: 89px;">number</td>
<td style="width: 366px;">The environment ID of the sample.</td>
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
<pre>crowdstrike-submit-sample entryId=1043@2</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "CrowdStrike": {
        "EnvironmentID": 100, 
        "JobID": "5c98a5860388384f701662c1"
    }, 
    "File": {
        "SHA256": "955017fdfeb29962d42f2273c4c9535a0da5bd4b4a430b7c9f7ad03e5a42b7a0"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>File submitted successfully<br> SHA256 - 955017fdfeb29962d42f2273c4c9535a0da5bd4b4a430b7c9f7ad03e5a42b7a0<br> Job ID - 5c98a5860388384f701662c1<br> Environment ID - 100</p>
</div>
<div class="cl-preview-section">
<h3 id="deprecated-query-the-database">7. (Deprecated) Query the database</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Searches the database using Falcon Sandbox search syntax. Deprecated, use the <a href="#query-the-database" target="_self"><code>crowdstrike-search</code></a> command instead.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vx-search</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">query</td>
<td style="width: 526px;">Falcon Sandbox query syntax (see <code>&lt;server url&gt;/faq#advanced-search-options</code>for more details). examples - url:google, host:95.181.53.78</td>
<td style="width: 71px;">Required</td>
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
<table style="width: 750px;">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>VX.Search.SHA256</td>
<td>unknown</td>
<td>The SHA-256 hash of the search result.</td>
</tr>
<tr>
<td>VX.Search.SHA1</td>
<td>unknown</td>
<td>The SHA-1 hash of the search result.</td>
</tr>
<tr>
<td>VX.Search.MD5</td>
<td>unknown</td>
<td>The MD5 hash of the search result.</td>
</tr>
<tr>
<td>VX.Search.environmentId</td>
<td>unknown</td>
<td>The environment ID of the search result.</td>
</tr>
<tr>
<td>VX.Search.start_time</td>
<td>unknown</td>
<td>The start time of the search result.</td>
</tr>
<tr>
<td>VX.Search.threatscore</td>
<td>unknown</td>
<td>The threat score of the search result (by server).</td>
</tr>
<tr>
<td>VX.Search.verdict</td>
<td>unknown</td>
<td>Verdict of search result</td>
</tr>
<tr>
<td>VX.Search.environmentDescription</td>
<td>unknown</td>
<td>The environment description of the search result.</td>
</tr>
<tr>
<td>VX.Search.submitname</td>
<td>unknown</td>
<td>The submission name of the search result.</td>
</tr>
<tr>
<td>VX.Search.vxfamily</td>
<td>unknown</td>
<td>The family of the search result</td>
</tr>
<tr>
<td>VX.Search.threatscore</td>
<td>unknown</td>
<td>The threat score of the search result.</td>
</tr>
<tr>
<td>VX.Search.type_short</td>
<td>unknown</td>
<td>The type of search result, for example: url or host.</td>
</tr>
<tr>
<td>VX.Search.size</td>
<td>unknown</td>
<td>The size of the search result.</td>
</tr>
<tr>
<td>File.Malicious.Vendor</td>
<td>unknown</td>
<td>For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td>File.Malicious.Description</td>
<td>unknown</td>
<td>For malicious files, the reason that the vendor made the decision.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="query-the-database">8. Query the database</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Searches the database using Falcon Sandbox search syntax.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-search</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 536px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">query</td>
<td style="width: 536px;">Falcon Sandbox query syntax, for example: url:google,host:95.181.53.78. This argument integrates all other arguments to one, and cannot be passed with the other arguments.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">filename</td>
<td style="width: 536px;">Filename, for example: invoice.exe</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">filetype</td>
<td style="width: 536px;">Filetype, for example: docx</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">filetype_desc</td>
<td style="width: 536px;">Filetype description, for example: PE32 executable</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">env_id</td>
<td style="width: 536px;">Environment ID</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">country</td>
<td style="width: 536px;">Country (3 digit ISO), for example: swe, usa, fra</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">verdict</td>
<td style="width: 536px;">Verdict</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">av_detect</td>
<td style="width: 536px;">AV Multiscan range, for example: 50-70 (min 0, max 100)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">vx_family</td>
<td style="width: 536px;">AV Family Substring, for example: nemucod</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">tag</td>
<td style="width: 536px;">Hashtag, for example: ransomware</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">port</td>
<td style="width: 536px;">Port, for example: 8080</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">host</td>
<td style="width: 536px;">Host, for example: 192.168.0.1</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">domain</td>
<td style="width: 536px;">Domain, for example: checkip.dyndns.org</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">url</td>
<td style="width: 536px;">HTTP Request Substring, for example: google</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">similar_to</td>
<td style="width: 536px;">Similar Samples</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">context</td>
<td style="width: 536px;">Sample Context</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">imp_hash</td>
<td style="width: 536px;">Import Hash</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">ssdeep</td>
<td style="width: 536px;">SSDeep</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">authentihash</td>
<td style="width: 536px;">Authentication Hash</td>
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
<th style="width: 207px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 474px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 207px;">File.SHA256</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The SHA-256 hash of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.SHA1</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The SHA-1 of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.MD5</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The MD5 hash of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.environmentId</td>
<td style="width: 59px;">number</td>
<td style="width: 474px;">The environment ID of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.start_time</td>
<td style="width: 59px;">unknown</td>
<td style="width: 474px;">The start time of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.threatscore</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The threat score of the search result (by server).</td>
</tr>
<tr>
<td style="width: 207px;">File.verdict</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The verdict of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.environmentDescription</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The environment description of search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.submitname</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The submission name of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.vxfamily</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The family of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.threatscore</td>
<td style="width: 59px;">number</td>
<td style="width: 474px;">The threat score of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.type_short</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">The type of search result, for example: url or host.</td>
</tr>
<tr>
<td style="width: 207px;">File.size</td>
<td style="width: 59px;">number</td>
<td style="width: 474px;">The size of the search result.</td>
</tr>
<tr>
<td style="width: 207px;">File.Malicious.Vendor</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 207px;">File.Malicious.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 474px;">For malicious files, the reason that the vendor made the decision.</td>
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
<pre>crowdstrike-search filetype=.docx</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "VX.Search": [], 
    "File": []
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>No data returned</p>
</div>
<div class="cl-preview-section">
<h3 id="deprecated-get-result-data-for-a-file">9. (Deprecated) Get result data for a file</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves result data for a file. This command returns a file. Deprecated, use the <code>crowdstrike-result</code> command instead.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vx-result</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">file</td>
<td style="width: 520px;">File hash (MD5, SHA-1, or SHA-256).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">environmentId</td>
<td style="width: 520px;">The ID of the environment to submit the file to. To get all IDs, run the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h3 id="get-result-data-for-a-file">10. Get result data for a file</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves result data for a file. This command returns a file.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-result</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
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
<td style="width: 143px;">file</td>
<td style="width: 526px;">File hash (MD5, SHA-1, or SHA-256). Madatory in v1.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">environmentId</td>
<td style="width: 526px;">The environment ID to submit file to. To get all environments, run the <a href="#get-a-list-of-all-environments" target="_self">crowdstrike-get-environments</a> command. Mandatory in v1.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">file-type</td>
<td style="width: 526px;">File type of report to return (supported only in v2).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">JobID</td>
<td style="width: 526px;">Job ID of file to generate report of (supported only in v2).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 230px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">DBotScore.Indicator</td>
<td style="width: 78px;">string</td>
<td style="width: 432px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 230px;">DBotScore.Type</td>
<td style="width: 78px;">string</td>
<td style="width: 432px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 230px;">DBotScore.Vendor</td>
<td style="width: 78px;">string</td>
<td style="width: 432px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 230px;">DBotScore.Score</td>
<td style="width: 78px;">number</td>
<td style="width: 432px;">The actual score.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>crowdstrike-result file=59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355</pre>
</div>
<div class="cl-preview-section">
<h3 id="deprecated-detonate-a-file">11. (Deprecated) Detonate a file</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Detonates file using Falcon Sandbox.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>vx-detonate-file</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">entryId</td>
<td style="width: 534px;">The War Room entry ID of the sample file.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">environmentID</td>
<td style="width: 534px;">The ID of the environment to submit the file to. To get all IDs, run the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command. Default is 100, or other WINDOWS ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">delay</td>
<td style="width: 534px;">The delay wait time between calls (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">timeout</td>
<td style="width: 534px;">The total wait time (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h3 id="deprecated-detonate-a-file-1">12. (Deprecated) Detonate a file</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Detonates a file using Falcon Sandbox.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-detonate-file</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">entryId</td>
<td style="width: 523px;">The War Room entry ID of the sample file.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">environmentID</td>
<td style="width: 523px;">The ID of the environment to submit the file to. To get all IDs, run the <code>crowdstrike-get-environments</code> command. Default is 100, or other WINDOWS ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">delay</td>
<td style="width: 523px;">The delay wait time between calls (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">timeout</td>
<td style="width: 523px;">The total wait time (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 228px;"><strong>Path</strong></th>
<th style="width: 55px;"><strong>Type</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 228px;">File.SHA256</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The SHA-256 hash of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.SHA1</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The SHA-1 hash of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.MD5</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.environmentId</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The environment ID of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.analysis_start_time</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The analysis start time of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.submitname</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The submission name of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.classification_tags</td>
<td style="width: 55px;">unknown</td>
<td style="width: 457px;">A list of classification tags of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.vxfamily</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The family classification of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.total_network_connections</td>
<td style="width: 55px;">number</td>
<td style="width: 457px;">The total network connections of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.total_processes</td>
<td style="width: 55px;">number</td>
<td style="width: 457px;">The total processes count of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.total_signatures</td>
<td style="width: 55px;">number</td>
<td style="width: 457px;">The total signatures count of the file.</td>
</tr>
<tr>
<td style="width: 228px;">File.hosts</td>
<td style="width: 55px;">unknown</td>
<td style="width: 457px;">A list of file’s hosts.</td>
</tr>
<tr>
<td style="width: 228px;">File.isinteresting</td>
<td style="width: 55px;">boolean</td>
<td style="width: 457px;">Whether the server found this file interesting.</td>
</tr>
<tr>
<td style="width: 228px;">File.domains</td>
<td style="width: 55px;">unknown</td>
<td style="width: 457px;">A list of the file’s related domains.</td>
</tr>
<tr>
<td style="width: 228px;">File.isurlanalysis</td>
<td style="width: 55px;">boolean</td>
<td style="width: 457px;">Whether the file was analyzed by URL.</td>
</tr>
<tr>
<td style="width: 228px;">File.Malicious.Vendor</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 228px;">File.Malicious.Description</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">For malicious files, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 228px;">DBotScore.Indicator</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 228px;">DBotScore.Type</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 228px;">DBotScore.Vendor</td>
<td style="width: 55px;">string</td>
<td style="width: 457px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 228px;">DBotScore.Score</td>
<td style="width: 55px;">number</td>
<td style="width: 457px;">The actual score.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="submit-a-url-for-analysis">13. Submit a URL for analysis</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Submits a URL for analysis. This command is only supported in v2.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-submit-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 472px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">url</td>
<td style="width: 472px;">The URL to analyze.</td>
<td style="width: 98px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">environmentID</td>
<td style="width: 472px;">The ID of the environment to submit the URL to.</td>
<td style="width: 98px;">Required</td>
</tr>
<td style="width: 170px;">dontThrowErrorOnFileDetonation</td>
<td style="width: 472px;">Determine if the command will throw an error on an unsupported file error. Default is false.</td>
<td style="width: 98px;"></td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 220px;"><strong>Path</strong></th>
<th style="width: 50px;"><strong>Type</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">File.SHA256</td>
<td style="width: 50px;">string</td>
<td style="width: 470px;">The SHA-256 hash of the file.</td>
</tr>
<tr>
<td style="width: 220px;">CrowdStrike.EnvironmentID</td>
<td style="width: 50px;">string</td>
<td style="width: 470px;">The ID of the environment in which the URL was analyzed.</td>
</tr>
<tr>
<td style="width: 220px;">CrowdStrike.JobID</td>
<td style="width: 50px;">string</td>
<td style="width: 470px;">The job ID of the URL analysis.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>crowdstrike-submit-url url=www.google.com environmentID=100</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "CrowdStrike": {
        "EnvironmentID": 100, 
        "JobID": "58c1c211aac2eda9503bc31f"
    }, 
    "File": {
        "SHA256": "d2edef8e43054be586d17ddcc761e7a1f4a6946c39e653d7e095a826ef34b6a1", 
        "hash": "d2edef8e43054be586d17ddcc761e7a1f4a6946c39e653d7e095a826ef34b6a1"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="url-www.google.com-was-submitted-for-analysis-on-crowdstrike-falcon-sandbox">URL <a href="http://www.google.com/">www.google.com</a> was submitted for analysis on CrowdStrike Falcon Sandbox</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>EnvironmentId</th>
<th>JobId</th>
<th>Sha256</th>
</tr>
</thead>
<tbody>
<tr>
<td>100</td>
<td>58c1c211aac2eda9503bc31f</td>
<td>d2edef8e43054be586d17ddcc761e7a1f4a6946c39e653d7e095a826ef34b6a1</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-screenshots-from-a-report">14. Get screenshots from a report</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves screenshots from a report. This command is only supported in v2.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-13">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-get-screenshots</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-13">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 167px;"><strong>Argument Name</strong></th>
<th style="width: 485px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">file</td>
<td style="width: 485px;">The SHA-2556 hash of the file to retrieve screenshots of.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">environmentID</td>
<td style="width: 485px;">The ID of the environment to retrieve screenshots from.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">JobID</td>
<td style="width: 485px;">The job ID to retrieve screenshots from.</td>
<td style="width: 88px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-13">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 201px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">File.SHA256</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The SHA-256 hash of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.SHA1</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The SHA-1 hash of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.MD5</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The MD5 hash of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.environmentId</td>
<td style="width: 70px;">number</td>
<td style="width: 469px;">The ID of the search result environment.</td>
</tr>
<tr>
<td style="width: 201px;">File.start_time</td>
<td style="width: 70px;">unknown</td>
<td style="width: 469px;">The start time of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.threatscore</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The threat score of the search result (by server).</td>
</tr>
<tr>
<td style="width: 201px;">File.verdict</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The verdict of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.environmentDescription</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The description of the search result environment.</td>
</tr>
<tr>
<td style="width: 201px;">File.submitname</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The submission name of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.vxfamily</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The family of search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.threatscore</td>
<td style="width: 70px;">number</td>
<td style="width: 469px;">The threat score of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.type_short</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">The type of search result, for example: url or host.</td>
</tr>
<tr>
<td style="width: 201px;">File.size</td>
<td style="width: 70px;">number</td>
<td style="width: 469px;">Size of the search result.</td>
</tr>
<tr>
<td style="width: 201px;">File.Malicious.Vendor</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 201px;">File.Malicious.Description</td>
<td style="width: 70px;">string</td>
<td style="width: 469px;">For malicious files, the reason that the vendor made the decision.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>crowdstrike-get-screenshots file=59e17f98cef7dd1bf4fb791eb1dcd0cea6dd870b6e36af7c37bd732c84d43355</pre>
</div>
<div class="cl-preview-section">
<h3 id="deprecated-detonate-a-url">15. (Deprecated) Detonate a URL</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Detonates a URL address using Falcon Sandbox. This command is only supported in v2.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-14">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-detonate-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-14">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">url</td>
<td style="width: 532px;">The URL address to be submitted.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">environmentID</td>
<td style="width: 532px;">The ID of the environment to submit the URL to. To get all IDs, run the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command. Default is 100, or other WINDOWS ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">delay</td>
<td style="width: 532px;">Delay wait time between calls (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">timeout</td>
<td style="width: 532px;">Total wait time (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">file-type</td>
<td style="width: 532px;">The report file type.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-14">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 226px;"><strong>Path</strong></th>
<th style="width: 82px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">DBotScore.Indicator</td>
<td style="width: 82px;">string</td>
<td style="width: 432px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Type</td>
<td style="width: 82px;">string</td>
<td style="width: 432px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Vendor</td>
<td style="width: 82px;">string</td>
<td style="width: 432px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Score</td>
<td style="width: 82px;">number</td>
<td style="width: 432px;">The actual score.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="submit-a-file-for-analysis-by-url">16. Submit a file for analysis (by URL)</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Submit a file for analysis (by URL). This command is only supported only in v2.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-15">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>crowdstrike-submit-file-by-url</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-15">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 525px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">environmentID</td>
<td style="width: 525px;">The ID of the environment to submit the file to. To get all IDs, run the <a href="#get-a-list-of-all-environments" target="_self"><code>crowdstrike-get-environments</code></a> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">url</td>
<td style="width: 525px;">The URL of the file to submit.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-15">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 220px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 467px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">File.SHA256</td>
<td style="width: 53px;">string</td>
<td style="width: 467px;">The SHA-256 hash of the file.</td>
</tr>
<tr>
<td style="width: 220px;">CrowdStrike.EnvironmentID</td>
<td style="width: 53px;">string</td>
<td style="width: 467px;">The ID of the environment in which the file was analyzed.</td>
</tr>
<tr>
<td style="width: 220px;">CrowdStrike.JobID</td>
<td style="width: 53px;">string</td>
<td style="width: 467px;">The job ID of the file analysis.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>crowdstrike-submit-file-by-url url=https://swagger.io/swagger/media/blog/wp-content/uploads/2017/06/Whitepaper_APIDocumentationDX.pdf</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "CrowdStrike": {
        "EnvironmentID": 100, 
        "JobID": "5c98a51e028838377b1662c0"
    }, 
    "File": {
        "SHA256": "f317cc246bc0fe55db49a8eb40acab49d9689f3ea764d19abbc464008f01b6d1"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="file-httpsswagger.ioswaggermediablogwp-contentuploads201706whitepaper_apidocumentationdx.pdf-was-submitted-for-analysis-on-crowdstrike-falcon-sandbox">File <a href="https://swagger.io/swagger/media/blog/wp-content/uploads/2017/06/Whitepaper_APIDocumentationDX.pdf">https://swagger.io/swagger/media/blog/wp-content/uploads/2017/06/Whitepaper_APIDocumentationDX.pdf</a> was submitted for analysis on CrowdStrike Falcon Sandbox</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>EnvironmentId</th>
<th>JobId</th>
<th>Sha256</th>
</tr>
</thead>
<tbody>
<tr>
<td>100</td>
<td>5c98a51e028838377b1662c0</td>
<td>f317cc246bc0fe55db49a8eb40acab49d9689f3ea764d19abbc464008f01b6d1</td>
</tr>
</tbody>
</table>
</div>
</div>
