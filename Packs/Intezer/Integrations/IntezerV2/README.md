<!-- HTML_DOC -->
<p><span>Use the Intezer v2 integration to detect and analyze malware, based on code reuse.</span></p>
<h2>Configure Intezer v2 on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Intezer v2.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>API Key</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2> </h2>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_6feb063f-66b1-45e5-89f0-1b6ff5142114" target="_self">Check file reputation by hash: intezer-analyze-by-hash</a></li>
<li><a href="#h_9127d647-9bbd-43c7-b567-812e4138e652" target="_self"> Check file reputation by uploading a file: intezer-analyze-by-file </a></li>
<li><a href="#h_89b3941d-6b65-4083-96b6-f67d0c2cb528" target="_self"> Check analysis status and results: intezer-get-analysis-result </a></li>
</ol>
<h3 id="h_6feb063f-66b1-45e5-89f0-1b6ff5142114">1. Check file reputation by hash</h3>
<hr>
<p>Checks file reputation of the given hash, supports SHA256, SHA1, and MD5.</p>
<h5>Base Command</h5>
<p><code>intezer-analyze-by-hash</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 84px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">file_hash</td>
<td style="width: 502px;">Hash of the file to query. Supports SHA256, MD5, and SHA1.</td>
<td style="width: 84px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 82px;"><strong>Type</strong></th>
<th style="width: 325px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">Intezer.Analysis.ID</td>
<td style="width: 82px;">string</td>
<td style="width: 325px;">Intezer analysis ID.</td>
</tr>
<tr>
<td style="width: 333px;">Intezer.Analysis.Status</td>
<td style="width: 82px;">string</td>
<td style="width: 325px;">Status of the analysis.</td>
</tr>
<tr>
<td style="width: 333px;">Intezer.Analysis.Type</td>
<td style="width: 82px;">string</td>
<td style="width: 325px;">Analysis type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>intezer-analyze-by-hash file_hash="8cbf90aeab2c93b2819fcfd6262b2cdb"</pre>
<h5>Context Example</h5>
<pre>{
    "Intezer.Analysis": {
        "Status": "Created", 
        "type": "File", 
        "ID": "59e2f081-45f3-4822-bf45-407670dcb4d7"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>Analysis created successfully</p>
<h3 id="h_9127d647-9bbd-43c7-b567-812e4138e652">2. Check the reputation of a file</h3>
<hr>
<p>Checks file reputation for an uploaded file. Maximum file size is 32 MB.</p>
<h5>Base Command</h5>
<p><code>intezer-analyze-by-file</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 222px;"><strong>Argument Name</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
<th style="width: 122px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 222px;">file_entry_id</td>
<td style="width: 396px;">The entry ID of the file to upload.</td>
<td style="width: 122px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 331px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 325px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 331px;">Intezer.Analysis.ID</td>
<td style="width: 84px;">string</td>
<td style="width: 325px;">Intezer analysis ID.</td>
</tr>
<tr>
<td style="width: 331px;">Intezer.Analysis.Status</td>
<td style="width: 84px;">string</td>
<td style="width: 325px;">Status of the analysis.</td>
</tr>
<tr>
<td style="width: 331px;">Intezer.Analysis.Type</td>
<td style="width: 84px;">string</td>
<td style="width: 325px;">Analysis type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>intezer-analyze-by-file file_entry_id=1188@6</pre>
<h5>Context Example</h5>
<pre>{
    "Intezer.Analysis": {
        "Status": "Created", 
        "type": "File", 
        "ID": "675515a1-62e9-4d55-880c-fd46a7963a56"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>Analysis created successfully</p>
<h3 id="h_89b3941d-6b65-4083-96b6-f67d0c2cb528">3. Check analysis status and results</h3>
<hr>
<p>Checks the analysis status and gets the analysis result, supports file and endpoint analysis.</p>
<h5>Base Command</h5>
<p><code>intezer-get-analysis-result</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 200px;"><strong>Argument Name</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
<th style="width: 110px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 200px;">analysis_id</td>
<td style="width: 430px;">The analysis ID for which to get results.</td>
<td style="width: 110px;">Optional</td>
</tr>
<tr>
<td style="width: 200px;">analysis_type</td>
<td style="width: 430px;">The type of analysis.</td>
<td style="width: 110px;">Optional</td>
</tr>
<tr>
<td style="width: 200px;">indicator_name</td>
<td style="width: 430px;">Indicator to classify.</td>
<td style="width: 110px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">File.SHA256</td>
<td style="width: 63px;">string</td>
<td style="width: 526px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 151px;">File.Malicious.Vendor</td>
<td style="width: 63px;">string</td>
<td style="width: 526px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 151px;">DBotScore.Indicator</td>
<td style="width: 63px;">string</td>
<td style="width: 526px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 151px;">DBotScore.Type</td>
<td style="width: 63px;">string</td>
<td style="width: 526px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 151px;">DBotScore.Vendor</td>
<td style="width: 63px;">string</td>
<td style="width: 526px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 151px;">DBotScore.Score</td>
<td style="width: 63px;">number</td>
<td style="width: 526px;">The actual score.</td>
</tr>
<tr>
<td style="width: 151px;">File.Metadata</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 526px;">Metadata returned from Intezer analysis (analysis id, analysis url, family, family type, sha256, verdict, sub_verdict). Metedata will only be returned for supported files.</td>
</tr>
<tr>
<td style="width: 151px;">Endpoint.Metadata</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 526px;">Metadata returned from Intezer analysis (endpoint analysis id, endpoint analysis url, families, verdict, host_name).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>intezer-get-analysis-result analysis_id="9e3acdc3-b7ea-412b-88ae-7103eebc9398"</pre>
<h5>Context Example</h5>
<pre>{
    "DBotScore": {
        "Vendor": "Intezer", 
        "Indicator": "fa5953e0c34a4bbf69ac31f3a1360024101c1232bb45cccaad3611b682c92387", 
        "Score": 0, 
        "Type": "hash"
    }, 
    "Intezer.Analysis": {
        "Status": "Done", 
        "ID": "9e3acdc3-b7ea-412b-88ae-7103eebc9398"
    }, 
    "File": {
        "ExistsInIntezer": true, 
        "SHA256": "fa5953e0c34a4bbf69ac31f3a1360024101c1232bb45cccaad3611b682c92387", 
        "Metadata": {
            "analysis_id": "9e3acdc3-b7ea-412b-88ae-7103eebc9398", 
            "sub_verdict": "file_type_not_supported", 
            "analysis_url": "https://analyze.intezer.com/#/analyses/9e3acdc3-b7ea-412b-88ae-7103eebc9398", 
            "verdict": "not_supported", 
            "sha256": "fa5953e0c34a4bbf69ac31f3a1360024101c1232bb45cccaad3611b682c92387", 
            "is_private": true, 
            "analysis_time": "Wed, 19 Jun 2019 07:48:12 GMT"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h2>Intezer File analysis result</h2>
<p>SHA256: fa5953e0c34a4bbf69ac31f3a1360024101c1232bb45cccaad3611b682c92387<br> Verdict:<span> </span><strong>not_supported</strong><span> </span>(file_type_not_supported)<br> Analysis Link</p>
<p> </p>