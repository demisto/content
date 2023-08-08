<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Deprecated. No available replacement.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Get reputation of IOCs (observables).</li>
<li>Get observables’ related entities.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="configure-eclecticiq-platform-on-demisto">Configure EclecticIQ Platform on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for integration-EclecticIQ_Platform.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1/">https://192.168.0.1</a>)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>IP threshold. Minimum maliciousness confidence level to consider the IP address malicious: High, Medium, Low, Safe, Unknown</strong></li>
<li><strong>URL threshold. Minimum maliciousness confidence level to consider the URL malicious: High, Medium, Low, Safe, Unknown</strong></li>
<li><strong>File threshold. Minimum maliciousness confidence level to consider the file malicious: High, Medium, Low, Safe, Unknown</strong></li>
<li><strong>Email threshold. Minimum maliciousness confidence level to consider the email address malicious: High, Medium, Low, Safe, Unknown</strong></li>
<li><strong>Domain threshold. Minimum maliciousness confidence level to consider the domain malicious: High, Medium, Low, Safe, Unknown</strong></li>
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
<li><a href="#get-the-reputation-of-an-ip-address-observable">Get the reputation of an IP address observable: ip</a></li>
<li><a href="#get-the-reputation-of-a-url-observable">Get the reputation of a URL observable: url</a></li>
<li><a href="#get-the-reputation-of-a-file-observable">Get the reputation of a file observable: file</a></li>
<li><a href="#get-related-entities-of-an-observable">Get related entities of an observable: eclecticiq-get-observable-related-entity</a></li>
<li><a href="#get-the-reputation-of-an-email-observable-email">Get the reputation of an email observable: email</a></li>
<li><a href="#get-the-reputation-of-a-domain-observable">Get the reputation of a domain observable: domain</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-the-reputation-of-an-ip-address-observable">1. Get the reputation of an IP address observable</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the reputation of an IP address observable.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ip</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 230px;"><strong>Argument Name</strong></th>
<th style="width: 377px;"><strong>Description</strong></th>
<th style="width: 133px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">ip</td>
<td style="width: 377px;">IPv4 to get the reputation of</td>
<td style="width: 133px;">Required</td>
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
<th style="width: 201px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">EclecticIQ.IP.Address</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">IP address that was tested</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.IP.Created</td>
<td style="width: 69px;">Date</td>
<td style="width: 470px;">Observable creation date</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.IP.LastUpdate</td>
<td style="width: 69px;">Date</td>
<td style="width: 470px;">Observable last updated date</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.IP.ID</td>
<td style="width: 69px;">Number</td>
<td style="width: 470px;">Observable ID</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.IP.Maliciousness</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">Maliciousness confidence level</td>
</tr>
<tr>
<td style="width: 201px;">IP.Address</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">IP address that was tested</td>
</tr>
<tr>
<td style="width: 201px;">IP.Malcious.Vendor</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">For malicious IPs, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 201px;">IP.Malcious.Description</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">For malicious IPs, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Type</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">Indicator type</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Vendor</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Score</td>
<td style="width: 69px;">Number</td>
<td style="width: 470px;">The actual score</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Indicator</td>
<td style="width: 69px;">String</td>
<td style="width: 470px;">The indicator that was tested</td>
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
<p><code>ip ip=8.8.8.8</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "IP": [
        {
            "Address": "8.8.8.8"
        }
    ], 
    "DBotScore": {
        "Vendor": "EclecticIQ", 
        "Indicator": "8.8.8.8", 
        "Score": 1, 
        "Type": "ip"
    }, 
    "EclecticIQ.IP": [
        {
            "Maliciousness": "safe", 
            "Created": "2019-01-16T11:55:11.732145+00:00", 
            "ID": 86, 
            "LastUpdated": "2019-01-16T11:55:11.708640+00:00", 
            "Address": "8.8.8.8"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="eclecticiq-ip-reputation---8.8.8.8">EclecticIQ IP reputation - 8.8.8.8</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Maliciousness</th>
<th>Created</th>
<th>ID</th>
<th>LastUpdated</th>
<th>Address</th>
</tr>
</thead>
<tbody>
<tr>
<td>safe</td>
<td>2019-01-16T11:55:11.732145+00:00</td>
<td>86</td>
<td>2019-01-16T11:55:11.708640+00:00</td>
<td>8.8.8.8</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-the-reputation-of-a-url-observable">2. Get the reputation of a URL observable</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the reputation of a URL observable.</p>
<p>Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>url</code></p>
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
<th style="width: 438px;"><strong>Description</strong></th>
<th style="width: 111px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 191px;">url</td>
<td style="width: 438px;">URL observable to get the reputation of</td>
<td style="width: 111px;">Required</td>
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
<th style="width: 199px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 476px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 199px;">EclecticIQ.URL.Data</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">URL that was tested</td>
</tr>
<tr>
<td style="width: 199px;">EclecticIQ.URL.Created</td>
<td style="width: 65px;">Date</td>
<td style="width: 476px;">Observable creation date</td>
</tr>
<tr>
<td style="width: 199px;">EclecticIQ.URL.LastUpdate</td>
<td style="width: 65px;">Date</td>
<td style="width: 476px;">Observable last updated date</td>
</tr>
<tr>
<td style="width: 199px;">EclecticIQ.URL.ID</td>
<td style="width: 65px;">Number</td>
<td style="width: 476px;">Observable ID</td>
</tr>
<tr>
<td style="width: 199px;">EclecticIQ.URL.Maliciousness</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">Maliciousness confidence level</td>
</tr>
<tr>
<td style="width: 199px;">URL.Data</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">URL that was tested</td>
</tr>
<tr>
<td style="width: 199px;">URL.Malcious.Vendor</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">For malicious URLs, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 199px;">URL.Malcious.Description</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">For malicious URLs, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 199px;">DBotScore.Type</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">Indicator type</td>
</tr>
<tr>
<td style="width: 199px;">DBotScore.Vendor</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 199px;">DBotScore.Score</td>
<td style="width: 65px;">Number</td>
<td style="width: 476px;">The actual score</td>
</tr>
<tr>
<td style="width: 199px;">DBotScore.Indicator</td>
<td style="width: 65px;">String</td>
<td style="width: 476px;">The indicator that was tested</td>
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
<p><code>url url=http://chstarkeco.com</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "DBotScore": {
        "Vendor": "OpenPhish", 
        "Indicator": "http://chstarkeco.com", 
        "Score": 0, 
        "Type": "url"
    }
}{
    "URL": {
        "Data": "http://chstarkeco.com"
    }, 
    "DBotScore": {
        "Vendor": "PhishTank", 
        "Indicator": "http://chstarkeco.com", 
        "Score": 0, 
        "Type": "url"
    }
}{
    "URL": [
        {
            "Data": "http://chstarkeco.com"
        }
    ], 
    "DBotScore": {
        "Vendor": "EclecticIQ", 
        "Indicator": "http://chstarkeco.com", 
        "Score": 2, 
        "Type": "url"
    }, 
    "EclecticIQ.URL": [
        {
            "Maliciousness": "medium", 
            "Data": "http://chstarkeco.com", 
            "ID": 83, 
            "LastUpdated": "2019-01-16T11:53:51.128167+00:00", 
            "Created": "2019-01-16T11:52:49.993110+00:00"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="openphish-database---url-query">OpenPhish Database - URL Query</h3>
</div>
<div class="cl-preview-section">
<h4 id="no-matches-for-url-httpchstarkeco.com">No matches for URL <a href="http://chstarkeco.com/">http://chstarkeco.com</a>
</h4>
</div>
<div class="cl-preview-section">
<h3 id="phishtank-database---url-query">PhishTank Database - URL Query</h3>
</div>
<div class="cl-preview-section">
<h4 id="no-matches-for-url-httpchstarkeco.com-1">No matches for URL <a href="http://chstarkeco.com/">http://chstarkeco.com</a>
</h4>
</div>
<div class="cl-preview-section">
<h3 id="eclecticiq-url-reputation---httpchstarkeco.com">EclecticIQ URL reputation - <a href="http://chstarkeco.com/">http://chstarkeco.com</a>
</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Maliciousness</th>
<th>Data</th>
<th>ID</th>
<th>LastUpdated</th>
<th>Created</th>
</tr>
</thead>
<tbody>
<tr>
<td>medium</td>
<td><a href="http://chstarkeco.com/">http://chstarkeco.com</a></td>
<td>83</td>
<td>2019-01-16T11:53:51.128167+00:00</td>
<td>2019-01-16T11:52:49.993110+00:00</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-the-reputation-of-a-file-observable">3. Get the reputation of a file observable</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the reputation of a file hash observable.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>file</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 182px;"><strong>Argument Name</strong></th>
<th style="width: 455px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 182px;">file</td>
<td style="width: 455px;">File hash observable to get the reputation of</td>
<td style="width: 103px;">Required</td>
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
<th style="width: 201px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 476px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">EclecticIQ.File.MD5</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File MD5 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.SHA1</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File SHA-1 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.SHA256</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File SHA-256 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.SHA512</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File SHA-512 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.Created</td>
<td style="width: 63px;">Date</td>
<td style="width: 476px;">Observable creation date</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.LastUpdate</td>
<td style="width: 63px;">Date</td>
<td style="width: 476px;">Observable last updated date</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.ID</td>
<td style="width: 63px;">Number</td>
<td style="width: 476px;">Observable ID</td>
</tr>
<tr>
<td style="width: 201px;">EclecticIQ.File.Maliciousness</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">Maliciousness confidence level</td>
</tr>
<tr>
<td style="width: 201px;">File.MD5</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File MD5 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">File.SHA1</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File SHA-1 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">File.SHA256</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File SHA-256 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">File.SHA512</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">File SHA-512 hash that was tested</td>
</tr>
<tr>
<td style="width: 201px;">File.Malcious.Vendor</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">For malicious files, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 201px;">File.Malcious.Description</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">For malicious files, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Type</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">Indicator type</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Vendor</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Score</td>
<td style="width: 63px;">Number</td>
<td style="width: 476px;">The actual score</td>
</tr>
<tr>
<td style="width: 201px;">DBotScore.Indicator</td>
<td style="width: 63px;">String</td>
<td style="width: 476px;">The indicator that was tested</td>
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
<p><code>file file=00112233445566778899aabbccddeeff</code></p>
</div>
<div class="cl-preview-section">
<h3 id="get-related-entities-of-an-observable">4. Get related entities of an observable</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns related entities of a single observable.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>eclecticiq-get-observable-related-entity</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
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
<td style="width: 137px;">observable_id</td>
<td style="width: 532px;">Observable ID to get entity information for (can be retrieved from one of the IOCs commands)</td>
<td style="width: 71px;">Required</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 278px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Analysis</td>
<td style="width: 71px;">String</td>
<td style="width: 391px;">Entity analysis description</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.EstimatedObservedTime</td>
<td style="width: 71px;">Date</td>
<td style="width: 391px;">Entity estimated observed time</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.EstimatedStartTime</td>
<td style="width: 71px;">Date</td>
<td style="width: 391px;">Entity estimated start time</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Exposure.Community</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 391px;">Is entity in the community feed</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Exposure.Detection</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 391px;">Is entity detected</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Exposure.Exposed</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 391px;">Is entity exposed</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Exposure.Prevention</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 391px;">Is entity in prevented feed</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Exposure.Sighting</td>
<td style="width: 71px;">Boolean</td>
<td style="width: 391px;">Is entity sighted</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.HalfLife</td>
<td style="width: 71px;">String</td>
<td style="width: 391px;">The time it takes an entity to decay in intelligence value, expressed in the number of days until a 50% decay</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.ID</td>
<td style="width: 71px;">String</td>
<td style="width: 391px;">Entity ID</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Source.Name</td>
<td style="width: 71px;">String</td>
<td style="width: 391px;">Entity source name</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Source.Reliability</td>
<td style="width: 71px;">String</td>
<td style="width: 391px;">Entity source reliability</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Title</td>
<td style="width: 71px;">String</td>
<td style="width: 391px;">Entity title</td>
</tr>
<tr>
<td style="width: 278px;">EclecticIQ.Entity.Source.Type</td>
<td style="width: 71px;">string</td>
<td style="width: 391px;">Entity source type</td>
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
<p><code>eclecticiq-get-observable-related-entity observable_id=63</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "EclecticIQ.Entity": [
        {
            "HalfLife": "30 Days", 
            "Title": "Indicator containing malicious file hashes", 
            "EstimatedObservedTime": "2018-11-21T13:34:35.890076+00:00", 
            "Analysis": "Indicator that contains malicious file hashes.", 
            "Source": [
                {
                    "Reliability": null, 
                    "Type": "incoming_feed", 
                    "Name": "TAXII Stand Samples"
                }
            ], 
            "EstimatedStartTime": "2014-05-08T09:00:00+00:00", 
            "ID": "56e218b0-3f6b-4237-beca-3b39ab8e96c2", 
            "Exposure": {
                "Detection": false, 
                "Sighting": false, 
                "Prevention": false, 
                "Community": false, 
                "Exposed": true
            }
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="observable-id-63-related-entities">Observable ID 63 related entities</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>HalfLife</th>
<th>Title</th>
<th>EstimatedObservedTime</th>
<th>Analysis</th>
<th>EstimatedStartTime</th>
<th>ID</th>
</tr>
</thead>
<tbody>
<tr>
<td>30 Days</td>
<td>Indicator containing malicious file hashes</td>
<td>2018-11-21T13:34:35.890076+00:00</td>
<td>Indicator that contains malicious file hashes.</td>
<td>2014-05-08T09:00:00+00:00</td>
<td>56e218b0-3f6b-4237-beca-3b39ab8e96c2</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="sources">Sources</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Type</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>incoming_feed</td>
<td>TAXII Stand Samples</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="exposure">Exposure</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Detection</th>
<th>Sighting</th>
<th>Community</th>
<th>Prevention</th>
<th>Exposed</th>
</tr>
</thead>
<tbody>
<tr>
<td>false</td>
<td>false</td>
<td>false</td>
<td>false</td>
<td>true</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-the-reputation-of-an-email-observable-email">5. Get the reputation of an email observable: email</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the reputation of an email address observable.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>email</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 165px;"><strong>Argument Name</strong></th>
<th style="width: 478px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 165px;">email</td>
<td style="width: 478px;">Email address observable to get the reputation of</td>
<td style="width: 97px;">Required</td>
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
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 240px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 435px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 240px;">EclecticIQ.Email.Address</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">Email that was tested</td>
</tr>
<tr>
<td style="width: 240px;">EclecticIQ.Email.Created</td>
<td style="width: 65px;">Date</td>
<td style="width: 435px;">Observable creation date</td>
</tr>
<tr>
<td style="width: 240px;">EclecticIQ.Email.LastUpdate</td>
<td style="width: 65px;">Date</td>
<td style="width: 435px;">Observable last updated date</td>
</tr>
<tr>
<td style="width: 240px;">EclecticIQ.Email.ID</td>
<td style="width: 65px;">Number</td>
<td style="width: 435px;">Observable ID</td>
</tr>
<tr>
<td style="width: 240px;">EclecticIQ.Email.Maliciousness</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">Maliciousness confidence level</td>
</tr>
<tr>
<td style="width: 240px;">Account.Email.Address</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">Email that was tested</td>
</tr>
<tr>
<td style="width: 240px;">Account.Email.Malcious.Vendor</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">For malicious email addresses, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 240px;">Account.Email.Malcious.Description</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">For malicious email addresses, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 240px;">DBotScore.Type</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">Indicator type</td>
</tr>
<tr>
<td style="width: 240px;">DBotScore.Vendor</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 240px;">DBotScore.Score</td>
<td style="width: 65px;">Number</td>
<td style="width: 435px;">The actual score</td>
</tr>
<tr>
<td style="width: 240px;">DBotScore.Indicator</td>
<td style="width: 65px;">String</td>
<td style="width: 435px;">The indicator that was tested</td>
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
<p><code>email email=disco-team@stealthemail.com</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "EclecticIQ.Email": [
        {
            "Maliciousness": "unknown", 
            "Created": "2018-11-21T13:34:31.126027+00:00", 
            "ID": 42, 
            "LastUpdated": "2018-11-21T13:34:31.126027+00:00", 
            "Address": "disco-team@stealthemail.com"
        }, 
        {
            "Maliciousness": "unknown", 
            "Created": "2018-11-21T13:34:31.134425+00:00", 
            "ID": 43, 
            "LastUpdated": "2018-11-21T13:34:31.134425+00:00", 
            "Address": "disco-team@stealthemail.com"
        }
    ], 
    "DBotScore": {
        "Vendor": "EclecticIQ", 
        "Indicator": "disco-team@stealthemail.com", 
        "Score": 0, 
        "Type": "email"
    }, 
    "Account.Email": [
        {
            "Address": "disco-team@stealthemail.com"
        }, 
        {
            "Address": "disco-team@stealthemail.com"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="eclecticiq-email-reputation---disco-teamstealthemail.com">EclecticIQ Email reputation - <a href="mailto:disco-team@stealthemail.com">disco-team@stealthemail.com</a>
</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Maliciousness</th>
<th>Created</th>
<th>ID</th>
<th>LastUpdated</th>
<th>Address</th>
</tr>
</thead>
<tbody>
<tr>
<td>unknown</td>
<td>2018-11-21T13:34:31.126027+00:00</td>
<td>42</td>
<td>2018-11-21T13:34:31.126027+00:00</td>
<td><a href="mailto:disco-team@stealthemail.com">disco-team@stealthemail.com</a></td>
</tr>
<tr>
<td>unknown</td>
<td>2018-11-21T13:34:31.134425+00:00</td>
<td>43</td>
<td>2018-11-21T13:34:31.134425+00:00</td>
<td><a href="mailto:disco-team@stealthemail.com">disco-team@stealthemail.com</a></td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-the-reputation-of-a-domain-observable">6. Get the reputation of a domain observable</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the reputation of a domain observable.</p>
<p>Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>domain</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">domain</td>
<td style="width: 456px;">Domain observable to get the reputation of</td>
<td style="width: 105px;">Required</td>
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
<th style="width: 229px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 449px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 229px;">EclecticIQ.Domain.Name</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">Domain name that was tested</td>
</tr>
<tr>
<td style="width: 229px;">EclecticIQ.Domain.Created</td>
<td style="width: 62px;">Date</td>
<td style="width: 449px;">Observable creation date</td>
</tr>
<tr>
<td style="width: 229px;">EclecticIQ.Domain.LastUpdate</td>
<td style="width: 62px;">Date</td>
<td style="width: 449px;">Observable last updated date</td>
</tr>
<tr>
<td style="width: 229px;">EclecticIQ.Domain.ID</td>
<td style="width: 62px;">Number</td>
<td style="width: 449px;">Observable ID</td>
</tr>
<tr>
<td style="width: 229px;">EclecticIQ.Domain.Maliciousness</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">Maliciousness confidence level</td>
</tr>
<tr>
<td style="width: 229px;">Domain.Name</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">Domain name that was tested</td>
</tr>
<tr>
<td style="width: 229px;">Domain.Malcious.Vendor</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 229px;">Domain.Malcious.Description</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">For malicious domains, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Type</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">Indicator type</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Vendor</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Score</td>
<td style="width: 62px;">Number</td>
<td style="width: 449px;">The actual score</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Indicator</td>
<td style="width: 62px;">String</td>
<td style="width: 449px;">The indicator that was tested</td>
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
<p><code>domain domain=gooc.om</code></p>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Domain": [
        {
            "Name": "gooc.om"
        }
    ], 
    "DBotScore": {
        "Vendor": "EclecticIQ", 
        "Indicator": "gooc.om", 
        "Score": 0, 
        "Type": "domain"
    }, 
    "EclecticIQ.Domain": [
        {
            "Maliciousness": "unknown", 
            "Name": "gooc.om", 
            "ID": 74, 
            "LastUpdated": "2018-11-21T13:34:38.964435+00:00", 
            "Created": "2018-11-21T13:34:38.964435+00:00"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="eclecticiq-domain-reputation---gooc.om">EclecticIQ Domain reputation - gooc.om
</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Maliciousness</th>
<th>Name</th>
<th>LastUpdated</th>
<th>Created</th>
</tr>
</thead>
<tbody>
<tr>
<td>74</td>
<td>unknown</td>
<td>gooc.om</td>
<td>2018-11-21T13:34:38.964435+00:00</td>
<td>2018-11-21T13:34:38.964435+00:00</td>
</tr>
</tbody>
</table>
</div>
</div>