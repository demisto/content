<!-- HTML_DOC -->
<p>Use the CheckPhish integration to check URLs for threats.</p>
<h2>Configure CheckPhish on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for CheckPhish.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>CheckPhish API URL</strong></li>
<li><strong>API Token</strong></li>
<li><strong>Good Dispositions (CheckPhish labels for non-phishing URLs. Default is "clean")</strong></li>
<li><strong>Suspicious dispositions (CheckPhish labels for suspicious phishing URLs). Default is "drug_spam", "gambling", "hacked_website", "streaming", "suspicious"</strong></li>
<li><strong>Bad dispositions (CheckPhish labels for phishing URLs). Defaults are "cryptojacking", "phish", "likely_phish", "scam".</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_02d49bcb-a56b-4fe7-880b-75f63f2c025c" target="_self">CheckPhish-check-urls</a></li>
</ol>
<h3 id="h_02d49bcb-a56b-4fe7-880b-75f63f2c025c">1. CheckPhish-check-urls</h3>
<hr>
<p>Checks URLs against the CheckPhish database and returns the results.</p>
<h5>Base Command</h5>
<p><code>CheckPhish-check-urls</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 235px;"><strong>Argument Name</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 235px;">url</td>
<td style="width: 371px;">A CSV list of URLs to check.</td>
<td style="width: 134px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 193px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">CheckPhish.URL.url</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">URL that was submitted.</td>
</tr>
<tr>
<td style="width: 193px;">CheckPhish.URL.status</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">CheckPhish job status of the URL.</td>
</tr>
<tr>
<td style="width: 193px;">CheckPhish.URL.jobID</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">CheckPhish jobID that was assigned to the URL when it was submitted.</td>
</tr>
<tr>
<td style="width: 193px;">CheckPhish.URL.disposition</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">The CheckPhish category (disposition) of the URL.</td>
</tr>
<tr>
<td style="width: 193px;">CheckPhish.URL.brand</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">The brand (attack target) countered by the URL.</td>
</tr>
<tr>
<td style="width: 193px;">DBotScore.Score</td>
<td style="width: 63px;">Number</td>
<td style="width: 484px;">DBot score.</td>
</tr>
<tr>
<td style="width: 193px;">DBotScore.Type</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">Indicator type that was tested.</td>
</tr>
<tr>
<td style="width: 193px;">DBotScore.Vendor</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">Vendor that provided the DBot score.</td>
</tr>
<tr>
<td style="width: 193px;">DBotScore.Indicator</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">Indicator that CheckPhish tested.</td>
</tr>
<tr>
<td style="width: 193px;">URL.Data</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">URL that was submitted.</td>
</tr>
<tr>
<td style="width: 193px;">URL.Malicious.Vendor</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">CheckPhish.</td>
</tr>
<tr>
<td style="width: 193px;">URL.Malicious.Description</td>
<td style="width: 63px;">String</td>
<td style="width: 484px;">The brand (attack target) countered by the URL.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>CheckPhish-check-urls url=google.com</pre>
<h5>Context Example</h5>
<pre>{
  "CheckPhish.URL(val.Data &amp;&amp; val.Data == obj.Data)": {
    "brand": "unknown",
    "disposition": "clean",
    "jobID": "6d7e9671-29a9-4012-9700-8866f4887f92",
    "status": "DONE",
    "url": "http://google.com/"
  },
  "DBotScore": {
    "Indicator": "http://google.com/",
    "Score": 1,
    "Type": "url",
    "Vendor": "CheckPhish"
  },
  "URL(val.Data \u0026\u0026 val.Data == obj.Data)": {
    "Data": "http://google.com/"
  }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CheckPhish reputation for<span> </span><a href="http://google.com/" rel="nofollow">http://google.com/</a>
</h3>
<table style="width: 654px;" border="2">
<thead>
<tr>
<th style="width: 136px;">url</th>
<th style="width: 87px;">disposition</th>
<th style="width: 66px;">brand</th>
<th style="width: 47px;">status</th>
<th style="width: 302px;">jobID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;"><a href="http://google.com/" rel="nofollow">http://google.com/</a></td>
<td style="width: 87px;">clean</td>
<td style="width: 66px;">unknown</td>
<td style="width: 47px;">DONE</td>
<td style="width: 302px;">6d7e9671-29a9-4012-9700-8866f4887f92</td>
</tr>
</tbody>
</table>