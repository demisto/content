<!-- HTML_DOC -->
<p>Use the Cloaken integration to unshorten URLs in AWS behind TOR.</p>
<h2>Use Cases</h2>
<ol>
<li>Unshorten a URL to run the expanded URL through intelligence sources.</li>
</ol>
<h2>Configure Cloaken on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Cloaken.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>credentials</strong><span> </span>: credentials for integration</li>
<li>
<strong>Server URL</strong><span> </span>: server url for cloaken instance</li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_dbafb55d-b213-43c2-8ee3-1f6176a5d1d9" target="_self">Unshorten a URL: cloaken-unshorten-url</a></li>
</ol>
<h3 id="h_dbafb55d-b213-43c2-8ee3-1f6176a5d1d9">1. Unshorten a URL</h3>
<p>Unshortens a URL.</p>
<h5>Base Command</h5>
<p><code>cloaken-unshorten-url</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 290px;"><strong>Argument Name</strong></th>
<th style="width: 285px;"><strong>Description</strong></th>
<th style="width: 165px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 290px;">url</td>
<td style="width: 285px;">URL to unshorten.</td>
<td style="width: 165px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 238px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 238px;">Cloaken.UnshortenedURL</td>
<td style="width: 72px;">string</td>
<td style="width: 430px;">The unshortened URL.</td>
</tr>
<tr>
<td style="width: 238px;">Cloaken.OriginalURL</td>
<td style="width: 72px;">string</td>
<td style="width: 430px;">The original URL.</td>
</tr>
<tr>
<td style="width: 238px;">Cloaken.Status</td>
<td style="width: 72px;">integer</td>
<td style="width: 430px;">Status of the response: BADREQUEST or OK.</td>
</tr>
<tr>
<td style="width: 238px;">URL.Data</td>
<td style="width: 72px;">string</td>
<td style="width: 430px;">The unshortened URL.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>cloaken-unshorten-url url=https://someurl.com</pre>
<h5>Context Example</h5>
<pre>{
URL:{Data:"http://badperson.com"},
Cloaken:{
    original_url:"https://tinyurl.com/x223z3223",
    unshortened_url:"http://badperson.com",
   response_status:201
}

</pre>
<h5>Human Readable Output</h5>
<h3>Cloakened URL:</h3>
<table style="width: 389px;" border="2">
<thead>
<tr>
<th style="width: 223px;">original_url</th>
<th style="width: 159px;">unshortened_url</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 223px;">https://tiny.url.com/x223z3223</td>
<td style="width: 159px;">http://badperson.com</td>
</tr>
</tbody>
</table>
### cloaken-screenshot-url
***
Creates a screenshot of the specified URL.


#### Base Command

`cloaken-screenshot-url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | The URL for which to take a screenshot. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CloakenScreenshot.Url | string | Url | 
| CloakenScreenshot.Status | string | Status of the screenshot. | 
