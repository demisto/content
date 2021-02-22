<!-- HTML_DOC -->
<p>Use urlscan.io integration to perform scans on suspected urls and see their reputation.</p>
<h2>Configure urlscan.io on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for urlscan.io.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. https://urlscan.io/api/v1/ )</strong></li>
<li><strong>API Key (needed only for submitting URLs for scanning)</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li>
<strong>URL Threshold. </strong>Minimum number of positive results from urlscan.io to consider the URL malicious.</li>
<li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_66414687541541575058084">Search for indicators: urlscan-search</a></li>
<li><a href="#h_872696191351541575062805">(Deprecated) Submit a URL: urlscan-submit</a></li>
<li><a href="#h_704691117651541575066607">Submit a URL (specify the "using" argument): url</a></li>
</ol>
<h3 id="h_66414687541541575058084">1. Search for indicators</h3>
<hr>
<p>Search for an indicator that is related to previous urlscan.io scans.</p>
<h5>Base Command</h5>
<p><code>urlscan-search</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">searchParameter</td>
<td style="width: 492px;">Enter a parameter to search as a string (IP, File name, sha256, url, domain)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 283px;"><strong>Path</strong></th>
<th style="width: 438px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 283px;">URLScan.URL</td>
<td style="width: 438px;">Bad URLs found</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.Domain</td>
<td style="width: 438px;">Domain of the URL scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.ASN</td>
<td style="width: 438px;">ASN of the URL scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.IP</td>
<td style="width: 438px;">IP of the url scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.ScanID</td>
<td style="width: 438px;">Scan ID for the URL scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.ScanDate</td>
<td style="width: 438px;">Latest scan date for the URL</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.Hash</td>
<td style="width: 438px;">SHA-256 of file scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.FileName</td>
<td style="width: 438px;">Filename of the file scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.FileSize</td>
<td style="width: 438px;">File size of the file scanned</td>
</tr>
<tr>
<td style="width: 283px;">URLScan.FileType</td>
<td style="width: 438px;">File type of the file scanned</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!urlscan-search searchParameter=8.8.8.8</code></p>
<h3 id="h_872696191351541575062805">2. (Deprecated) Submit a URL directly to urlscan.io</h3>
<hr>
<p>Submits a URL to urlscan.io.</p>
<p>This command is deprecated, but will still work if it is used in a playbook.</p>
<h5>Base Command</h5>
<p><code>urlscan-submit</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 165px;"><strong>Argument Name</strong></th>
<th style="width: 446px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 165px;">url</td>
<td style="width: 446px;">URL to scan</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 165px;">timeout</td>
<td style="width: 446px;">How many seconds to wait to the scan id result. Default is 30 seconds.</td>
<td style="width: 97px;">Optional</td>
</tr>
<tr>
<td style="width: 165px;">public</td>
<td style="width: 446px;">Will the submission be public or private</td>
<td style="width: 97px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 264px;"><strong>Path</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 264px;">URLScan.URLs</td>
<td style="width: 457px;">URLs related to the scanned URL</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.RelatedIPs</td>
<td style="width: 457px;">IPs related to the scanned URL</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.RelatedASNs</td>
<td style="width: 457px;">ASNs related to the scanned URL</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.Countries</td>
<td style="width: 457px;">Countries associated with the scanned URL</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.relatedhashes</td>
<td style="width: 457px;">IOCs found for the scanned URL</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.Subdomains</td>
<td style="width: 457px;">Associated subdomains for the url scanned</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.ASN</td>
<td style="width: 457px;">ASN of the URL scanned</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.Data</td>
<td style="width: 457px;">URL of the file found</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.Malicious.Vendor</td>
<td style="width: 457px;">Vendor reporting the malicious indicator for the file</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.Malicious.Description</td>
<td style="width: 457px;">Description of the malicious indicator</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.File.Hash</td>
<td style="width: 457px;">SHA256 of file found</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.File.FileName</td>
<td style="width: 457px;">File name of file found</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.File.FileType</td>
<td style="width: 457px;">File type of the file found</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.File.Hostname</td>
<td style="width: 457px;">URL where the file was found</td>
</tr>
<tr>
<td style="width: 264px;">URLScan.Certificates</td>
<td style="width: 457px;">Certificates found for the scanned URL</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!urlscan-submit url=http://www.github.com/</code></p>
<h3 id="h_704691117651541575066607">3. Submit a URL (specify using urlscan.io)</h3>
<hr>
<p>Submit a URL to scan and specify the <var>using</var> argument as urlscan.io.</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 166px;"><strong>Argument Name</strong></th>
<th style="width: 446px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 166px;">url</td>
<td style="width: 446px;">URL to scan</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">timeout</td>
<td style="width: 446px;">How many seconds to wait for the scan ID result. Default is 30 seconds.</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">public</td>
<td style="width: 446px;">Whether the submission will be public or private</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">retries</td>
<td style="width: 446px;">Number of retries if the API rate limit is reached. This argument is optional, but if you specify this argument, you need to specify the wait argument.</td>
<td style="width: 96px;"> Optional</td>
</tr>
<tr>
<td style="width: 166px;">wait</td>
<td style="width: 446px;">Time interval (in seconds) between retries, if the API rate limit is reached. This argument is optional, but if you specify the retries argument, you need to specify this argument.</td>
<td style="width: 96px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 267px;"><strong>Path</strong></th>
<th style="width: 454px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 267px;">URLScan.URLs</td>
<td style="width: 454px;">URLs related to the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.RelatedIPs</td>
<td style="width: 454px;">IPs related to the URL scanned</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.RelatedASNs</td>
<td style="width: 454px;">ASNs related to the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.Countries</td>
<td style="width: 454px;">Countries associated with the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.relatedhashes</td>
<td style="width: 454px;">IOCs found for the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.Subdomains</td>
<td style="width: 454px;">Associated sub-domains for the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.ASN</td>
<td style="width: 454px;">ASN of the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.Data</td>
<td style="width: 454px;">URL of the file found</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.Malicious.Vendor</td>
<td style="width: 454px;">Vendor reporting the malicious indicator for the file</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.Malicious.Description</td>
<td style="width: 454px;">Description of the malicious indicator</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.File.Hash</td>
<td style="width: 454px;">SHA-256 of file found</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.File.FileName</td>
<td style="width: 454px;">File name of file found</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.File.FileType</td>
<td style="width: 454px;">File type of the file found</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.File.Hostname</td>
<td style="width: 454px;">URL where the file was found</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.Certificates</td>
<td style="width: 454px;">Certificates found for the scanned URL</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.RedirectedURLS</td>
<td style="width: 454px;">Redirected URLs from the URL scanned</td>
</tr>
<tr>
<td style="width: 267px;">URLScan.EffectiveURL </td>
<td style="width: 454px;">Effective URL of the original URL</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!url url=http://www.github.com/ using="urlscan.io"</code></p>
<p> </p>