<!-- HTML_DOC -->
<p>Use the VirusTotal integration to analyze suspicious hashes, URLs, domains, and IP addresses.</p>
<h2>Configure VirusTotal on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services.</strong>
</li>
<li>Search for VirusTotal.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.<span> </span>https://192.168.0.1)</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>File Threshold. Minimum number of positive results from VT scanners to consider the file malicious.</strong></li>
<li><strong>IP Threshold. Minimum number of positive results from VT scanners to consider the IP malicious.</strong></li>
<li><strong>URL Threshold. Minimum number of positive results from VT scanners to consider the URL malicious.</strong></li>
<li><strong>Domain Threshold. Minimum number of positive results from VT scanners to consider the domain malicious.</strong></li>
<li><strong>Preferred Vendors List. CSV list of vendors which are considered more trustworthy.</strong></li>
<li><strong>Preferred Vendor Threshold. The minimum number of highly trusted vendors required to consider a domain, IP address, URL, or file as malicious.</strong></li>
<li><strong>Determines whether to return all results, which can number in the thousands. If “true”, returns all results and overrides the<span> </span><em>fullResponse</em>,<span> </span><em>long</em><span> </span>arguments (if set to “false”) in a command. If “false”, the<span> </span><em>fullResponse</em>,<span> </span><em>long</em><span> </span>arguments in the command determines how results are returned.</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#%E2%80%9Ch_ae006d30-0dfa-4713-bb09-0a14c5025361%E2%80%9D" target="_self">Get the reputation of a file: file</a></li>
<li><a href="#h_b4dc406b-b389-45ed-9f42-8c70b7db6bae" target="_self">Get the reputation of an IP address: ip</a></li>
<li><a href="#h_dd1ec32e-5018-4d50-b789-85e89ef7b2bf" target="_self">Get the reputation of a URL: url</a></li>
<li><a href="#h_e8a4543e-4ba9-4304-b54e-b9a83e44d4a1" target="_self">Get the reputation of a domain: domain</a></li>
<li><a href="#h_92d67975-2612-496a-812e-f6145940776e" target="_self">Submit a file for scanning: file-scan</a></li>
<li><a href="#h_eec7f2e8-1ea2-4993-8db0-a7d73b528b70" target="_self">Re-scan an already submitted file: file-rescan</a></li>
<li><a href="#h_025c1f6e-75bb-4b41-b5f1-34ffa1d1dafc" target="_self">Scan a URL: url-scan</a></li>
<li><a href="#h_ccb076d6-ab8f-4872-8329-b7fc96d4483d" target="_self">Add comments to resources: vt-comments-add</a></li>
<li><a href="#h_d274159f-999b-476b-a7f7-91dcf4042957" target="_self">Get a URL for large files: vt-file-scan-upload-url</a></li>
<li><a href="#h_3bb5bb86-b6b2-424e-8e75-c227a913e7a2" target="_self">Get comments for a given resource: vt-comments-get</a></li>
</ol>
<h3 id="“h_ae006d30-0dfa-4713-bb09-0a14c5025361”">1. Get the reputation of a file</h3>
<hr>
<p>Checks the file reputation of the specified hash.</p>
<h5>Base Command</h5>
<p><code>file</code></p>
<h5 id="h_d56f490d-390a-4aba-b91c-df1674b7a0dd">Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 165.667px;"><strong>Argument Name</strong></th>
<th style="width: 502.333px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 165.667px;">file</td>
<td style="width: 502.333px;">A CSV list of hashes of the file to query. Supports MD5, SHA1, and SHA256.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 165.667px;">long</td>
<td style="width: 502.333px;">Whether to return the full response for scans. Default is “false”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 165.667px;">threshold</td>
<td style="width: 502.333px;">If the number of positives is higher than the threshold, the file will be considered malicious. If the threshold is not specified, the default file threshold, as configured in the instance settings, will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 165.667px;">wait</td>
<td style="width: 502.333px;">Time (in seconds) to wait between tries if the API rate limit is reached. Default is “60”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 165.667px;">retries</td>
<td style="width: 502.333px;">Number of retries for the API rate limit. Default is “0”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 205.333px;"><strong>Path</strong></th>
<th style="width: 70.6667px;"><strong>Type</strong></th>
<th style="width: 464px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 205.333px;">File.MD5</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">Bad MD5 hash.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.SHA1</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">Bad SHA1 hash.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.SHA256</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">Bad SHA256 hash.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.Malicious.Vendor</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">For malicious files, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.Malicious.Detections</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">For malicious files, the total number of detections.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.Malicious.TotalEngines</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">For malicious files, the total number of engines that checked the file hash.</td>
</tr>
<tr>
<td style="width: 205.333px;">DBotScore.Indicator</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 205.333px;">DBotScore.Type</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 205.333px;">DBotScore.Vendor</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 205.333px;">DBotScore.Score</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">The actual score.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.VirusTotal.Scans.Source</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">The vendor used to scan the hash.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.VirusTotal.Scans.Detected</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">Scan detection for this hash (True or False).</td>
</tr>
<tr>
<td style="width: 205.333px;">File.VirusTotal.Scans.Result</td>
<td style="width: 70.6667px;">unknown</td>
<td style="width: 464px;">Scan result for this hash, for example, signature.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.VirusTotal.ScanID</td>
<td style="width: 70.6667px;">string</td>
<td style="width: 464px;">Scan ID for this hash.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.PositiveDetections</td>
<td style="width: 70.6667px;">number</td>
<td style="width: 464px;">Number of engines that positively detected the indicator as malicious.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.DetectionEngines</td>
<td style="width: 70.6667px;">number</td>
<td style="width: 464px;">Total number of engines that checked the indicator.</td>
</tr>
<tr>
<td style="width: 205.333px;">File.VirusTotal.vtLink</td>
<td style="width: 70.6667px;">string</td>
<td style="width: 464px;">VirusTotal permanent link.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre> !file file=4604aeb7382c60bf29397ec655a72623 using=vt</pre>
<h5>Context Example</h5>
<pre>{
“DBotScore”: [
{
“Vendor”: “VirusTotal”,
“Indicator”: “4604aeb7382c60bf29397ec655a72623”,
“Score”: 3,
“Type”: “hash”
}
],
“File”: [
{
“SHA1”: “0f56a92bdd99954f7aba764201e481f128167565”,
“VirusTotal”: {
“ScanID”: “6bc32a390752c8da585a9985f9d586f9bfba15cc42ac628701bff4005add1158-1532554702”
},
“Malicious”: {
“Detections”: 55,
“Vendor”: “VirusTotal”,
“TotalEngines”: 68
},
“PositiveDetections”: 55,
“DetectionEngines”: 68,
“properties_to_append”: [
“Malicious”
],
“SHA256”: “6bc32a390752c8da585a9985f9d586f9bfba15cc42ac628701bff4005add1158”,
“MD5”: “4604aeb7382c60bf29397ec655a72623”
}
]
}
</pre>
<p> </p>
<h5>Human Readable Output</h5>
<h2>VirusTotal Hash Reputation for: 4604aeb7382c60bf29397ec655a72623</h2>
<p>Scan date:<span> </span><strong>2018-07-25 21:38:22</strong><br> Positives / Total:<span> </span><strong>55/68</strong><br> VT Link:<span> </span>4604aeb7382c60bf29397ec655a72623<br> MD5 / SHA1 / SHA256:<span> </span><strong>4604aeb7382c60bf29397ec655a72623 / 0f56a92bdd99954f7aba764201e481f128167565 / 6bc32a390752c8da585a9985f9d586f9bfba15cc42ac628701bff4005add1158</strong></p>
<h3 id="h_b4dc406b-b389-45ed-9f42-8c70b7db6bae">2. Get the reputation of an IP address</h3>
<hr>
<p>Checks the reputation of an IP address.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 168.333px;"><strong>Argument Name</strong></th>
<th style="width: 500.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168.333px;">ip</td>
<td style="width: 500.667px;">IP address to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 168.333px;">long</td>
<td style="width: 500.667px;">Whether to return full response for detected URLs. Default is “false”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">threshold</td>
<td style="width: 500.667px;">If the number of positives is higher than the threshold, the IP address will be considered malicious. If the threshold is not specified, the default IP threshold, as configured in the instance settings, will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">sampleSize</td>
<td style="width: 500.667px;">The number of samples from each type (resolutions, detections, etc.) to display for long format. Default is “10”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">wait</td>
<td style="width: 500.667px;">Time (in seconds) to wait between tries if the API rate limit is reached. Default is “60”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">retries</td>
<td style="width: 500.667px;">Number of retries for API rate limit. Default is “0”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">fullResponse</td>
<td style="width: 500.667px;">Whether to return all results, which can be thousands. Default is “false”. We recommend that you don’t return full results in playbooks.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 168.333px;"><strong>Path</strong></th>
<th style="width: 247.667px;"><strong>Type</strong></th>
<th style="width: 324px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168.333px;">IP.Address</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Bad IP address.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.ASN</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Bad IP ASN.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.Geo.Country</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Bad IP country.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.Malicious.Vendor</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">For malicious IPs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.Malicious.Description</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">For malicious IPs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 168.333px;">DBotScore.Indicator</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 168.333px;">DBotScore.Type</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 168.333px;">DBotScore.Vendor</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 168.333px;">DBotScore.Score</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">The actual score.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.DownloadedHashes</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest files that were detected by at least one antivirus solution, and were downloaded by VirusTotal from the IP address.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.UnAVDetectedDownloadedHashes</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest files that were not detected by any antivirus solution, and were downloaded by VirusTotal from the specified IP address.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.DetectedURLs</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest URLs hosted in this IP address that were detected by at least one URL scanner.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.CommunicatingHashes</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest detected files that communicate with this IP address.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.UnAVDetectedCommunicatingHashes</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest undetected files that communicate with this IP address.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.Resolutions.hostname</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Domains that resolved to the specified IP address.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.ReferrerHashes</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest detected files that embed this IP address in their strings.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.UnAVDetectedReferrerHashes</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Latest undetected files that embed this IP address in their strings.</td>
</tr>
<tr>
<td style="width: 168.333px;">IP.VirusTotal.Resolutions.last_resolved</td>
<td style="width: 247.667px;">unknown</td>
<td style="width: 324px;">Last resolution times of the domains that resolved to the specified IP address.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ip ip=8.8.8.8 using=vt</pre>
<h3 id="h_dd1ec32e-5018-4d50-b789-85e89ef7b2bf">3. Get the reputation of a URL</h3>
<hr>
<p>Checks the reputation of a URL.</p>
<p>Public API key</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">url</td>
<td style="width: 499px;">The URL to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">sampleSize</td>
<td style="width: 499px;">The number of samples from each type (resolutions, detections, etc.) to display for long format.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">long</td>
<td style="width: 499px;">Whether to return the full response for the detected URLs.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">threshold</td>
<td style="width: 499px;">If the number of positives is higher than the threshold, the URL will be considered malicious. If the threshold is not specified, the default URL threshold, as configured in the instance settings, will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">submitWait</td>
<td style="width: 499px;">Time (in seconds) to wait if the URL does not exist and is submitted for scanning. Default is “0”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">wait</td>
<td style="width: 499px;">Time (in seconds) to wait between tries if the API rate limit is reached. Default is “60”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">retries</td>
<td style="width: 499px;">Number of retries for API rate limit. Default is “0”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170.333px;"><strong>Path</strong></th>
<th style="width: 109.667px;"><strong>Type</strong></th>
<th style="width: 460px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170.333px;">URL.Data</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">Bad URLs found.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.Malicious.Vendor</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.Malicious.Description</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 170.333px;">DBotScore.Indicator</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 170.333px;">DBotScore.Type</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 170.333px;">DBotScore.Vendor</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 170.333px;">DBotScore.Score</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">The actual score.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.VirusTotal.Scans.Source</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">The vendor that scanned this URL.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.VirusTotal.Scans.Detected</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">Scan detection for this URL (True or False).</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.VirusTotal.Scans.Result</td>
<td style="width: 109.667px;">unknown</td>
<td style="width: 460px;">Scan result for this URL, for example, signature.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.DetectionEngines</td>
<td style="width: 109.667px;">number</td>
<td style="width: 460px;">Total number of engines that checked the indicator.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.PositiveDetections</td>
<td style="width: 109.667px;">number</td>
<td style="width: 460px;">Number of engines that positively detected the indicator as malicious.</td>
</tr>
<tr>
<td style="width: 170.333px;">URL.VirusTotal.vtLink</td>
<td style="width: 109.667px;">string</td>
<td style="width: 460px;">VirusTotal permanent link.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!url url=www.google.com using=vt</pre>
<h3 id="h_e8a4543e-4ba9-4304-b54e-b9a83e44d4a1">4. Get the reputation of a domain</h3>
<hr>
<p>Checks the reputation of a domain.</p>
<h5>Required Permissions</h5>
<p>Public API key</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 168.333px;"><strong>Argument Name</strong></th>
<th style="width: 500.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168.333px;">domain</td>
<td style="width: 500.667px;">Domain name to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 168.333px;">long</td>
<td style="width: 500.667px;">Whether to return the full response for detected URLs. Default is “false”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">sampleSize</td>
<td style="width: 500.667px;">The number of samples from each type (resolutions, detections, etc.) to display for long format.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">threshold</td>
<td style="width: 500.667px;">If the number of positives is higher than the threshold, the domain will be considered malicious. If the threshold is not specified, the default domain threshold, as configured in the instance settings, will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">wait</td>
<td style="width: 500.667px;">Time (in seconds) to wait between tries if the API rate limit is reached. Default is “60”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">retries</td>
<td style="width: 500.667px;">Number of retries for API rate limit. Default is “0”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168.333px;">fullResponse</td>
<td style="width: 500.667px;">Whether to return all results, which can be thousands. Default is “false”. We recommend that you don’t return full results in playbooks.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 172.333px;"><strong>Path</strong></th>
<th style="width: 285.667px;"><strong>Type</strong></th>
<th style="width: 282px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172.333px;">Domain.Name</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Bad domain found.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.Malicious.Vendor</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.Malicious.Description</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">For malicious domains, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 172.333px;">DBotScore.Indicator</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 172.333px;">DBotScore.Type</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 172.333px;">DBotScore.Vendor</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 172.333px;">DBotScore.Score</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">The actual score.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.DownloadedHashes</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Hashes of files that were downloaded from this domain.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.CommunicatingHashes</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Hashes of files that communicated with this domain in a sandbox.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.Resolutions.ip_address</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">IP addresses that resolved to this domain.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.Whois</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Whois report.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.Subdomains</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Subdomains.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.UnAVDetectedDownloadedHashes</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Latest files that were not detected by any antivirus solution, and were downloaded by VirusTotal from the specified IP address.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.DetectedURLs</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Latest URLs hosted in this domain address that were detected by at least one URL scanner.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.ReferrerHashes</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Latest detected files that embed this domain address in their strings.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.UnAVDetectedReferrerHashes</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Latest undetected files that embed this domain address in their strings.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.UnAVDetectedCommunicatingHashes</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Latest undetected files that communicated with this domain in a sandbox.</td>
</tr>
<tr>
<td style="width: 172.333px;">Domain.VirusTotal.Resolutions.last_resolved</td>
<td style="width: 285.667px;">unknown</td>
<td style="width: 282px;">Last resolution times of the IP addresses that resolve to this domain.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!domain domain=google.com using=vt</pre>
<h5>Context Example</h5>
<pre>{
“Domain”: {
“Name”: "google.com“,
“VirusTotal”: {
“UnAVDetectedCommunicatingHashes”: [
{
“date”: “2019-08-07 00:29:58”,
“positives”: 0,
“sha256”: “734da9d7571b423630e4296b40e73c135b84ac0b2632eb819309f714aff72ea9”,
“total”: 67
},
{
“date”: “2019-08-07 09:58:38”,
“positives”: 0,
“sha256”: “e1fe285f2bb1c29316ffb8204d20256da429e13f18ba830d23942150c0ef7ea4”,
“total”: 0
},
{
“date”: “2019-08-07 09:56:17”,
“positives”: 0,
“sha256”: “b8de2a06de99117c4b53d371cc5dfa836fdc17dea75a446dddf205599530fa3b”,
“total”: 0
},
{
“date”: “2019-08-07 09:55:38”,
“positives”: 0,
“sha256”: “ee55c456c8c67f7d32296ae86e16115fa9b960f1179737ee7df559a19e149778”,
“total”: 0
},
{
“date”: “2019-08-07 09:51:34”,
“positives”: 0,
“sha256”: “1690cb305e31fd9eb34204bb01839be99df33fd2d6834c9fa761420ea467ebb5”,
“total”: 0
},
{
“date”: “2019-08-07 09:50:32”,
“positives”: 0,
“sha256”: “6b708a9ba8336cecfb3221423d475a9788d271931f7d47cb99447a209eec1c72”,
“total”: 0
},
{
“date”: “2019-08-07 09:50:37”,
“positives”: 0,
“sha256”: “6d3e68373da38d395b4a99670eef6d8b10e47a3fcf441d5645bd503f83351849”,
“total”: 0
},
{
“date”: “2019-08-07 09:47:46”,
“positives”: 0,
“sha256”: “ebcf3669d05677e1d48866fcbbfb3c6e1e92e2459cafad2a83b0f5be8cef6e3a”,
“total”: 0
},
{
“date”: “2019-08-07 09:47:32”,
“positives”: 0,
“sha256”: “0f27dfd00f3fc3bcd9267d8c70a41ed03b8d7a9c8a7d752569f69aed53739b3b”,
“total”: 0
},
{
“date”: “2019-08-07 09:45:17”,
“positives”: 0,
“sha256”: “07d3f99aa2b20ee0621b859218b54dc013d456459ae730cdbaf11f1e4dea567b”,
“total”: 0
},
{
“date”: “2019-08-07 09:44:47”,
“positives”: 0,
“sha256”: “37931c99958c1463cefc8abc5e1e4ac1baa24c2b4483f1786772f0b89f459d5d”,
“total”: 0
},
{
“date”: “2019-08-07 09:44:06”,
“positives”: 0,
“sha256”: “a8141e74507b70b622feaee95f05a3bd16adb19f217d29ad605582ebf11c4bcc”,
“total”: 0
},
{
“date”: “2019-08-07 09:42:08”,
“positives”: 0,
“sha256”: “514a6ca1cf417212a231d28c03a55b597997c5c06ac10b85ef8cd630e616be8a”,
“total”: 0
},
{
“date”: “2019-08-07 09:41:44”,
“positives”: 0,
“sha256”: “2bf9d511e4396ef62e640784c0b48d7546a6729e199991e35e041b486fb3f8ac”,
“total”: 0
},
{
“date”: “2019-08-07 09:40:35”,
“positives”: 0,
“sha256”: “2ef3c445258f243b7884a337de8fab6c478664f01e852739a3830d359e5fb9f8”,
“total”: 0
},
{
“date”: “2019-08-07 09:39:43”,
“positives”: 0,
“sha256”: “cab88ae307cc4992530bb05d18bee6a0982c7ac6f3aec3c72ad629757c8eccec”,
“total”: 0
},
{
“date”: “2019-08-07 09:39:08”,
“positives”: 0,
“sha256”: “fb41dc1e04e6656662c26a8b5f0ad2943f8f95d0347294f90e25ca4294ecafcc”,
“total”: 0
},
{
“date”: “2019-08-07 09:37:51”,
“positives”: 0,
“sha256”: “ad5c05679e370225da5649a92d267b7385af2d39dd18743cb8c225f2d7eeea4c”,
“total”: 0
},
{
“date”: “2019-08-07 09:37:08”,
“positives”: 0,
“sha256”: “998b55153730f890bdfeffb60fb9f0575f45d7de361cdef63aad55f39155e93a”,
“total”: 0
},
{
“date”: “2019-08-07 09:35:51”,
“positives”: 0,
“sha256”: “35c79ad47b2f5f842d0ddfb36db069b17c588f4e535571f216b5d0735789dd63”,
“total”: 0
},
{
“date”: “2019-08-07 09:31:22”,
“positives”: 0,
“sha256”: “669fd8fbe7cbdb03dd428a93fc0cf6f5176889d36309dd8dfe5d229554912713”,
“total”: 0
},
{
“date”: “2019-08-07 09:30:30”,
“positives”: 0,
“sha256”: “d37ed7f6e0b90472f91bae87747e64523d27299b4ac02ad607305a9fa6df3c25”,
“total”: 0
},
{
“date”: “2019-08-07 09:28:36”,
“positives”: 0,
“sha256”: “f857abd3897c7da6e36d87b6f56fcbd35b9e399183955f099943e98d1ff72c0d”,
“total”: 0
},
{
“date”: “2019-08-07 09:27:06”,
“positives”: 0,
“sha256”: “24dc767f9e022c955da3c81b94383978bdff777f6fe5f0476b9e9eba2e078fe9”,
“total”: 0
},
{
“date”: “2019-08-07 09:25:58”,
“positives”: 0,
“sha256”: “7bed096423175adbbdc3075639ea782d847af967818fdcf790393dbfe8edffaf”,
“total”: 0
},
{
“date”: “2019-08-07 09:24:43”,
“positives”: 0,
“sha256”: “d4a8c4bd5694817a8e9fe8c5d0b1c2aa90b7270809a399521d375b7ab120e18b”,
“total”: 0
},
{
“date”: “2019-08-07 09:24:13”,
“positives”: 0,
“sha256”: “7df89772bd21d7e00389f51b2697425a25c68bbaee32a0d50a3761d28de80157”,
“total”: 0
},
{
“date”: “2019-08-07 09:20:42”,
“positives”: 0,
“sha256”: “7fb1e87cf6de1c58a9d82338b534f5e5609a41395699f421478ae5b9e1949c29”,
“total”: 0
},
{
“date”: “2019-08-07 09:19:24”,
“positives”: 0,
“sha256”: “d7787a14be2b47be23d8e043faae5487f29bb9ca6771586f423d354aa5a3b650”,
“total”: 0
},
{
“date”: “2019-08-07 09:16:27”,
“positives”: 0,
“sha256”: “c53efab72b45eb68f30ebe383e87c1cf97054c2f97ca5eb43d94bab59288dc9a”,
“total”: 0
},
{
“date”: “2019-08-07 09:15:22”,
“positives”: 0,
“sha256”: “2c2fb29a51f0c93dfa20faf6c9a704c0090b60e368166c327a7ebf0dd31967d9”,
“total”: 0
},
{
“date”: “2019-08-07 09:14:29”,
“positives”: 0,
“sha256”: “1d6846d5636763ebd632a42505a40637c26d05353e1d0cc0f83ba4af27c5c567”,
“total”: 0
},
{
“date”: “2019-08-07 09:13:42”,
“positives”: 0,
“sha256”: “8c4db73501cb0c1be3d589980c4a52969d07a3ab25b0530499883d0f440e981b”,
“total”: 0
},
{
“date”: “2019-08-07 09:13:07”,
“positives”: 0,
“sha256”: “671522a8843dde22655483d7e6704ee67645e09e30e7cdb8357d22414685d5a5”,
“total”: 0
},
{
“date”: “2019-08-07 09:12:02”,
“positives”: 0,
“sha256”: “c6e0e014a48bef222450c772a7b494d1308ce6da485897a073fde05ac1723df1”,
“total”: 0
},
{
“date”: “2019-08-07 09:11:33”,
“positives”: 0,
“sha256”: “f0f4f6f52894a89e3468f9dfd81f6825ee05edbbba80f77974ee8ce7403e5b2f”,
“total”: 0
},
{
“date”: “2019-08-07 09:09:49”,
“positives”: 0,
“sha256”: “123346c93cf60fe413938c572363416f59b5158cd2b6ed82cc09d7ef001ee030”,
“total”: 0
},
{
“date”: “2019-08-07 09:09:51”,
“positives”: 0,
“sha256”: “86268a08b1133ccda815b6de57c51b202440ec8fbe1326ab02d5f009da7b0b03”,
“total”: 0
},
{
“date”: “2019-08-07 09:09:34”,
“positives”: 0,
“sha256”: “7f0a33762057ca132929db4ac7edc402f4609e3d29bcb71191457cd50c4a3319”,
“total”: 0
},
{
“date”: “2019-08-07 09:07:53”,
“positives”: 0,
“sha256”: “00d10c61564d8934e54bfed4e3e001240a2794c5b48981c927404a8e7749ae1e”,
“total”: 0
},
{
“date”: “2019-08-07 09:06:32”,
“positives”: 0,
“sha256”: “7f2aa82d691fcf208dd136f7de8b98b9231ce6f1f5ab0a5186e263c05f1db293”,
“total”: 0
},
{
“date”: “2019-08-07 09:04:46”,
“positives”: 0,
“sha256”: “1a1ab7c7ce8bee3c3d3a772c31bc1643778c9ddce091fb22d408be8543382200”,
“total”: 0
},
{
“date”: “2019-08-07 09:04:10”,
“positives”: 0,
“sha256”: “868296db1554d2023999ca23e7872d201bbf1095f990f411cda22b26f4881e75”,
“total”: 0
},
{
“date”: “2019-08-07 09:01:25”,
“positives”: 0,
“sha256”: “9e3d4aae51b178437d302ce96152759de72473835dc9b50ad8a4b52c1f2c1782”,
“total”: 0
},
{
“date”: “2019-08-07 09:00:26”,
“positives”: 0,
“sha256”: “4b10b4896fb1b161e3e6d3c116addeffa4f2c12d3c9e44f921bb3fe35ef8a97e”,
“total”: 0
},
{
“date”: “2019-08-07 08:58:19”,
“positives”: 0,
“sha256”: “369d61f61f81d0ac31be33b6b32108dde0f692b0b7e965d03bc81c7e1fdeae6b”,
“total”: 0
},
{
“date”: “2019-08-07 08:56:53”,
“positives”: 0,
“sha256”: “b053147cf05890955199dd2a122321e45b4c9f968c9bb0366ae9da67aefffad0”,
“total”: 0
},
{
“date”: “2019-08-07 08:56:12”,
“positives”: 0,
“sha256”: “2c6d9eda35b0181d967a1e82cecf300d59f23081b039e78965f0bff2d5825f09”,
“total”: 0
},
{
“date”: “2019-08-07 08:55:07”,
“positives”: 0,
“sha256”: “21bb78e9a6e54955ec235e007073f488293f28b48a8ab9902d125efa2ebd7a35”,
“total”: 0
},
{
“date”: “2019-08-07 08:50:31”,
“positives”: 0,
“sha256”: “6953ff62217c873c242c7afb8de4a375700a0bad1b616382b43bdac8bca5677a”,
“total”: 0
}
],
“UnAVDetectedReferrerHashes”: [
{
“date”: “2019-08-07 08:49:13”,
“positives”: 0,
“sha256”: “267b2209e5655be95b2e9d838acf3f0e63723f9d1e7e1b36d6db61ebedc49ecb”,
“total”: 66
},
{
“date”: “2019-08-07 02:15:36”,
“positives”: 0,
“sha256”: “d809490af36c73d3ee60752cae3465b48ddd1dbbf05ab12ec66d4b81a7814740”,
“total”: 71
},
{
“date”: “2019-08-07 03:21:07”,
“positives”: 0,
“sha256”: “827ed4f96595d0454ab017f0eee5f554aecb1c2e6eaa09a0921208bca48e6438”,
“total”: 66
},
{
“date”: “2019-08-07 02:11:18”,
“positives”: 0,
“sha256”: “5090bf2c9bcece04860e23e0d400b134caf95b046057c67e28454ca43429a891”,
“total”: 73
},
{
“date”: “2019-08-07 02:23:22”,
“positives”: 0,
“sha256”: “bd46b1f2956345e4c38ca33eb3d4352208918f9dc3ec2469f63b2af2a137bfe2”,
“total”: 73
},
{
“date”: “2019-08-06 16:48:53”,
“positives”: 0,
“sha256”: “37f2958998d4636d0bb5337bc45ec53765e69fc42bb1a24255b369e2f292d24b”,
“total”: 72
},
{
“date”: “2019-08-06 16:36:02”,
“positives”: 0,
“sha256”: “d95c46cc0f987e6e3c738e2a2c795f5fdb4196a9ac52334f0860138c8c093cc6”,
“total”: 68
},
{
“date”: “2019-08-07 00:17:55”,
“positives”: 0,
“sha256”: “3cbc8ad7b2f9e2eb79aafc8edbd0502b28c0902b770e352918857dd90bebd443”,
“total”: 71
},
{
“date”: “2019-08-07 03:13:48”,
“positives”: 0,
“sha256”: “41036d940a8eb6e6142f0de1c5259828e0da8139f903762046eb818481f3c4a7”,
“total”: 67
},
{
“date”: “2019-08-06 23:21:18”,
“positives”: 0,
“sha256”: “fd7d373dce8b1697ef55c1f9cfe3aa208914e750cb002522a4c3f41fe7301932”,
“total”: 73
},
{
“date”: “2019-08-06 23:18:20”,
“positives”: 0,
“sha256”: “5888fe2f30cfe4603edf53bded11443f580a10ff5a95429a6917e1ee8df2966b”,
“total”: 71
},
{
“date”: “2019-08-06 22:55:38”,
“positives”: 0,
“sha256”: “d06abf1c396c287016619777267f2b4bea3c899dda269324062633121819b43c”,
“total”: 72
},
{
“date”: “2019-08-06 22:57:26”,
“positives”: 0,
“sha256”: “379da0dc2a032e3619095380bdd01910aaa7d2761907164d84aaa54dfbf73ad4”,
“total”: 71
},
{
“date”: “2019-08-06 23:40:03”,
“positives”: 0,
“sha256”: “d2e62718b5ee0b928b77d07397772beb74f13bb0e3a5e2a3f78daae739928fa3”,
“total”: 67
},
{
“date”: “2019-08-06 22:29:20”,
“positives”: 0,
“sha256”: “8f8f5bc2fca7aa24b16f758a20298eba38ef007a71eeeae23ea0b4b09088d0d2”,
“total”: 73
},
{
“date”: “2019-08-06 14:19:14”,
“positives”: 0,
“sha256”: “17dd221b5528611ce3ef06c4c8a04e163a8ac76891ed2608f4642bda37739857”,
“total”: 67
},
{
“date”: “2019-08-06 18:09:25”,
“positives”: 0,
“sha256”: “ff9aa00ccd06d4ed95cae592651cb09f5013af11a69d8a26b2a8b3cfccab6f1a”,
“total”: 71
},
{
“date”: “2019-08-06 16:19:29”,
“positives”: 0,
“sha256”: “5457c7a5a6739bdb2fd834c3e939e4c76732d146b7952e4977bd23c4c7055cc6”,
“total”: 73
},
{
“date”: “2019-08-06 14:49:03”,
“positives”: 0,
“sha256”: “1e0989415edde1b4a4353ef16fe207d012835aadd1a5ddc957aabca7dd22c220”,
“total”: 72
},
{
“date”: “2019-08-06 13:24:36”,
“positives”: 0,
“sha256”: “3bcacf1b39ed321bf151e28d863b56bbab52a598476b36c9af46a00bf4802b66”,
“total”: 72
},
{
“date”: “2019-08-06 11:47:31”,
“positives”: 0,
“sha256”: “74c414711f12a63ada2f70d6abbb8e495b32d513a2fb7869edc9db11bbb8ff19”,
“total”: 72
},
{
“date”: “2019-08-06 11:43:09”,
“positives”: 0,
“sha256”: “bc7bcce9e9005fe78ac1f76a9a6a6864e4f87949dd9492410f65025fa71bffd0”,
“total”: 71
},
{
“date”: “2019-08-06 11:53:40”,
“positives”: 0,
“sha256”: “fdd8b6c153fd0de7b4eb2aede59cf864ee34ed241004c23116d940cdd5d36621”,
“total”: 70
},
{
“date”: “2019-08-06 11:50:58”,
“positives”: 0,
“sha256”: “724f326543da21f0ae2b8fbac4c89f42d2dae610396c4cd2e362bbca1e33d1e3”,
“total”: 69
},
{
“date”: “2019-08-06 11:49:39”,
“positives”: 0,
“sha256”: “bd62ea87b5cf26f261d09be833d46690fa9948ef951d07e71e57f99b15a3d67c”,
“total”: 71
},
{
“date”: “2019-08-06 11:22:14”,
“positives”: 0,
“sha256”: “38f8d9e15151334990e5690f0eadd19c4c038ba8d6c0e0fe43a2d1728d5f7bdf”,
“total”: 71
},
{
“date”: “2019-08-06 11:12:00”,
“positives”: 0,
“sha256”: “0509e943c1ac77f04cfdfa59925c00475a1c91118fd4dc401cacd4f91ba92f22”,
“total”: 69
},
{
“date”: “2019-08-06 11:07:10”,
“positives”: 0,
“sha256”: “8bd9ec2489bba078943be58a93b8bc4e04661746dca2f7499c0b0944545b23c5”,
“total”: 72
},
{
“date”: “2019-08-06 11:07:23”,
“positives”: 0,
“sha256”: “4da7294aa49cb862bd69c7bc0a13723f9c1102f9d600c0cc8b0115f4e1d3f345”,
“total”: 72
},
{
“date”: “2019-08-06 10:46:38”,
“positives”: 0,
“sha256”: “eade52ec6c9012142cc71ab4d2e5e9c615751d1497be5945029bb181c1dc9efc”,
“total”: 73
},
{
“date”: “2019-08-06 10:00:51”,
“positives”: 0,
“sha256”: “bfe45000934c667453013dfacfce264c10ed09c7d0c7a791fec298d8a94cc14a”,
“total”: 72
},
{
“date”: “2019-08-06 09:39:57”,
“positives”: 0,
“sha256”: “98995aafe477fc6b9b3cc4bb46625f70945d78abc5af4e5542d0d1733c32c7ac”,
“total”: 72
},
{
“date”: “2019-08-06 08:13:32”,
“positives”: 0,
“sha256”: “1d63d7d0ebacd698bb62e8d0cc3e077447b9e0a6ead6fd49a149d36a759ae69f”,
“total”: 73
},
{
“date”: “2019-08-06 08:08:39”,
“positives”: 0,
“sha256”: “f94658113ef8e28601bb5f41e4105fa15c6877ebae5013af3a26afe827d00dc8”,
“total”: 72
},
{
“date”: “2019-08-06 08:00:04”,
“positives”: 0,
“sha256”: “e700eed7da280edcb1d6139cdffae26c99f5365f6b2fa0fd9ff1d1fb50770f69”,
“total”: 71
},
{
“date”: “2019-08-06 07:51:54”,
“positives”: 0,
“sha256”: “247395236318a1d74922990929d4290edb6a72dc888243fa104f48695de6afae”,
“total”: 72
},
{
“date”: “2019-08-06 07:27:04”,
“positives”: 0,
“sha256”: “d8155663ce3d276f961afa21e1d48a1ad7b29dd780931f266c044ba701f7c36a”,
“total”: 72
},
{
“date”: “2019-08-06 07:13:48”,
“positives”: 0,
“sha256”: “40c4f776c299ba953879e5bae1b1c9fc1c5259b2b0ab1085880a939dbb62d76c”,
“total”: 72
},
{
“date”: “2019-08-06 07:13:29”,
“positives”: 0,
“sha256”: “2f784d896da725d068d9d049a4180b0070991ce040b6e76fbf089605cfa67c85”,
“total”: 72
},
{
“date”: “2019-08-06 06:21:50”,
“positives”: 0,
“sha256”: “2bbee1cdb6e09688ca18353a27b5f0bbc3b39a3ea01d96ee66d3d4bdaf9954c7”,
“total”: 72
},
{
“date”: “2019-08-06 05:59:55”,
“positives”: 0,
“sha256”: “eafc2b350ca201c07b6ff6a2818fca24828d20c34e5a0565e90e61f87bb4b8f4”,
“total”: 72
},
{
“date”: “2019-08-06 05:59:18”,
“positives”: 0,
“sha256”: “763e9656f4e726f6820895c0a81a35ef183d1a28174734420bc927787981a85c”,
“total”: 73
},
{
“date”: “2019-08-06 05:53:04”,
“positives”: 0,
“sha256”: “0d1fedf8599af0df77b51e6777ff3e97497c075cedef553cd3540f7fabead22f”,
“total”: 71
},
{
“date”: “2019-08-06 05:47:46”,
“positives”: 0,
“sha256”: “ceec71ba2f93d19680b8cd0bb58df6230b0c0b9343068535bb865112c6e56986”,
“total”: 74
},
{
“date”: “2019-08-06 05:46:13”,
“positives”: 0,
“sha256”: “3de3561d0712dd37a6afa8d9a16b027fc811f647906552b9443a0a814123530b”,
“total”: 73
},
{
“date”: “2019-08-06 05:42:15”,
“positives”: 0,
“sha256”: “e7adb4e4ed7cf239c72f0ca7a0a1282e48ebbb9f1d6cfc7ac32e216407bb42dc”,
“total”: 72
},
{
“date”: “2019-08-06 05:25:46”,
“positives”: 0,
“sha256”: “87f7ecb07bf2652ab2591ba1791cac5e71f4802a7142e89732ad5d6adfb33148”,
“total”: 73
},
{
“date”: “2019-08-06 05:24:03”,
“positives”: 0,
“sha256”: “f765915e1804b791ad2ebb8534029eefb8d114cc8d3e61339400ce0022c217b9”,
“total”: 72
},
{
“date”: “2019-08-06 05:21:07”,
“positives”: 0,
“sha256”: “b17f827cd3c1fc68e2f9cf725547fabb9b635fc0c168fae8a948fd69a3448d65”,
“total”: 72
},
{
“date”: “2019-08-06 05:17:45”,
“positives”: 0,
“sha256”: “f76d2917fdf76a17360626519939e94cede07cbb1bc96171ea8cdb895970af3a”,
“total”: 71
}
],
“CommunicatingHashes”: [
{
“date”: “2019-08-07 12:49:25”,
“positives”: 53,
“sha256”: “2340b502e47f8fa071c505872ff78d63189853040c2aad99357ccb32614834ad”,
“total”: 68
},
{
“date”: “2019-08-07 14:48:29”,
“positives”: 44,
“sha256”: “355d097f22eb14032c77968b012639e6a749cc6788c7d0639c5faea04525f582”,
“total”: 62
},
{
“date”: “2019-08-07 12:48:43”,
“positives”: 48,
“sha256”: “355d18ed8b8ec12b0d3f1121f71588b97ce820838fe3cb74f5ecabc1d73cbdc8”,
“total”: 65
},
{
“date”: “2019-08-07 12:46:26”,
“positives”: 52,
“sha256”: “0151e71a631770ec73ebaf61f14f0211d62fde26f1287e1ecb881cc5c704aa4c”,
“total”: 67
},
{
“date”: “2019-08-07 12:47:26”,
“positives”: 53,
“sha256”: “0fa9067a6794dfe8186a8cef7c240e0eea007b3664fb334c3196a92a5a23d5b6”,
“total”: 67
},
{
“date”: “2019-08-06 05:40:29”,
“positives”: 62,
“sha256”: “2f358baa7badf371632ce079ec38b313b904c4ac2ed71e3595f6769d0703a1ca”,
“total”: 73
},
{
“date”: “2019-08-07 12:40:49”,
“positives”: 41,
“sha256”: “e98952c37850e5722d304034af4ea0a78d506df0bb254928620e94feb161d362”,
“total”: 66
},
{
“date”: “2019-08-06 01:40:16”,
“positives”: 61,
“sha256”: “8aff6f10e665ce27de141279557cd0a376b85aa5f7d90afb3609e969fb7996cc”,
“total”: 73
},
{
“date”: “2019-08-07 12:45:04”,
“positives”: 52,
“sha256”: “31a8169deb948d0750244f0ac28bd07996c869f547bbdf0c65a07d8915a139ce”,
“total”: 68
},
{
“date”: “2019-08-07 12:46:06”,
“positives”: 48,
“sha256”: “9657446ade62fa37e064ac11fea0e1f78d9687f24136d4b043b0704fe765d23c”,
“total”: 66
},
{
“date”: “2019-08-07 12:40:30”,
“positives”: 53,
“sha256”: “d3b7e99b8cc06d8877f87db3797c43bbdff5ed818d0e9b7cf63488169cc398e5”,
“total”: 68
},
{
“date”: “2019-08-07 12:45:10”,
“positives”: 50,
“sha256”: “ef14c5d6dcd878a8ae63f983ca4a1539a89ec7cd6656d642afbc9987c3e904e4”,
“total”: 64
},
{
“date”: “2019-08-07 12:44:49”,
“positives”: 52,
“sha256”: “3eb4d04955b231e15014d45eda384dd350f688ec201f36aad04c2f1b41ed9773”,
“total”: 67
},
{
“date”: “2019-08-07 12:44:17”,
“positives”: 53,
“sha256”: “889f69d82a5352120f6257f139090aa319cbc9139c07874602dd309359327171”,
“total”: 68
},
{
“date”: “2019-08-07 14:48:57”,
“positives”: 46,
“sha256”: “8d5da269917dee37217ce1e566f96656e42a7686da231a8f8a7d5b521f66cc15”,
“total”: 62
},
{
“date”: “2019-08-07 12:43:44”,
“positives”: 49,
“sha256”: “9550f6e578f9c84d67e28e94cb83f8b4a63f270a519b9fe37ddc9c76694c6628”,
“total”: 64
},
{
“date”: “2019-08-07 07:00:50”,
“positives”: 56,
“sha256”: “718a76698bc01a2b0e11448f204b7a34f861080a22ae2bf7e849df1078211508”,
“total”: 69
},
{
“date”: “2019-08-07 12:43:24”,
“positives”: 47,
“sha256”: “47982f9fc379dea14f7c82635f3b0c2e959800de27e48753e05958628cc652df”,
“total”: 63
},
{
“date”: “2019-08-07 12:42:39”,
“positives”: 48,
“sha256”: “627c6254302a4252ca417daa98e686bb2396cd30ac1712f1e441eceddbe60250”,
“total”: 63
},
{
“date”: “2019-08-07 14:47:00”,
“positives”: 54,
“sha256”: “5b0399c563ecf88973d7074935390d6448fc73fa8248e1689519b6f61ebcbd7f”,
“total”: 67
},
{
“date”: “2019-08-05 15:22:01”,
“positives”: 62,
“sha256”: “9be5173f5d406c25c48de48869084a5dd975d27c2c23fbcb0b37393ca0855335”,
“total”: 71
},
{
“date”: “2019-08-07 12:44:40”,
“positives”: 52,
“sha256”: “a62fa483182251e3c1ba7543d8ad435290941ada11a4c2cbc2bf86f11fa14eac”,
“total”: 68
},
{
“date”: “2019-08-06 10:01:26”,
“positives”: 61,
“sha256”: “577089b9052d4f4215d147b430e7adc8d90e18de347a95956c9945f0bbebc3ae”,
“total”: 73
},
{
“date”: “2019-08-07 12:41:31”,
“positives”: 46,
“sha256”: “8914d2feb0f8d26d030c661c5fd5ce1c1f407b66e45fc8850d6f67636519a548”,
“total”: 60
},
{
“date”: “2019-08-07 12:40:05”,
“positives”: 47,
“sha256”: “cd42bd7e4c1b94de62d3f3fedef1e50db0cb0b5f49490e4b1a1db055f469d5de”,
“total”: 66
},
{
“date”: “2019-08-07 14:44:05”,
“positives”: 45,
“sha256”: “fa431508abea04c2fa352d5a6c34a0615f79798abf442e22fde37e9bdac5b38c”,
“total”: 61
},
{
“date”: “2019-08-07 12:39:22”,
“positives”: 44,
“sha256”: “d8a791bc1d66ca930cd5b5180c975c63229f00e0cf40f21a17c13ac48edb5695”,
“total”: 57
},
{
“date”: “2019-08-06 06:11:40”,
“positives”: 61,
“sha256”: “703777e403f53916733d89d6e53f6904d8ce8be212c128a7290d8af8b70440ec”,
“total”: 72
},
{
“date”: “2019-08-07 14:43:04”,
“positives”: 52,
“sha256”: “363d76969fcad9bb625180adf95cc5ea6bcfb34e311b9ee08c9cbe86679e2772”,
“total”: 66
},
{
“date”: “2019-08-07 14:36:06”,
“positives”: 42,
“sha256”: “ff9988ca38f4f11b936d51d246f5e1d66ab65c853d011df1c072a7b8b97f8441”,
“total”: 64
},
{
“date”: “2019-08-06 10:01:51”,
“positives”: 61,
“sha256”: “7380717cf91c075914cef1e81f1cdd51a29051c5a34e30be4db1fb8d079648b9”,
“total”: 72
},
{
“date”: “2019-08-07 12:38:48”,
“positives”: 51,
“sha256”: “7ad3599de38a6bc35fb04b5688a2030ba257cd393256a710df19e04ac83af10c”,
“total”: 69
},
{
“date”: “2019-08-07 14:41:30”,
“positives”: 46,
“sha256”: “a5136b9df35e6ddb41cdfdc8ad15936c8814f1c94bee5d99ce1bab3e6ac0c9db”,
“total”: 62
},
{
“date”: “2019-08-07 14:41:23”,
“positives”: 58,
“sha256”: “810ab69da3febcb0b0970a5bbf0fbb05dcb69ceeb063a519346b1b655724c798”,
“total”: 71
},
{
“date”: “2019-08-06 10:00:44”,
“positives”: 60,
“sha256”: “28b4e7cb6eeba055b2049c0afb32adb0ca31ab082a28f8238a43f68263f47047”,
“total”: 72
},
{
“date”: “2019-08-07 12:37:56”,
“positives”: 51,
“sha256”: “252fc869ed003b42daadf885e716325b358ac10afe12eb32b9a67ef6e7e5cbcf”,
“total”: 66
},
{
“date”: “2019-08-07 12:30:19”,
“positives”: 54,
“sha256”: “10045165322c740219fd7955ffc9401e71bb357cf552c274fd30ce69f451a380”,
“total”: 67
},
{
“date”: “2019-08-07 14:39:55”,
“positives”: 48,
“sha256”: “c07c5b39c5533829776e77da944551b847c96108b0ff5973e48c6b2f013d29ed”,
“total”: 63
},
{
“date”: “2019-08-07 12:36:21”,
“positives”: 48,
“sha256”: “5a5dab2db74a5c0683f45ace7b7d4587ec142abec8eeb30d7c332c038bc27ca7”,
“total”: 68
},
{
“date”: “2019-08-07 12:36:16”,
“positives”: 50,
“sha256”: “12815a9f93729bba9730ff60a76c8ba7599810067842d853848d5c4d5ec659c9”,
“total”: 65
},
{
“date”: “2019-08-07 12:35:59”,
“positives”: 44,
“sha256”: “e3ab3d822603b6663d8dcea54f5ed83292cbeda78f5e7ba55706f67e9656802c”,
“total”: 67
},
{
“date”: “2019-08-07 14:37:38”,
“positives”: 43,
“sha256”: “7a2656db5971a922d712fd187ec80502e5f2d1a2596f16395e1389a82b2f0b68”,
“total”: 57
},
{
“date”: “2019-08-06 10:01:53”,
“positives”: 60,
“sha256”: “74b0611fad30585b8168b399ddbfbcc72daa1e35032f162b48d0b0a79c78abfc”,
“total”: 74
},
{
“date”: “2019-08-07 12:34:20”,
“positives”: 55,
“sha256”: “d20373208492db25c4b0ddbd7d2ad8599daddc5bd826a272499d679adc2c8de8”,
“total”: 69
},
{
“date”: “2019-08-06 10:03:40”,
“positives”: 61,
“sha256”: “e5ea85521494b8e38e16493cc7700a6f0714429a0d8054bc43d54f9e97349da7”,
“total”: 72
},
{
“date”: “2019-08-07 14:36:17”,
“positives”: 38,
“sha256”: “8db2f939cab48fef7695719ec8fa5bc1880eca00ad44d941bf95301291150611”,
“total”: 60
},
{
“date”: “2019-08-07 12:30:27”,
“positives”: 50,
“sha256”: “f0e6353c6eb7a88bec600afcd9c9ab6b69b770aae92ce4898472a0c80a7d2734”,
“total”: 64
},
{
“date”: “2019-08-07 13:54:14”,
“positives”: 58,
“sha256”: “20ff1657cfda39eef1e9e611c707d873d448f7ceeff66ece0ed9a65d0ce36e3a”,
“total”: 68
},
{
“date”: “2019-08-07 12:24:22”,
“positives”: 49,
“sha256”: “1ac9c6e7d1f903dce640daa6504ab43a6115dbc9215b1652683963f66c633afa”,
“total”: 64
},
{
“date”: “2019-08-07 14:34:34”,
“positives”: 52,
“sha256”: “6a02bb82657b353347e23f344d7752c71c51b758dd52b9436d8f179d4c9d3250”,
“total”: 66
}
],
“Whois”: “Domain Name: GOOGLE.COM\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2018-02-21T18:36:40Z\nCreation Date: 1997-09-15T04:00:00Z\nRegistry Expiry Date: 2020-09-14T04:00:00Z\nRegistrar: MarkMonitor Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS1.GOOGLE.COM\nName Server: NS2.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nDNSSEC: unsigned\nDomain Name: google.com\nUpdated Date: 2018-02-21T10:45:07-0800\nCreation Date: 1997-09-15T00:00:00-0700\nRegistrar Registration Expiration Date: 2020-09-13T21:00:00-0700\nRegistrar: MarkMonitor, Inc.\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Country: US\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US\nTech Organization: Google LLC\nTech State/Province: CA\nTech Country: US\nName Server: ns4.google.com\nName Server: ns3.google.com\nName Server: ns2.google.com\nName Server: ns1.google.com“,
“Subdomains”: [],
“DetectedURLs”: [
{
“total”: 70,
“positives”: 1,
“scan_date”: “2019-07-17 00:11:47”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Fwww.gum-gum-stream.co%2Frezero-kara-hajimeru-isekai-seikatsu-1-vostfr%2F&amp;ved=2ahukewibzb2hn_bfahwwbgmbhu2ibzqqfjaaegqiaxab&amp;usg=aovvaw0ea31fvs0yqb5e_checpbq"
},
{
“total”: 70,
“positives”: 1,
“scan_date”: “2019-07-10 16:30:18”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q&amp;esrc=s&amp;source=web&amp;cd=1&amp;cad=rja&amp;uact=8&amp;ved=0ahukewjq0owqw9lxahuh9wmkhezmbpsqfgglmaa&amp;url=www.iphone92.com/&amp;usg=aovvaw1vc53g5kb9jsto9afwo85t"
},
{
“total”: 70,
“positives”: 1,
“scan_date”: “2019-07-03 23:20:19”,
“url”: "https://google.com/url?q=https://escenas.cl&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNFLMok704-YTHi3NDlgWBOzeQNguw"
},
{
“total”: 70,
“positives”: 1,
“scan_date”: “2019-07-03 03:21:19”,
“url”: "http://google.com/url?q=http://acre-services.com/2/200.php&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNHiDCcL1XyiuL6yQLSlfEcLM6ec_g,"
},
{
“total”: 70,
“positives”: 2,
“scan_date”: “2019-07-01 22:10:18”,
“url”: "https://google.com/url?sa=t&amp;rct=j&amp;q=&amp;esrc=s&amp;source=web&amp;cd=42&amp;cad=rja&amp;uact=8&amp;ved=2ahUKEwiSx5Kj6-DiAhXUAxAIHRFJAO44KBAWMAF6BAgAEAE&amp;url=https%3A//www.gogosohel.com/geometry-will-draw-the-soul-toward-truth-and-create-the-spirit-of-philosophy/&amp;usg=AOvVaw05JoPGQDy0_cRbZx47-RuA"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2019-03-04 22:18:05”,
“url”: "https://google.com/url?q=https://kinaneevents.com/wp-content/plugins/css-ready-selectors/live/live/L/&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNG5oh-gnG8ghel6NNmIwzsv2huELQ"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2019-03-04 22:15:50”,
“url”: "https://google.com/url?q=https%3A%2F%2Fkinaneevents.com%2Fwp-content%2Fplugins%2Fcss-ready-selectors%2Flive%2Flive%2FL%2F&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNG5oh-gnG8ghel6NNmIwzsv2huELQ"
},
{
“total”: 66,
“positives”: 2,
“scan_date”: “2019-03-01 00:08:18”,
“url”: "https://google.com/url?q=http%3A%2F%2Fqlql.ru%2FFAG"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2019-02-27 00:10:06”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Fwww.voglioporno.com%2Fvideo%2Fla-perfetta-massaggiatrice-stimola-un-cazzo-e-poi-se-lo-scopa%2F&amp;ved=2ahukewjts5q0jyhfahxqsbuihz7paigqfjabegqichab&amp;usg=aovvaw3dnqkbel0dsqwwnggbbhzf"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2019-01-22 00:10:34”,
“url”: "http://google.com/url?q=3Dhttp://amandanovotny49.com/hnbufy8guydf/KE11Y&amp;source="
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2019-01-16 00:07:20”,
“url”: "http://google.com/url?q=http%3A%2F%2Fhelpdeskaccount.sitey.me%2F"
},
{
“total”: 70,
“positives”: 2,
“scan_date”: “2019-01-14 14:43:09”,
“url”: "https://google.com/url?q=http://qlql.ru/FAG&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNEqIPs9_89fHaDBlD4yVR4cdTcMFA"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2019-01-13 00:06:18”,
“url”: "http://google.com/url?rct=j&amp;sa=t&amp;url=http%3A%2F%2Frainbowschool.com.pk%2F4yg0ujy%2Fsrsm5pu.php%3Fdsibnmucf%3Dbreaking-news-in-hindi&amp;ct=ga&amp;cd=caiyhwq5zgziyjliztljmjjkotu6y29tomvuolbloljm&amp;usg=afqjcnhf7ttwdf3oqdirqnqn9emodzrmxq"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-12-21 00:07:06”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Fwww.voglioporno.com%2Fvideo%2Fil-sesso-a-due-va-bene-ma-meglio-a-tre%2F&amp;ved=0ahukewj46p3o9i7fahvd1xokhesgdhsqo7qbcduwca&amp;usg=aovvaw35s_nlvhjfkxenjg9yqwz1"
},
{
“total”: 66,
“positives”: 2,
“scan_date”: “2018-12-04 23:51:19”,
“url”: "http://google.com/url?sa=d&amp;q=http%3A%2F%2Ft1t.us%2F&amp;usg=afqjcnf9tnqjtqrzguielhubj9nwwfejlg"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-12-04 23:41:18”,
“url”: "http://google.com/url?q=https%3A%2F%2Fgowthamelectricals.com%2Fimages%2Fgallery2%2Fmicrosoftexcelverification%2F"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-12-04 23:41:03”,
“url”: "https://google.com/url?cad=rja&amp;cd=46&amp;esrc=s&amp;q=&amp;rct=j&amp;sa=t&amp;source=web&amp;uact=8&amp;url=http%3A%2F%2Fbestdostavka.md%2Fuploads%2Fstorage%2Fimages%2Fsoveti%2F&amp;usg=AOvVaw3jjz8q0aFWIRMXIQavoQRU&amp;ved=2ahUKEwj8opXvgtPdAhVkqYsKHTNrBfA4KBAWMAV6BAgAEAE"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-12-01 23:40:49”,
“url”: "http://google.com/setup.exe"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-11-03 23:51:20”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q&amp;esrc=s&amp;source=web&amp;cd=1&amp;cad=rja&amp;uact=8&amp;ved=0ahukewjq0owqw9lxahuh9wmkhezmbpsqfgglmaa&amp;url=http%3A%2F%2Fwww.iphone92.com%2F&amp;usg=aovvaw1vc53g5kb9jsto9afwo85t"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-08-25 23:31:25”,
“url”: "http://google.com/"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-06-01 00:10:41”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q&amp;esrc=s&amp;source=web&amp;cd=1&amp;cad=rja&amp;uact=8&amp;ved=0ahukewjagogyuzdyahviqyykhsr4chgqfggmmaa&amp;url=https%3A%2F%2Frepelis.tv%2F&amp;usg=aovvaw3jwqofqzt"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-05-29 23:40:51”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;cd=21&amp;ved=0ahukewjmk_npxitzahwt0ymkhbhld5mqfghhmbq&amp;url=https%3A%2F%2Frepelis.tv%2F8339%2Fpelicula%2Fthe-last-house-on-the-left.html&amp;usg=aovvaw0w9wtgtb-tm9ldfpgmu9wr"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-05-27 20:00:21”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F222%2Fpelicula%2Finvictus.html&amp;ved=0ahukewjax9kp5lfxahxd7sykhvffctgqfggjmaa&amp;usg=aovvaw1qoqscrgng8dapr5uuc"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-05-09 08:20:22”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q&amp;esrc=s&amp;source=web&amp;cd=1&amp;cad=rja&amp;uact=8&amp;ved=0ahukewjagogyuzdyahviqyykhsr4chgqfggmmaa&amp;url=https%3A%2F%2Frepelis.tv%2F&amp;usg=aovvaw3jwqofqzt-rcxz8upcj6nh"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-04-01 23:40:52”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Fonhax.net%2Fnova-launcher-prime-beta-3-cracked-apk-is-herelatest&amp;ved=2ahukewiatvmco9zyahxll5qkhqnlansqfjaaegqidxab&amp;usg=aovvaw2ksyh7lweyohntr7g1z6wc"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-03-26 08:31:34”,
“url”: "https://google.com/url?amp&amp;&amp;&amp;&amp;hl=en&amp;q=https://kzkoicaalumni.com/admin/PaymentAdvice.doc&amp;source=gmail&amp;usg=AFQjCNEH6BQ_oidMNm-JPqfp1XOoIVCVgg&amp;ust=1507345174557000"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-03-19 23:40:36”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F222%2Fpelicula%2Finvictus.html&amp;ved=0ahukewjax9kp5lfxahxd7sykhvffctgqfggjmaa&amp;usg=aovvaw1qoqscrgng8dapr5uuc_6x"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-03-19 23:40:21”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Fwww.yedsed.com%2Fclips%2Fclipslud%2F4226.html&amp;ved=0ahukewjisnzas8nuahxkm5qkhcpkaqmqfggcmae&amp;usg=afqjcnhshlrcifw2kz6ikrjapx8f81fq9q&amp;sig2=mcpfutm0admdaotsqdd2ia"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-20 00:59:44”,
“url”: "http://google.com/url?q=https%3A%2F%2Fgowthamelectricals.com%2Fimages%2Fgallery2%2Fmicrosoftexcelverification%2F&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNG9ul7C_e52qoS5awK1wlHTgDK1Ng"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-15 03:30:34”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F13780%2Fpelicula%2Farrival.html&amp;ved=0ahukewjarcjby93xahvyqn8kht2_ccgqfggjmaa&amp;usg=aovvaw15iwdxqbzvocptodrmym4r"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-12 06:11:19”,
“url”: "http://google.com/url?q=https%3A%2F%2Fdocs.google.com%2Fforms%2Fd%2Fe%2F1faipqlscidbl1urgomft7qunnh-6z-8rawjt3vdv-a_qun1vzxipicq%2Fviewform&amp;sa=d&amp;ust=1516540585233000&amp;usg=afqjcngbdpi5lunifo8qi9ixqa3hxgnikg"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-12 06:11:04”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q&amp;esrc=s&amp;source=web&amp;cd=8&amp;cad=rja&amp;uact=8&amp;ved=0ahukewjpmqn8_e_pahvbp5qkhbbyabaqfghfmac&amp;url=http%3A%2F%2Fen.peperonity.com%2Fsites%2Fgamezclub0%2F38112355&amp;usg=afqjcngugmvnenpch5w-uwts6b4snw4zoq&amp;bvm=bv.136593572%2Cd.dgo"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-12 06:10:49”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F11220%2Fpelicula%2Fel-rey-de-la-habana.html&amp;ved=2ahukewiri7oepphyahvcdt8khq5sdpmqfjaaegqicxab&amp;usg=aovvaw1u-ban0ssu4nhasdrwkps2"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-12 06:10:34”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F3851%2Fpelicula%2Fel-rey-leon-2-el-tesoro-de-simba-lion-king-ii-simbas-pride.html&amp;ved=2ahukewj1knlqsd_yahucjq0khywvafsqfjaaegqierab&amp;usg=aovvaw3dupw7cof6lkql1v4ohqbe"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-12 06:10:19”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F&amp;ved=2ahukewj44t7niinzahve7gmkhtfua6iqfjavegqibhab&amp;usg=aovvaw3jwqofqzt-rcxz8upcj6nh"
},
{
“total”: 67,
“positives”: 1,
“scan_date”: “2018-02-03 04:10:21”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Fwww.comandotorrents.com%2Fa-forma-da-agua-torrent-2018-legendado-dublado-bluray-720p-1080p-download%2F&amp;ved=2ahukewiaqkkvgpvyahxjf5akhvg_cegqfjaaegqiehab&amp;usg=aovvaw19gegbi8wc3aor9vzhdsqq"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-28 15:40:20”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Fgamesofpc.com%2Fgta-5-download-grand-theft-auto-v%2F&amp;ved=2ahukewjm_lvltphyahwdyqqkhf3bda0qfjamegqierab&amp;usg=aovvaw1c1xdz1onwx94mf7vi4pcv"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-19 23:50:51”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Fwww.ainfekka.com%2Fforums%2Fshowthread.php%3Ftid%3D63930&amp;ved=0ahukewjf2pzk3q7xahwpguwkhdvoc0uqfghama0&amp;usg=aovvaw3t0hmh9kvz3xqsvwurda8w"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-19 23:50:36”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Fwww.cinecalidad.to%2Fpeliculas%2Fbenedict-cumberbatch%2F&amp;ved=0ahukewiyidtglvhxahulst8khqoubiwqfggimaa&amp;usg=aovvaw2w2gdjnzfsgoi6wikm7ngh"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-19 23:50:21”,
“url”: "http://google.com/chrome.apk"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-16 23:50:35”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Frepelis.tv%2F&amp;ved=0ahukewir88kuh4pyahxqk-akhyawc4uqfggcmaa&amp;usg=aovvaw3jwqofqzt-rcxz8upcj6nh"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-16 14:50:35”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q&amp;esrc=s&amp;source=web&amp;cd=1&amp;cad=rja&amp;uact=8&amp;ved=0ahukewjynf331drxahxhq98khr4_d6cqfggkmaa&amp;url=http%3A%2F%2Fwww.cinecalidad.to%2F&amp;usg=aovvaw0kyl3puqllcmqtwitwyhe0"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2018-01-16 14:31:06”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Fvideo.djpunjab.in%2Fpunjabi-videos%2Fdaang-mankirt-aulakh-video-songs-ynptnq.html&amp;ved=0ahukewix68vo2onyahwexrokhctmb1aqwqsbccuwaa&amp;usg=aovvaw0r4l1q-zxaqgdn-seovhb8"
},
{
“total”: 66,
“positives”: 1,
“scan_date”: “2017-12-25 15:49:24”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=http%3A%2F%2Ftvonlinegratis1.com%2Ftv-online-gratis-1-venha-assistir-em-hd%2F&amp;ved=0ahukewinwnoomctxahvgkjakhedtcf8qfgglmaa&amp;usg=aovvaw1gfd78nqgpsc-l8hz8zlcq"
},
{
“total”: 65,
“positives”: 1,
“scan_date”: “2017-11-20 18:52:41”,
“url”: "http://google.com/url?sa=t&amp;source=web&amp;rct=j&amp;url=https%3A%2F%2Ffbpasshacking.com%2F&amp;ved=0ahukewi_xbim6c3xahxdrrokhc6cdhcqfggnmaa&amp;usg=aovvaw14kcmwymrtd5nd6yerfjxr"
},
{
“total”: 64,
“positives”: 1,
“scan_date”: “2017-11-07 09:12:15”,
“url”: "http://google.com/url?q=http%3A%2F%2Fwebmaster-poczta-help-desk.sitey.me"
},
{
“total”: 64,
“positives”: 1,
“scan_date”: “2017-10-07 14:06:20”,
“url”: "https://google.com/url?q=http%3A%2F%2Fqlql.ru%2FFAG&amp;sa=D&amp;sntz=1"
},
{
“total”: 64,
“positives”: 1,
“scan_date”: “2017-10-04 12:48:17”,
“url”: "http://google.com/url?q=http%3A%2F%2Fkinyumbamutakabbir.com%2Fjcyvm.php%3Fas6e3tqzhyu&amp;sa=d&amp;sntz=1&amp;usg=afqjcnenlj28lncajpu4l-1-iygrxhxqdg"
},
{
“total”: 64,
“positives”: 1,
“scan_date”: “2017-09-20 11:27:13”,
“url”: "https://google.com/url?q=http%3A%2F%2Fqlql.ru%2FFAG&amp;sa=D&amp;sntz=1&amp;usg=AFQjCNEqIPs9_89fHaDBlD4yVR4cdTcMFA"
},
{
“total”: 64,
“positives”: 1,
“scan_date”: “2017-09-20 08:47:52”,
“url”: "http://google.com/url?sa=t&amp;rct=j&amp;q=&amp;esrc=s&amp;source=web&amp;cd=16&amp;ved=0ahUKEwitxb-BzvjPAhUBTCYKHQKjAywQFghqMA8&amp;url=http://www.arkham-mass.com/&amp;usg=AFQjCNG_3XT3rrZn8a57NMDF0pV9CscjPQ&amp;sig2=wza4OM9_eThdq0F5bt4hmw"
}
],
“UnAVDetectedDownloadedHashes”: [
{
“date”: “2018-05-09 08:25:13”,
“positives”: 0,
“sha256”: “c3d40562984207ca4629d46c875d119e200efb45bbf270eba900fce4262bfe9f”,
“total”: 70
},
{
“date”: “2019-07-09 17:27:41”,
“positives”: 0,
“sha256”: “ab9dbab873fff677deb2cfd95ea60b9295ebd53b58ec8533e9e1110b2451e540”,
“total”: 67
},
{
“date”: “2019-07-11 19:12:56”,
“positives”: 0,
“sha256”: “374cd3a5952d6015012dedbced08e81e659f6b0eb0acf5061a98a4f3366eb66f”,
“total”: 72
},
{
“date”: “2019-07-22 01:41:42”,
“positives”: 0,
“sha256”: “30f7775f096b1e5e627c442ca79eb27bc0effc8bb184b72135a3c9e086ac7923”,
“total”: 57
},
{
“date”: “2019-07-02 12:45:31”,
“positives”: 0,
“sha256”: “45f53a1e92608afb768a952f5438b6cd23d67e81322866c96df8186be8a3465f”,
“total”: 74
},
{
“date”: “2019-07-07 04:36:46”,
“positives”: 0,
“sha256”: “f111d71287e0e91002f0aca8a75ae09c3dd86e9c4f1c88e4fd506b5a4e15a2a8”,
“total”: 59
},
{
“date”: “2019-07-05 23:55:12”,
“positives”: 0,
“sha256”: “81792df1916a8a626a31669b5e3aa35d5ee438d8d922a0e38e672c3af0197891”,
“total”: 59
},
{
“date”: “2019-07-04 10:21:06”,
“positives”: 0,
“sha256”: “8e8b57a41e781579357e8fa119873634e74abe6c3c417f97dbb78b29c04736de”,
“total”: 58
},
{
“date”: “2019-07-03 15:31:29”,
“positives”: 0,
“sha256”: “802c945883fcd0634e9a4dfe52bc9e38a1858d61e61d0e787f579186a2ceb342”,
“total”: 58
},
{
“date”: “2018-11-30 10:04:43”,
“positives”: 0,
“sha256”: “f317b85a0b636eea6294cfd9b7426dbf6ee5dfe0f2f24b2a9c6ad166455ed367”,
“total”: 69
},
{
“date”: “2019-07-02 12:50:45”,
“positives”: 0,
“sha256”: “46ec2fc577cdcbba98be3ba4d8a8485c702940577e25141aada712f435009b29”,
“total”: 58
},
{
“date”: “2019-06-19 09:05:37”,
“positives”: 0,
“sha256”: “2009149b8081e462df915139d4dd4977b46a356b9cb9cb73f0c6c22cb2cc620d”,
“total”: 70
},
{
“date”: “2018-05-08 17:16:55”,
“positives”: 0,
“sha256”: “2d5dda7b4ae8eb369aea8944525479257bc0e460c192ee6bb9058db19b5acd3d”,
“total”: 70
},
{
“date”: “2017-04-28 09:40:28”,
“positives”: 0,
“sha256”: “8efbcf0f13c52d43196a68f73f5de68cf2aa0302777ebf9eb2b184b9e5cefa09”,
“total”: 65
},
{
“date”: “2019-06-08 13:22:37”,
“positives”: 0,
“sha256”: “2cc0e4b48c042ac869e719f1379a778709e906f50ec06e08d9807d536fb74d80”,
“total”: 57
},
{
“date”: “2019-05-29 12:54:45”,
“positives”: 0,
“sha256”: “560c0a010f7581e3127d2c79a35c4aa5576e8f61c88f0262d6e38a9db35461c0”,
“total”: 58
},
{
“date”: “2019-05-23 08:50:36”,
“positives”: 0,
“sha256”: “6999b5f816fc762d0c23bd2e8ebe851fafced05ade765cb3ba1266fcda3648c4”,
“total”: 56
},
{
“date”: “2019-05-20 03:46:25”,
“positives”: 0,
“sha256”: “5d7f02ce177d02fd7e3059f8152dc85e021ec2821e6168a059a95703b9fd4c87”,
“total”: 57
},
{
“date”: “2019-05-14 07:36:31”,
“positives”: 0,
“sha256”: “a2a8e535867fe4f0eaf078d16ee681b0284b11583266760c992519c5a15c91f6”,
“total”: 59
},
{
“date”: “2019-05-14 00:47:43”,
“positives”: 0,
“sha256”: “cd64087bedd1ca40ae46c2f46f506e86a2a46526572bdff959ea9c3151d94319”,
“total”: 58
},
{
“date”: “2019-05-08 09:32:39”,
“positives”: 0,
“sha256”: “f686d61c7377b7f82a05a85fd200effdb3dcc3b7015db5dc463129501f3e8123”,
“total”: 59
},
{
“date”: “2019-05-06 20:13:23”,
“positives”: 0,
“sha256”: “b9ad99909c4b37a550817c74db0833d91a0fdd7dcd19fe74e1f1143625e86c88”,
“total”: 58
},
{
“date”: “2019-05-06 02:31:16”,
“positives”: 0,
“sha256”: “90776f786b71c7dd16ab047f8f1d21513a318904371a8d20c57bd3fd10ffb6fd”,
“total”: 59
},
{
“date”: “2019-05-06 00:06:21”,
“positives”: 0,
“sha256”: “85454fa2dc600e09634d86720b14ecce10b27fa47e9252bd01c811782714467c”,
“total”: 57
},
{
“date”: “2019-04-30 08:49:16”,
“positives”: 0,
“sha256”: “4471d5b9100e2e4f421d20f743922c3c8673c7308cf16baf33d80fd580be9c02”,
“total”: 59
},
{
“date”: “2019-04-28 15:05:26”,
“positives”: 0,
“sha256”: “f45b7b0d607143e3326bb30dd4433b2a57d4d102768e3d42e60913688e3d524d”,
“total”: 55
},
{
“date”: “2019-04-12 02:07:12”,
“positives”: 0,
“sha256”: “ff7ab76cd5b03baccc19c6ece089462cdbdc7034f183d9b99116e962ae3727a5”,
“total”: 58
},
{
“date”: “2019-04-08 09:16:44”,
“positives”: 0,
“sha256”: “d73269d7c02c5e45df3b46838933d1b70e4721a0578ee94116de6ca1211b28f0”,
“total”: 55
},
{
“date”: “2019-04-06 01:46:39”,
“positives”: 0,
“sha256”: “b52a9b9daab35cc52f960125ce0e8170b2064b4b154feffd8cc87695c52e83c7”,
“total”: 58
},
{
“date”: “2019-04-03 03:40:11”,
“positives”: 0,
“sha256”: “6da5620880159634213e197fafca1dde0272153be3e4590818533fab8d040770”,
“total”: 57
},
{
“date”: “2019-03-27 09:12:44”,
“positives”: 0,
“sha256”: “ad0d3e970c9ab535f030b4f141baf3178e69e3afd510212ba6f20597e28616e8”,
“total”: 57
},
{
“date”: “2019-03-04 20:36:43”,
“positives”: 0,
“sha256”: “8b5d8fcb4bfad5cfd563683098e066c407a67e1f5a274c7d1960c0dc049d37c4”,
“total”: 63
},
{
“date”: “2019-03-04 19:30:34”,
“positives”: 0,
“sha256”: “2382fe29dd9eb4c3bfcc405b789f35458125cafb36c6537422353e3aaa0b2cb0”,
“total”: 62
},
{
“date”: “2019-03-04 09:40:19”,
“positives”: 0,
“sha256”: “85e8f4807d23c5389dc37b50999f83142098310fe32756fbdd3d12f3587c0814”,
“total”: 68
},
{
“date”: “2019-03-04 05:44:38”,
“positives”: 0,
“sha256”: “fdbd38457a7c6cddfaff369ef1e62b8a10bed36a4cc78cb560311194b46bca64”,
“total”: 58
},
{
“date”: “2019-03-02 12:13:04”,
“positives”: 0,
“sha256”: “684db9ad1b40999f6bacb6eaf079a102bda4817e901359d883e2e8159585f92c”,
“total”: 63
},
{
“date”: “2019-03-01 11:38:19”,
“positives”: 0,
“sha256”: “6f9e14cf55387a9183f38f69db5d7f89c8b4bb0f8e2140474b1f259dbdb6a9fa”,
“total”: 69
},
{
“date”: “2019-02-28 15:22:56”,
“positives”: 0,
“sha256”: “19b843cc92cb12aa314bb3c3913b2feeb852e85969bf06cb9d096931bfda34ba”,
“total”: 55
},
{
“date”: “2019-02-27 13:12:34”,
“positives”: 0,
“sha256”: “e9d3283d6a9a0c32f973a90f300e9ad148f16825e6dbc1f0076f4f771bc8173a”,
“total”: 68
},
{
“date”: “2019-02-27 07:00:34”,
“positives”: 0,
“sha256”: “71f7dd3ee246b83ea2ac639ec0d776357a3abfe2213615e6368981eddd29653e”,
“total”: 68
},
{
“date”: “2019-02-26 10:04:02”,
“positives”: 0,
“sha256”: “70344820712a9f3d84e99e231b8726e7e803b1898a70a3bfc46678e605033e0d”,
“total”: 68
},
{
“date”: “2019-02-25 03:48:00”,
“positives”: 0,
“sha256”: “749bd5febdd8e46d63ee86ea4f14045f0fe2a7f68565ecd0229b70212d28cff1”,
“total”: 52
},
{
“date”: “2019-02-24 09:44:17”,
“positives”: 0,
“sha256”: “b522e37e18b54feaf4fe26facc2e344302f665b2d03dba45c3a23ca76644e2ee”,
“total”: 58
},
{
“date”: “2019-02-24 06:54:32”,
“positives”: 0,
“sha256”: “22f92fcd6558b86659acfa6f90a5ba5349cea7a6a09ddbee70d03edc4a63f246”,
“total”: 65
},
{
“date”: “2019-02-23 21:44:24”,
“positives”: 0,
“sha256”: “9cd9c9d02dd0faeea806e8a2503e0c67c9f6e3be8c47d9a3d276157dd8aa8151”,
“total”: 69
},
{
“date”: “2019-02-23 00:29:52”,
“positives”: 0,
“sha256”: “161c35a7962c1cfb06360228d59d0be2b0bc8fd6a683713cf6ecd4e7f6f644fa”,
“total”: 68
},
{
“date”: “2019-02-22 06:41:19”,
“positives”: 0,
“sha256”: “1771b2218fdf89a752044648398ec3920d4040931c44e6f73282ed29b127cc17”,
“total”: 65
},
{
“date”: “2019-02-22 03:16:01”,
“positives”: 0,
“sha256”: “e000bee39dfa62ceec55959d4785125ef3a0f6c1d0fdf90076458b7888073642”,
“total”: 68
},
{
“date”: “2019-02-18 18:06:12”,
“positives”: 0,
“sha256”: “995592824e87d73ff3b76200f0b340d23d701df3db5ba5f103405242a5d9de68”,
“total”: 69
},
{
“date”: “2019-02-16 05:54:14”,
“positives”: 0,
“sha256”: “f69405b024ada90ca5b0e73c2e07d32a2e6101e1aee2cdab1eea7717e407d816”,
“total”: 56
}
],
“Resolutions”: [
{
“last_resolved”: “2017-05-19 00:00:00”,
“ip_address”: “108.167.133.29”
},
{
“last_resolved”: “2016-02-16 00:00:00”,
“ip_address”: “108.177.10.100”
},
{
“last_resolved”: “2016-02-16 00:00:00”,
“ip_address”: “108.177.10.102”
},
{
“last_resolved”: “2018-10-13 19:59:38”,
“ip_address”: “108.177.11.100”
},
{
“last_resolved”: “2018-10-13 19:59:38”,
“ip_address”: “108.177.11.101”
},
{
“last_resolved”: “2018-10-13 19:59:38”,
“ip_address”: “108.177.11.102”
},
{
“last_resolved”: “2018-10-13 19:59:38”,
“ip_address”: “108.177.11.113”
},
{
“last_resolved”: “2018-10-13 19:59:38”,
“ip_address”: “108.177.11.138”
},
{
“last_resolved”: “2018-10-13 19:59:38”,
“ip_address”: “108.177.11.139”
},
{
“last_resolved”: “2019-08-07 00:05:39”,
“ip_address”: “108.177.111.100”
},
{
“last_resolved”: “2019-08-07 00:05:39”,
“ip_address”: “108.177.111.101”
},
{
“last_resolved”: “2019-08-07 00:05:39”,
“ip_address”: “108.177.111.102”
},
{
“last_resolved”: “2019-08-07 00:05:39”,
“ip_address”: “108.177.111.113”
},
{
“last_resolved”: “2019-08-07 00:05:39”,
“ip_address”: “108.177.111.138”
},
{
“last_resolved”: “2019-08-07 00:05:39”,
“ip_address”: “108.177.111.139”
},
{
“last_resolved”: “2019-08-06 00:05:30”,
“ip_address”: “108.177.112.100”
},
{
“last_resolved”: “2019-08-06 00:05:31”,
“ip_address”: “108.177.112.101”
},
{
“last_resolved”: “2019-08-06 00:05:30”,
“ip_address”: “108.177.112.102”
},
{
“last_resolved”: “2019-08-06 00:05:30”,
“ip_address”: “108.177.112.113”
},
{
“last_resolved”: “2019-08-06 00:05:31”,
“ip_address”: “108.177.112.138”
},
{
“last_resolved”: “2019-08-06 00:05:31”,
“ip_address”: “108.177.112.139”
},
{
“last_resolved”: “2018-07-11 11:27:21”,
“ip_address”: “108.177.119.100”
},
{
“last_resolved”: “2018-07-11 11:27:22”,
“ip_address”: “108.177.119.101”
},
{
“last_resolved”: “2018-07-11 11:27:21”,
“ip_address”: “108.177.119.102”
},
{
“last_resolved”: “2018-07-11 11:27:21”,
“ip_address”: “108.177.119.113”
},
{
“last_resolved”: “2018-07-11 11:27:21”,
“ip_address”: “108.177.119.138”
},
{
“last_resolved”: “2018-07-11 11:27:21”,
“ip_address”: “108.177.119.139”
},
{
“last_resolved”: “2018-10-13 16:19:24”,
“ip_address”: “108.177.12.100”
},
{
“last_resolved”: “2018-10-13 16:19:24”,
“ip_address”: “108.177.12.101”
},
{
“last_resolved”: “2018-10-13 16:19:24”,
“ip_address”: “108.177.12.102”
},
{
“last_resolved”: “2018-10-13 16:19:24”,
“ip_address”: “108.177.12.113”
},
{
“last_resolved”: “2018-10-13 16:19:24”,
“ip_address”: “108.177.12.138”
},
{
“last_resolved”: “2018-10-13 16:19:24”,
“ip_address”: “108.177.12.139”
},
{
“last_resolved”: “2019-08-02 11:38:30”,
“ip_address”: “108.177.120.100”
},
{
“last_resolved”: “2019-08-02 11:38:30”,
“ip_address”: “108.177.120.101”
},
{
“last_resolved”: “2019-08-02 11:38:30”,
“ip_address”: “108.177.120.102”
},
{
“last_resolved”: “2019-08-02 11:38:30”,
“ip_address”: “108.177.120.113”
},
{
“last_resolved”: “2019-08-02 11:38:30”,
“ip_address”: “108.177.120.138”
},
{
“last_resolved”: “2019-08-02 11:38:30”,
“ip_address”: “108.177.120.139”
},
{
“last_resolved”: “2019-07-27 00:11:27”,
“ip_address”: “108.177.121.100”
},
{
“last_resolved”: “2019-07-27 00:11:27”,
“ip_address”: “108.177.121.101”
},
{
“last_resolved”: “2019-07-27 00:11:27”,
“ip_address”: “108.177.121.102”
},
{
“last_resolved”: “2019-07-27 00:11:27”,
“ip_address”: “108.177.121.113”
},
{
“last_resolved”: “2019-07-27 00:11:27”,
“ip_address”: “108.177.121.138”
},
{
“last_resolved”: “2019-07-27 00:11:27”,
“ip_address”: “108.177.121.139”
},
{
“last_resolved”: “2018-06-27 13:14:54”,
“ip_address”: “108.177.122.100”
},
{
“last_resolved”: “2018-06-27 13:14:55”,
“ip_address”: “108.177.122.101”
},
{
“last_resolved”: “2018-06-27 13:14:55”,
“ip_address”: “108.177.122.102”
},
{
“last_resolved”: “2018-06-27 13:14:55”,
“ip_address”: “108.177.122.113”
},
{
“last_resolved”: “2018-06-27 13:14:55”,
“ip_address”: “108.177.122.138”
}
],
“DownloadedHashes”: [
{
“date”: “2019-03-04 21:06:36”,
“positives”: 1,
“sha256”: “10a01be40c332fffbbad2df799c98d6a45af24cd78a10c264f37c51b7fc50869”,
“total”: 71
},
{
“date”: “2019-03-01 00:08:36”,
“positives”: 1,
“sha256”: “61bb6b68bc02d5d445bae6d1a19214fc9899acf8b0a327e0c38288a48ed3cc47”,
“total”: 71
},
{
“date”: “2019-02-22 00:00:16”,
“positives”: 1,
“sha256”: “1bb61eb0990a5a8bc99ea093b0b3f943f62fa043bcf028f936a3fa3eb709d468”,
“total”: 65
},
{
“date”: “2019-02-14 00:22:37”,
“positives”: 1,
“sha256”: “7c95e739912f8f7043b6b7d8355dc48e692fd1b9c0285c6736bfc6411b07d561”,
“total”: 70
},
{
“date”: “2019-02-06 21:49:30”,
“positives”: 1,
“sha256”: “aa5bb15e4e5d72c43bf28a70dcc7e513a751dd948c5100db2fd3dec636d9b7ef”,
“total”: 69
},
{
“date”: “2018-12-15 02:21:06”,
“positives”: 1,
“sha256”: “169f959197cc4f23ee7fc955708b467385c85f61ae34d58c29c246e106ffa60c”,
“total”: 69
},
{
“date”: “2018-12-14 06:06:30”,
“positives”: 1,
“sha256”: “27f890d1b7521c2e29ec925f9ae7d04b761bbb3151ba1c93b1f2f05c52bcd858”,
“total”: 67
},
{
“date”: “2018-12-14 01:15:17”,
“positives”: 1,
“sha256”: “76b8ba14f684a2f0df4c746a5c15b95ef10b47abbf2a30ef6c6923d9dd2d9485”,
“total”: 69
},
{
“date”: “2018-12-07 10:37:50”,
“positives”: 1,
“sha256”: “a2ce3e44380c080c72add41413e465c52fb6f635896f9c4ef6cba9d263367c00”,
“total”: 70
},
{
“date”: “2018-12-05 18:50:21”,
“positives”: 1,
“sha256”: “d175945ea26c1af3709a9956b66a99a951736812592d0a83c2b66343b2445fdf”,
“total”: 70
},
{
“date”: “2018-11-28 10:28:22”,
“positives”: 1,
“sha256”: “9a7990ee05873518a5bc5ab0307ab42313c0f185107e36f9583b1df73580083d”,
“total”: 69
},
{
“date”: “2018-11-20 00:10:47”,
“positives”: 1,
“sha256”: “d2dff7afe56bf27e135aef92b519bf6cdd3dfd9f82e6d33a085a0090d8a7e8fb”,
“total”: 68
},
{
“date”: “2018-11-16 00:02:43”,
“positives”: 1,
“sha256”: “36635ce9020ef0cafd3b4603f6a036d5d03ad31899362ec716462b6e84515d2d”,
“total”: 66
},
{
“date”: “2018-11-13 00:02:48”,
“positives”: 1,
“sha256”: “5a2154ee2d0a2e0024c2363eca6bb9f35d61ed4ce25ff060ff5cba5d4b51551e”,
“total”: 64
},
{
“date”: “2018-11-07 02:49:16”,
“positives”: 1,
“sha256”: “19176ea12c99c10ddfd2a973349d128542696a33cdbb6afb9188c8a0dc742970”,
“total”: 67
},
{
“date”: “2018-06-13 11:21:01”,
“positives”: 1,
“sha256”: “7c1a2baea371d2cb76074f64f97c2839f23fea9f25d68d77cb036f0a503ae96a”,
“total”: 68
},
{
“date”: “2018-06-13 04:29:41”,
“positives”: 1,
“sha256”: “a2bdd7125ebc65d7b07b04573baa0533fad583c8e808c713717aadcf965526bb”,
“total”: 68
},
{
“date”: “2018-03-20 20:56:08”,
“positives”: 1,
“sha256”: “3ce6aa59e4dacef546f50ade8bdb0fdb8ecd1c6c2ea39e0da91b21c9a88a4c9b”,
“total”: 64
},
{
“date”: “2018-03-13 19:20:49”,
“positives”: 1,
“sha256”: “65c55562e909086dae9d1cae533a6d984a3dc03d84a26197062a9b4e3e5bc180”,
“total”: 67
},
{
“date”: “2018-02-23 04:53:06”,
“positives”: 1,
“sha256”: “3c2fb865e1dbdaef7201dc4c6977d461855178544e2aa327f1f2d4af730fddb1”,
“total”: 65
},
{
“date”: “2018-02-16 05:38:24”,
“positives”: 1,
“sha256”: “7b08a31ff8c5b4e7e7d521a1cb9f2fb1dcea2aeefa527ec745518eb2e78ebca3”,
“total”: 66
},
{
“date”: “2018-02-16 00:49:40”,
“positives”: 1,
“sha256”: “cfb2f86095a7d1062ff37751349667e989307083a911c40d3de6ccf9374e22ca”,
“total”: 66
},
{
“date”: “2018-02-15 18:35:09”,
“positives”: 1,
“sha256”: “1322fabdae55a4170b461e8f47322c736566bbddb1fd0c69549516b97b5f009e”,
“total”: 66
},
{
“date”: “2018-02-15 04:59:13”,
“positives”: 1,
“sha256”: “e5c39e5eb4330b66f42bd996ef398184929fb255392ef42d0ea33dfeab1df173”,
“total”: 67
},
{
“date”: “2018-02-15 04:23:20”,
“positives”: 1,
“sha256”: “5fef649857ff1fc36e0f0058953d19d068b84cd3933fc2cd31a78a0d78fda6e3”,
“total”: 68
},
{
“date”: “2018-02-15 04:13:30”,
“positives”: 1,
“sha256”: “974000faef14e4079d2b1cd1c3d552792760e797959b1992440d5ed69112ed3f”,
“total”: 66
},
{
“date”: “2017-12-15 05:41:12”,
“positives”: 1,
“sha256”: “f89f86d74823c5858e787cf106c843e5bdfa63d0f885a000b15e2d943152e6f6”,
“total”: 68
},
{
“date”: “2017-12-15 04:54:17”,
“positives”: 1,
“sha256”: “f979244b3337e7bb06c9838c17f1f10428aa576eec82d5c4c349110f117ba4b8”,
“total”: 67
},
{
“date”: “2017-12-15 03:55:13”,
“positives”: 1,
“sha256”: “434bb718bda0c483feaccf7638b550504b16ac69726d6bf2f1ec1b6d47e97cd9”,
“total”: 68
},
{
“date”: “2017-12-15 03:11:54”,
“positives”: 1,
“sha256”: “d33c656d9edfd4e822d2160ca671aa86850fef610bb09106c57c9b508350e6e9”,
“total”: 69
},
{
“date”: “2017-12-14 07:12:14”,
“positives”: 1,
“sha256”: “8e12b99bf88bef72e0e7032bfd814c6eec212dc5209f87a6352cbd962f5556d5”,
“total”: 68
},
{
“date”: “2017-12-14 00:22:31”,
“positives”: 1,
“sha256”: “b54f0f0e4de92baddd73ffd305988ed76ae48d6f80a2bf318c890cb39ebf57f6”,
“total”: 67
},
{
“date”: “2017-11-29 11:37:33”,
“positives”: 2,
“sha256”: “d666e0976b1e98b55278c1d5dc21adc74eec11411e60f712111b1ab70fd4b71b”,
“total”: 68
},
{
“date”: “2017-11-27 06:59:11”,
“positives”: 2,
“sha256”: “6a8c3679a95ce6f4ae8bca3c3eef05b4fdbf8143ee049b0d93f5ef01bab5e878”,
“total”: 67
},
{
“date”: “2017-11-24 07:21:26”,
“positives”: 1,
“sha256”: “c0d19f454e2e9002a1e1386cf1db4a76f73f4dd6e4230350cf52f36765347258”,
“total”: 68
},
{
“date”: “2017-11-24 03:56:35”,
“positives”: 1,
“sha256”: “0f23c1e5e8687b46d1ccb0a729df866c58ab59697180aecd8af02f6727657031”,
“total”: 68
},
{
“date”: “2017-11-21 22:23:00”,
“positives”: 1,
“sha256”: “f7c6445b8e6d5313a7b625e7897f017fb2184609aed610893d723c4618a2e258”,
“total”: 68
},
{
“date”: “2017-11-08 04:37:04”,
“positives”: 1,
“sha256”: “ca7e75bd2297f76f915ed74ef468d7cfc4cd79a3b68c1c6b9d5c87ee71718fc0”,
“total”: 67
},
{
“date”: “2017-11-07 22:17:07”,
“positives”: 1,
“sha256”: “aaa197e09b0d95c6041b9f6c9943c501c5279a4055018f8354958a1216e0a918”,
“total”: 67
},
{
“date”: “2017-11-06 20:00:09”,
“positives”: 1,
“sha256”: “4e88f2052863ea40c5643967930208e59a2fedd96429208a8607c3d4566ab39c”,
“total”: 68
},
{
“date”: “2017-11-06 19:35:32”,
“positives”: 1,
“sha256”: “77c07383082188698cf4ed926cbdade7f2bfe2b327e83fd03215d6d1ef7b6225”,
“total”: 66
},
{
“date”: “2017-10-27 06:37:50”,
“positives”: 1,
“sha256”: “6601e33723a691c81f6c5937750b891dc6349c2e6050df61dbc1061e85b74ea3”,
“total”: 67
},
{
“date”: “2017-10-24 22:03:20”,
“positives”: 1,
“sha256”: “17388b47122dd6088049ab9f2cdc65d9831751e8fae4882c1369265fdd12d6ec”,
“total”: 67
},
{
“date”: “2017-09-27 12:52:41”,
“positives”: 1,
“sha256”: “424483c1c0b45afc74248fdc7f468c274ff8a2b065eb7c9d08b78a4eb2225df3”,
“total”: 65
},
{
“date”: “2017-09-22 18:54:13”,
“positives”: 1,
“sha256”: “2e6097ddf04e4d8d52ffacab22ba3c3e854c5a71c287227b3dcd402867578aa5”,
“total”: 65
},
{
“date”: “2017-09-22 06:29:46”,
“positives”: 1,
“sha256”: “8c3682f3d63f9e670438010bfd4a5ce8c56f742997c92e2fb92d0fdb108b48e7”,
“total”: 63
},
{
“date”: “2017-09-22 05:46:51”,
“positives”: 1,
“sha256”: “4283c45779e24b9e40fa0ee503861e1c8745af147f56a5f6e4cb91870fab96a4”,
“total”: 65
},
{
“date”: “2017-09-20 11:27:17”,
“positives”: 1,
“sha256”: “09752c64d53c7d2e5e4808f6d211c28662dca763e1ea74565a874ad0bec3bcd6”,
“total”: 57
},
{
“date”: “2017-09-18 20:04:26”,
“positives”: 2,
“sha256”: “926ef97aa2f7e996b72548e2ad8f4e5d0f8f435d38ae3793587a0e4968b35ca4”,
“total”: 64
},
{
“date”: “2017-09-17 17:59:40”,
“positives”: 3,
“sha256”: “854b8efa75a8f9dcdda22616124bf245cba0bd4fb8fe3b31770f320065826421”,
“total”: 65
}
],
“ReferrerHashes”: [
{
“date”: “2019-08-07 04:18:23”,
“positives”: 1,
“sha256”: “6a23380c245cfb52ab23df3a3960dacba9384fcbad9a04009f3748f8633c90ae”,
“total”: 67
},
{
“date”: “2019-08-06 12:14:22”,
“positives”: 3,
“sha256”: “1a87a0f0d5d923fd5e5b172d9bbc1e21dcba5eef6b014eaca0f785bc488c7042”,
“total”: 71
},
{
“date”: “2019-08-06 21:35:56”,
“positives”: 57,
“sha256”: “862cf0bcb53023bba7bc00e8a2e94224f282b0e560534c5d893bf01a957ef89a”,
“total”: 73
},
{
“date”: “2019-08-07 01:20:45”,
“positives”: 1,
“sha256”: “0f5d6e02d8a02ac2676f9fb290f079f0a6cddb30c6b46abf16373cf0fd751828”,
“total”: 65
},
{
“date”: “2019-08-06 22:13:39”,
“positives”: 13,
“sha256”: “44a1b44fa0e6bb6ec0e54f91675309a66477ee8331021ef04483a077ecdd933a”,
“total”: 71
},
{
“date”: “2019-08-06 13:06:30”,
“positives”: 1,
“sha256”: “9376db6bc55e4f5bdb182c31ba50817247029964da6bee94c68f6378e6f95dce”,
“total”: 73
},
{
“date”: “2019-08-06 05:53:55”,
“positives”: 62,
“sha256”: “6ee8e56399595d3ff86085c979d5ef9f601974c287f10f232b9d86e53f7dfce7”,
“total”: 72
},
{
“date”: “2019-08-06 00:30:27”,
“positives”: 1,
“sha256”: “2d692b2a45118e215632f4febf6525a2ffaa8036f157fc16d8b8593237f570fb”,
“total”: 68
},
{
“date”: “2019-08-05 23:22:16”,
“positives”: 5,
“sha256”: “d6de8e9d9da6935a587e52ce4717e337b4374dd7e073a3f9116dc743f461db30”,
“total”: 71
},
{
“date”: “2019-08-04 09:04:16”,
“positives”: 1,
“sha256”: “fb34109483cc2a8492a4d5784cd221f042d285dba06078f602c96963916bfd18”,
“total”: 70
},
{
“date”: “2019-08-04 06:27:07”,
“positives”: 1,
“sha256”: “d240a43566eaea3c1360bfec0c66b750c39e24c10f3a123068ac79066fa72890”,
“total”: 66
},
{
“date”: “2019-08-02 11:16:25”,
“positives”: 8,
“sha256”: “972716af22ff14625ef7fe1b2e52a2e0a75f601a59a753edb375c06751881078”,
“total”: 72
},
{
“date”: “2019-08-02 07:51:32”,
“positives”: 1,
“sha256”: “fd0f38e548fd4991d72a59eaa2a372639c8972e1dfbcf7319ef3e24814188370”,
“total”: 73
},
{
“date”: “2019-08-01 20:56:38”,
“positives”: 49,
“sha256”: “def29f89b873e5ca99f244b8372003d278dfbecff2fc8ce2b54487269835847a”,
“total”: 72
},
{
“date”: “2019-08-01 10:01:19”,
“positives”: 30,
“sha256”: “c69abe7d288f42dc96e2e0adecc231580c067f660b20a97e5bd2f918c8a3b55e”,
“total”: 71
},
{
“date”: “2019-08-01 09:42:24”,
“positives”: 1,
“sha256”: “23c65bcbd8637e7a3f0a1d793a1e4721f67821d355d88bc26ca54c9b6979b730”,
“total”: 73
},
{
“date”: “2019-08-01 08:48:07”,
“positives”: 2,
“sha256”: “2e75f02b6f0f662781ab60bd440f85f7d5d503ee2fd9056f2eafd65e72c00319”,
“total”: 71
},
{
“date”: “2019-08-01 07:16:04”,
“positives”: 56,
“sha256”: “c1122304ecafd8d84bafa35aa9639616c822bc7809d6c2f4b3665a9829b75b0e”,
“total”: 72
},
{
“date”: “2019-08-01 04:23:52”,
“positives”: 10,
“sha256”: “b24829ad9a413777faf4180d36d6edd0d7d1533a1580b67a9adbefef2f9dcc84”,
“total”: 74
},
{
“date”: “2019-08-01 00:22:44”,
“positives”: 1,
“sha256”: “4094e46442a0434eb4d42e7c6af999b054ffc88998c32775487962e511194d59”,
“total”: 71
},
{
“date”: “2019-07-31 23:23:13”,
“positives”: 3,
“sha256”: “3f24f0ff7310887aba56297559e1a9620acb86227ef08198128e62186aca89a3”,
“total”: 71
},
{
“date”: “2019-07-31 13:06:19”,
“positives”: 1,
“sha256”: “31bbceff0f7d7bf2b69c8d33d7a90c49ffa70e1adbc57dbee6233a3bf98f7839”,
“total”: 72
},
{
“date”: “2019-07-31 12:38:08”,
“positives”: 1,
“sha256”: “840ea4c13b584078dcf0d22fe2f0bb849f170a1b26e9f0d0f73cc4f5dc375e68”,
“total”: 68
},
{
“date”: “2019-07-31 02:05:36”,
“positives”: 1,
“sha256”: “8c630b98a377b5e95c00cfedb8941f0698a12c743965c37bf32fdd71f077a521”,
“total”: 72
},
{
“date”: “2019-07-30 22:33:03”,
“positives”: 6,
“sha256”: “9ed87645ff9e169caf8ba16e10f4f343374d1397f2c786ffbd6241028125842b”,
“total”: 71
},
{
“date”: “2019-07-30 18:31:29”,
“positives”: 2,
“sha256”: “5505e70b14ec24981a56963476aec10e18f3f6e7fbf331ae8d669784bd07e2e2”,
“total”: 72
},
{
“date”: “2019-07-30 17:32:07”,
“positives”: 1,
“sha256”: “d977d34dc655bff576a528058a819bea13df60d1dd41ace5e5411b4e7f2b7deb”,
“total”: 71
},
{
“date”: “2019-07-30 17:31:26”,
“positives”: 8,
“sha256”: “2ee00694ac487e3edff21da729e5268d40c5f2ed14fd7fefc64cd3b07220e7e9”,
“total”: 72
},
{
“date”: “2019-07-30 16:10:06”,
“positives”: 1,
“sha256”: “8eb3c1a1ddbba81745e339cb1cf24af6063089e42844a84328eab3f55741ab4c”,
“total”: 70
},
{
“date”: “2019-07-30 10:31:43”,
“positives”: 1,
“sha256”: “d431766ef11bc75fd9bb4e411cfb477881f01718aba8e3f7af1906687246e126”,
“total”: 73
},
{
“date”: “2019-07-30 09:54:21”,
“positives”: 12,
“sha256”: “8bb8bbe0fb4295f2c4c85fc8923f01c1a47b1c11dfc404d2ee09ed607f029566”,
“total”: 73
},
{
“date”: “2019-07-29 09:35:45”,
“positives”: 19,
“sha256”: “caffb544913d8edf4e54c4290102d8223e1aee87cb7390d11db36f3150bf2a1d”,
“total”: 72
},
{
“date”: “2019-07-29 08:11:55”,
“positives”: 1,
“sha256”: “0e566ca909ddebc95773fa03631d2943627d0ad0f645ae927f8ee3b26bb0462f”,
“total”: 73
},
{
“date”: “2019-07-29 06:39:40”,
“positives”: 1,
“sha256”: “492f936d0cc75bfecd435569b47d52781427d03020b9343a45d485534d6047a7”,
“total”: 73
},
{
“date”: “2019-07-29 06:03:10”,
“positives”: 1,
“sha256”: “59ba791ef058382c652a920ee6e9a7863d878febff77c7f79c050a0ee9234bd5”,
“total”: 71
},
{
“date”: “2019-07-28 22:55:06”,
“positives”: 5,
“sha256”: “16bc74d38ecf74d097288ec32914ffbff843ad019dcd1f57b88db8d765a62f59”,
“total”: 71
},
{
“date”: “2019-07-28 22:29:55”,
“positives”: 2,
“sha256”: “f1758757134372e3ba5c35758c6801f8e9c8dc41ab6107fede46c391764104ef”,
“total”: 69
},
{
“date”: “2019-07-28 19:47:32”,
“positives”: 1,
“sha256”: “5a4d23942b8b8f8adf64bb120926cdcb16e4e2fea46713128f9872359af6bc37”,
“total”: 71
},
{
“date”: “2019-07-28 19:26:12”,
“positives”: 5,
“sha256”: “59b010f9277faa4cbe23ba8c827cc51dbe0d2d0a20a26762c462543c4904af98”,
“total”: 72
},
{
“date”: “2019-07-28 16:16:05”,
“positives”: 1,
“sha256”: “418875b84c0f12355bd904495ebebbc532cbdf186bc6e4a0d755e5198e6783ab”,
“total”: 73
},
{
“date”: “2019-07-28 07:42:30”,
“positives”: 3,
“sha256”: “e58de457123bd77d7b5da7a28bb64be4e80b0ca530e670f23a50e4982e5d4b0f”,
“total”: 72
},
{
“date”: “2019-07-28 05:35:30”,
“positives”: 2,
“sha256”: “85792283f879c79d2ebc1cd1feecfe709db7513ed67a5bc4971bc5e986150892”,
“total”: 72
},
{
“date”: “2019-07-27 18:33:53”,
“positives”: 1,
“sha256”: “942fe0e396b81f2f1b36fac4b1d63da45aad18f0a01ca75a0e62cbf8d98ef8a1”,
“total”: 71
},
{
“date”: “2019-07-25 23:58:29”,
“positives”: 59,
“sha256”: “ac103046aaaaa44a7d6139011230347ac9357c66ad953137441f70a3f3af058b”,
“total”: 72
},
{
“date”: “2019-07-25 04:12:32”,
“positives”: 57,
“sha256”: “7aaf397e3c59716f6b4c73a913449ef08e341b6495a8b87f7e76cf9d270caa65”,
“total”: 71
},
{
“date”: “2019-07-24 04:08:57”,
“positives”: 59,
“sha256”: “617ab529df4c52e509f8941cb7b2962884605614b598960b521e84acf2161a23”,
“total”: 72
},
{
“date”: “2019-07-24 00:15:16”,
“positives”: 59,
“sha256”: “ececea4c4674dfb7434735951afab4977f6e3f4d3c970c646330155a352d2ccd”,
“total”: 72
},
{
“date”: “2019-07-24 00:10:15”,
“positives”: 57,
“sha256”: “6da68c8871bb9951464546903c365712870cc31e74556ddfc4741a1cdfd3deb4”,
“total”: 72
},
{
“date”: “2019-07-23 23:32:30”,
“positives”: 3,
“sha256”: “584c0d3ddc6d0b768fb1e21dede8512a2e83a5cfc08f0e4c1cfeda6432cb3940”,
“total”: 70
},
{
“date”: “2019-07-23 23:31:28”,
“positives”: 1,
“sha256”: “c7987c7726a5a5fd0558ef3acd34447643798406ade398aa1dd54d394f110b6a”,
“total”: 73
}
]
}
},
“DBotScore”: {
“Vendor”: “VirusTotal”,
“Indicator”: "google.com“,
“Score”: 1,
“Type”: “domain”
}
}
</pre>
<h5>Human Readable Output</h5>
<h2>VirusTotal Domain Reputation for: google.com</h2>
<h4>Domain categories:<span> </span><em>searchengines,search engines and portals</em>
</h4>
<p> </p>
<p>VT Link:<span> </span>google.com<br> Detected URL count:<span> </span><strong>100</strong><br> Detected downloaded sample count:<span> </span><strong>100</strong><br> Undetected downloaded sample count:<span> </span><strong>100</strong><br> Detected communicating sample count:<span> </span><strong>100</strong><br> Undetected communicating sample count:<span> </span><strong>100</strong><br> Detected referrer sample count:<span> </span><strong>100</strong><br> Undetected referrer sample count:<span> </span><strong>100</strong><br> Resolutions count:<span> </span><strong>1000</strong></p>
<p> </p>
<h3>Whois Lookup</h3>
<hr>
<p><strong>Domain Name</strong>: GOOGLE.COM<br> <strong>Registry Domain ID</strong>: 2138514_DOMAIN_COM-VRSN<br> <strong>Registrar WHOIS Server</strong>: whois.markmonitor.com<br> <strong>Registrar URL</strong>:<span> </span>http://www.markmonitor.com<br> <strong>Updated Date</strong>: 2018-02-21T18:36:40Z<br> <strong>Creation Date</strong>: 1997-09-15T04:00:00Z<br> <strong>Registry Expiry Date</strong>: 2020-09-14T04:00:00Z<br> <strong>Registrar</strong>: MarkMonitor Inc.<br> <strong>Registrar IANA ID</strong>: 292<br> <strong>Registrar Abuse Contact Email</strong>:<span> </span>https://icann.org/epp#clientDeleteProhibited<br> <strong>Domain Status</strong>: clientTransferProhibited<span> </span>https://icann.org/epp#clientTransferProhibited<br> <strong>Domain Status</strong>: clientUpdateProhibited<span> </span>https://icann.org/epp#clientUpdateProhibited<br> <strong>Domain Status</strong>: serverDeleteProhibited<span> </span>https://icann.org/epp#serverDeleteProhibited<br> <strong>Domain Status</strong>: serverTransferProhibited<span> </span>https://icann.org/epp#serverTransferProhibited<br> <strong>Domain Status</strong>: serverUpdateProhibited<span> </span>https://icann.org/epp#serverUpdateProhibited<br> <strong>Name Server</strong>: NS1.GOOGLE.COM<br> <strong>Name Server</strong>: NS2.GOOGLE.COM<br> <strong>Name Server</strong>: NS3.GOOGLE.COM<br> <strong>Name Server</strong>: NS4.GOOGLE.COM<br> <strong>DNSSEC</strong>: unsigned<br> <strong>Domain Name</strong>: google.com<br> <strong>Updated Date</strong>: 2018-02-21T10:45:07-0800<br> <strong>Creation Date</strong>: 1997-09-15T00:00:00-0700<br> <strong>Registrar Registration Expiration Date</strong>: 2020-09-13T21:00:00-0700<br> <strong>Registrar</strong>: MarkMonitor, Inc.<br> <strong>Domain Status</strong>: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)<br> <strong>Domain Status</strong>: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)<br> <strong>Domain Status</strong>: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)<br> <strong>Domain Status</strong>: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)<br> <strong>Domain Status</strong>: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)<br> <strong>Domain Status</strong>: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)<br> <strong>Registrant Country</strong>: US<br> <strong>Admin Organization</strong>: Google LLC<br> <strong>Admin State/Province</strong>: CA<br> <strong>Admin Country</strong>: US<br> <strong>Tech Organization</strong>: Google LLC<br> <strong>Tech State/Province</strong>: CA<br> <strong>Tech Country</strong>: US<br> <strong>Name Server</strong>: ns4.google.com<br> <strong>Name Server</strong>: ns3.google.com<br> <strong>Name Server</strong>: ns2.google.com<br> <strong>Name Server</strong>: ns1.google.com</p>
<h3 id="h_92d67975-2612-496a-812e-f6145940776e">5. Submit a file for scanning</h3>
<hr>
<p>Submits a file for scanning.</p>
<h5>Required Permissions</h5>
<p>Public API key</p>
<h5>Base Command</h5>
<p><code>file-scan</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162.667px;"><strong>Argument Name</strong></th>
<th style="width: 453.333px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162.667px;">entryID</td>
<td style="width: 453.333px;">The file entry ID to submit.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162.667px;">uploadURL</td>
<td style="width: 453.333px;">Private API extension. Special upload URL for files larger than 32 MB.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 175px;"><strong>Path</strong></th>
<th style="width: 98px;"><strong>Type</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">vtScanID</td>
<td style="width: 98px;">unknown</td>
<td style="width: 468px;">Scan IDs of the submitted files.</td>
</tr>
<tr>
<td style="width: 175px;">vtLink</td>
<td style="width: 98px;">string</td>
<td style="width: 468px;">VirusTotal permanent link.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!file-scan entryID=88@3</pre>
<p> </p>
<h5>Context Example</h5>
<pre>{
“vtScanID”: “ebb031c3945e884e695dbc63c52a5efcd075375046c49729980073585ee13c52-1565189506”
}
</pre>
<h5>Human Readable Output</h5>
<h2>VirusTotal scan file for<span> </span>88@3</h2>
<p>Resource:<span> </span><strong>ebb031c3945e884e695dbc63c52a5efcd075375046c49729980073585ee13c52</strong><br> MD5 / SHA1 / SHA256:<span> </span><strong>8bd6509aba6eafe623392995b08c7047 / c1f95108a34228535a9262085e784d7c3e27fc68 / ebb031c3945e884e695dbc63c52a5efcd075375046c49729980073585ee13c52</strong></p>
<h3 id="h_eec7f2e8-1ea2-4993-8db0-a7d73b528b70">6. Re-scan a file</h3>
<hr>
<p>Re-scans an already submitted file. This avoids having to upload the file again.</p>
<h5>Required Permissions</h5>
<p>Public API key</p>
<h5>Base Command</h5>
<p><code>file-rescan</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 166.667px;"><strong>Argument Name</strong></th>
<th style="width: 491.333px;"><strong>Description</strong></th>
<th style="width: 82px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 166.667px;">file</td>
<td style="width: 491.333px;">Hash of the file to re-scan. Supports MD5, SHA1, and SHA256.</td>
<td style="width: 82px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 167px;"><strong>Path</strong></th>
<th style="width: 106px;"><strong>Type</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">vtScanID</td>
<td style="width: 106px;">unknown</td>
<td style="width: 468px;">Scan IDs of the submitted files.</td>
</tr>
<tr>
<td style="width: 167px;">vtLink</td>
<td style="width: 106px;">string</td>
<td style="width: 468px;">VirusTotal permanent link.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!file-rescan file=4604aeb7382c60bf29397ec655a72623</pre>
<h5>Context Example</h5>
<pre>{
“vtScanID”: [
“6bc32a390752c8da585a9985f9d586f9bfba15cc42ac628701bff4005add1158-1565189306”
]
}
</pre>
<h5>Human Readable Output</h5>
<h2>VirusTotal File Rescan for:<span> </span>4604aeb7382c60bf29397ec655a72623</h2>
<p>Scan ID:<span> </span><strong>6bc32a390752c8da585a9985f9d586f9bfba15cc42ac628701bff4005add1158-1565189306</strong><br> MD5 / SHA1 / SHA256:<span> </span><strong>undefined / undefined / 6bc32a390752c8da585a9985f9d586f9bfba15cc42ac628701bff4005add1158</strong></p>
<h3 id="h_025c1f6e-75bb-4b41-b5f1-34ffa1d1dafc">7. Scan a URL</h3>
<hr>
<p>Scans a specified URL.</p>
<h5>Required Permissions</h5>
<p><strong>Public API key</strong></p>
<p> </p>
<h5>Base Command</h5>
<p><code>url-scan</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
<th style="width: 167px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">url</td>
<td style="width: 400px;">The URL to scan.</td>
<td style="width: 167px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<pre>{
“vtScanID”: [
“dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1565190453”
]
}
</pre>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 172.333px;"><strong>Path</strong></th>
<th style="width: 94.6667px;"><strong>Type</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172.333px;">vtScanID</td>
<td style="width: 94.6667px;">unknown</td>
<td style="width: 473px;">Scan IDs of the submitted URLs.</td>
</tr>
<tr>
<td style="width: 172.333px;">vtLink</td>
<td style="width: 94.6667px;">string</td>
<td style="width: 473px;">VirusTotal permanent link.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!url-scan url=www.google.com</pre>
<h5>Human Readable Output</h5>
<h2>VirusTotal URL scan for:<span> </span>http://www.google.com/</h2>
<p> </p>
<p>Scan ID: dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1565190453<br> Scan Date: 2019-08-07 15:07:33</p>
<h3 id="h_ccb076d6-ab8f-4872-8329-b7fc96d4483d">8. Add comments to a resource</h3>
<hr>
<p>Adds comments to files and URLs.</p>
<h5>Required Permissions</h5>
<p>Public API key</p>
<h5>Base Command</h5>
<p><code>vt-comments-add</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170.333px;"><strong>Argument Name</strong></th>
<th style="width: 498.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170.333px;">resource</td>
<td style="width: 498.667px;">The file hash (MD5, SHA1, or SHA256) or URL on which you’re commenting.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 170.333px;">comment</td>
<td style="width: 498.667px;">The actual review, which you can tag by using the “#” twitter-like syntax, for example, #disinfection #zbot, and reference users using the “@” syntax, for example, @VirusTotalTeam).</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!vt-comments-add resource=ebb031c3945e884e695dbc63c52a5efcd075375046c49729980073585ee13c52 comment=“Documentation item”</pre>
<h5>Human Readable Output</h5>
<p>Your comment was successfully posted</p>
<h3 id="h_d274159f-999b-476b-a7f7-91dcf4042957">9. Get a URL for large files</h3>
<hr>
<p>Get a special URL for files larger than 32 MB.</p>
<h5>Required Permissions</h5>
<p>Private API key</p>
<h5>Base Command</h5>
<p><code>vt-file-scan-upload-url</code></p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 171.667px;"><strong>Path</strong></th>
<th style="width: 101.333px;"><strong>Type</strong></th>
<th style="width: 468px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 171.667px;">vtUploadURL</td>
<td style="width: 101.333px;">unknown</td>
<td style="width: 468px;">The special upload URL for large files.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3bb5bb86-b6b2-424e-8e75-c227a913e7a2">10. Get comments for a resource</h3>
<hr>
<p>Retrieves comments for a given resource.</p>
<h5>Required Permissions</h5>
<p>Private API key</p>
<h5>Base Command</h5>
<p><code>vt-comments-get</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 169.333px;"><strong>Argument Name</strong></th>
<th style="width: 499.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169.333px;">resource</td>
<td style="width: 499.667px;">The file hash (MD5, SHA1, orSHA256) or URL from which you’re retrieving comments.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 169.333px;">before</td>
<td style="width: 499.667px;">Datetime token in the format YYYYMMDDHHMISS. You can use this for paging.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h3>Notes</h3>
<p>The <code>!ip</code> and <code>!domain</code> DBbot scores are calculated according to the positives result in the response.</p>
<p>In the VT API (as opposed to the VT UI), domain and ip are analyzed according to the files downloaded from them.</p>
<p>We take detected samples (files that was marked malicious by VT engines) into consideration when calculating the DBot score.</p>
<h5>How DBot score is calculated:</h5>
<p>Bad - If the number of positives downloads exceeds the specified thresholds.</p>
<p>Suspicious - If the number of positives downloads divided by 2 exceeds the specified thresholds,</p>
<p>otherwise the DBot score will be marked as good.</p>

