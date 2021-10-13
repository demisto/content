<!-- HTML_DOC -->
<p>Use the URLhaus integration to get information about URLs and domains, and to download malware samples.</p>
<h2>
<a id="Configure_URLhaus_on_Demisto_3"></a>Configure URLhaus on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for URLhaus.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.<span> </span>https://192.168.0.1)</strong></li>
<li><strong>Source Reliability.</strong> Reliability of the source providing the intelligence data. (The default value is C - Fairly reliable)</li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>Blacklists appearances threshold</strong></li>
<li><strong>Compromised (is malicious)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>
<a id="Commands_16"></a>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_d1d27e6a-8238-418c-bdb3-d4a9f01495d1" target="_self">Get information for a URL: url</a></li>
<li><a href="#h_986aaa83-1a4c-410c-ad19-827ee0b3b282" target="_self">Get information for a domain: domain</a></li>
<li><a href="#h_ef2f4237-410b-4ddb-9730-48b02fe64e33" target="_self">Get information for a file: file</a></li>
<li><a href="#h_826fb182-fa39-469e-821e-ca38c292c534" target="_self">Download a malware sample: urlhaus-download-sample</a></li>
</ol>
<h3 id="h_d1d27e6a-8238-418c-bdb3-d4a9f01495d1">
<a id="1_Get_information_for_a_URL_22"></a>1. Get information for a URL</h3>
<hr>
<p>Retrieves URL information from URLhaus.</p>
<h5>
<a id="Base_Command_25"></a>Base Command</h5>
<p><code>url</code></p>
<h5>
<a id="Input_28"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 332px;"><strong>Argument Name</strong></th>
<th style="width: 229px;"><strong>Description</strong></th>
<th style="width: 179px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332px;">url</td>
<td style="width: 229px;">URL to query.</td>
<td style="width: 179px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_35"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 226px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 461px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">URL.Data</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">The URL.</td>
</tr>
<tr>
<td style="width: 226px;">URL.Malicious.Vendor</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">Vendor that reported the URL as malicious.</td>
</tr>
<tr>
<td style="width: 226px;">URL.Malicious.Description</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">Description of the malicious URL.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.ID</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">Unique identifier of the URLhaus database entry.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Status</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">The current status of the URL.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Host</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">The extracted host of the malware URL (IP address or domain name/FQDN).</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.DateAdded</td>
<td style="width: 53px;">date</td>
<td style="width: 461px;">Date the URL was added to URLhaus.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Threat</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">The threat corresponding to this malware URL.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Blacklist.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 461px;">Name of the blacklist.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Tags</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">A list of tags associated with the queried malware URL.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Payload.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 461px;">Payload file name.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Payload.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 461px;">Payload file type.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Payload.MD5</td>
<td style="width: 53px;">String</td>
<td style="width: 461px;">MD5 hash of the HTTP response body (payload).</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Payload.VT.Result</td>
<td style="width: 53px;">Number</td>
<td style="width: 461px;">VirusTotal results for the payload.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Type</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">Indicator type.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Vendor</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Score</td>
<td style="width: 53px;">number</td>
<td style="width: 461px;">The actual score.</td>
</tr>
<tr>
<td style="width: 226px;">DBotScore.Indicator</td>
<td style="width: 53px;">string</td>
<td style="width: 461px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Blacklist.Status</td>
<td style="width: 53px;">String</td>
<td style="width: 461px;">Status of the URL in the blacklist.</td>
</tr>
<tr>
<td style="width: 226px;">URLhaus.URL.Payload.VT.Link</td>
<td style="width: 53px;">String</td>
<td style="width: 461px;">Link to the VirusTotal report.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_61"></a>Command Example</h5>
<pre>!url url="http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/"</pre>
<h5>
<a id="Human_Readable_Output_64"></a>Human Readable Output</h5>
<h3 id="h_986aaa83-1a4c-410c-ad19-827ee0b3b282">
<a id="2_Get_information_for_a_domain_67"></a>2. Get information for a domain</h3>
<hr>
<p>Retrieves domain information from URLhaus.</p>
<h5>
<a id="Base_Command_70"></a>Base Command</h5>
<p><code>domain</code></p>
<h5>
<a id="Input_73"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 302px;"><strong>Argument Name</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
<th style="width: 165px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 302px;">domain</td>
<td style="width: 273px;">Domain to query.</td>
<td style="width: 165px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_80"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 265px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 409px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 265px;">Domain.Name</td>
<td style="width: 66px;">String</td>
<td style="width: 409px;">The domain name, for example,<span> </span>google.com.</td>
</tr>
<tr>
<td style="width: 265px;">DBotScore.Type</td>
<td style="width: 66px;">string</td>
<td style="width: 409px;">Indicator type.</td>
</tr>
<tr>
<td style="width: 265px;">DBotScore.Vendor</td>
<td style="width: 66px;">string</td>
<td style="width: 409px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 265px;">DBotScore.Score</td>
<td style="width: 66px;">number</td>
<td style="width: 409px;">The actual score.</td>
</tr>
<tr>
<td style="width: 265px;">DBotScore.Indicator</td>
<td style="width: 66px;">string</td>
<td style="width: 409px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 265px;">URLhaus.Domain.FirstSeen</td>
<td style="width: 66px;">Date</td>
<td style="width: 409px;">Date that the IP was seen for the first time (UTC).</td>
</tr>
<tr>
<td style="width: 265px;">URLhaus.Domain.Blacklist.Name</td>
<td style="width: 66px;">String</td>
<td style="width: 409px;">The status of the domain in different blacklists.</td>
</tr>
<tr>
<td style="width: 265px;">URLhaus.Domain.URL</td>
<td style="width: 66px;">String</td>
<td style="width: 409px;">URLs observed on this domain.</td>
</tr>
<tr>
<td style="width: 265px;">Domain.Malicious.Vendor</td>
<td style="width: 66px;">String</td>
<td style="width: 409px;">Vendor that reported the domain as malicious.</td>
</tr>
<tr>
<td style="width: 265px;">Domain.Malicious.Description</td>
<td style="width: 66px;">String</td>
<td style="width: 409px;">Description of the malicious domain.</td>
</tr>
<tr>
<td style="width: 265px;">URLhaus.Domain.Blacklist.Status</td>
<td style="width: 66px;">String</td>
<td style="width: 409px;">Status of the URL in the blacklist.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_97"></a>Command Example</h5>
<pre>!domain domain="vektorex.com"</pre>
<h5>
<a id="Human_Readable_Output_100"></a>Human Readable Output</h5>
<h3 id="h_ef2f4237-410b-4ddb-9730-48b02fe64e33">
<a id="3_Get_information_for_a_file_103"></a>3. Get information for a file</h3>
<hr>
<p>Retrieves file information from URLhaus.</p>
<h5>
<a id="Base_Command_106"></a>Base Command</h5>
<p><code>file</code></p>
<h5>
<a id="Input_109"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 455px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">file</td>
<td style="width: 455px;">MD5 hash or SHA256 hash of the file to query.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_116"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 230px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 452px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">File.Size</td>
<td style="width: 58px;">Number</td>
<td style="width: 452px;">File size (in bytes).</td>
</tr>
<tr>
<td style="width: 230px;">File.MD5</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 230px;">File.SHA256</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.MD5</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.SHA256</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.Type</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">File type guessed by URLhaus, for example: .exe, .doc.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.Size</td>
<td style="width: 58px;">Number</td>
<td style="width: 452px;">File size (in bytes).</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.Signature</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">Malware family.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.FirstSeen</td>
<td style="width: 58px;">Date</td>
<td style="width: 452px;">Date and time (UTC) that URLhaus first saw this file (payload).</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.LastSeen</td>
<td style="width: 58px;">Date</td>
<td style="width: 452px;">Date and time (UTC) that URLhaus last saw this file (payload).</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.DownloadLink</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">Location (URL) where you can download a copy of this file.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.VirusTotal.Percent</td>
<td style="width: 58px;">Number</td>
<td style="width: 452px;">AV detection (percentage), for example: 24.14.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.VirusTotal.Link</td>
<td style="width: 58px;">String</td>
<td style="width: 452px;">Link to the VirusTotal report.</td>
</tr>
<tr>
<td style="width: 230px;">URLhaus.File.URL</td>
<td style="width: 58px;">Unknown</td>
<td style="width: 452px;">A list of malware URLs associated with this payload (max. 100).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_136"></a>Command Example</h5>
<pre>!file hash="01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b01" hash_type="SHA256"</pre>
<h3 id="h_826fb182-fa39-469e-821e-ca38c292c534">
<a id="4_Download_a_malware_sample_142"></a>4. Download a malware sample</h3>
<hr>
<p>Downloads a malware sample from URLhaus.</p>
<h5>
<a id="Base_Command_145"></a>Base Command</h5>
<p><code>urlhaus-download-sample</code></p>
<h5>
<a id="Input_148"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 202px;"><strong>Argument Name</strong></th>
<th style="width: 423px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 202px;">file</td>
<td style="width: 423px;">SHA256 hash of the file to download.</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_155"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 220px;"><strong>Path</strong></th>
<th style="width: 130px;"><strong>Type</strong></th>
<th style="width: 390px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">File.Size</td>
<td style="width: 130px;">number</td>
<td style="width: 390px;">File size.</td>
</tr>
<tr>
<td style="width: 220px;">File.SHA1</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 220px;">File.SHA256</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 220px;">File.Name</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">File name.</td>
</tr>
<tr>
<td style="width: 220px;">File.SSDeep</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">SSDeep hash of the file.</td>
</tr>
<tr>
<td style="width: 220px;">File.EntryID</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">File entry ID.</td>
</tr>
<tr>
<td style="width: 220px;">File.Info</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">File information.</td>
</tr>
<tr>
<td style="width: 220px;">File.Type</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">File type.</td>
</tr>
<tr>
<td style="width: 220px;">File.MD5</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 220px;">File.Extension</td>
<td style="width: 130px;">string</td>
<td style="width: 390px;">File extension.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_171"></a>Command Example</h5>
<pre>!file hash="01fa56184fcaa42b6ee1882787a34098c79898c182814774fd81dc18a6af0b01" hash_type="SHA256"</pre>