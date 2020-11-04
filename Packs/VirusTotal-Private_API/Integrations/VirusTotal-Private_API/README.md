<!-- HTML_DOC -->
<p>Use the Virus Total - Private API integration to investigate suspicious files, domains, URLs, IP addresses, and hashes.</p>
<p>This integration was integrated and tested with Virus Total API v2.0.</p>
<h2>Use Cases</h2>
<ul>
<li>Get extensive reports on interactions between files, domains, URLs, IP addresses, and hashes.</li>
<li>Investigate activity of recognized malware.</li>
</ul>
<h2>Configure Virus Total - Private API on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Virus Total - Private API.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance</li>
<li><strong>Virus Total private API key</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li>
<strong>Trust any certificate</strong> (not secure)</li>
<li>
<strong>File Threshold: </strong>If the number of positive results from the VT scanners exceeds the threshold, the file will be considered malicious.</li>
<li>
<strong>IP Threshold:</strong> If the number of positive results from the VT scanners exceeds the threshold, the IP address is considered malicious.</li>
<li>
<strong>URL Threshold:</strong> If the number of positive results from the VT scanners exceeds the threshold, the URL is considered malicious.</li>
<li>
<strong>Domain Threshold:</strong> If the number of positive results from the VT scanners is bigger than the threshold, the domain is considered malicious.</li>
<li>
<strong>Preferred Vendors List</strong>: A CSV list of vendors that are considered trustworthy.</li>
<li>
<strong>Preferred Vendors Threshold</strong>: The minimum number of highly trusted vendors required to consider a domain IP, URL, or file as malicious.</li>
<li>
<strong>fullResponseGlobal</strong>: Determines whether to return all results, which can number in the thousands. If <strong>true</strong>, returns all results and overrides the <em>fullResponse</em> and <em>long</em> arguments (if they are set to <strong>false</strong>) in a command. If <strong>false</strong>, the <em>fullResponse</em> and <em>long</em> arguments in the command determines how results are returned.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate URLs and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_45334592931731530695733677">Get file dynamic behavioral report: vt-private-check-file-behaviour</a></li>
<li><a href="#h_18551445133181530695739961">Get a domain report: vt-private-get-domain-report</a></li>
<li><a href="#h_65752050558221530710946829">Get malicious file report: vt-private-get-file-report</a></li>
<li><a href="#h_69328637159591530710957914">Get URL report: vt-private-get-url-report</a></li>
<li><a href="#h_2661925843991533461800180">Get IP address report: vt-private-get-ip-report</a></li>
<li><a href="#h_61744244738791530695809935">Submit a query: vt-private-search-file</a></li>
<li><a href="#h_81696018363741530710990114">Return hashes for a specific IP address: vt--private-hash-communication</a></li>
<li><a href="#h_49009414365071530711001039">Download a file: vt-private-download-file</a></li>
</ol>
<h3 id="h_45334592931731530695733677">1. Get file dynamic behavioral report</h3>
<hr>
<p>Find out which domains, files, hosts, IP addresses, mutexes, URLs, and registry keys, are associated with a specific file.</p>
<h5>Base Command</h5>
<p><code>vt-private-check-file-behaviour</code></p>
<h5>Input</h5>
<table style="width: 746px;">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 588px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">resource</td>
<td style="width: 588px;">The MD5, SHA-1, and SHA-256 hash of the file whose dynamic behavioral report you want to retrieve</td>
</tr>
<tr>
<td style="width: 133px;">threshold</td>
<td style="width: 588px;">If the number of positives is larger than the threshold, the file is considered malicious. If threshold is not specified, the default file threshold is used.<br> You configure the default in the instance settings.</td>
</tr>
<tr>
<td style="width: 133px;">fullResponse</td>
<td style="width: 588px;">Returns all results. Results can number in the thousands, we recommend not using fullResponse in playbooks. The default value is <code>false</code>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 271px;"><strong>Path</strong></th>
<th style="width: 450px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 271px;">File.MD5</td>
<td style="width: 450px;">MD5 of the file</td>
</tr>
<tr>
<td style="width: 271px;">File.SHA1</td>
<td style="width: 450px;">SHA-1 of the file</td>
</tr>
<tr>
<td style="width: 271px;">File.SHA256</td>
<td style="width: 450px;">SHA-256 of the file</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedDomains</td>
<td style="width: 450px;">Domains that the hash communicates with</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedURLs</td>
<td style="width: 450px;">URLs that the hash communicates with</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedIPs</td>
<td style="width: 450px;">IPs that the hash communicates with</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedHosts</td>
<td style="width: 450px;">Hosts that the hash communicates with</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedFiles</td>
<td style="width: 450px;">Files that are related to this hash</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedRegistryKeys</td>
<td style="width: 450px;">Keys that are related to this hash</td>
</tr>
<tr>
<td style="width: 271px;">File.VirusTotal.RelatedMutexes</td>
<td style="width: 450px;">Mutexes that are related to this hash</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!vt-private-check-file-behaviour resource="2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae" threshold=20</pre>
<h5>Context Example</h5>
<pre>{
  "SHA256": "2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae",
  "VirusTotal": {
    "RelatedDomains": [
      "stromoliks.com",
      "promoliks.com",
      "google.com",
      "fkjdeljfeew32233.com",
      "pornoliks.com",
      "fdwelklwe3093443.com"
    ],
    "RelatedFiles": [
      "C:\\WINDOWS\\system32\\ntdll.dll",
      "C:\\DOCUME~1\\JANETT~1\\LOCALS~1\\Temp\\~TM4.tmp",
      "C:\\DOCUME~1\\JANETT~1\\LOCALS~1\\Temp\\~DF3C0D.tmp",
      "C:\\WINDOWS\\system32\\kernel32.dll",
      "C:\\DOCUME~1\\JANETT~1\\LOCALS~1\\Temp\\~TM3.tmp",
      "Cmgr.exe"
    ],
    "RelatedHosts": [
      "224.0.0.22",
      "51.140.127.197",
      "10.0.2.2",
      "239.255.255.250",
      "255.255.255.255",
      "10.0.2.255",
      "10.0.2.15",
      "82.112.184.197",
      "0.0.0.0",
      "216.58.206.238"
    ],
    "RelatedIPs": [
      "51.140.127.197",
      "10.0.2.2",
      "239.255.255.250",
      "10.0.2.255",
      "10.0.2.15",
      "82.112.184.197",
      "255.255.255.255",
      "127.0.0.1",
      "216.58.206.238"
    ],
    "RelatedMutexes": [
      "ShimCacheMutex",
      "{65D180CA-BACE-614C-7239-5ABDD5E947B0}"
    ],
    "RelatedRegistryKeys": [
      "HKEY_LOCAL_MACHINE\\\\SOFTWARE\\Microsoft\\VBA\\Monitors",
      "HKEY_LOCAL_MACHINE\\\\System\\Setup",
      "HKEY_CLASSES_ROOT\\\\http\\shell\\open\\command",
      "0x000000b8\\\\Help",
      "HKEY_LOCAL_MACHINE\\\\Software\\Microsoft\\Rpc",
      "HKEY_LOCAL_MACHINE\\\\Software\\Microsoft\\Windows",
      "0x000000b8\\\\HTML Help",
      "HKEY_LOCAL_MACHINE\\\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Cmgr.exe\\RpcThreadPoolThrottle",
      "HKEY_LOCAL_MACHINE\\\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
      "0x00000090\\\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
      "0x000000ac\\\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
      "HKEY_LOCAL_MACHINE\\\\Software\\Microsoft\\Rpc\\PagedBuffers"
    ],
    "RelatedURLs": []
  }
}
</pre>
<h5>Human Readable Output</h5>
<p>We found the following data about hash 2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae:</p>
<h3>Hosts that the hash communicates with are:</h3>
<table>
<thead>
<tr>
<th>Host</th>
</tr>
</thead>
<tbody>
<tr>
<td>224.0.0.22</td>
</tr>
<tr>
<td>51.140.127.197</td>
</tr>
<tr>
<td>10.0.2.2</td>
</tr>
<tr>
<td>239.255.255.250</td>
</tr>
<tr>
<td>255.255.255.255</td>
</tr>
<tr>
<td>10.0.2.255</td>
</tr>
<tr>
<td>10.0.2.15</td>
</tr>
<tr>
<td>82.112.184.197</td>
</tr>
<tr>
<td>0.0.0.0</td>
</tr>
<tr>
<td>216.58.206.238</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>IPs that the hash communicates with are:</h3>
<table>
<thead>
<tr>
<th>IP</th>
</tr>
</thead>
<tbody>
<tr>
<td>51.140.127.197</td>
</tr>
<tr>
<td>10.0.2.2</td>
</tr>
<tr>
<td>239.255.255.250</td>
</tr>
<tr>
<td>10.0.2.255</td>
</tr>
<tr>
<td>10.0.2.15</td>
</tr>
<tr>
<td>82.112.184.197</td>
</tr>
<tr>
<td>255.255.255.255</td>
</tr>
<tr>
<td>127.0.0.1</td>
</tr>
<tr>
<td>216.58.206.238</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Domains that the hash communicates with are:</h3>
<table>
<thead>
<tr>
<th>Domain</th>
</tr>
</thead>
<tbody>
<tr>
<td>stromoliks.com</td>
</tr>
<tr>
<td>promoliks.com</td>
</tr>
<tr>
<td>google.com</td>
</tr>
<tr>
<td>fkjdeljfeew32233.com</td>
</tr>
<tr>
<td>pornoliks.com</td>
</tr>
<tr>
<td>fdwelklwe3093443.com</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Files that are related the hash</h3>
<table>
<thead>
<tr>
<th>File</th>
</tr>
</thead>
<tbody>
<tr>
<td>C:\WINDOWS\system32\ntdll.dll</td>
</tr>
<tr>
<td>C:\DOCUME<del>1\JANETT</del>1\LOCALS~1\Temp~TM4.tmp</td>
</tr>
<tr>
<td>C:\DOCUME<del>1\JANETT</del>1\LOCALS~1\Temp~DF3C0D.tmp</td>
</tr>
<tr>
<td>C:\WINDOWS\system32\kernel32.dll</td>
</tr>
<tr>
<td>C:\DOCUME<del>1\JANETT</del>1\LOCALS~1\Temp~TM3.tmp</td>
</tr>
<tr>
<td>Cmgr.exe</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Registry Keys that are related to the hash</h3>
<table>
<thead>
<tr>
<th>Key</th>
</tr>
</thead>
<tbody>
<tr>
<td>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\VBA\Monitors</td>
</tr>
<tr>
<td>HKEY_LOCAL_MACHINE\System\Setup</td>
</tr>
<tr>
<td>HKEY_CLASSES_ROOT\http\shell\open\command</td>
</tr>
<tr>
<td>0x000000b8\Help</td>
</tr>
<tr>
<td>HKEY_LOCAL_MACHINE\Software\Microsoft\Rpc</td>
</tr>
<tr>
<td>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows</td>
</tr>
<tr>
<td>0x000000b8\HTML Help</td>
</tr>
<tr>
<td>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Cmgr.exe\RpcThreadPoolThrottle</td>
</tr>
<tr>
<td>HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc</td>
</tr>
<tr>
<td>0x00000090\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</td>
</tr>
<tr>
<td>0x000000ac\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</td>
</tr>
<tr>
<td>HKEY_LOCAL_MACHINE\Software\Microsoft\Rpc\PagedBuffers</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Opened mutexes that are related to the hash</h3>
<table>
<thead>
<tr>
<th>Mutex</th>
</tr>
</thead>
<tbody>
<tr>
<td>ShimCacheMutex</td>
</tr>
<tr>
<td>{65D180CA-BACE-614C-7239-5ABDD5E947B0}</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_18551445133181530695739961">2. Get domain report</h3>
<hr>
<p>Generates a report about a specific domain.</p>
<h5>Base Command</h5>
<p><code>vt-private-get-domain-report</code></p>
<h5>Input</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 152px;"><strong>Argument Name</strong></th>
<th style="width: 569px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">domain</td>
<td style="width: 569px;">Domain name</td>
</tr>
<tr>
<td style="width: 152px;">threshold</td>
<td style="width: 569px;">If the number of positives is larger than the threshold, the domain is considered malicious. If threshold is not specified, the default domain threshold is used.<br> You configure the default.</td>
</tr>
<tr>
<td style="width: 152px;">fullResponse</td>
<td style="width: 569px;">Returns all results. Results can number in the thousands, we recommend not using fullResponse in playbooks. The default value is <code>false</code>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 280px;"><strong>Path</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280px;">Domain.Name</td>
<td style="width: 441px;">Domain name</td>
</tr>
<tr>
<td style="width: 280px;">Domain.VirusTotal.DownloadedHashes</td>
<td style="width: 441px;">Hashes of files that were downloaded from this domain</td>
</tr>
<tr>
<td style="width: 280px;">Domain.VirusTotal.CommunicatingHashes</td>
<td style="width: 441px;">Hashes of files that communicated with this domain in a sandbox</td>
</tr>
<tr>
<td style="width: 280px;">Domain.VirusTotal.Resolutions.ip_address</td>
<td style="width: 441px;">IPs that resolved to this domain</td>
</tr>
<tr>
<td style="width: 280px;">Domain.VirusTotal.Whois</td>
<td style="width: 441px;">Whois report</td>
</tr>
<tr>
<td style="width: 280px;">Domain.VirusTotal.Subdomains</td>
<td style="width: 441px;">Subdomains</td>
</tr>
<tr>
<td style="width: 280px;">Domain.VirusTotal.Resolutions.last_resolved</td>
<td style="width: 441px;">Resolution date of IPs that resolved to this domain</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!vt-private-get-domain-report domain=demisto.com</pre>
<h5>Context Example</h5>
<pre>{
  "Name": "google.com",
  "VirusTotal": {
    "CommunicatingHashes": [
      {
        "date": "2018-07-24 07:24:39",
        "positives": 62,
        "sha256": "2675ef3e888481502fe41addc74f7310639d83df4893a97e8127eb5eb1740798",
        "total": 68
      },
      {
        "date": "2018-07-24 07:23:48",
        "positives": 49,
        "sha256": "629be3e06580b7e532b019c48488c5a18e7ca1a37a374a9519d66a64e49051d1",
        "total": 68
      },
      {
        "date": "2018-07-24 07:21:23",
        "positives": 52,
        "sha256": "31afab5e2079d9fd2590f521237ac8f59ed42fe7234a4cf360daa4f7526bf900",
        "total": 66
      },
      {
        "date": "2018-07-24 07:20:18",
        "positives": 45,
        "sha256": "49b777157965d0f2ee2ab53b47876cbfd815512ec8ea41a6cd1a633b29be6524",
        "total": 66
      },
      {
        "date": "2018-07-24 07:19:39",
        "positives": 45,
        "sha256": "46799d5e6883cdf3f3466645de4a98c7710b4db03fece1780bd6e871d8b858e8",
        "total": 66
      },
      {
        "date": "2018-07-24 07:19:38",
        "positives": 50,
        "sha256": "db8c7cc64521286a1c63de5f8b41c749c4dae5434191baa5179f1233f0722ae8",
        "total": 68
      },
      {
        "date": "2018-07-24 07:19:27",
        "positives": 51,
        "sha256": "a1b2e5eeb9a1b81e167000f6f38446100696e8c5b1b38013a8895f3d6519a111",
        "total": 68
      },
      {
        "date": "2018-07-24 07:19:18",
        "positives": 54,
        "sha256": "6cb02d9888c3653616106241d4de68800b7fb9509b3a71f7ecea0eaf66b48655",
        "total": 68
      },
      {
        "date": "2018-07-24 07:18:57",
        "positives": 51,
        "sha256": "872575af2d9caabe5818c9dbcbc76f1fdebf80b3cf4fea961b99706b179e4fb2",
        "total": 68
      },
      {
        "date": "2018-07-24 07:18:47",
        "positives": 50,
        "sha256": "a3a4225ff984894a4752913069d63faafa3db4398c92dc007497f91602892737",
        "total": 68
      },
      {
        "date": "2018-07-24 07:18:19",
        "positives": 48,
        "sha256": "9b716f7272bb1b57653190ed190f7ceaa658820f5169a2857266ba599034efc9",
        "total": 67
      },
      {
        "date": "2018-07-24 07:18:16",
        "positives": 53,
        "sha256": "10478d5c4db5de5b8a69dfcf78b5de338145d9f1903f54a6429e16c9bb749f3a",
        "total": 68
      },
      {
        "date": "2018-07-24 07:18:08",
        "positives": 51,
        "sha256": "b1b566a462e575e5ddcd1bb73e7457607d036c40efe470a11c5839d2aa6913cf",
        "total": 67
      },
      {
        "date": "2018-07-24 07:17:59",
        "positives": 50,
        "sha256": "18d5e3fec37d15e0b6da54e8fe10a34617f92650b58a9846884b866e74165252",
        "total": 68
      },
      {
        "date": "2018-07-24 07:17:45",
        "positives": 50,
        "sha256": "c63b3787c8b85d96af2ccc8203f1ed905a28538c030efbd5bc91d446bc7e4131",
        "total": 68
      },
      {
        "date": "2018-07-24 07:15:50",
        "positives": 53,
        "sha256": "5391f03a01c67aef9d27cc26d72a5637ea1e4cd11228d04dfca3979b0dcf5afc",
        "total": 67
      },
      {
        "date": "2018-07-24 07:15:39",
        "positives": 50,
        "sha256": "b0556569ac21b97a687153876676488c35ede8eca18383436db731f07856b9a6",
        "total": 68
      },
      {
        "date": "2018-07-24 07:15:25",
        "positives": 49,
        "sha256": "1bf888901165a4cb23510133d5b91b663ec1895425c71b8fdddf0348732b11a9",
        "total": 68
      },
      {
        "date": "2018-07-24 07:14:06",
        "positives": 52,
        "sha256": "f1e29295a668a973b7940f5fbab2edcd05b68395e24fd315662726f1c1767cf4",
        "total": 68
      },
      {
        "date": "2018-07-24 07:14:01",
        "positives": 53,
        "sha256": "6b53c57843888c61c3e0126b816d92872f5e44fc803bbd6029c017e29e828fca",
        "total": 68
      },
      {
        "date": "2018-07-24 07:13:59",
        "positives": 48,
        "sha256": "8e1ab57267d8497b31e4d4f26bf3e6d9b31e139e3744f57ec577c32c6bd97448",
        "total": 68
      },
      {
        "date": "2018-07-24 07:13:18",
        "positives": 50,
        "sha256": "ffe93ef77385d59d7030dfd474373b3fe427ebaa9c7f5541e3f11e43629c3b9f",
        "total": 68
      },
      {
        "date": "2018-07-23 10:45:17",
        "positives": 48,
        "sha256": "aa9a757094b2b8cad5b3ef8152dbf2e5f3880fed2c3f58c84a34ecb1673ba4eb",
        "total": 70
      },
      {
        "date": "2018-07-24 07:10:40",
        "positives": 50,
        "sha256": "f8eaee7c0ea2261e55ee58ea09ac7e954ffa26c55c13f225015a63f4eda55da9",
        "total": 68
      },
      {
        "date": "2018-07-24 07:09:42",
        "positives": 52,
        "sha256": "238c20cf0e7bf2dea360ef9728daaaa1f019625e7451e5722cb75479bbd7e184",
        "total": 68
      },
      {
        "date": "2018-07-24 07:08:21",
        "positives": 58,
        "sha256": "c70659c5034f9b7db6b583a5cc5151b1686cc8fbcbd8860d164b07c1c23bcf5b",
        "total": 66
      },
      {
        "date": "2018-07-24 01:20:19",
        "positives": 16,
        "sha256": "c48447d03aa768b8f99877ec9450f764abb912dc35716603cea74bce71737728",
        "total": 69
      },
      {
        "date": "2018-07-24 05:10:10",
        "positives": 34,
        "sha256": "f48fe93a0ce6db1dfd239bb2705a296ac7c1d3f6a1ab335b8ff15b7960cfe5b0",
        "total": 70
      },
      {
        "date": "2018-07-23 12:20:35",
        "positives": 15,
        "sha256": "cbac4ff65098eb0eb9b459ab9a0a7529b412d86dc61f9961638752a309b301be",
        "total": 68
      },
      {
        "date": "2018-07-22 17:43:18",
        "positives": 11,
        "sha256": "f7076372575863bbbb5d96d3f13d8180d1e07f1b9f70c3ff9c833781482f48ce",
        "total": 70
      },
      {
        "date": "2018-07-24 00:18:28",
        "positives": 31,
        "sha256": "0bd4d66a39c461f7175762f802d26158288cf35bc00b1067d5d3a7e7334e9619",
        "total": 70
      },
      {
        "date": "2018-07-24 06:22:30",
        "positives": 49,
        "sha256": "4c2494bd1988e1d55e418e6e67881103cbe4a7b1a36423a17b54518764e720e0",
        "total": 68
      },
      {
        "date": "2018-07-24 06:22:15",
        "positives": 49,
        "sha256": "de5579608fa1c48dbf6985b80c207d0705d5b0692d8e8f4ee914849bb23a7fc4",
        "total": 68
      },
      {
        "date": "2018-07-24 06:22:10",
        "positives": 47,
        "sha256": "005e579a1fbfff7fb719c2dd142ff253da229067c834a3c77002ccf5d5c88860",
        "total": 67
      },
      {
        "date": "2018-07-24 06:21:54",
        "positives": 49,
        "sha256": "8a232930ea2481d40ef678d71a9a19da52625e94caf74dca07783e948ff5818f",
        "total": 68
      },
      {
        "date": "2018-07-24 06:20:43",
        "positives": 54,
        "sha256": "79b2a672433973b3fdce947a45ab409da4ba5a4f7b6ed94014835b8ac3521abc",
        "total": 67
      },
      {
        "date": "2018-07-23 09:04:38",
        "positives": 52,
        "sha256": "51b74df5019508d78f2b9ea6f7c24fc33e700a59226faef76a814ade67dbddd6",
        "total": 70
      },
      {
        "date": "2018-07-23 11:59:58",
        "positives": 60,
        "sha256": "0e4842f53bae8a32b0673ebee8b5ad3f61b7377634c7122d5d582ec82041154f",
        "total": 69
      },
      {
        "date": "2018-07-22 17:26:07",
        "positives": 56,
        "sha256": "61ea4df7140be285a82a93600592dbc9f3bc5cea95941259de1d05490a15c0e5",
        "total": 70
      },
      {
        "date": "2018-07-23 10:51:19",
        "positives": 49,
        "sha256": "2253a68cc3f4202c1239566437e30ffa112b40d342a8969e63c4177066464682",
        "total": 70
      },
      {
        "date": "2018-07-23 10:54:35",
        "positives": 54,
        "sha256": "94e2bc7b7b7be2b83ac40560d9a93d48511bf3104102e69d3ff21399b7f31dfa",
        "total": 70
      },
      {
        "date": "2018-07-23 10:45:12",
        "positives": 52,
        "sha256": "e5ac53dd24af0985e1617e86f09cb0eb2027e2b12479b47594233ac8b4701bb7",
        "total": 70
      },
      {
        "date": "2018-07-22 20:03:38",
        "positives": 55,
        "sha256": "57512332300ada12813e0a876cdf0090d81aee28953dcc24f3b610e022f89327",
        "total": 69
      },
      {
        "date": "2018-07-24 06:05:19",
        "positives": 54,
        "sha256": "3656d67014dc5ad09c77b06ee1b3da751526fe47cdc21d5002869524beabcd48",
        "total": 68
      },
      {
        "date": "2018-07-24 05:50:15",
        "positives": 53,
        "sha256": "b946b5de6599f02a9fa1af3c166fc50d3b4636a56c0ac73a56d939231a9b42a8",
        "total": 67
      },
      {
        "date": "2018-07-24 05:45:38",
        "positives": 44,
        "sha256": "2bda400f65b3097eb48fd77c8ecb610689884675542062ae2b234d2a1acee9d0",
        "total": 67
      },
      {
        "date": "2018-07-23 17:44:19",
        "positives": 18,
        "sha256": "db7c591fa32343770f3a03c3383e8fb89b1f30ae106263fc6d066aa45c1321f6",
        "total": 70
      },
      {
        "date": "2018-07-24 05:34:57",
        "positives": 47,
        "sha256": "27ae8d443e224eba7fe0da8c03e771be3784ff9485f018074eee191b2bf35644",
        "total": 67
      },
      {
        "date": "2018-07-24 05:34:40",
        "positives": 58,
        "sha256": "263713235cbbeb7714aef21da83f1162f9c5e6e64a6054c97769b339fb2ffe9a",
        "total": 68
      },
      {
        "date": "2018-07-24 05:34:36",
        "positives": 49,
        "sha256": "18e3295f7c6c5528483f25c383dd0e4aadb4c4c74a63ccb86fa30782b5c5c91e",
        "total": 67
      }
    ],
    "DownloadedHashes": [],
    "Resolutions": [
      {
        "ip_address": "108.167.133.29",
        "last_resolved": "2017-05-19 00:00:00"
      },
      {
        "ip_address": "108.177.10.100",
        "last_resolved": "2016-02-16 00:00:00"
      },
      {
        "ip_address": "108.177.10.102",
        "last_resolved": "2016-02-16 00:00:00"
      },
      {
        "ip_address": "108.177.111.100",
        "last_resolved": "2018-03-14 00:00:00"
      },
      {
        "ip_address": "108.177.111.101",
        "last_resolved": "2018-03-14 00:00:00"
      },
      {
        "ip_address": "108.177.111.102",
        "last_resolved": "2018-03-15 00:00:00"
      },
      {
        "ip_address": "108.177.111.113",
        "last_resolved": "2018-03-18 00:00:00"
      },
      {
        "ip_address": "108.177.111.138",
        "last_resolved": "2018-03-15 00:00:00"
      },
      {
        "ip_address": "108.177.111.139",
        "last_resolved": "2018-03-14 00:00:00"
      },
      {
        "ip_address": "108.177.112.100",
        "last_resolved": "2018-07-20 03:31:21"
      },
      {
        "ip_address": "108.177.112.101",
        "last_resolved": "2018-07-20 03:31:21"
      },
      {
        "ip_address": "108.177.112.102",
        "last_resolved": "2018-07-20 03:31:21"
      },
      {
        "ip_address": "108.177.112.113",
        "last_resolved": "2018-07-20 03:31:21"
      },
      {
        "ip_address": "108.177.112.138",
        "last_resolved": "2018-07-20 03:31:21"
      },
      {
        "ip_address": "108.177.112.139",
        "last_resolved": "2018-07-20 03:31:21"
      },
      {
        "ip_address": "108.177.119.100",
        "last_resolved": "2018-07-11 11:27:21"
      },
      {
        "ip_address": "108.177.119.101",
        "last_resolved": "2018-07-11 11:27:22"
      },
      {
        "ip_address": "108.177.119.102",
        "last_resolved": "2018-07-11 11:27:21"
      },
      {
        "ip_address": "108.177.119.113",
        "last_resolved": "2018-07-11 11:27:21"
      },
      {
        "ip_address": "108.177.119.138",
        "last_resolved": "2018-07-11 11:27:21"
      },
      {
        "ip_address": "108.177.119.139",
        "last_resolved": "2018-07-11 11:27:21"
      },
      {
        "ip_address": "108.177.120.100",
        "last_resolved": "2018-07-12 01:45:40"
      },
      {
        "ip_address": "108.177.120.101",
        "last_resolved": "2018-07-12 01:45:39"
      },
      {
        "ip_address": "108.177.120.102",
        "last_resolved": "2018-07-12 01:45:40"
      },
      {
        "ip_address": "108.177.120.113",
        "last_resolved": "2018-07-12 01:45:39"
      },
      {
        "ip_address": "108.177.120.138",
        "last_resolved": "2018-07-12 01:45:40"
      },
      {
        "ip_address": "108.177.120.139",
        "last_resolved": "2018-07-12 01:45:40"
      },
      {
        "ip_address": "108.177.121.100",
        "last_resolved": "2018-07-19 03:28:50"
      },
      {
        "ip_address": "108.177.121.101",
        "last_resolved": "2018-07-19 03:28:50"
      },
      {
        "ip_address": "108.177.121.102",
        "last_resolved": "2018-07-19 03:28:50"
      },
      {
        "ip_address": "108.177.121.113",
        "last_resolved": "2018-07-19 03:28:50"
      },
      {
        "ip_address": "108.177.121.138",
        "last_resolved": "2018-07-19 03:28:50"
      },
      {
        "ip_address": "108.177.121.139",
        "last_resolved": "2018-07-19 03:28:50"
      },
      {
        "ip_address": "108.177.122.100",
        "last_resolved": "2018-06-27 13:14:54"
      },
      {
        "ip_address": "108.177.122.101",
        "last_resolved": "2018-06-27 13:14:55"
      },
      {
        "ip_address": "108.177.122.102",
        "last_resolved": "2018-06-27 13:14:55"
      },
      {
        "ip_address": "108.177.122.113",
        "last_resolved": "2018-06-27 13:14:55"
      },
      {
        "ip_address": "108.177.122.138",
        "last_resolved": "2018-06-27 13:14:55"
      },
      {
        "ip_address": "108.177.122.139",
        "last_resolved": "2018-06-27 13:14:55"
      },
      {
        "ip_address": "108.177.127.100",
        "last_resolved": "2018-06-14 06:42:21"
      },
      {
        "ip_address": "108.177.127.101",
        "last_resolved": "2018-06-14 06:42:21"
      },
      {
        "ip_address": "108.177.127.102",
        "last_resolved": "2018-06-14 06:42:21"
      },
      {
        "ip_address": "108.177.127.113",
        "last_resolved": "2018-06-14 06:42:21"
      },
      {
        "ip_address": "108.177.127.138",
        "last_resolved": "2018-06-14 06:42:21"
      },
      {
        "ip_address": "108.177.127.139",
        "last_resolved": "2018-06-14 06:42:21"
      },
      {
        "ip_address": "108.177.15.100",
        "last_resolved": "2018-07-23 10:36:03"
      },
      {
        "ip_address": "108.177.15.101",
        "last_resolved": "2018-07-23 10:35:18"
      },
      {
        "ip_address": "108.177.15.102",
        "last_resolved": "2018-07-23 10:33:47"
      },
      {
        "ip_address": "108.177.15.113",
        "last_resolved": "2018-07-19 14:15:34"
      },
      {
        "ip_address": "108.177.15.138",
        "last_resolved": "2018-07-23 10:32:53"
      }
    ],
    "Subdomains": [
      "27.docs.google.com",
      "8.chart.apis.google.com",
      "geoauth.google.com",
      "adservice.google.com",
      "ogs.google.com",
      "accounts.google.com",
      "play.google.com",
      "news.url.google.com",
      "mt2.google.com",
      "alt5-mtalk.google.com",
      "books.google.com",
      "id.google.com",
      "apis.google.com",
      "notifications.google.com",
      "meet.google.com",
      "mts0.google.com",
      "www.google.com",
      "alt2-mtalk.google.com",
      "policies.google.com",
      "taskassist-pa.clients6.google.com",
      "search.google.com",
      "xmpp.l.google.com",
      "1.client-channel.google.com",
      "safebrowsing-cache.google.com",
      "encrypted.google.com",
      "groups.google.com",
      "68.docs.google.com",
      "feedburner.google.com",
      "clients2.google.com",
      "suggestqueries.google.com",
      "toolbarqueries.google.com",
      "mtalk4.google.com",
      "chatenabled.mail.google.com",
      "alt6-mtalk.google.com",
      "mt0.google.com",
      "alt2.gmail-smtp-in.l.google.com",
      "reminders-pa.clients6.google.com",
      "7.client-channel.google.com",
      "hangouts.google.com",
      "android.clients.google.com",
      "mtalk.google.com",
      "wide-youtube.l.google.com",
      "15.client-channel.google.com",
      "history.google.com",
      "drive.google.com",
      "8.client-channel.google.com",
      "status.cloud.google.com",
      "safebrowsing.google.com",
      "contributor.google.com",
      "docs.google.com"
    ],
    "Whois": "Domain Name: GOOGLE.COM\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2018-02-21T18:36:40Z\nCreation Date: 1997-09-15T04:00:00Z\nRegistry Expiry Date: 2020-09-14T04:00:00Z\nRegistrar: MarkMonitor Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS1.GOOGLE.COM\nName Server: NS2.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nDNSSEC: unsigned\nDomain Name: google.com\nUpdated Date: 2018-02-21T10:45:07-0800\nCreation Date: 1997-09-15T00:00:00-0700\nRegistrar Registration Expiration Date: 2020-09-13T21:00:00-0700\nRegistrar: MarkMonitor, Inc.\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Country: US\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US\nTech Organization: Google LLC\nTech State/Province: CA\nTech Country: US\nName Server: ns3.google.com\nName Server: ns2.google.com\nName Server: ns4.google.com\nName Server: ns1.google.com"
  }
}</pre>
<h5>Human Readable Output</h5>
<h3>Latest detected files that communicated with google.com</h3>
<table style="width: 864px;">
<thead>
<tr>
<th style="width: 1074px;">date</th>
<th style="width: 10px;">positives</th>
<th style="width: 23px;">total</th>
<th style="width: 627px;">sha256</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 1074px;">2018-07-24 07:24:39</td>
<td style="width: 10px;">62</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">2675ef3e888481502fe41addc74f7310639d83df4893a97e8127eb5eb1740798</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:23:48</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">629be3e06580b7e532b019c48488c5a18e7ca1a37a374a9519d66a64e49051d1</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:21:23</td>
<td style="width: 10px;">52</td>
<td style="width: 23px;">66</td>
<td style="width: 627px;">31afab5e2079d9fd2590f521237ac8f59ed42fe7234a4cf360daa4f7526bf900</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:20:18</td>
<td style="width: 10px;">45</td>
<td style="width: 23px;">66</td>
<td style="width: 627px;">49b777157965d0f2ee2ab53b47876cbfd815512ec8ea41a6cd1a633b29be6524</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:19:39</td>
<td style="width: 10px;">45</td>
<td style="width: 23px;">66</td>
<td style="width: 627px;">46799d5e6883cdf3f3466645de4a98c7710b4db03fece1780bd6e871d8b858e8</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:19:38</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">db8c7cc64521286a1c63de5f8b41c749c4dae5434191baa5179f1233f0722ae8</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:19:27</td>
<td style="width: 10px;">51</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">a1b2e5eeb9a1b81e167000f6f38446100696e8c5b1b38013a8895f3d6519a111</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:19:18</td>
<td style="width: 10px;">54</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">6cb02d9888c3653616106241d4de68800b7fb9509b3a71f7ecea0eaf66b48655</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:18:57</td>
<td style="width: 10px;">51</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">872575af2d9caabe5818c9dbcbc76f1fdebf80b3cf4fea961b99706b179e4fb2</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:18:47</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">a3a4225ff984894a4752913069d63faafa3db4398c92dc007497f91602892737</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:18:19</td>
<td style="width: 10px;">48</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">9b716f7272bb1b57653190ed190f7ceaa658820f5169a2857266ba599034efc9</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:18:16</td>
<td style="width: 10px;">53</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">10478d5c4db5de5b8a69dfcf78b5de338145d9f1903f54a6429e16c9bb749f3a</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:18:08</td>
<td style="width: 10px;">51</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">b1b566a462e575e5ddcd1bb73e7457607d036c40efe470a11c5839d2aa6913cf</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:17:59</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">18d5e3fec37d15e0b6da54e8fe10a34617f92650b58a9846884b866e74165252</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:17:45</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">c63b3787c8b85d96af2ccc8203f1ed905a28538c030efbd5bc91d446bc7e4131</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:15:50</td>
<td style="width: 10px;">53</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">5391f03a01c67aef9d27cc26d72a5637ea1e4cd11228d04dfca3979b0dcf5afc</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:15:39</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">b0556569ac21b97a687153876676488c35ede8eca18383436db731f07856b9a6</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:15:25</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">1bf888901165a4cb23510133d5b91b663ec1895425c71b8fdddf0348732b11a9</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:14:06</td>
<td style="width: 10px;">52</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">f1e29295a668a973b7940f5fbab2edcd05b68395e24fd315662726f1c1767cf4</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:14:01</td>
<td style="width: 10px;">53</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">6b53c57843888c61c3e0126b816d92872f5e44fc803bbd6029c017e29e828fca</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:13:59</td>
<td style="width: 10px;">48</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">8e1ab57267d8497b31e4d4f26bf3e6d9b31e139e3744f57ec577c32c6bd97448</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:13:18</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">ffe93ef77385d59d7030dfd474373b3fe427ebaa9c7f5541e3f11e43629c3b9f</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 10:45:17</td>
<td style="width: 10px;">48</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">aa9a757094b2b8cad5b3ef8152dbf2e5f3880fed2c3f58c84a34ecb1673ba4eb</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:10:40</td>
<td style="width: 10px;">50</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">f8eaee7c0ea2261e55ee58ea09ac7e954ffa26c55c13f225015a63f4eda55da9</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:09:42</td>
<td style="width: 10px;">52</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">238c20cf0e7bf2dea360ef9728daaaa1f019625e7451e5722cb75479bbd7e184</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 07:08:21</td>
<td style="width: 10px;">58</td>
<td style="width: 23px;">66</td>
<td style="width: 627px;">c70659c5034f9b7db6b583a5cc5151b1686cc8fbcbd8860d164b07c1c23bcf5b</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 01:20:19</td>
<td style="width: 10px;">16</td>
<td style="width: 23px;">69</td>
<td style="width: 627px;">c48447d03aa768b8f99877ec9450f764abb912dc35716603cea74bce71737728</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 05:10:10</td>
<td style="width: 10px;">34</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">f48fe93a0ce6db1dfd239bb2705a296ac7c1d3f6a1ab335b8ff15b7960cfe5b0</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 12:20:35</td>
<td style="width: 10px;">15</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">cbac4ff65098eb0eb9b459ab9a0a7529b412d86dc61f9961638752a309b301be</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-22 17:43:18</td>
<td style="width: 10px;">11</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">f7076372575863bbbb5d96d3f13d8180d1e07f1b9f70c3ff9c833781482f48ce</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 00:18:28</td>
<td style="width: 10px;">31</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">0bd4d66a39c461f7175762f802d26158288cf35bc00b1067d5d3a7e7334e9619</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 06:22:30</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">4c2494bd1988e1d55e418e6e67881103cbe4a7b1a36423a17b54518764e720e0</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 06:22:15</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">de5579608fa1c48dbf6985b80c207d0705d5b0692d8e8f4ee914849bb23a7fc4</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 06:22:10</td>
<td style="width: 10px;">47</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">005e579a1fbfff7fb719c2dd142ff253da229067c834a3c77002ccf5d5c88860</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 06:21:54</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">8a232930ea2481d40ef678d71a9a19da52625e94caf74dca07783e948ff5818f</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 06:20:43</td>
<td style="width: 10px;">54</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">79b2a672433973b3fdce947a45ab409da4ba5a4f7b6ed94014835b8ac3521abc</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 09:04:38</td>
<td style="width: 10px;">52</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">51b74df5019508d78f2b9ea6f7c24fc33e700a59226faef76a814ade67dbddd6</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 11:59:58</td>
<td style="width: 10px;">60</td>
<td style="width: 23px;">69</td>
<td style="width: 627px;">0e4842f53bae8a32b0673ebee8b5ad3f61b7377634c7122d5d582ec82041154f</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-22 17:26:07</td>
<td style="width: 10px;">56</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">61ea4df7140be285a82a93600592dbc9f3bc5cea95941259de1d05490a15c0e5</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 10:51:19</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">2253a68cc3f4202c1239566437e30ffa112b40d342a8969e63c4177066464682</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 10:54:35</td>
<td style="width: 10px;">54</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">94e2bc7b7b7be2b83ac40560d9a93d48511bf3104102e69d3ff21399b7f31dfa</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 10:45:12</td>
<td style="width: 10px;">52</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">e5ac53dd24af0985e1617e86f09cb0eb2027e2b12479b47594233ac8b4701bb7</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-22 20:03:38</td>
<td style="width: 10px;">55</td>
<td style="width: 23px;">69</td>
<td style="width: 627px;">57512332300ada12813e0a876cdf0090d81aee28953dcc24f3b610e022f89327</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 06:05:19</td>
<td style="width: 10px;">54</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">3656d67014dc5ad09c77b06ee1b3da751526fe47cdc21d5002869524beabcd48</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 05:50:15</td>
<td style="width: 10px;">53</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">b946b5de6599f02a9fa1af3c166fc50d3b4636a56c0ac73a56d939231a9b42a8</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 05:45:38</td>
<td style="width: 10px;">44</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">2bda400f65b3097eb48fd77c8ecb610689884675542062ae2b234d2a1acee9d0</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-23 17:44:19</td>
<td style="width: 10px;">18</td>
<td style="width: 23px;">70</td>
<td style="width: 627px;">db7c591fa32343770f3a03c3383e8fb89b1f30ae106263fc6d066aa45c1321f6</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 05:34:57</td>
<td style="width: 10px;">47</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">27ae8d443e224eba7fe0da8c03e771be3784ff9485f018074eee191b2bf35644</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 05:34:40</td>
<td style="width: 10px;">58</td>
<td style="width: 23px;">68</td>
<td style="width: 627px;">263713235cbbeb7714aef21da83f1162f9c5e6e64a6054c97769b339fb2ffe9a</td>
</tr>
<tr>
<td style="width: 1074px;">2018-07-24 05:34:36</td>
<td style="width: 10px;">49</td>
<td style="width: 23px;">67</td>
<td style="width: 627px;">18e3295f7c6c5528483f25c383dd0e4aadb4c4c74a63ccb86fa30782b5c5c91e</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Latest detected files that were downloaded from google.com</h3>
<p><strong>No entries.</strong></p>
<h3>google.com has been resolved to the following IP addresses:</h3>
<table>
<thead>
<tr>
<th style="width: 180px;">last_resolved</th>
<th style="width: 137px;">ip_address</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">2017-05-19 00:00:00</td>
<td style="width: 137px;">108.167.133.29</td>
</tr>
<tr>
<td style="width: 180px;">2016-02-16 00:00:00</td>
<td style="width: 137px;">108.177.10.100</td>
</tr>
<tr>
<td style="width: 180px;">2016-02-16 00:00:00</td>
<td style="width: 137px;">108.177.10.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-03-14 00:00:00</td>
<td style="width: 137px;">108.177.111.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-03-14 00:00:00</td>
<td style="width: 137px;">108.177.111.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-03-15 00:00:00</td>
<td style="width: 137px;">108.177.111.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-03-18 00:00:00</td>
<td style="width: 137px;">108.177.111.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-03-15 00:00:00</td>
<td style="width: 137px;">108.177.111.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-03-14 00:00:00</td>
<td style="width: 137px;">108.177.111.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-20 03:31:21</td>
<td style="width: 137px;">108.177.112.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-20 03:31:21</td>
<td style="width: 137px;">108.177.112.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-20 03:31:21</td>
<td style="width: 137px;">108.177.112.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-20 03:31:21</td>
<td style="width: 137px;">108.177.112.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-20 03:31:21</td>
<td style="width: 137px;">108.177.112.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-20 03:31:21</td>
<td style="width: 137px;">108.177.112.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-11 11:27:21</td>
<td style="width: 137px;">108.177.119.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-11 11:27:22</td>
<td style="width: 137px;">108.177.119.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-11 11:27:21</td>
<td style="width: 137px;">108.177.119.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-11 11:27:21</td>
<td style="width: 137px;">108.177.119.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-11 11:27:21</td>
<td style="width: 137px;">108.177.119.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-11 11:27:21</td>
<td style="width: 137px;">108.177.119.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-12 01:45:40</td>
<td style="width: 137px;">108.177.120.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-12 01:45:39</td>
<td style="width: 137px;">108.177.120.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-12 01:45:40</td>
<td style="width: 137px;">108.177.120.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-12 01:45:39</td>
<td style="width: 137px;">108.177.120.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-12 01:45:40</td>
<td style="width: 137px;">108.177.120.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-12 01:45:40</td>
<td style="width: 137px;">108.177.120.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 03:28:50</td>
<td style="width: 137px;">108.177.121.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 03:28:50</td>
<td style="width: 137px;">108.177.121.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 03:28:50</td>
<td style="width: 137px;">108.177.121.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 03:28:50</td>
<td style="width: 137px;">108.177.121.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 03:28:50</td>
<td style="width: 137px;">108.177.121.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 03:28:50</td>
<td style="width: 137px;">108.177.121.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-27 13:14:54</td>
<td style="width: 137px;">108.177.122.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-27 13:14:55</td>
<td style="width: 137px;">108.177.122.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-27 13:14:55</td>
<td style="width: 137px;">108.177.122.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-27 13:14:55</td>
<td style="width: 137px;">108.177.122.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-27 13:14:55</td>
<td style="width: 137px;">108.177.122.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-27 13:14:55</td>
<td style="width: 137px;">108.177.122.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-14 06:42:21</td>
<td style="width: 137px;">108.177.127.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-14 06:42:21</td>
<td style="width: 137px;">108.177.127.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-14 06:42:21</td>
<td style="width: 137px;">108.177.127.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-14 06:42:21</td>
<td style="width: 137px;">108.177.127.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-14 06:42:21</td>
<td style="width: 137px;">108.177.127.138</td>
</tr>
<tr>
<td style="width: 180px;">2018-06-14 06:42:21</td>
<td style="width: 137px;">108.177.127.139</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-23 10:36:03</td>
<td style="width: 137px;">108.177.15.100</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-23 10:35:18</td>
<td style="width: 137px;">108.177.15.101</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-23 10:33:47</td>
<td style="width: 137px;">108.177.15.102</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-19 14:15:34</td>
<td style="width: 137px;">108.177.15.113</td>
</tr>
<tr>
<td style="width: 180px;">2018-07-23 10:32:53</td>
<td style="width: 137px;">108.177.15.138</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Whois analysis:</h3>
<p>Domain Name: GOOGLE.COM<br> Registry Domain ID: 2138514_DOMAIN_COM-VRSN<br> Registrar WHOIS Server: whois.markmonitor.com<br> Registrar URL: <a href="http://www.markmonitor.com/" rel="nofollow">http://www.markmonitor.com</a><br> Updated Date: 2018-02-21T18:36:40Z<br> Creation Date: 1997-09-15T04:00:00Z<br> Registry Expiry Date: 2020-09-14T04:00:00Z<br> Registrar: MarkMonitor Inc.<br> Registrar IANA ID: 292<br> Registrar Abuse Contact Email: <a href="mailto:abusecomplaints@markmonitor.com">abusecomplaints@markmonitor.com</a><br> Registrar Abuse Contact Phone: +1.2083895740<br> Domain Status: clientDeleteProhibited <a href="https://icann.org/epp#clientDeleteProhibited" rel="nofollow">https://icann.org/epp#clientDeleteProhibited</a><br> Domain Status: clientTransferProhibited <a href="https://icann.org/epp#clientTransferProhibited" rel="nofollow">https://icann.org/epp#clientTransferProhibited</a><br> Domain Status: clientUpdateProhibited <a href="https://icann.org/epp#clientUpdateProhibited" rel="nofollow">https://icann.org/epp#clientUpdateProhibited</a><br> Domain Status: serverDeleteProhibited <a href="https://icann.org/epp#serverDeleteProhibited" rel="nofollow">https://icann.org/epp#serverDeleteProhibited</a><br> Domain Status: serverTransferProhibited <a href="https://icann.org/epp#serverTransferProhibited" rel="nofollow">https://icann.org/epp#serverTransferProhibited</a><br> Domain Status: serverUpdateProhibited <a href="https://icann.org/epp#serverUpdateProhibited" rel="nofollow">https://icann.org/epp#serverUpdateProhibited</a><br> Name Server: NS1.GOOGLE.COM<br> Name Server: NS2.GOOGLE.COM<br> Name Server: NS3.GOOGLE.COM<br> Name Server: NS4.GOOGLE.COM<br> DNSSEC: unsigned<br> Domain Name: google.com<br> Updated Date: 2018-02-21T10:45:07-0800<br> Creation Date: 1997-09-15T00:00:00-0700<br> Registrar Registration Expiration Date: 2020-09-13T21:00:00-0700<br> Registrar: MarkMonitor, Inc.<br> Domain Status: clientUpdateProhibited (<a href="https://www.icann.org/epp#clientUpdateProhibited" rel="nofollow">https://www.icann.org/epp#clientUpdateProhibited</a>)<br> Domain Status: clientTransferProhibited (<a href="https://www.icann.org/epp#clientTransferProhibited" rel="nofollow">https://www.icann.org/epp#clientTransferProhibited</a>)<br> Domain Status: clientDeleteProhibited (<a href="https://www.icann.org/epp#clientDeleteProhibited" rel="nofollow">https://www.icann.org/epp#clientDeleteProhibited</a>)<br> Domain Status: serverUpdateProhibited (<a href="https://www.icann.org/epp#serverUpdateProhibited" rel="nofollow">https://www.icann.org/epp#serverUpdateProhibited</a>)<br> Domain Status: serverTransferProhibited (<a href="https://www.icann.org/epp#serverTransferProhibited" rel="nofollow">https://www.icann.org/epp#serverTransferProhibited</a>)<br> Domain Status: serverDeleteProhibited (<a href="https://www.icann.org/epp#serverDeleteProhibited" rel="nofollow">https://www.icann.org/epp#serverDeleteProhibited</a>)<br> Registrant Country: US<br> Admin Organization: Google LLC<br> Admin State/Province: CA<br> Admin Country: US<br> Tech Organization: Google LLC<br> Tech State/Province: CA<br> Tech Country: US<br> Name Server: ns3.google.com<br> Name Server: ns2.google.com<br> Name Server: ns4.google.com<br> Name Server: ns1.google.com</p>
<h3>Observed subdomains</h3>
<table>
<thead>
<tr>
<th>Domain</th>
</tr>
</thead>
<tbody>
<tr>
<td>27.docs.google.com</td>
</tr>
<tr>
<td>8.chart.apis.google.com</td>
</tr>
<tr>
<td>geoauth.google.com</td>
</tr>
<tr>
<td>adservice.google.com</td>
</tr>
<tr>
<td>ogs.google.com</td>
</tr>
<tr>
<td>accounts.google.com</td>
</tr>
<tr>
<td>play.google.com</td>
</tr>
<tr>
<td>news.url.google.com</td>
</tr>
<tr>
<td>mt2.google.com</td>
</tr>
<tr>
<td>alt5-mtalk.google.com</td>
</tr>
<tr>
<td>books.google.com</td>
</tr>
<tr>
<td>id.google.com</td>
</tr>
<tr>
<td>apis.google.com</td>
</tr>
<tr>
<td>notifications.google.com</td>
</tr>
<tr>
<td>meet.google.com</td>
</tr>
<tr>
<td>mts0.google.com</td>
</tr>
<tr>
<td>www.google.com</td>
</tr>
<tr>
<td>alt2-mtalk.google.com</td>
</tr>
<tr>
<td>policies.google.com</td>
</tr>
<tr>
<td>taskassist-pa.clients6.google.com</td>
</tr>
<tr>
<td>search.google.com</td>
</tr>
<tr>
<td>xmpp.l.google.com</td>
</tr>
<tr>
<td>1.client-channel.google.com</td>
</tr>
<tr>
<td>safebrowsing-cache.google.com</td>
</tr>
<tr>
<td>encrypted.google.com</td>
</tr>
<tr>
<td>groups.google.com</td>
</tr>
<tr>
<td>68.docs.google.com</td>
</tr>
<tr>
<td>feedburner.google.com</td>
</tr>
<tr>
<td>clients2.google.com</td>
</tr>
<tr>
<td>suggestqueries.google.com</td>
</tr>
<tr>
<td>toolbarqueries.google.com</td>
</tr>
<tr>
<td>mtalk4.google.com</td>
</tr>
<tr>
<td>chatenabled.mail.google.com</td>
</tr>
<tr>
<td>alt6-mtalk.google.com</td>
</tr>
<tr>
<td>mt0.google.com</td>
</tr>
<tr>
<td>alt2.gmail-smtp-in.l.google.com</td>
</tr>
<tr>
<td>reminders-pa.clients6.google.com</td>
</tr>
<tr>
<td>7.client-channel.google.com</td>
</tr>
<tr>
<td>hangouts.google.com</td>
</tr>
<tr>
<td>android.clients.google.com</td>
</tr>
<tr>
<td>mtalk.google.com</td>
</tr>
<tr>
<td>wide-youtube.l.google.com</td>
</tr>
<tr>
<td>15.client-channel.google.com</td>
</tr>
<tr>
<td>history.google.com</td>
</tr>
<tr>
<td>drive.google.com</td>
</tr>
<tr>
<td>8.client-channel.google.com</td>
</tr>
<tr>
<td>status.cloud.google.com</td>
</tr>
<tr>
<td>safebrowsing.google.com</td>
</tr>
<tr>
<td>contributor.google.com</td>
</tr>
<tr>
<td>docs.google.com</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_65752050558221530710946829">3. Get malicious file report</h3>
<hr>
<p>Retrieves metadata for a malicious file. </p>
<h5>Base Command</h5>
<p><code>vt-private-get-file-report</code></p>
<h5>Input</h5>
<table style="width: 746px;">
<thead>
<tr>
<td style="width: 136px;"><strong>Argument Name</strong></td>
<td style="width: 585px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">resource</td>
<td style="width: 585px;">MD5/SHA-1/SHA-256 hash of file to retrieve the most recent antivirus report for.<br> It is also possible to specify a scan_id (SHA-256-timestamp as returned by the scan API) to access a specific report.</td>
</tr>
<tr>
<td style="width: 136px;">allInfo </td>
<td style="width: 585px;">Virus Total metadata, signature information, structural information, and more.<br> Can be viewed with <code>raw-response=true</code>.</td>
</tr>
<tr>
<td style="width: 136px;">threshold</td>
<td style="width: 585px;">If the number of positive results from the VT scanners is bigger than the threshold, the file will be considered malicious.<br> Default is configured in the instance settings.</td>
</tr>
<tr>
<td style="width: 136px;">longFormat</td>
<td style="width: 585px;">Returns a full response with scans.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 252px;"><strong>Path</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 252px;">File.MD5</td>
<td style="width: 469px;">File's MD5</td>
</tr>
<tr>
<td style="width: 252px;">File.SHA1</td>
<td style="width: 469px;">File's SHA1</td>
</tr>
<tr>
<td style="width: 252px;">File.SHA256</td>
<td style="width: 469px;">File's SHA256</td>
</tr>
<tr>
<td style="width: 252px;">File.Malicious.Vendor</td>
<td style="width: 469px;">For malicious files, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 252px;">File.Malicious.Detections</td>
<td style="width: 469px;">For malicious files. Total detections.</td>
</tr>
<tr>
<td style="width: 252px;">File.Malicious.TotalEngines</td>
<td style="width: 469px;">For malicious files. Total engines</td>
</tr>
<tr>
<td style="width: 252px;">DBotScore.Indicator</td>
<td style="width: 469px;">The indicator we tested</td>
</tr>
<tr>
<td style="width: 252px;">DBotScore.Type</td>
<td style="width: 469px;">The type of the indicator</td>
</tr>
<tr>
<td style="width: 252px;">DBotScore.Vendor</td>
<td style="width: 469px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 252px;">DBotScore.Score</td>
<td style="width: 469px;">The actual score</td>
</tr>
<tr>
<td style="width: 252px;">File.VirusTotal.Scans.Source</td>
<td style="width: 469px;">Scan vendor for this hash</td>
</tr>
<tr>
<td style="width: 252px;">File.VirusTotal.Scans.Detected</td>
<td style="width: 469px;">Scan detection for this hash (True,False)</td>
</tr>
<tr>
<td style="width: 252px;">File.VirusTotal.Scans.Result</td>
<td style="width: 469px;">Scan result for this hash - signature, etc.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!vt-private-get-file-report resource=2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae allInfo=true longFormat=true</pre>
<h5>Context Example</h5>
<pre>{
  "MD5": "fedeb68e5bc9a1627b32504da4d7475a",
  "Malicious": {
    "Detections": 58,
    "TotalEngines": 68,
    "Vendor": "VirusTotal"
  },
  "SHA1": "9ad524ddd2fb551490187bf3d506449f31e20423",
  "SHA256": "2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae",
  "VirusTotal": {
    "Scans": [
      {
        "Details": null,
        "Detected": true,
        "Result": "Trojan.Slingup.A",
        "Source": "ALYac",
        "Update": "20180624"
      },
      {
        "Details": null,
        "Detected": true,
        "Result": "Win32:RmnDrp",
        "Source": "AVG",
        "Update": "20180624"
      },
      {
        "Details": null,
        "Detected": true,
        "Result": "Virus.Win32.Ramnit.b (v)",
        "Source": "AVware",
        "Update": "20180624"
      },
      {
        "Details": null,
        "Detected": true,
        "Result": "Trojan.Slingup.A",
        "Source": "Ad-Aware",
        "Update": "20180624"
      }
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<h3>VirusTotal Hash Reputation for: 2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae</h3>
<p>Scan ID: <strong>2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae-1529842805</strong><br> Scan date: <strong>2018-06-24 12:20:05</strong><br> Detections / Total: <strong>58/68</strong><br> VT Link: <a href="https://www.virustotal.com/file/2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae/analysis/1529842805/" rel="nofollow">2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae</a><br> MD5: <strong>fedeb68e5bc9a1627b32504da4d7475a</strong><br> SHA1: <strong>9ad524ddd2fb551490187bf3d506449f31e20423</strong><br> SHA256: <strong>2d8bb37078ff9efd02d9361975c9e625ae56bd8a8a65d50fc568341bc88392ae</strong></p>
<h3>Scans</h3>
<table style="width: 742px;">
<thead>
<tr>
<th style="width: 16px;">Details</th>
<th style="width: 277px;">Source</th>
<th style="width: 10px;">Detected</th>
<th style="width: 393px;">Result</th>
<th style="width: 40px;">Update</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">ALYac</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Trojan.Slingup.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">AVG</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32:RmnDrp</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">AVware</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Ramnit.b (v)</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Ad-Aware</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Trojan.Slingup.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">AegisLab</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32.Nimnul.tp20</td>
<td style="width: 40px;">20180622</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">AhnLab-V3</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32/Ramnit.J</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Antiy-AVL</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus/Win32.Nimnul.a</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Arcabit</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Trojan.Slingup.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Avast</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32:RmnDrp</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Avira</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Ramnit.C</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Baidu</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Virus.Nimnul.a</td>
<td style="width: 40px;">20180622</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Bkav</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32.Tmgrtext.PE</td>
<td style="width: 40px;">20180623</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">CAT-QuickHeal</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32.Ramnit.BA</td>
<td style="width: 40px;">20180623</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">CMC</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Ramit.1!O</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">ClamAV</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win.Trojan.Ramnit-1847</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Comodo</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Ramnit.K</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">CrowdStrike</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">malicious_confidence_100% (W)</td>
<td style="width: 40px;">20180530</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Cybereason</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">malicious.e5bc9a</td>
<td style="width: 40px;">20180225</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Cylance</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Unsafe</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Cyren</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Ramnit.B!Generic</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">DrWeb</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Rmnet.8</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">ESET-NOD32</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32/Ramnit.H</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Emsisoft</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Trojan.Slingup.A (B)</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Endgame</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">malicious (high confidence)</td>
<td style="width: 40px;">20180612</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">F-Prot</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Ramnit.B!Generic</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Fortinet</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Ramnit.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">GData</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Virus.Nimnul.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Ikarus</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Backdoor.Win32.Slingup</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Invincea</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">heuristic</td>
<td style="width: 40px;">20180601</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Jiangmin</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32/IRCNite.wi</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">K7AntiVirus</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus ( 002fe95d1 )</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">K7GW</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus ( 002fe95d1 )</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Kaspersky</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Nimnul.a</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Kingsoft</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Ramnit.lx.30720</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">MAX</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">malware (ai score=88)</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">McAfee</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Ramnit.a</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">McAfee-GW-Edition</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">BehavesLike.Win32.Ramnit.dh</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">MicroWorld-eScan</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Trojan.Slingup.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Microsoft</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus:Win32/Ramnit.P</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">NANO-Antivirus</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Nimnul.bmnup</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Panda</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Nimnul.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Qihoo-360</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Ramnit.A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Rising</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Malware.Heuristic!ET#98% (RDM+:cmRtazo2yjxeYhdDtLZXcAxee5+7)</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">SentinelOne</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">static engine - malicious</td>
<td style="width: 40px;">20180618</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Sophos</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32/Ramnit-A</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Symantec</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">W32.Ramnit.B!inf</td>
<td style="width: 40px;">20180623</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">TACHYON</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus/W32.Ramnit</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Tencent</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Nimnul.e</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">TotalDefense</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32/Ramnit.C</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">TrendMicro</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">PE_RAMNIT.DEN</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">TrendMicro-HouseCall</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">PE_RAMNIT.DEN</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">VBA32</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Nimnul.b</td>
<td style="width: 40px;">20180622</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">VIPRE</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Ramnit.b (v)</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">ViRobot</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Nimnul.A</td>
<td style="width: 40px;">20180623</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Yandex</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Nimnul.Gen.2</td>
<td style="width: 40px;">20180622</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Zillya</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Nimnul.Win32.1</td>
<td style="width: 40px;">20180622</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">ZoneAlarm</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Virus.Win32.Nimnul.a</td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Zoner</td>
<td style="width: 10px;">true</td>
<td style="width: 393px;">Win32.Ramnit.H</td>
<td style="width: 40px;">20180623</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Alibaba</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180622</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Avast-Mobile</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180623</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Babable</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180406</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">F-Secure</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Malwarebytes</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Paloalto</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">SUPERAntiSpyware</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">TheHacker</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">Webroot</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
<tr>
<td style="width: 16px;"> </td>
<td style="width: 277px;">eGambit</td>
<td style="width: 10px;">false</td>
<td style="width: 393px;"> </td>
<td style="width: 40px;">20180624</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_69328637159591530710957914">4. Get URL report</h3>
<hr>
<p>Generates a report about a specific URL.</p>
<h5>Base Command</h5>
<p><code>vt-private-get-url-report</code></p>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">resource</td>
<td style="width: 534px;">A CSV list of one or more URLs to retrieve the most recent report for. You can also specify a scan_id (sha-256 timestamp returned by the URL submission API) to access a specific report.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">retries</td>
<td style="width: 534px;">The number of times the command will try to get the URL report, if the report was not ready on the first attempt.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">allInfo</td>
<td style="width: 534px;">This additional info includes VirusTotal related metadata (first seen date, last seen date, files downloaded from the given URL, etc.) and the output of other tools and datasets when fed with the URL.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">shortFormat</td>
<td style="width: 534px;">If "true", to hide VT scans tables</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">threshold</td>
<td style="width: 534px;">If the number of positives is larger than the threshold, the file will be considered malicious. If threshold is not specified, the default file threshold, as configured in the instance settings, will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">fullResponse</td>
<td style="width: 534px;">Return all of the results, note that it can be thousands of results. Prefer not to use in playbooks. The default value is <code>false</code>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">retry_time</td>
<td style="width: 534px;">The amount of time (in seconds) that the integration will wait before trying to get a URL report for URLS whose scans have not completed.</td>
<td style="width: 71px;">Optional</td>
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
<th style="width: 294px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 294px;">URL.Data</td>
<td style="width: 60px;">string</td>
<td style="width: 386px;">URL address</td>
</tr>
<tr>
<td style="width: 294px;">URL.Malicious.Vendor</td>
<td style="width: 60px;">string</td>
<td style="width: 386px;">For malicious URLs, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 294px;">URL.Malicious.Description</td>
<td style="width: 60px;">string</td>
<td style="width: 386px;">For malicious URLs, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 294px;">DBotScore.Indicator</td>
<td style="width: 60px;">string</td>
<td style="width: 386px;">The indicator that was tested</td>
</tr>
<tr>
<td style="width: 294px;">DBotScore.Type</td>
<td style="width: 60px;">string</td>
<td style="width: 386px;">The indicator type</td>
</tr>
<tr>
<td style="width: 294px;">DBotScore.Vendor</td>
<td style="width: 60px;">string</td>
<td style="width: 386px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 294px;">DBotScore.Score</td>
<td style="width: 60px;">number</td>
<td style="width: 386px;">The actual score</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.Resolutions.ip_address</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">IPs that resolved to this URL</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.Resolutions.last_resolved</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">Resolve date of IPs that resolved to this URL</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.ResponseContentSHA256</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">SHA256 hash of the response content</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.ResponseHeaders</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">The response headers</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.Scans.Source</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">Scan vendor for this URL</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.Scans.Detected</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">Scan detection for this URL (True/False)</td>
</tr>
<tr>
<td style="width: 294px;">URL.VirusTotal.Scans.Result</td>
<td style="width: 60px;">Unknown</td>
<td style="width: 386px;">Scan result for this URL - signature, etc.</td>
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
<pre>!vt-private-get-url-report resource="www.google.com,https://ctgold.in.net/G5?POP!=junk.name@jonk.com"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "URL": [
        {
            "Data": "https://ctgold.in.net/G5?POP!=junk.name@jonk.com", 
            "VirusTotal": {
                "Scans": [
                    {
                        "Source": "CRDF", 
                        "Detected": true, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "malicious site"
                    }, 
                    {
                        "Source": "CyRadar", 
                        "Detected": true, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "malicious site"
                    }, 
                    {
                        "Source": "Forcepoint ThreatSeeker", 
                        "Detected": true, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "phishing site"
                    }, 
                    {
                        "Source": "Google Safebrowsing", 
                        "Detected": true, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "phishing site"
                    }, 
                    {
                        "Source": "Kaspersky", 
                        "Detected": true, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "phishing site"
                    }, 
                    {
                        "Source": "Sophos", 
                        "Detected": true, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "malicious site"
                    }, 
                    {
                        "Source": "ADMINUSLabs", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "AegisLab WebGuard", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "AlienVault", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Antiy-AVL", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "AutoShun", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Avira", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Baidu-International", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "BitDefender", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Blueliv", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "C-SIRT", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "CLEAN MX", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Certly", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Comodo Site Inspector", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "CyberCrime", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "DNS8", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Dr.Web", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ESET", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Emsisoft", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Fortinet", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "FraudScore", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "FraudSense", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "G-Data", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "K7AntiVirus", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malc0de Database", 
                        "Detected": false, 
                        "Details": "http://malc0de.com/database/index.php?search=ctgold.in.net", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malekal", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malware Domain Blocklist", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "MalwareDomainList", 
                        "Detected": false, 
                        "Details": "http://www.malwaredomainlist.com/mdl.php?search=ctgold.in.net", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "MalwarePatrol", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malwarebytes hpHosts", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malwared", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Netcraft", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "NotMining", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Nucleon", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "OpenPhish", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Opera", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "PhishLabs", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Phishtank", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Quttera", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Rising", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "SCUMWARE.org", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "SecureBrain", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Spam404", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "StopBadware", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Sucuri SiteCheck", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Tencent", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ThreatHive", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Trustwave", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "URLQuery", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "VX Vault", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Virusdie External Site Scan", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Web Security Guard", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Yandex Safebrowsing", 
                        "Detected": false, 
                        "Details": "http://yandex.com/infected?l10n=en&amp;url=https://ctgold.in.net/G5?POP!=junk.name@jonk.com", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZCloudsec", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZDB Zeus", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZeroCERT", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Zerofox", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZeusTracker", 
                        "Detected": false, 
                        "Details": "https://zeustracker.abuse.ch/monitor.php?host=ctgold.in.net", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "desenmascara.me", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "malwares.com URL checker", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "securolytics", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "zvelo", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }
                ]
            }
        }, 
        {
            "Data": "www.google.com", 
            "VirusTotal": {
                "Scans": [
                    {
                        "Source": "ADMINUSLabs", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "AegisLab WebGuard", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "AlienVault", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Antiy-AVL", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "AutoShun", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Avira", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Baidu-International", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "BitDefender", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Blueliv", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "C-SIRT", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "CLEAN MX", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Certly", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Comodo Site Inspector", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "CyRadar", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "CyberCrime", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "DNS8", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Dr.Web", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ESET", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Emsisoft", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Forcepoint ThreatSeeker", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Fortinet", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "FraudScore", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "FraudSense", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "G-Data", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Google Safebrowsing", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "K7AntiVirus", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Kaspersky", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malc0de Database", 
                        "Detected": false, 
                        "Details": "http://malc0de.com/database/index.php?search=www.google.com", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malekal", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malware Domain Blocklist", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "MalwareDomainList", 
                        "Detected": false, 
                        "Details": "http://www.malwaredomainlist.com/mdl.php?search=www.google.com", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "MalwarePatrol", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malwarebytes hpHosts", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Malwared", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Netcraft", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "NotMining", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Nucleon", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "OpenPhish", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Opera", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "PhishLabs", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Phishtank", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Quttera", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Rising", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "SCUMWARE.org", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "SecureBrain", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Sophos", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Spam404", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "StopBadware", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "Sucuri SiteCheck", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Tencent", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ThreatHive", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Trustwave", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "URLQuery", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "unrated site"
                    }, 
                    {
                        "Source": "VX Vault", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Virusdie External Site Scan", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Web Security Guard", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Yandex Safebrowsing", 
                        "Detected": false, 
                        "Details": "http://yandex.com/infected?l10n=en&amp;url=http://www.google.com/", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZCloudsec", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZDB Zeus", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZeroCERT", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "Zerofox", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "ZeusTracker", 
                        "Detected": false, 
                        "Details": "https://zeustracker.abuse.ch/monitor.php?host=www.google.com", 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "desenmascara.me", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "malwares.com URL checker", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "securolytics", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }, 
                    {
                        "Source": "zvelo", 
                        "Detected": false, 
                        "Details": null, 
                        "Update": null, 
                        "Result": "clean site"
                    }
                ]
            }
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "VirusTotal - Private API", 
            "Indicator": "https://ctgold.in.net/G5?POP!=junk.name@jonk.com", 
            "Score": 2, 
            "Type": "url"
        }, 
        {
            "Vendor": "VirusTotal - Private API", 
            "Indicator": "www.google.com", 
            "Score": 1, 
            "Type": "url"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h2 id="virustotal-url-report-for-httpsctgold.in.netg5popjunk.namejonk.com">VirusTotal URL report for: <a href="https://ctgold.in.net/G5?POP!=junk.name@jonk.com">https://ctgold.in.net/G5?POP!=junk.name@jonk.com</a>
</h2>
</div>
<div class="cl-preview-section">
<p>Scan ID: <strong>899b8b5d10d3e3b6b20ff94075b9b8d8db771cd24097e2cdd71457e69f4ad705-1552987965</strong><br> Scan date: <strong>2019-03-19 09:32:45</strong><br> Detections / Total: <strong>6/67</strong><br> VT Link: <a href="https://www.virustotal.com/url/899b8b5d10d3e3b6b20ff94075b9b8d8db771cd24097e2cdd71457e69f4ad705/analysis/1552987965/">https://ctgold.in.net/G5?POP!=junk.name@jonk.com</a></p>
</div>
<div class="cl-preview-section">
<h3 id="scans">Scans</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 671px;">
<thead>
<tr>
<th style="width: 204px;">Details</th>
<th style="width: 259px;">Source</th>
<th style="width: 71px;">Detected</th>
<th style="width: 66px;">Result</th>
<th style="width: 56px;">Update</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">CRDF</td>
<td style="width: 71px;">true</td>
<td style="width: 66px;">malicious site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">CyRadar</td>
<td style="width: 71px;">true</td>
<td style="width: 66px;">malicious site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Forcepoint ThreatSeeker</td>
<td style="width: 71px;">true</td>
<td style="width: 66px;">phishing site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Google Safebrowsing</td>
<td style="width: 71px;">true</td>
<td style="width: 66px;">phishing site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Kaspersky</td>
<td style="width: 71px;">true</td>
<td style="width: 66px;">phishing site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Sophos</td>
<td style="width: 71px;">true</td>
<td style="width: 66px;">malicious site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">ADMINUSLabs</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">AegisLab WebGuard</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">AlienVault</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Antiy-AVL</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">AutoShun</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Avira</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Baidu-International</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">BitDefender</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Blueliv</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">C-SIRT</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">CLEAN MX</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Certly</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Comodo Site Inspector</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">CyberCrime</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">DNS8</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Dr.Web</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">ESET</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Emsisoft</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Fortinet</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">FraudScore</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">FraudSense</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">G-Data</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">K7AntiVirus</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"><a href="http://malc0de.com/database/index.php?search=ctgold.in.net">http://malc0de.com/database/index.php?search=ctgold.in.net</a></td>
<td style="width: 259px;">Malc0de Database</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Malekal</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Malware Domain Blocklist</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"><a href="http://www.malwaredomainlist.com/mdl.php?search=ctgold.in.net">http://www.malwaredomainlist.com/mdl.php?search=ctgold.in.net</a></td>
<td style="width: 259px;">MalwareDomainList</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">MalwarePatrol</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Malwarebytes hpHosts</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Malwared</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Netcraft</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">NotMining</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Nucleon</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">OpenPhish</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Opera</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">PhishLabs</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Phishtank</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Quttera</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Rising</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">SCUMWARE.org</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">SecureBrain</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Spam404</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">StopBadware</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Sucuri SiteCheck</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Tencent</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">ThreatHive</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Trustwave</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">URLQuery</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">VX Vault</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Virusdie External Site Scan</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Web Security Guard</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"><a href="http://yandex.com/infected?l10n=en&amp;url=https://ctgold.in.net/G5?POP!=junk.name@jonk.com">http://yandex.com/infected?l10n=en&amp;url=https://ctgold.in.net/G5?POP!=junk.name@jonk.com</a></td>
<td style="width: 259px;">Yandex Safebrowsing</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">ZCloudsec</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">ZDB Zeus</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">ZeroCERT</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">Zerofox</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"><a href="https://zeustracker.abuse.ch/monitor.php?host=ctgold.in.net">https://zeustracker.abuse.ch/monitor.php?host=ctgold.in.net</a></td>
<td style="width: 259px;">ZeusTracker</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">desenmascara.me</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">malwares.com URL checker</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">securolytics</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 204px;"> </td>
<td style="width: 259px;">zvelo</td>
<td style="width: 71px;">false</td>
<td style="width: 66px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h2 id="virustotal-url-report-for-www.google.com">VirusTotal URL report for: <a href="http://www.google.com/">www.google.com</a>
</h2>
</div>
<div class="cl-preview-section">
<p>Scan ID: <strong>dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf-1552987806</strong><br> Scan date: <strong>2019-03-19 09:30:06</strong><br> Detections / Total: <strong>0/66</strong><br> VT Link: <a href="https://www.virustotal.com/url/dd014af5ed6b38d9130e3f466f850e46d21b951199d53a18ef29ee9341614eaf/analysis/1552987806/">www.google.com</a></p>
</div>
<div class="cl-preview-section">
<h3 id="scans-1">Scans</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 661px;">
<thead>
<tr>
<th style="width: 330px;">Details</th>
<th style="width: 133px;">Source</th>
<th style="width: 71px;">Detected</th>
<th style="width: 55px;">Result</th>
<th style="width: 56px;">Update</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">ADMINUSLabs</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">AegisLab WebGuard</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">AlienVault</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Antiy-AVL</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">AutoShun</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Avira</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Baidu-International</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">BitDefender</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Blueliv</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">C-SIRT</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">CLEAN MX</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Certly</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Comodo Site Inspector</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">CyRadar</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">CyberCrime</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">DNS8</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Dr.Web</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">ESET</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Emsisoft</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Forcepoint ThreatSeeker</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Fortinet</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">FraudScore</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">FraudSense</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">G-Data</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Google Safebrowsing</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">K7AntiVirus</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Kaspersky</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"><a href="http://malc0de.com/database/index.php?search=www.google.com">http://malc0de.com/database/index.php?search=www.google.com</a></td>
<td style="width: 133px;">Malc0de Database</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Malekal</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Malware Domain Blocklist</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"><a href="http://www.malwaredomainlist.com/mdl.php?search=www.google.com">http://www.malwaredomainlist.com/mdl.php?search=www.google.com</a></td>
<td style="width: 133px;">MalwareDomainList</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">MalwarePatrol</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Malwarebytes hpHosts</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Malwared</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Netcraft</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">NotMining</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Nucleon</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">OpenPhish</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Opera</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">PhishLabs</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Phishtank</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Quttera</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Rising</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">SCUMWARE.org</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">SecureBrain</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Sophos</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Spam404</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">StopBadware</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Sucuri SiteCheck</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Tencent</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">ThreatHive</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Trustwave</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">URLQuery</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">unrated site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">VX Vault</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Virusdie External Site Scan</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Web Security Guard</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"><a href="http://yandex.com/infected?l10n=en&amp;url=http://www.google.com/">http://yandex.com/infected?l10n=en&amp;url=http://www.google.com/</a></td>
<td style="width: 133px;">Yandex Safebrowsing</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">ZCloudsec</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">ZDB Zeus</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">ZeroCERT</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">Zerofox</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"><a href="https://zeustracker.abuse.ch/monitor.php?host=www.google.com">https://zeustracker.abuse.ch/monitor.php?host=www.google.com</a></td>
<td style="width: 133px;">ZeusTracker</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">desenmascara.me</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">malwares.com URL checker</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">securolytics</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
<tr>
<td style="width: 330px;"> </td>
<td style="width: 133px;">zvelo</td>
<td style="width: 71px;">false</td>
<td style="width: 55px;">clean site</td>
<td style="width: 56px;"> </td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<h3 id="h_2661925843991533461800180">5. Get IP address report</h3>
<hr>
<p>Generates a report about a specific IP address.</p>
<p>An IP tested with this command is considered malicious if it has a number of detected communicating samples (files that VT marked as malicious and communicated with this IP) that exceeds the IP threshold, or if it has a URL that was hosted in this IP and had a positive amount that exceeds the URL threshold.</p>
<h5>Base Command</h5>
<p><code>vt-private-get-ip-report</code></p>
<h5>Input</h5>
<table style="width: 742px;">
<thead>
<tr>
<td style="width: 134px;"><strong>Argument Name</strong></td>
<td style="width: 587px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">ip</td>
<td style="width: 587px;">Valid IPv4 address in dotted quad notation.<br> Only IPv4 addresses are supported.</td>
</tr>
<tr>
<td style="width: 134px;">threshold</td>
<td style="width: 587px;">If the number of positive results from the VT scanners is bigger than the threshold, the IP address will be considered malicious.<br> Default is as configured in the instance settings.</td>
</tr>
<tr>
<td style="width: 134px;">fullResponse</td>
<td style="width: 587px;">Return all results. This can number in the thousands, so we recommend not using in playbooks. Default is <code>false</code>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 280px;"><strong>Path</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280px;">IP.Address</td>
<td style="width: 441px;">Bad IP address found</td>
</tr>
<tr>
<td style="width: 280px;">IP.ASN</td>
<td style="width: 441px;">Bad IP ASN</td>
</tr>
<tr>
<td style="width: 280px;">IP.Geo.Country</td>
<td style="width: 441px;">Bad IP country</td>
</tr>
<tr>
<td style="width: 280px;">IP.Malicious.Vendor</td>
<td style="width: 441px;">For malicious IPs, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 280px;">IP.Malicious.Description</td>
<td style="width: 441px;">For malicious IPs, the reason that the vendor made the decision</td>
</tr>
<tr>
<td style="width: 280px;">DBotScore.Indicator</td>
<td style="width: 441px;">The indicator that was tested</td>
</tr>
<tr>
<td style="width: 280px;">DBotScore.Type</td>
<td style="width: 441px;">The type of the indicator</td>
</tr>
<tr>
<td style="width: 280px;">DBotScore.Vendor</td>
<td style="width: 441px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 280px;">DBotScore.Score</td>
<td style="width: 441px;">The actual score</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.DownloadedHashes</td>
<td style="width: 441px;">Latest files that are detected by at least one antivirus solution and were downloaded by VirusTotal from the IP address</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.UnAVDetectedDownloadedHashes</td>
<td style="width: 441px;">Latest files that are not detected by any antivirus solution and were downloaded by VirusTotal from the IP address provided</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.DetectedURLs</td>
<td style="width: 441px;">Latest URLs hosted in this IP address detected by at least one URL scanner</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.CommunicatingHashes</td>
<td style="width: 441px;">Latest detected files that communicate with this IP address</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.UnAVDetectedCommunicatingHashes</td>
<td style="width: 441px;">Latest undetected files that communicate with this IP address</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.Resolutions.hostname</td>
<td style="width: 441px;">The following domains resolved to the given IP</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.ReferrerHashes</td>
<td style="width: 441px;">Latest detected files that embed this IP address in their strings</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.UnAVDetectedReferrerHashes</td>
<td style="width: 441px;">Latest undetected files that embed this IP address in their strings</td>
</tr>
<tr>
<td style="width: 280px;">IP.VirusTotal.Resolutions.last_resolved</td>
<td style="width: 441px;">The last time the following domains resolved to the given IP</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!vt-private-get-ip-report ip=8.8.8.8 fullResponse="false"</pre>
<h5>Context Example</h5>
<pre>{
  "ASN": "15169",
  "Address": "8.8.8.8",
  "Geo": {
    "Country": "US"
  },
  "VirusTotal": {
    "CommunicatingHashes": [
      {
        "date": "2018-07-24 04:25:53",
        "positives": 37,
        "sha256": "63309a3ece4c0c0568db02d3c3e562c75aff756bb9387f56fc86d7a89c59ee7f",
        "total": 70
      },
      {
        "date": "2018-07-24 07:15:21",
        "positives": 32,
        "sha256": "4aeb98aaeb459f8be2fb737f8228e52387f33ec84df4a7933927670f790e3e02",
        "total": 68
      },
      {
        "date": "2018-07-24 07:06:31",
        "positives": 52,
        "sha256": "60b65e182b33241e895e10a672ca1451e1f04b430fdbf98065211ace3a6264a4",
        "total": 67
      },
      {
        "date": "2018-07-24 00:13:33",
        "positives": 3,
        "sha256": "c69d3691cd8d03a1823879ed5dbb1afe3e5b26cb5c72eed05f38f85f6bbaad93",
        "total": 70
      },
      {
        "date": "2018-07-24 03:38:37",
        "positives": 32,
        "sha256": "ef7e0c62ddb624f1b0ec2f64940d8ad218e40dd182031818ef022ba8ddd47d11",
        "total": 70
      }
      ]
  }
}
</pre>
<h3 id="h_61744244738791530695809935">6. Submit a query</h3>
<hr>
<p>Submits a query to Virus Total.</p>
<h5>Base Command</h5>
<p><code>vt-private-search-file</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 152px;"><strong>Argument Name</strong></td>
<td style="width: 569px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">query</td>
<td style="width: 569px;">File search query</td>
</tr>
<tr>
<td style="width: 152px;">fullResponse</td>
<td style="width: 569px;">Return all results. This can number in the thousands, so we recommend not using in playbooks. Default is <code>false</code>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 268px;"><strong>Path</strong></td>
<td style="width: 453px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 268px;">VirusTotal.SearchFile.SearchResult</td>
<td style="width: 453px;">Hashes of files that match the query</td>
</tr>
<tr>
<td style="width: 268px;">VirusTotal.SearchFile.Query</td>
<td style="width: 453px;">Original search query</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!vt-private-search-file query="type:peexe size:90kb+ positives:5+ behaviour:'taskkill'"</pre>
<h5>Context Example</h5>
<pre>{
  "SearchFile": {
    "Query": "type:peexe size:90kb+ positives:5+ behaviour:'taskkill'",
    "SearchResult": [
      "698a9a11c38763b514fd6fc74ee773c2510b0a88faefaf0e5807d51d39f59af7",
      "7c6ebc9225163da5e6a01766895b9b520c8aa24320e6ff9a6ea87c8b8eecfa8e",
      "c42011a62bf4621962788d48ed3938bfddf8b32685f5ced6442934ad80c12c25",
      "0f965f6e2285002fa7d082fd3d28b49d96a05ba59d916624061f24e3b94a54c3",
      "1cb4ffa0e9914d6c5b4aad008636849096a39d3aaf66297ba826a3e01865ff98",
      "ee89e5627b4be45efdd30b8b3cfe5275c1591a4a350cce7ae24a6efc4819f1ef",
      "d6582514f1d68ab7976de7ac447a89a9fb9ae7cff8219d27b327c0712cc8e2d1",
      "150a67b251607bda468aebfd462976de081ace5015dc43f7024cab58fb6ec5dd",
      "16d186b7d4a805b66610fbc626c1af51f5b9cfe47c06d0604a1002bce5e92219",
      "aef0b520e96da26126a88de23ee000bc31a15ba0214c5a50e09c9944284dd16e",
      "22822ce94523e24e03cb3f63d1f9522929b1d53902818fe8d009b467f68033c3",
      "0554588ca5dbf78e1e30375621d32e1d323a18a4296fbf54deb70169113541a7",
      "ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e",
      "89d7ebfd154c44d17939107b58422736a605d1e80099d6c8fd73462b492227d7",
      "c8a44fe52a058ad03b23e07f387c35da6d9cf2cd4ded95835c09b04b8308ac4c",
      "296d70d8f10c964f6a8e4cc88760e25c07c0f050ffa2768c30cbd281d94af8d9",
      "0556433422e53ededb408d14f522d0956cc5dacb4d1f3d235a05898307f6838a",
      "75b0d5a5be55b30975e4694077b178b477ea4c82031f48deab63356a8fef4dd6",
      "7cd606da7ff2204a2d5d6d67511e120011c6d0489788ed390e9a5c858b34df8e",
      "590d40c79f48aaeae22d07a9e1b0ca4f4c059f5001444902a90a49f1f7d09923",
      "a25d8da463ffa1f44138c40fb0f4df6c10f03e7d6c00436531168a5a2aa9707d",
      "54ad2ddd1cd747fb6644e9184e9751c4ca2ad5a57c232f33023001d210c48098",
      "6b2629629924224a6909bd2c5814b13f8721ebc5caef8c55ee6233be891b7112",
      "71acde730859ec1902ed0ec72e16db8fcc5eefb84f1079a5eb2eb19589ea4d88",
      "5392685717eb8710017fabea59954ebc8a62d791634439c6d84dbae059578069",
      "58fd0f2dd2e60e507b4ac78c10f32c1fb92eef45f43f94b934d2c643b3911731",
      "2a2176f026f93116807553342338a59010cfd97fdb96129143e33807f4d66b13",
      "4e4fb7ab71072d2a42769dab76f4f54e3bb29a0c288943dcbdc20beb55edf321",
      "a6db7d675f031cbcd64a83115bf00e3d50b40cd708ebedf39b94be298137d301",
      "9342d1831165c52b92549b7340d9631a05f1ef5609ba74534e9fedd44a8256fc",
      "e71235a6a104fbf7f2916153659c460752213ca6c698c9a8f656c1b7187523fa",
      "e3f4e83633326ed9a9f085468aac13be840bc6a29fc62b8d90299884800bbf66",
      "e760c373a6641ad9b3e817d1f7545f68a6cc7a0811c17e0ff2a5cb3738fb2418",
      "a5263a9071152c02f2c16891203263a27876b4da626cd40bef28e46f49472352",
      "6edec978e399cde55d66afde8c64f4e1b4bd001b8288c976ce399341145f431b",
      "2d375422c0499c929ca7d958ae8354048b1d2972fffc3676f32c6445bc3d20b8",
      "10fa90e7c6d7c3a0e172346a8c0fbf0c48f852a9abc9482231007cadae62a539",
      "f67b7fab4f5c1c4fda2b51eaeac8a57020a71352d0b5daf27fea3524fd39ba63",
      "59df7d186b4f810d870ada1ffe85dad04b5acb12a499dcc51c9e1048ea3a480c",
      "2984d96b73586481363af095a9bd630507af604b11b61ed4a20aef7275ef85e3",
      "20cd8e956a1700161b9cba57fcae2f0f49cb00217de10e07712007a40b5cd865",
      "02db5e24cf325a5ee266624cbbd73a541d007c1c230f89dcd70e08600b356409",
      "5b0217cba668bb19ec22e5d567e3391652d9bcaff3632521ac54900f04288ee2",
      "b0f67e11ae7a412be4467d16774a188e6571b959bcba856b6188694fb2e36e09",
      "c6e09206fd8666c954ccfe8765376dba37591e39f87f404aec87490c9dbbd0c9",
      "3bb937aa5151a6eb1232855811d13ea64419e6d1e8176bd2a15d44b4e432972f",
      "ed0c33b943a089acf49879b97accfad897141043d97f20ea291b5b09d213b057",
      "69f414a12a822242951cefcf8b1b00b4ee9773f394211ca7ab9019be93031621",
      "916241775e3a96d6809e2f7b29d89a1f261b025e0f1f891180b8f532572f6aca",
      "f06b2052228c6e3c7cd3b713b23ec29cd56c8c7ea112ea2a9ab87309b4c9ff92"
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Found the following hashes for the query :type:peexe size:90kb+ positives:5+ behaviour:'taskkill'</h3>
<h3>Hashes are:</h3>
<table>
<thead>
<tr>
<th>Hash</th>
</tr>
</thead>
<tbody>
<tr>
<td>698a9a11c38763b514fd6fc74ee773c2510b0a88faefaf0e5807d51d39f59af7</td>
</tr>
<tr>
<td>7c6ebc9225163da5e6a01766895b9b520c8aa24320e6ff9a6ea87c8b8eecfa8e</td>
</tr>
<tr>
<td>c42011a62bf4621962788d48ed3938bfddf8b32685f5ced6442934ad80c12c25</td>
</tr>
<tr>
<td>0f965f6e2285002fa7d082fd3d28b49d96a05ba59d916624061f24e3b94a54c3</td>
</tr>
<tr>
<td>1cb4ffa0e9914d6c5b4aad008636849096a39d3aaf66297ba826a3e01865ff98</td>
</tr>
<tr>
<td>ee89e5627b4be45efdd30b8b3cfe5275c1591a4a350cce7ae24a6efc4819f1ef</td>
</tr>
<tr>
<td>d6582514f1d68ab7976de7ac447a89a9fb9ae7cff8219d27b327c0712cc8e2d1</td>
</tr>
<tr>
<td>150a67b251607bda468aebfd462976de081ace5015dc43f7024cab58fb6ec5dd</td>
</tr>
<tr>
<td>16d186b7d4a805b66610fbc626c1af51f5b9cfe47c06d0604a1002bce5e92219</td>
</tr>
<tr>
<td>aef0b520e96da26126a88de23ee000bc31a15ba0214c5a50e09c9944284dd16e</td>
</tr>
<tr>
<td>22822ce94523e24e03cb3f63d1f9522929b1d53902818fe8d009b467f68033c3</td>
</tr>
<tr>
<td>0554588ca5dbf78e1e30375621d32e1d323a18a4296fbf54deb70169113541a7</td>
</tr>
<tr>
<td>ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e</td>
</tr>
<tr>
<td>89d7ebfd154c44d17939107b58422736a605d1e80099d6c8fd73462b492227d7</td>
</tr>
<tr>
<td>c8a44fe52a058ad03b23e07f387c35da6d9cf2cd4ded95835c09b04b8308ac4c</td>
</tr>
<tr>
<td>296d70d8f10c964f6a8e4cc88760e25c07c0f050ffa2768c30cbd281d94af8d9</td>
</tr>
<tr>
<td>0556433422e53ededb408d14f522d0956cc5dacb4d1f3d235a05898307f6838a</td>
</tr>
<tr>
<td>75b0d5a5be55b30975e4694077b178b477ea4c82031f48deab63356a8fef4dd6</td>
</tr>
<tr>
<td>7cd606da7ff2204a2d5d6d67511e120011c6d0489788ed390e9a5c858b34df8e</td>
</tr>
<tr>
<td>590d40c79f48aaeae22d07a9e1b0ca4f4c059f5001444902a90a49f1f7d09923</td>
</tr>
<tr>
<td>a25d8da463ffa1f44138c40fb0f4df6c10f03e7d6c00436531168a5a2aa9707d</td>
</tr>
<tr>
<td>54ad2ddd1cd747fb6644e9184e9751c4ca2ad5a57c232f33023001d210c48098</td>
</tr>
<tr>
<td>6b2629629924224a6909bd2c5814b13f8721ebc5caef8c55ee6233be891b7112</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_81696018363741530710990114">7. Return hashes for a specific IP address</h3>
<hr>
<p>Returns information about the hashes that communicate with a specific IP address.</p>
<h5>Command Name</h5>
<p><code>vt-private-hash-communication</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 131px;"><strong>Argument Name</strong></td>
<td style="width: 590px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">hash</td>
<td style="width: 590px;">File hash</td>
</tr>
<tr>
<td style="width: 131px;">fullResponse</td>
<td style="width: 590px;">Return all results. This can number in the thousands, so we recommend not using in playbooks. Default is <code>false</code>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 332px;"><strong>Path</strong></th>
<th style="width: 389px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332px;">File.VirusTotal.CommunicatedDomains</td>
<td style="width: 389px;">Domains that the hash communicates with</td>
</tr>
<tr>
<td style="width: 332px;">File.VirusTotal.CommunicatedURLs</td>
<td style="width: 389px;">URLs that the hash communicates with</td>
</tr>
<tr>
<td style="width: 332px;">File.VirusTotal.CommunicatedIPs</td>
<td style="width: 389px;">IPs that the hash communicates with</td>
</tr>
<tr>
<td style="width: 332px;">File.VirusTotal.CommunicatedHosts</td>
<td style="width: 389px;">Hosts that the hash communicates with</td>
</tr>
<tr>
<td style="width: 332px;">File.MD5</td>
<td style="width: 389px;">MD5 of the file</td>
</tr>
<tr>
<td style="width: 332px;">File.SHA1</td>
<td style="width: 389px;">SHA-1 of the file</td>
</tr>
<tr>
<td style="width: 332px;">File.SHA256</td>
<td style="width: 389px;">SHA-256 of the file</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!vt-private-hash-communication hash="ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e" fullResponse="false"</pre>
<h5>Context Example</h5>
<pre>{
  "SearchFile": {
    "Query": "type:peexe size:90kb+ positives:5+ behaviour:'taskkill'",
    "SearchResult": [
      "698a9a11c38763b514fd6fc74ee773c2510b0a88faefaf0e5807d51d39f59af7",
      "7c6ebc9225163da5e6a01766895b9b520c8aa24320e6ff9a6ea87c8b8eecfa8e",
      "c42011a62bf4621962788d48ed3938bfddf8b32685f5ced6442934ad80c12c25",
      "0f965f6e2285002fa7d082fd3d28b49d96a05ba59d916624061f24e3b94a54c3",
      "1cb4ffa0e9914d6c5b4aad008636849096a39d3aaf66297ba826a3e01865ff98",
      "ee89e5627b4be45efdd30b8b3cfe5275c1591a4a350cce7ae24a6efc4819f1ef",
      "d6582514f1d68ab7976de7ac447a89a9fb9ae7cff8219d27b327c0712cc8e2d1",
      "150a67b251607bda468aebfd462976de081ace5015dc43f7024cab58fb6ec5dd",
      "16d186b7d4a805b66610fbc626c1af51f5b9cfe47c06d0604a1002bce5e92219",
      "aef0b520e96da26126a88de23ee000bc31a15ba0214c5a50e09c9944284dd16e",
      "22822ce94523e24e03cb3f63d1f9522929b1d53902818fe8d009b467f68033c3",
      "0554588ca5dbf78e1e30375621d32e1d323a18a4296fbf54deb70169113541a7",
      "ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e",
      "89d7ebfd154c44d17939107b58422736a605d1e80099d6c8fd73462b492227d7",
      "c8a44fe52a058ad03b23e07f387c35da6d9cf2cd4ded95835c09b04b8308ac4c",
      "296d70d8f10c964f6a8e4cc88760e25c07c0f050ffa2768c30cbd281d94af8d9",
      "0556433422e53ededb408d14f522d0956cc5dacb4d1f3d235a05898307f6838a",
      "75b0d5a5be55b30975e4694077b178b477ea4c82031f48deab63356a8fef4dd6",
      "7cd606da7ff2204a2d5d6d67511e120011c6d0489788ed390e9a5c858b34df8e",
      "590d40c79f48aaeae22d07a9e1b0ca4f4c059f5001444902a90a49f1f7d09923",
      "a25d8da463ffa1f44138c40fb0f4df6c10f03e7d6c00436531168a5a2aa9707d",
      "54ad2ddd1cd747fb6644e9184e9751c4ca2ad5a57c232f33023001d210c48098",
      "6b2629629924224a6909bd2c5814b13f8721ebc5caef8c55ee6233be891b7112",
      "71acde730859ec1902ed0ec72e16db8fcc5eefb84f1079a5eb2eb19589ea4d88",
      "5392685717eb8710017fabea59954ebc8a62d791634439c6d84dbae059578069",
      "58fd0f2dd2e60e507b4ac78c10f32c1fb92eef45f43f94b934d2c643b3911731",
      "2a2176f026f93116807553342338a59010cfd97fdb96129143e33807f4d66b13",
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<p>Communication result for hash ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e</p>
<h3>Hosts that the hash communicates with are:</h3>
<table>
<thead>
<tr>
<th>Host</th>
</tr>
</thead>
<tbody>
<tr>
<td>224.0.0.22</td>
</tr>
<tr>
<td>10.0.2.2</td>
</tr>
<tr>
<td>239.255.255.250</td>
</tr>
<tr>
<td>255.255.255.255</td>
</tr>
<tr>
<td>10.0.2.255</td>
</tr>
<tr>
<td>10.0.2.15</td>
</tr>
<tr>
<td>51.141.32.51</td>
</tr>
<tr>
<td>0.0.0.0</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>IPs that the hash communicates with are:</h3>
<table>
<thead>
<tr>
<th>IP</th>
</tr>
</thead>
<tbody>
<tr>
<td>10.0.2.2</td>
</tr>
<tr>
<td>239.255.255.250</td>
</tr>
<tr>
<td>10.0.2.255</td>
</tr>
<tr>
<td>10.0.2.15</td>
</tr>
<tr>
<td>51.141.32.51</td>
</tr>
<tr>
<td>255.255.255.255</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_49009414365071530711001039">8. Download a file</h3>
<hr>
<p>Downloads a file according to file hash.</p>
<h5>Base Command</h5>
<p><code>vt-private-download-file</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<td style="width: 160px;"><strong>Argument Name</strong></td>
<td style="width: 561px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">hash</td>
<td style="width: 561px;">MD5/SHA-1/SHA-256 hash of the file you want to download</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Command Example</h5>
<pre>!vt-private-download-file hash=ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e</pre>
<h5>Context Example</h5>
<pre>{
  "EntryID": "4103@14268",
  "Extension": "",
  "Info": "application/x-dosexec",
  "MD5": "d62f1fba82927e7db4bdf5b70fe5a5c2",
  "Name": "ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e-vt-file",
  "SHA1": "2bd01a1ecfdfcd1824cfa45a54c048c5a31851b1",
  "SHA256": "ba5d0f897e89ff70cffb3e95e4d54ea152d6a273a95bdff2224a224c90c0d16e",
  "SSDeep": "12288:zhB3ospNelPCXzYaf2oS8tZqZdK87+KDVZpdsYifqI8IqCbK:zh+3/Y/tZCdJPLuK",
  "Size": 465064,
  "Type": "MS-DOS executable, MZ for MS-DOS\n"
}
</pre>
<h5>Human Readable Output</h5>
<p>File downloaded successfully.</p>
