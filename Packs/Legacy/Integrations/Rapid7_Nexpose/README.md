<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Rapid7 Nexpose provides vulnerability management, assessment, and response to changes in the environment while prioritizing risk across vulnerabilities, configurations, and controls.<br>Use the Nexpose integration to access sites, assets, vulnerabilities and their solutions, scans and reports. The integration was developed with the Nexpose API v3.</p>
<h2>Rapid7 Nexpose Playbooks</h2>
<hr>
<p>For scans (Demisto v4.0) there are two sub-playbooks available, depending on the command. To start a site scan, use the <code>Nexpose Scan Site</code> sub-playbook. To start an assets scan, use the <code>Nexpose Scan Assets</code> sub-playbook.</p>
<p>When using the <code>sort</code> parameter, the fields to sort must be provided as they are in the API, e.g <code>riskScore</code>. All the available fields for any type of response can be found in the <a href="https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Asset" rel="nofollow">API Documentation.</a></p>
<p><strong>Nexpose Scan Assets</strong><br><a href="https://user-images.githubusercontent.com/35098543/44656891-67544580-aa03-11e8-8032-e56ee87c454d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44656891-67544580-aa03-11e8-8032-e56ee87c454d.png" alt="image" width="750" height="1335"></a></p>
<p><strong>Nexpose Scan Site</strong><br><a href="https://user-images.githubusercontent.com/35098543/44656828-2825f480-aa03-11e8-9ff8-2d443a9329b0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44656828-2825f480-aa03-11e8-9ff8-2d443a9329b0.png" alt="image" width="752" height="1348"></a></p>
<p><strong>Vulnerability Handling - Nexpose</strong><br><a href="https://user-images.githubusercontent.com/35098543/44337123-31064b80-a482-11e8-9f53-2b67ecb88033.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44337123-31064b80-a482-11e8-9f53-2b67ecb88033.png" alt="image"></a></p>
<p><strong>Vulnerability Management - Nexpose</strong><br><a href="https://user-images.githubusercontent.com/35098543/44337150-47140c00-a482-11e8-9bc8-6fa8f308952b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44337150-47140c00-a482-11e8-9bc8-6fa8f308952b.png" alt="image" width="751" height="1063"></a></p>
<h2> </h2>
<h2>Known Limitations</h2>
<hr>
<p>When starting a scan, the API cannot specify scan targets for sites configured with an Amazon Web Services discovery connection. To configure AWS with Nexpose, see <a href="https://nexpose.help.rapid7.com/docs/amazon-web-services" rel="nofollow">https://nexpose.help.rapid7.com/docs/amazon-web-services</a>.</p>
<blockquote>
<p>A regular scan engine requires authorization and compliance with AWS. Receiving authorization from AWS can take up to 72 hours and must be renewed every 90 days after creating a connection. Nexpose imposes no restrictions on the scan engine however you must still abide by AWS terms. More information can be found at <a href="https://aws.amazon.com/security/penetration-testing/" rel="nofollow">https://aws.amazon.com/security/penetration-testing/</a>.</p>
</blockquote>
<h2> </h2>
<h2>Use cases</h2>
<hr>
<p>The integration is used to retrieve information about assets/endpoints in the environment. This information can be used in playbooks to determine asset vulnerabilities and risk, and to take action according to the information, like creating reports for assets, sites and scans as a downloadable PDF file and start scans(See additional information below) for sites or assets.</p>
<h2> </h2>
<h2>Configure Rapid7 Nexpose on Demisto</h2>
<hr>
<p>To use Nexpose on Demisto, you need user credentials for Nexpose. You can also use a two-factor authentication token.</p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Rapid7 Nexpose.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1:8080/" rel="nofollow">https://192.168.0.1:8080</a>)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>2FA token</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<p>When using the <code>sort</code> parameter, you need to specify the fields to sort as they are in the API, for example, <code>riskScore</code>. All the available fields for any type of response can be found in the <a href="https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Asset" rel="nofollow">API Documentation.</a></p>
<ol>
<li><a href="#h_571602980101535881085821">Get a single asset: nexpose-get-asset</a></li>
<li><a href="#h_813073471451535881091195">Get all assets: nexpose-get-assets</a></li>
<li><a href="#h_1817527592791535881096604">Get all assets that match the filters: nexpose-search-assets</a></li>
<li><a href="#h_7872292294121535881104722">Get a specified scan: nexpose-get-scan</a></li>
<li><a href="#h_2913227705441535881110994">Get an asset's details: nexpose-get-asset-vulnerability</a></li>
<li><a href="#h_7950557746751535881116441">Create a site: nexpose-create-site</a></li>
<li><a href="#h_675310243481541583699711">Delete a site: nexpose-delete-site</a></li>
<li><a href="#h_4870988458051535881123130">Retrieve sites: nexpose-get-sites</a></li>
<li><a href="#h_5809229089341535881129094">Get report templates: nexpose-get-report-templates</a></li>
<li><a href="#h_49840302010611535881137854">Create an assets report: nexpose-create-assets-report</a></li>
<li><a href="#h_42411979411881535881149772">Create a sites report: nexpose-create-sites-report</a></li>
<li><a href="#h_80086420113141535881163018">Create a scan report: nexpose-create-scan-report</a></li>
<li><a href="#h_61925084014391535881184314">Start a site scan: nexpose-start-site-scan</a></li>
<li><a href="#h_16017905415631535881190325">Start an assets scan: nexpose-start-assets-scan</a></li>
<li><a href="#h_5435525813991541581547102">Stop a scan: nexpose-stop-scan</a></li>
<li><a href="#h_9633814268321541581557452">Pause a scan: nexpose-pause-scan</a></li>
<li><a href="#h_16956847714031541581564270">Resume a scan: nexpose-resume-scan</a></li>
<li><a href="#h_15635634821101541581569860">Get a list of scans: nexpose-get-scans</a></li>
</ol>
<h3 id="h_571602980101535881085821">1. Get a single asset</h3>
<hr>
<p>Returns the specified asset.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-asset</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 205px;"><strong>Argument Name</strong></th>
<th style="width: 384px;"><strong>Description</strong></th>
<th style="width: 119px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 205px;">id</td>
<td style="width: 384px;">integer The identifier of the asset.</td>
<td style="width: 119px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 283px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 358px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 283px;">Nexpose.Asset.Addresses</td>
<td style="width: 67px;">unknown</td>
<td style="width: 358px;">All addresses discovered on the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.AssetId</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">Id of the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Hardware</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The primary Media Access Control (MAC) address of the asset. The format is six groups of two hexadecimal digits separated by colons.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Aliases</td>
<td style="width: 67px;">unknown</td>
<td style="width: 358px;">All host names or aliases discovered on the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.HostType</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The type of asset, Valid values are unknown, guest, hypervisor, physical, mobile</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Site</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">Asset site name.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.OperatingSystem</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">Operating system of the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerabilities</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The total number of vulnerabilities on the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.CPE</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The Common Platform Enumeration (CPE) of the operating system.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.LastScanDate</td>
<td style="width: 67px;">date</td>
<td style="width: 358px;">Last scan date of the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.LastScanId</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">Id of the asset's last scan.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.RiskScore</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The risk score (with criticality adjustments) of the asset.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Software.Software</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The description of the software.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Software.Version</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The version of the software.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Services.Name</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The name of the service.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Services.Port</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The port of the service.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Services.Product</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The product running the service.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Services.protocol</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The protocol of the service, valid values are ip, icmp, igmp, ggp, tcp, pup, udp, idp, esp, nd, raw</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Users.FullName</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The full name of the user account.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Users.Name</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The name of the user account.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Users.UserId</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The identifier of the user account.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Id</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The identifier of the vulnerability.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Instances</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The number of vulnerable occurrences of the vulnerability. This does not include invulnerable instances.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Title</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The title (summary) of the vulnerability.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Malware</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The malware kits that are known to be used to exploit the vulnerability.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Exploit</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The exploits that can be used to exploit a vulnerability.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.CVSS</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The CVSS exploit score.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Risk</td>
<td style="width: 67px;">number</td>
<td style="width: 358px;">The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.PublishedOn</td>
<td style="width: 67px;">date</td>
<td style="width: 358px;">The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.ModifiedOn</td>
<td style="width: 67px;">date</td>
<td style="width: 358px;">The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD.</td>
</tr>
<tr>
<td style="width: 283px;">Nexpose.Asset.Vulnerability.Severity</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">The severity of the vulnerability, one of: "Moderate", "Severe", "Critical".</td>
</tr>
<tr>
<td style="width: 283px;">Endpoint.IP</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 283px;">Endpoint.HostName</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">Endpoint host name.</td>
</tr>
<tr>
<td style="width: 283px;">Endpoint.OS</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">Endpoint operating system.</td>
</tr>
<tr>
<td style="width: 283px;">CVE.ID</td>
<td style="width: 67px;">string</td>
<td style="width: 358px;">Common Vulnerabilities and Exposures ids</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-asset id="5"</code></p>
<h5>Context Example</h5>
<pre>{
    "Endpoint": [
        {
            "HostName": [
                "hostname1",
                "HostName2"
            ],
            "IP": [
                "1.2.3.4"
            ],
            "MAC": [],
            "OS": "Linux 2.6.X"
        }
    ],
    "Nexpose": {
        "Asset": {
            "Addresses": [
                "1.2.3.4"
            ],
            "Aliases": [
                "alias1",
                "alias2"
            ],
            "AssetId": 5,
            "CPE": null,
            "Hardware": [],
            "HostType": null,
            "LastScanDate": "2018-06-13T13:33:17.451Z",
            "LastScanId": 42794,
            "OperatingSystem": "Linux 2.6.X",
            "RiskScore": 2071.67822265625,
            "Service": [
                {
                    "Name": "SSH",
                    "Port": 22,
                    "Product": "OpenSSH",
                    "Protocol": "tcp"
                },
                {
                    "Name": "HTTPS",
                    "Port": 443,
                    "Product": null,
                    "Protocol": "tcp"
                }
            ],
            "Site": "Site 1",
            "Software": null,
            "User": null,
            "Vulnerabilities": 5,
            "Vulnerability": [
                {
                    "CVSS": 7.1,
                    "Exploit": 0,
                    "Id": "certificate-common-name-mismatch",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2018-03-21",
                    "PublishedOn": "2007-08-03",
                    "Risk": 786.41,
                    "Severity": "Severe",
                    "Title": "X.509 Certificate Subject CN Does Not Match the Entity Name"
                },
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "generic-tcp-timestamp",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2018-03-21",
                    "PublishedOn": "1997-08-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "TCP timestamp response"
                },
                {
                    "CVSS": 4.3,
                    "Exploit": 0,
                    "Id": "ssl-self-signed-certificate",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2012-07-12",
                    "PublishedOn": "1995-01-01",
                    "Risk": 248.19,
                    "Severity": "Severe",
                    "Title": "Self-signed TLS/SSL certificate"
                },
                {
                    "CVSS": 2.6,
                    "Exploit": 0,
                    "Id": "ssl-static-key-ciphers",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2018-08-02",
                    "PublishedOn": "2015-02-01",
                    "Risk": 342.17,
                    "Severity": "Moderate",
                    "Title": "TLS/SSL Server Supports The Use of Static Key Ciphers"
                },
                {
                    "CVSS": 5.8,
                    "Exploit": 0,
                    "Id": "tls-untrusted-ca",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2015-07-27",
                    "PublishedOn": "1995-01-01",
                    "Risk": 694.92,
                    "Severity": "Severe",
                    "Title": "Untrusted TLS/SSL server X.509 certificate"
                }
            ]
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44337476-855dfb00-a483-11e8-9d29-3064a3112c4e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44337476-855dfb00-a483-11e8-9d29-3064a3112c4e.png" alt="image" width="750" height="302"></a></p>
<h3 id="h_813073471451535881091195">2. Get all assets</h3>
<hr>
<p>Returns all assets for which you have access.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-assets</code></p>
<h5>Input</h5>
<table style="width: 740px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 410px;"><strong>Description</strong></th>
<th style="width: 160px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">sort</td>
<td style="width: 410px;">Multiple criteria of The criteria to sort the records by, in the format: property[,ASC DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">limit</td>
<td style="width: 410px;">integer The number of records retrieve.</td>
<td style="width: 160px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 227px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 422px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 227px;">Nexpose.Asset.AssetId</td>
<td style="width: 59px;">number</td>
<td style="width: 422px;">The identifier of the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Address</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">The primary IPv4 or IPv6 address of the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">The primary host name (local or FQDN) of the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Site</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">Asset site name.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Exploits</td>
<td style="width: 59px;">number</td>
<td style="width: 422px;">The number of distinct exploits that can exploit any of the vulnerabilities on the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Malware</td>
<td style="width: 59px;">number</td>
<td style="width: 422px;">The number of distinct malware kits that vulnerabilities on the asset are susceptible to.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.OperatingSystem</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">Operating system of the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Vulnerabilities</td>
<td style="width: 59px;">number</td>
<td style="width: 422px;">The total number of vulnerabilities.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.RiskScore</td>
<td style="width: 59px;">number</td>
<td style="width: 422px;">The risk score (with criticality adjustments) of the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.Assessed</td>
<td style="width: 59px;">boolean</td>
<td style="width: 422px;">Whether the asset has been assessed for vulnerabilities at least once.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.LastScanDate</td>
<td style="width: 59px;">date</td>
<td style="width: 422px;">Last scan date of the asset.</td>
</tr>
<tr>
<td style="width: 227px;">Nexpose.Asset.LastScanId</td>
<td style="width: 59px;">number</td>
<td style="width: 422px;">Id of the asset's last scan.</td>
</tr>
<tr>
<td style="width: 227px;">Endpoint.IP</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 227px;">Endpoint.HostName</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">Endpoint host name.</td>
</tr>
<tr>
<td style="width: 227px;">Endpoint.OS</td>
<td style="width: 59px;">string</td>
<td style="width: 422px;">Endpoint operating system.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-assets limit=2 sort="riskScore,ASC"</code></p>
<h5>Context Example</h5>
<pre>{
    "Endpoint": [
        {
            "HostName": "hostname1",
            "IP": "1.2.3.4",
            "OS": "Ubuntu Linux"
        },
        {
            "HostName": "hostname2",
            "IP": "3.4.5.6",
            "OS": "Ubuntu Linux"
        }
    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "1.2.3.4",
                "Assessed": true,
                "AssetId": 2,
                "Exploits": 0,
                "LastScanDate": "2018-04-29T11:21:19.350Z",
                "LastScanId": 15,
                "Malware": 0,
                "Name": "hostname1",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 0,
                "Site": "Site 1",
                "Vulnerabilities": 1
            },
            {
                "Address": "3.4.5.6",
                "Assessed": true,
                "AssetId": 1,
                "Exploits": 0,
                "LastScanDate": "2018-04-29T11:21:18.637Z",
                "LastScanId": 15,
                "Malware": 0,
                "Name": "hostname2",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 0,
                "Site": "Site 1",
                "Vulnerabilities": 1
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44337654-09b07e00-a484-11e8-8f8f-52030c45634d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44337654-09b07e00-a484-11e8-8f8f-52030c45634d.png" alt="image" width="748" height="39"></a></p>
<h3 id="h_1817527592791535881096604">3. Get all assets that match the filters</h3>
<hr>
<p>Returns all assets for which you have access that match the given search criteria.</p>
<h5>Base Command</h5>
<p><code>nexpose-search-assets</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 174px;"><strong>Argument Name</strong></th>
<th style="width: 463px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174px;">query</td>
<td style="width: 463px;">Multiple criteria of Filter to match assets, according to the Search Criteria API standard. multiple filters can be provided using ';' separator. For example: 'ip-address in range 1.2.3.4,1.2.3.8;host-name is myhost'. For more information regarding Search Criteria, refer to <a href="https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses" rel="nofollow">https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses</a>
</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">limit</td>
<td style="width: 463px;">integer The number of records retrieve.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">sort</td>
<td style="width: 463px;">Multiple criteria of The criteria to sort the records by, in the format: property[,ASC DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">ipAddressIs</td>
<td style="width: 463px;">Search by a specific IP address</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">hostNameIs</td>
<td style="width: 463px;">Search by a specific host name</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">riskScoreHigherThan</td>
<td style="width: 463px;">Get all assets whose risk score is higher</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">vulnerabilityTitleContains</td>
<td style="width: 463px;">Search by vulnerability title</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">siteIdIn</td>
<td style="width: 463px;">Multiple criteria of integer Search by site ids</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">match</td>
<td style="width: 463px;">Operator to determine how to match filters. all requires that all filters match for an asset to be included. any requires only one filter to match for an asset to be included.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 228px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 422px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 228px;">Nexpose.Asset.AssetId</td>
<td style="width: 58px;">number</td>
<td style="width: 422px;">The identifier of the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Address</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">The primary IPv4 or IPv6 address of the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Name</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">The primary host name (local or FQDN) of the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Site</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">Asset site name.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Exploits</td>
<td style="width: 58px;">number</td>
<td style="width: 422px;">The number of distinct exploits that can exploit any of the vulnerabilities on the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Malware</td>
<td style="width: 58px;">number</td>
<td style="width: 422px;">The number of distinct malware kits that vulnerabilities on the asset are susceptible to.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.OperatingSystem</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">Operating system of the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Vulnerabilities</td>
<td style="width: 58px;">number</td>
<td style="width: 422px;">The total number of vulnerabilities.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.RiskScore</td>
<td style="width: 58px;">number</td>
<td style="width: 422px;">The risk score (with criticality adjustments) of the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.Assessed</td>
<td style="width: 58px;">boolean</td>
<td style="width: 422px;">Whether the asset has been assessed for vulnerabilities at least once.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.LastScanDate</td>
<td style="width: 58px;">date</td>
<td style="width: 422px;">Last scan date of the asset.</td>
</tr>
<tr>
<td style="width: 228px;">Nexpose.Asset.LastScanId</td>
<td style="width: 58px;">number</td>
<td style="width: 422px;">Id of the asset's last scan.</td>
</tr>
<tr>
<td style="width: 228px;">Endpoint.IP</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 228px;">Endpoint.HostName</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">Endpoint host name.</td>
</tr>
<tr>
<td style="width: 228px;">Endpoint.OS</td>
<td style="width: 58px;">string</td>
<td style="width: 422px;">Endpoint operating system.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-search-assets query="risk-score is 0" limit="2" sort="riskScore,ASC" match="all"</code></p>
<h5>Context Example</h5>
<pre>{
    "Endpoint": [
        {
            "HostName": "hostname1",
            "IP": "1.2.3.4",
            "OS": "Ubuntu Linux"
        },
        {
            "HostName": "hostname2",
            "IP": "3.4.5.6",
            "OS": "Ubuntu Linux"
        }
    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "1.2.3.4",
                "Assessed": true,
                "AssetId": 2,
                "Exploits": 0,
                "LastScanDate": "2018-04-29T11:21:19.350Z",
                "LastScanId": 15,
                "Malware": 0,
                "Name": "hostname1",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 0,
                "Site": "Site 1",
                "Vulnerabilities": 1
            },
            {
                "Address": "3.4.5.6",
                "Assessed": true,
                "AssetId": 1,
                "Exploits": 0,
                "LastScanDate": "2018-04-29T11:21:18.637Z",
                "LastScanId": 15,
                "Malware": 0,
                "Name": "hostname2",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 0,
                "Site": "Site 1",
                "Vulnerabilities": 1
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44337654-09b07e00-a484-11e8-8f8f-52030c45634d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44337654-09b07e00-a484-11e8-8f8f-52030c45634d.png" alt="image" width="748" height="39"></a></p>
<h3 id="h_7872292294121535881104722">4. Get a specified scan</h3>
<hr>
<p>Returns the specified scan.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-scan</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 435px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">id</td>
<td style="width: 435px;">Multiple criteria of integer Identifiers of scans</td>
<td style="width: 100px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 263px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 263px;">Nexpose.Scan.Id</td>
<td style="width: 66px;">number</td>
<td style="width: 379px;">The identifier of the scan.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.ScanType</td>
<td style="width: 66px;">string</td>
<td style="width: 379px;">The scan type (automated, manual, scheduled).</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.StartedBy</td>
<td style="width: 66px;">string</td>
<td style="width: 379px;">The name of the user that started the scan.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Assets</td>
<td style="width: 66px;">number</td>
<td style="width: 379px;">The number of assets found in the scan</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.TotalTime</td>
<td style="width: 66px;">string</td>
<td style="width: 379px;">The duration of the scan in minutes.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Status</td>
<td style="width: 66px;">string</td>
<td style="width: 379px;">The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Completed</td>
<td style="width: 66px;">date</td>
<td style="width: 379px;">The end time of the scan in ISO8601 format.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Vulnerabilities.Critical</td>
<td style="width: 66px;">number</td>
<td style="width: 379px;">The number of critical vulnerabilities.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Vulnerabilities.Moderate</td>
<td style="width: 66px;">number</td>
<td style="width: 379px;">The number of moderate vulnerabilities.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Vulnerabilities.Severe</td>
<td style="width: 66px;">number</td>
<td style="width: 379px;">The number of severe vulnerabilities.</td>
</tr>
<tr>
<td style="width: 263px;">Nexpose.Scan.Vulnerabilities.Total</td>
<td style="width: 66px;">number</td>
<td style="width: 379px;">The total number of vulnerabilities.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-scan id=15</code></p>
<h5>Context Example</h5>
<pre>{
    "Nexpose": {
        "Scan": {
            "Assets": 32,
            "Completed": "2018-04-29T11:24:58.721Z",
            "Id": 15,
            "Message": null,
            "ScanName": "Sun 29 Apr 2018 11:17 AM",
            "ScanType": "Manual",
            "StartedBy": null,
            "Status": "finished",
            "TotalTime": "9.76666666667 minutes",
            "Vulnerabilities": {
                "Critical": 0,
                "Moderate": 48,
                "Severe": 61,
                "Total": 109
            }
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44337970-24cfbd80-a485-11e8-97d5-5a0cd3d87260.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44337970-24cfbd80-a485-11e8-97d5-5a0cd3d87260.png" alt="image"></a></p>
<h3 id="h_2913227705441535881110994">5. Get an asset's details</h3>
<hr>
<p>Returns the details and possible remediations for an asset's given vulnerability.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-asset-vulnerability</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Argument Name</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
<th style="width: 119px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">id</td>
<td style="width: 383px;">integer The identifier of the asset.</td>
<td style="width: 119px;">Required</td>
</tr>
<tr>
<td style="width: 206px;">vulnerabilityId</td>
<td style="width: 383px;">The identifier of the vulnerability.</td>
<td style="width: 119px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 414px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 229px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 414px;">Nexpose.Asset.AssetId</td>
<td style="width: 65px;">number</td>
<td style="width: 229px;">Identifier of the asset.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Id</td>
<td style="width: 65px;">number</td>
<td style="width: 229px;">The identifier of the vulnerability.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Title</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The title (summary) of the vulnerability.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Severity</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The severity of the vulnerability, one of: "Moderate", "Severe", "Critical".</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.RiskScore</td>
<td style="width: 65px;">number</td>
<td style="width: 229px;">The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.CVSS</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The CVSS vector(s) for the vulnerability.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.CVSSV3</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The CVSS v3 vector.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Published</td>
<td style="width: 65px;">date</td>
<td style="width: 229px;">The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Added</td>
<td style="width: 65px;">date</td>
<td style="width: 229px;">The date the vulnerability coverage was added. The format is an ISO 8601 date, YYYY-MM-DD.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Modified</td>
<td style="width: 65px;">date</td>
<td style="width: 229px;">The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.CVSSScore</td>
<td style="width: 65px;">number</td>
<td style="width: 229px;">The CVSS score, which ranges from 0-10.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.CVSSV3Score</td>
<td style="width: 65px;">number</td>
<td style="width: 229px;">The CVSS3 score, which ranges from 0-10.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Categories</td>
<td style="width: 65px;">unknown</td>
<td style="width: 229px;">All vulnerability categories assigned to this vulnerability.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.CVES</td>
<td style="width: 65px;">unknown</td>
<td style="width: 229px;">All CVEs assigned to this vulnerability.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Check.Port</td>
<td style="width: 65px;">number</td>
<td style="width: 229px;">The port of the service the result was discovered on.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Check.Protocol</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The protocol of the service the result was discovered on, valid values ip, icmp, igmp, ggp, tcp, pup, udp, idp, esp, nd, raw</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Check.Since</td>
<td style="width: 65px;">date</td>
<td style="width: 229px;">The date and time the result was first recorded, in the ISO8601 format. If the result changes status this value is the date and time of the status change.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Check.Proof</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The proof explaining why the result was found vulnerable.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Check.Status</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The status of the vulnerability check result. Valid values are, unknown, not-vulnerable, vulnerable, vulnerable-version, vulnerable-potential, vulnerable-with-exception-applied, vulnerable-version-with-exception-applied, vulnerable-potential-with-exception-applied</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Solution.Type</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The type of the solution. One of: "Configuration", "Rollup patch", "Patch".</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Solution.Summary</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The summary of the solution.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Solution.Steps</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The steps required to remediate the vulnerability.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Solution.Estimate</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">The estimated duration to apply the solution, in minutes.</td>
</tr>
<tr>
<td style="width: 414px;">Nexpose.Asset.Vulnerability.Solution.AdditionalInformation</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">Additional information or resources that can assist in applying the remediation</td>
</tr>
<tr>
<td style="width: 414px;">CVE.ID</td>
<td style="width: 65px;">string</td>
<td style="width: 229px;">Common Vulnerabilities and Exposures ids</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-asset-vulnerability id=37 vulnerabilityId=apache-httpd-cve-2017-3169</code></p>
<h5>Context Example</h5>
<pre>{
    "CVE": {
        "ID": "CVE-2017-3169"
    },
    "Nexpose": {
        "Asset": {
            "AssetId": "37",
            "Vulnerability": [
                {
                    "Added": "2017-06-20",
                    "CVES": [
                        "CVE-2017-3169"
                    ],
                    "CVSS": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                    "CVSSScore": 7.5,
                    "CVSSV3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "CVSSV3Score": 9.8,
                    "Categories": [
                        "Apache",
                        "Apache HTTP Server",
                        "Web"
                    ],
                    "Check": [
                        {
                            "Port": 8080,
                            "Proof": "Running HTTP serviceProduct HTTPD exists -- Apache HTTPD 2.4.6Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.6",
                            "Protocol": "tcp",
                            "Since": "2018-04-29T11:36:54.597Z",
                            "Status": "vulnerable-version"
                        },
                        {
                            "Port": 443,
                            "Proof": "Running HTTPS serviceProduct HTTPD exists -- Apache HTTPD 2.4.6Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.6",
                            "Protocol": "tcp",
                            "Since": "2018-04-29T11:36:54.597Z",
                            "Status": "vulnerable-version"
                        }
                    ],
                    "Id": "apache-httpd-cve-2017-3169",
                    "Modified": "2018-01-08",
                    "Published": "2017-06-20",
                    "RiskScore": 574.63,
                    "Severity": "Critical",
                    "Solution": [
                        {
                            "AdditionalInformation": "The latest version of Apache HTTPD is 2.4.34.\n\nMany platforms and distributions provide pre-built binary packages for Apache HTTP server. These pre-built packages are usually customized and optimized for a particular distribution, therefore we recommend that you use the packages if they are available for your operating system.",
                            "Estimate": "120.0 minutes",
                            "Steps": "Download and apply the upgrade from: http://archive.apache.org/dist/httpd/httpd-2.4.34.tar.gz (http://archive.apache.org/dist/httpd/httpd-2.4.34.tar.gz)",
                            "Summary": "Upgrade to the latest version of Apache HTTPD",
                            "Type": "rollup-patch"
                        }
                    ],
                    "Title": "Apache HTTPD: mod_ssl Null Pointer Dereference (CVE-2017-3169)"
                }
            ]
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44338298-31084a80-a486-11e8-881c-99dccae4d854.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44338298-31084a80-a486-11e8-881c-99dccae4d854.png" alt="image" width="749" height="345"></a></p>
<h3 id="h_7950557746751535881116441">6. Create a site</h3>
<hr>
<p>Creates a new site with the specified configuration.</p>
<h5>Base Command</h5>
<p><code>nexpose-create-site</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">name</td>
<td style="width: 506px;">The site name. Name must be unique.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">description</td>
<td style="width: 506px;">The site's description.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 131px;">assets</td>
<td style="width: 506px;">Multiple criteria of Specify asset addresses to be included in site scans</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">scanTemplateId</td>
<td style="width: 506px;">The identifier of a scan template. Use nexpose-get-report-templates to get all templates, default scan template is selected when not specified.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 131px;">importance</td>
<td style="width: 506px;">The site importance. Defaults to "normal" if not specified.</td>
<td style="width: 71px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 261px;"><strong>Path</strong></th>
<th style="width: 138px;"><strong>Type</strong></th>
<th style="width: 309px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">Nexpose.Site.Id</td>
<td style="width: 138px;">number</td>
<td style="width: 309px;">The created site Id</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-create-site name="site_test" assets="127.0.0.1"</code></p>
<h5>Context Example</h5>
<pre>{
    "Nexpose": {
        "Site": {
            "Id": 11
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44338427-8d6b6a00-a486-11e8-9340-660932cc4c41.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44338427-8d6b6a00-a486-11e8-9340-660932cc4c41.png" alt="image" width="750" height="88"></a></p>
<h3 id="h_675310243481541583699711">7. Delete a site</h3>
<hr>
<p>Deletes a site.</p>
<h5>Base Command</h5>
<p><code>nexpose-delete-site</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 248px;"><strong>Argument Name</strong></th>
<th style="width: 314px;"><strong>Description</strong></th>
<th style="width: 146px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 248px;">id</td>
<td style="width: 314px;">ID of the site to delete</td>
<td style="width: 146px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!nexpose-delete-site id=1258</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/48120909-263aa600-e27c-11e8-9f96-91c1528722fc.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/48120909-263aa600-e27c-11e8-9f96-91c1528722fc.png" alt="image"></a></p>
<h3 id="h_4870988458051535881123130">8. Retrieve sites</h3>
<hr>
<p>Retrieves accessible sites.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-sites</code></p>
<h5>Input</h5>
<table style="width: 732px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 405px;"><strong>Description</strong></th>
<th style="width: 169px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">limit</td>
<td style="width: 405px;">integer The number of records retrieve.</td>
<td style="width: 169px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">sort</td>
<td style="width: 405px;">Multiple criteria of The criteria to sort the records by, in the format: property[,ASC DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'</td>
<td style="width: 169px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 203px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 444px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 203px;">Nexpose.Site.Id</td>
<td style="width: 61px;">number</td>
<td style="width: 444px;">The identifier of the site.</td>
</tr>
<tr>
<td style="width: 203px;">Nexpose.Site.Name</td>
<td style="width: 61px;">string</td>
<td style="width: 444px;">The site name.</td>
</tr>
<tr>
<td style="width: 203px;">Nexpose.Site.Assets</td>
<td style="width: 61px;">number</td>
<td style="width: 444px;">The number of assets that belong to the site.</td>
</tr>
<tr>
<td style="width: 203px;">Nexpose.Site.Type</td>
<td style="width: 61px;">string</td>
<td style="width: 444px;">The type of the site. Valid values are agent, dynamic, static</td>
</tr>
<tr>
<td style="width: 203px;">Nexpose.Site.Vulnerabilities</td>
<td style="width: 61px;">number</td>
<td style="width: 444px;">The total number of vulnerabilities.</td>
</tr>
<tr>
<td style="width: 203px;">Nexpose.Site.Risk</td>
<td style="width: 61px;">number</td>
<td style="width: 444px;">The risk score (with criticality adjustments) of the site.</td>
</tr>
<tr>
<td style="width: 203px;">Nexpose.Site.LastScan</td>
<td style="width: 61px;">date</td>
<td style="width: 444px;">The date and time of the site's last scan.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-sites limit=1 sort="riskScore,DESC"</code></p>
<h5>Context Example</h5>
<pre>{
    "Nexpose": {
        "Site": {
            "Assets": 29,
            "Id": 2,
            "LastScan": "2018-07-27T07:46:35.159Z",
            "Name": "Site 1",
            "Risk": 131586,
            "Type": "dynamic",
            "Vulnerabilities": 351
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44338565-ea672000-a486-11e8-8613-b58bcf422331.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44338565-ea672000-a486-11e8-8613-b58bcf422331.png" alt="image"></a></p>
<h3 id="h_5809229089341535881129094">9. Get report templates</h3>
<hr>
<p>Returns all available report templates.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-report-templates</code></p>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 216px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 439px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">Nexpose.Template.Id</td>
<td style="width: 53px;">number</td>
<td style="width: 439px;">The identifier of the report template.</td>
</tr>
<tr>
<td style="width: 216px;">Nexpose.Template.Name</td>
<td style="width: 53px;">string</td>
<td style="width: 439px;">The name of the report template.</td>
</tr>
<tr>
<td style="width: 216px;">Nexpose.Template.Description</td>
<td style="width: 53px;">string</td>
<td style="width: 439px;">The description of the report template.</td>
</tr>
<tr>
<td style="width: 216px;">Nexpose.Template.Type</td>
<td style="width: 53px;">string</td>
<td style="width: 439px;">The type of the report template. document is a templatized, typically printable, report that has various sections of content. export is data-oriented output, typically CSV. file is a printable report template using a report template file.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-report-templates</code></p>
<h5>Context Example</h5>
<pre>{
    "Nexpose": {
        "Template": [
            {
                "Description": "Provides comprehensive details about discovered assets, vulnerabilities, and users.",
                "Id": "audit-report",
                "Name": "Audit Report",
                "Type": "document"
            },
            {
                "Description": "Compares current scan results to those of an earlier baseline scan.",
                "Id": "baseline-comparison",
                "Name": "Baseline Comparison",
                "Type": "document"
            },
            {
                "Description": "Includes a basic set of data fields for vulnerability check results in CSV format.",
                "Id": "basic-vulnerability-check-results",
                "Name": "Basic Vulnerability Check Results (CSV)",
                "Type": "export"
            },
            {
                "Description": "Provides a high-level view of security data, including general results information and statistical charts.",
                "Id": "executive-overview",
                "Name": "Executive Overview",
                "Type": "document"
            },
            {
                "Description": "Provides information and metrics about 10 discovered vulnerabilities with the highest risk scores.",
                "Id": "highest-risk-vulns",
                "Name": "Highest Risk Vulnerabilities",
                "Type": "document"
            },
            {
                "Description": "Serves as a cover sheet for the completed set of PCI-mandated reports.",
                "Id": "pci-attestation-v12",
                "Name": "PCI Attestation of Scan Compliance",
                "Type": "document"
            },
            {
                "Description": "PCI-mandated compliance summary with overview of Pass/Fail results, statistical charts, and vulnerability metrics.",
                "Id": "pci-executive-summary-v12",
                "Name": "PCI Executive Summary",
                "Type": "document"
            },
            {
                "Description": "Provides detailed, sorted scan information about each asset discovered in a PCI scan.",
                "Id": "pci-host-details-v12",
                "Name": "PCI Host Details",
                "Type": "document"
            },
            {
                "Description": "Provides a PCI-mandated listing of details, metrics, and Pass/Fail score for every vulnerability discovered in a PCI scan.",
                "Id": "pci-vuln-details-v12",
                "Name": "PCI Vulnerability Details",
                "Type": "document"
            },
            {
                "Description": "Shows detailed results for each policy rule scanned on an asset, including the percentage of policy rules that assets comply with and test results for each rule.",
                "Id": "policy-details",
                "Name": "Policy Details",
                "Type": "file"
            },
            {
                "Description": "Lists results for standard policy scans (AS/400, Oracle, Domino, Windows Group, CIFS/SMB account). Does not include Policy Manager results.",
                "Id": "policy-eval",
                "Name": "Policy Evaluation",
                "Type": "document"
            },
            {
                "Description": "Shows results for each tested policy, including the numbers and percentages of compliant assets, and the percentage of policy rules that assets comply with.",
                "Id": "policy-summary",
                "Name": "Policy Compliance Status",
                "Type": "file"
            },
            {
                "Description": "Lists top remediations as prioritized by vulnerability-related criteria that you select.",
                "Id": "prioritized-remediations",
                "Name": "Top Remediations",
                "Type": "file"
            },
            {
                "Description": "Lists top remediations as prioritized by vulnerability-related criteria that you select. Also provides steps for each remediation and lists each affected asset.",
                "Id": "prioritized-remediations-with-details",
                "Name": "Top Remediations with Details",
                "Type": "file"
            },
            {
                "Description": "Lists information about new assets discovered within a specific time period. This allows you to track changes to your network environment over time.",
                "Id": "r7-discovered-assets",
                "Name": "Newly Discovered Assets",
                "Type": "file"
            },
            {
                "Description": "Shows vulnerability exception activity during a specified time frame.",
                "Id": "r7-vulnerability-exceptions",
                "Name": "Vulnerability Exception Activity",
                "Type": "file"
            },
            {
                "Description": "Provides detailed remediation instructions for each discovered vulnerability.",
                "Id": "remediation-plan",
                "Name": "Remediation Plan",
                "Type": "document"
            },
            {
                "Description": "Lists test results for each discovered vulnerability, including how it was verified.",
                "Id": "report-card",
                "Name": "Report Card",
                "Type": "document"
            },
            {
                "Description": "Grades sets of assets based on risk and provides data and statistics for determining risk factors.",
                "Id": "risk-scorecard",
                "Name": "Risk Scorecard",
                "Type": "file"
            },
            {
                "Description": "Shows results for each asset against the selected policies' rules, including the percentage of policy rules that assets comply with.",
                "Id": "rule-breakdown-summary",
                "Name": "Policy Rule Breakdown Summary",
                "Type": "file"
            },
            {
                "Description": "Lists top policy compliance remediations as prioritized by policies that you select.",
                "Id": "top-policy-remediations",
                "Name": "Top Policy Remediations",
                "Type": "file"
            },
            {
                "Description": "Lists top policy compliance remediations as prioritized by policies that you select. Also provides steps for each remediation and lists each affected asset.",
                "Id": "top-policy-remediations-with-details",
                "Name": "Top Policy Remediations with Details",
                "Type": "file"
            },
            {
                "Description": "Lists risk scores, total vulnerabilities, and malware and exploit exposures for 10 assets with the highest risk scores.",
                "Id": "top-riskiest-assets",
                "Name": "Top 10 Assets by Vulnerability Risk",
                "Type": "file"
            },
            {
                "Description": "Lists total vulnerabilities and malware and exploit exposures for 10 assets with the most vulnerabilities.",
                "Id": "top-vulnerable-assets",
                "Name": "Top 10 Assets by Vulnerabilities",
                "Type": "file"
            },
            {
                "Description": "Tracks trends for vulnerabilities found, assets scanned, malware kit and exploit exposures, severity levels, and vulnerability age over a date range that you  select.",
                "Id": "vulnerability-trends",
                "Name": "Vulnerability Trends",
                "Type": "file"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44338618-1da9af00-a487-11e8-8313-329f6460e03c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44338618-1da9af00-a487-11e8-8313-329f6460e03c.png" alt="image"></a></p>
<h3 id="h_49840302010611535881137854">10. Create an assets report</h3>
<hr>
<p>Generates a new report on given assets according to a template and arguments.</p>
<h5>Base Command</h5>
<p><code>nexpose-create-assets-report</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 494px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">assets</td>
<td style="width: 494px;">Multiple criteria of integer Asset ids to create the report on, comma separated.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">template</td>
<td style="width: 494px;">Report template id to create the report with. If none is provided, the first template available will be used.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 143px;">name</td>
<td style="width: 494px;">The report name</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 143px;">format</td>
<td style="width: 494px;">The report format, default is PDF</td>
<td style="width: 71px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 220px;"><strong>Path</strong></th>
<th style="width: 107px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">InfoFile.EntryId</td>
<td style="width: 107px;">string</td>
<td style="width: 381px;">Entry Id of the report file</td>
</tr>
<tr>
<td style="width: 220px;">InfoFile.Name</td>
<td style="width: 107px;">string</td>
<td style="width: 381px;">Name of the report file</td>
</tr>
<tr>
<td style="width: 220px;">InfoFile.Extension</td>
<td style="width: 107px;">string</td>
<td style="width: 381px;">File extension of the report file</td>
</tr>
<tr>
<td style="width: 220px;">InfoFile.Info</td>
<td style="width: 107px;">string</td>
<td style="width: 381px;">Info about the report file</td>
</tr>
<tr>
<td style="width: 220px;">InfoFile.Size</td>
<td style="width: 107px;">number</td>
<td style="width: 381px;">Size of the report file</td>
</tr>
<tr>
<td style="width: 220px;">InfoFile.Type</td>
<td style="width: 107px;">string</td>
<td style="width: 381px;">Type of the report file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-create-assets-report assets="1,2,3,4"</code></p>
<h5>Context Example</h5>
<pre>{
    "InfoFile": {
        "EntryID": "759@cc00e449-9e7b-4609-8a68-1c8c01114562",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report 2018-08-20 11:41:54.343571.pdf",
        "Size": 143959,
        "Type": "PDF document, version 1.4\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44338707-77aa7480-a487-11e8-8e21-aa427b402f41.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44338707-77aa7480-a487-11e8-8e21-aa427b402f41.png" alt="image"></a></p>
<h3 id="h_42411979411881535881149772">11. Create a sites report</h3>
<hr>
<p>Generates a new report on given sites according to a template and arguments.</p>
<h5>Base Command</h5>
<p><code>nexpose-create-sites-report</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">sites</td>
<td style="width: 506px;">Multiple criteria of integer Site ids to create the report on, comma separated.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">template</td>
<td style="width: 506px;">Report template id to create the report with. If none is provided, the first template available will be used.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 131px;">name</td>
<td style="width: 506px;">The report name</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 131px;">format</td>
<td style="width: 506px;">The report format, default is PDF</td>
<td style="width: 71px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 221px;"><strong>Path</strong></th>
<th style="width: 106px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 221px;">InfoFile.EntryId</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Entry Id of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Name</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Name of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Extension</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">File extension of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Info</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Info about the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Size</td>
<td style="width: 106px;">number</td>
<td style="width: 381px;">Size of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Type</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Type of the report file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-create-sites-report sites=1,3</code></p>
<h5>Context Example</h5>
<pre>{
    "InfoFile": {
        "EntryID": "765@cc00e449-9e7b-4609-8a68-1c8c01114562",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report 2018-08-20 11:45:33.531668.pdf",
        "Size": 255774,
        "Type": "PDF document, version 1.4\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44338813-d66fee00-a487-11e8-8eff-f200418262b4.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44338813-d66fee00-a487-11e8-8eff-f200418262b4.png" alt="image"></a></p>
<h3 id="h_80086420113141535881163018">12. Create a scan report</h3>
<hr>
<p>Generates a new report for a specified scan.</p>
<h5>Base Command</h5>
<p><code>nexpose-create-scan-report</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">scan</td>
<td style="width: 492px;">integer The identifier of the scan.</td>
<td style="width: 71px;">True</td>
</tr>
<tr>
<td style="width: 145px;">template</td>
<td style="width: 492px;">Report template id to create the report with. If none is provided, the first template available will be used.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 145px;">name</td>
<td style="width: 492px;">The report name</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 145px;">format</td>
<td style="width: 492px;">The report format, default is PDF</td>
<td style="width: 71px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 221px;"><strong>Path</strong></th>
<th style="width: 106px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 221px;">InfoFile.EntryId</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Entry Id of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Name</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Name of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Extension</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">File extension of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Info</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Info about the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Size</td>
<td style="width: 106px;">number</td>
<td style="width: 381px;">Size of the report file</td>
</tr>
<tr>
<td style="width: 221px;">InfoFile.Type</td>
<td style="width: 106px;">string</td>
<td style="width: 381px;">Type of the report file</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-create-scan-report scan="15"</code></p>
<h5>Context Example</h5>
<pre>{
    "InfoFile": {
        "EntryID": "771@cc00e449-9e7b-4609-8a68-1c8c01114562",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report 2018-08-20 11:49:56.187193.pdf",
        "Size": 205544,
        "Type": "PDF document, version 1.4\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44339013-7cbbf380-a488-11e8-96ae-9c7a689f4644.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44339013-7cbbf380-a488-11e8-96ae-9c7a689f4644.png" alt="image"></a></p>
<h3 id="h_61925084014391535881184314">13. Start a site scan</h3>
<hr>
<p>Starts a scan for the specified site.</p>
<h5>Base Command</h5>
<p><code>nexpose-start-site-scan</code></p>
<h5>Input</h5>
<table style="width: 736px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">site</td>
<td style="width: 469px;">integer The identifier of the site.</td>
<td style="width: 71px;">True</td>
</tr>
<tr>
<td style="width: 168px;">hosts</td>
<td style="width: 469px;">Multiple criteria of The hosts that should be included as a part of the scan. This should be a mixture of IP Addresses and Hostnames as a comma separated string array.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 168px;">name</td>
<td style="width: 469px;">The user-driven scan name for the scan.</td>
<td style="width: 71px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 256px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">Nexpose.Scan.Id</td>
<td style="width: 73px;">number</td>
<td style="width: 379px;">The identifier of the scan.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.ScanType</td>
<td style="width: 73px;">string</td>
<td style="width: 379px;">The scan type (automated, manual, scheduled).</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.StartedBy</td>
<td style="width: 73px;">date</td>
<td style="width: 379px;">The name of the user that started the scan.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Assets</td>
<td style="width: 73px;">number</td>
<td style="width: 379px;">The number of assets found in the scan</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.TotalTime</td>
<td style="width: 73px;">string</td>
<td style="width: 379px;">The duration of the scan in minutes.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Completed</td>
<td style="width: 73px;">date</td>
<td style="width: 379px;">The end time of the scan in ISO8601 format.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Status</td>
<td style="width: 73px;">string</td>
<td style="width: 379px;">The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Vulnerabilities.Critical</td>
<td style="width: 73px;">number</td>
<td style="width: 379px;">The number of critical vulnerabilities.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Vulnerabilities.Moderate</td>
<td style="width: 73px;">number</td>
<td style="width: 379px;">The number of moderate vulnerabilities.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Vulnerabilities.Severe</td>
<td style="width: 73px;">number</td>
<td style="width: 379px;">The number of severe vulnerabilities.</td>
</tr>
<tr>
<td style="width: 256px;">Nexpose.Scan.Vulnerabilities.Total</td>
<td style="width: 73px;">number</td>
<td style="width: 379px;">The total number of vulnerabilities.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-start-site-scan site=2 hosts=127.0.0.1</code></p>
<h5>Context Example</h5>
<pre>{
    "Nexpose": {
        "Scan": {
            "Assets": 0,
            "Completed": null,
            "Id": 89391,
            "Message": null,
            "ScanName": "scan 2018-08-20 11:54:59.673365",
            "ScanType": "Manual",
            "StartedBy": null,
            "Status": "running",
            "TotalTime": "0 minutes",
            "Vulnerabilities": {
                "Critical": 0,
                "Moderate": 0,
                "Severe": 0,
                "Total": 0
            }
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44340427-7ed48100-a48d-11e8-89ec-dbe8b8958f8c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44340427-7ed48100-a48d-11e8-89ec-dbe8b8958f8c.png" alt="image" width="751" height="492"></a></p>
<h3 id="h_16017905415631535881190325">14. Start an assets scan</h3>
<hr>
<p>Starts a scan for specified asset IP addresses and host names.</p>
<h5>Base Command</h5>
<p><code>nexpose-start-assets-scan</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 480px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">IPs</td>
<td style="width: 480px;">Multiple criteria of IP addresses of assets, comma separated.</td>
<td style="width: 81px;">False</td>
</tr>
<tr>
<td style="width: 147px;">hostNames</td>
<td style="width: 480px;">Multiple criteria of Host names of assets, comma separated.</td>
<td style="width: 81px;">False</td>
</tr>
<tr>
<td style="width: 147px;">name</td>
<td style="width: 480px;">The user-driven scan name for the scan.</td>
<td style="width: 81px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 268px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 268px;">Nexpose.Scan.Id</td>
<td style="width: 61px;">number</td>
<td style="width: 379px;">The identifier of the scan.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.ScanType</td>
<td style="width: 61px;">string</td>
<td style="width: 379px;">The scan type (automated, manual, scheduled).</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.StartedBy</td>
<td style="width: 61px;">date</td>
<td style="width: 379px;">The name of the user that started the scan.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Assets</td>
<td style="width: 61px;">number</td>
<td style="width: 379px;">The number of assets found in the scan</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.TotalTime</td>
<td style="width: 61px;">string</td>
<td style="width: 379px;">The duration of the scan in minutes.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Completed</td>
<td style="width: 61px;">date</td>
<td style="width: 379px;">The end time of the scan in ISO8601 format.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Status</td>
<td style="width: 61px;">string</td>
<td style="width: 379px;">The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Vulnerabilities.Critical</td>
<td style="width: 61px;">number</td>
<td style="width: 379px;">The number of critical vulnerabilities.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Vulnerabilities.Moderate</td>
<td style="width: 61px;">number</td>
<td style="width: 379px;">The number of moderate vulnerabilities.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Vulnerabilities.Severe</td>
<td style="width: 61px;">number</td>
<td style="width: 379px;">The number of severe vulnerabilities.</td>
</tr>
<tr>
<td style="width: 268px;">Nexpose.Scan.Vulnerabilities.Total</td>
<td style="width: 61px;">number</td>
<td style="width: 379px;">The total number of vulnerabilities.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-start-assets-scan IPs=127.0.0.1</code></p>
<h5>Context Example</h5>
<pre>{
    "Nexpose": {
        "Scan": {
            "Assets": 0,
            "Completed": null,
            "Id": 89410,
            "Message": null,
            "ScanName": "scan 2018-08-20 12:31:52.951818",
            "ScanType": "Manual",
            "StartedBy": null,
            "Status": "running",
            "TotalTime": "0 minutes",
            "Vulnerabilities": {
                "Critical": 0,
                "Moderate": 0,
                "Severe": 0,
                "Total": 0
            }
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/44340807-b68ff880-a48e-11e8-827d-50ed6dff3798.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/44340807-b68ff880-a48e-11e8-827d-50ed6dff3798.png" alt="image" width="750" height="477"></a></p>
<h3 id="h_5435525813991541581547102">15. Stop a scan that is in progress</h3>
<hr>
<p>Stops the specified scan, which is in progress.</p>
<h5>Base Command</h5>
<p><code>nexpose-stop-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 249px;"><strong>Argument Name</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
<th style="width: 148px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">id</td>
<td style="width: 311px;">ID of the scan to stop</td>
<td style="width: 148px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!nexpose-stop-scan id=143200</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/48055922-62f19900-e1b9-11e8-9108-285b21378642.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/48055922-62f19900-e1b9-11e8-9108-285b21378642.png" alt="image"></a></p>
<h3 id="h_9633814268321541581557452">16. Pause a scan that is in progress</h3>
<hr>
<p>Pauses the specified scan, which is in progress.</p>
<h5>Base Command</h5>
<p><code>nexpose-pause-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 181px;"><strong>Argument Name</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
<th style="width: 107px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 181px;">id</td>
<td style="width: 420px;">ID of the scan to pause</td>
<td style="width: 107px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!nexpose-pause-scan id=143200</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/48055988-8a486600-e1b9-11e8-983a-0f05d8de466e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/48055988-8a486600-e1b9-11e8-983a-0f05d8de466e.png" alt="image"></a></p>
<h3 id="h_16956847714031541581564270">17. Resume a scan</h3>
<hr>
<p>Resumes a scan that is paused or stopped.</p>
<h5>Base Command</h5>
<p><code>nexpose-resume-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 236px;"><strong>Argument Name</strong></th>
<th style="width: 333px;"><strong>Description</strong></th>
<th style="width: 139px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 236px;">id</td>
<td style="width: 333px;">ID of the scan to resume</td>
<td style="width: 139px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!nexpose-resume-scan id=143200</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/48056180-ea3f0c80-e1b9-11e8-8d3c-6603ca6cbcec.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/48056180-ea3f0c80-e1b9-11e8-8d3c-6603ca6cbcec.png" alt="image"></a></p>
<h3 id="h_15635634821101541581569860">18. Get a list of scans</h3>
<hr>
<p>Returns a list of scans.</p>
<h5>Base Command</h5>
<p><code>nexpose-get-scans</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 139px;"><strong>Description</strong></th>
<th style="width: 422px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">active</td>
<td style="width: 139px;">Return active or previous scans (boolean)</td>
<td style="width: 422px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">limit</td>
<td style="width: 139px;">The number of records retrieve</td>
<td style="width: 422px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">sort</td>
<td style="width: 139px;">Multiple criteria of &lt;string&gt; The criteria to sort the records by, in the format: property [ASC, DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'</td>
<td style="width: 422px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 171px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 171px;">Nexpose.Scan.Id</td>
<td style="width: 64px;">number</td>
<td style="width: 473px;">The ID of the scan</td>
</tr>
<tr>
<td style="width: 171px;">Nexpose.Scan.ScanType</td>
<td style="width: 64px;">string</td>
<td style="width: 473px;">The scan type ("automated", "manual", "scheduled")</td>
</tr>
<tr>
<td style="width: 171px;">Nexpose.Scan.StartedBy</td>
<td style="width: 64px;">date</td>
<td style="width: 473px;">The name of the user that started the scan</td>
</tr>
<tr>
<td style="width: 171px;">Nexpose.Scan.Assets</td>
<td style="width: 64px;">number</td>
<td style="width: 473px;">The number of assets found in the scan</td>
</tr>
<tr>
<td style="width: 171px;">Nexpose.Scan.TotalTime</td>
<td style="width: 64px;">string</td>
<td style="width: 473px;">The duration of the scan (in minutes)</td>
</tr>
<tr>
<td style="width: 171px;">Nexpose.Scan.Completed</td>
<td style="width: 64px;">date</td>
<td style="width: 473px;">The end time of the scan in ISO8601 format</td>
</tr>
<tr>
<td style="width: 171px;">Nexpose.Scan.Status</td>
<td style="width: 64px;">string</td>
<td style="width: 473px;">The scan status ("aborted", "unknown", "running", "finished", "stopped", "error", "paused", "dispatched", "integrating")</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!nexpose-get-scans active=false limit=5</code></p>
<h5>Context Example</h5>
<pre><code>{
    "Nexpose": {
        "Scan": [
            {
                "Assets": 32,
                "Completed": "2018-04-29T11:24:58.721Z",
                "Id": 15,
                "Message": null,
                "ScanName": "Sun 29 Apr 2018 11:17 AM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "9.76666666667 minutes"
            },
            {
                "Assets": 19,
                "Completed": "2018-04-29T11:42:16.765Z",
                "Id": 25,
                "Message": null,
                "ScanName": "Sun 29 Apr 2018 11:32 AM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "24.6333333333 minutes"
            },
            {
                "Assets": 29,
                "Completed": "2018-06-13T13:36:54.288Z",
                "Id": 42794,
                "Message": null,
                "ScanName": "Wed 13 Jun 2018 01:29 PM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "18.3 minutes"
            },
            {
                "Assets": 1,
                "Completed": "2018-06-13T13:41:59.184Z",
                "Id": 42799,
                "Message": null,
                "ScanName": "Wed 13 Jun 2018 01:35 PM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "21.85 minutes"
            },
            {
                "Assets": 1,
                "Completed": "2018-06-13T14:16:41.766Z",
                "Id": 42824,
                "Message": null,
                "ScanName": "Wed 13 Jun 2018 02:09 PM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "7.3 minutes"
            }
        ]
    }
}
</code></pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/35098543/48056509-9f71c480-e1ba-11e8-9e05-e697d576365b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/35098543/48056509-9f71c480-e1ba-11e8-9e05-e697d576365b.png" alt="image" width="749" height="107"></a></p>
<blockquote>
<p> </p>
</blockquote>
<h2>Troubleshooting</h2>
<hr>
<ul>
<li>In case of a timeout error, the API server address or port may be incorrect.</li>
<li>In case of a <code>400 Bad Request</code> error, incorrect values were provided to an API resource, e.g incorrect search fields.</li>
<li>In case of a <code>401 Unauthorized</code> error, incorrect credentials were provided or there are insufficient privileges for a specific resource.</li>
<li>In case of a <code>404 Not Found</code> error, a specified resource was not found, e.g a vulnerability that doesn't exist in an asset.<br><br>
</li>
</ul>