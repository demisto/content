<!-- HTML_DOC -->
<p>Use the CIRCL integration to research malware history for IPs, DNSs, and hostnames, and to query certificate history and details.</p>
<p>This integration was integrated and tested with CIRCL v2.0.</p>
<h2>Use Cases</h2>
<ol>
<li>Query IP, DNS, or hostname for malware history.</li>
<li>Query IP or IP CIDR for certificate history.</li>
<li>Query certificate for IP history.</li>
<li>Query certificate details.</li>
</ol>
<h2>Configure CIRCL on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for CIRCL.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://www.circl.lu/" rel="nofollow">https://www.circl.lu</a>)</strong></li>
<li>Enter <strong>Authentication</strong> details</li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_69075190541546439897277">Get DNS records: circl-dns-get</a></li>
<li><a href="#h_327258507361546439902765">Get SSL certificate history for IP address or CIDR blocks: circl-ssl-list-certificates</a></li>
<li><a href="#h_418653939671546439908013">Get IP addresses associated with an SSL certificate: circl-ssl-query-certificate</a></li>
<li><a href="#h_677391388971546439913147">Get information for an SSL certificate: circl-ssl-get-certificate</a></li>
</ol>
<h3 id="h_69075190541546439897277">1. Get DNS records</h3>
<hr>
<p>Get DNS records for your query value from CIRCL's Passive DNS.</p>
<h5>Base Command</h5>
<p><code>circl-dns-get</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 192px;"><strong>Argument Name</strong></th>
<th style="width: 437px;"><strong>Description</strong></th>
<th style="width: 111px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 192px;">queryValue</td>
<td style="width: 437px;">IP address, hostname, or domain name</td>
<td style="width: 111px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 359px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 359px;">CIRCLdns.Query.Value</td>
<td style="width: 59px;">string</td>
<td style="width: 322px;">Query Value</td>
</tr>
<tr>
<td style="width: 359px;">CIRCLdns.Query.Record.Data</td>
<td style="width: 59px;">string</td>
<td style="width: 322px;">DNS Record or IP Address</td>
</tr>
<tr>
<td style="width: 359px;">CIRCLdns.Query.Record.LastTime</td>
<td style="width: 59px;">date</td>
<td style="width: 322px;">DNS record last recorded time</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!circl-dns-get queryValue=69.172.200.235</code></p>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
	<span class="pl-s"><span class="pl-pds">"</span>Query<span class="pl-pds">"</span></span>: [
		{
			<span class="pl-s"><span class="pl-pds">"</span>Record<span class="pl-pds">"</span></span>: [
				{
					<span class="pl-s"><span class="pl-pds">"</span>Data<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>ns65.worldnic.com<span class="pl-pds">"</span></span>,
					<span class="pl-s"><span class="pl-pds">"</span>LastTime<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-10-28 20:43:59<span class="pl-pds">"</span></span>
				},
				{
					<span class="pl-s"><span class="pl-pds">"</span>Data<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>204.12.0.50<span class="pl-pds">"</span></span>,
					<span class="pl-s"><span class="pl-pds">"</span>LastTime<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2011-08-15 11:35:51<span class="pl-pds">"</span></span>
				},
				{
					<span class="pl-s"><span class="pl-pds">"</span>Data<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>50.23.225.49<span class="pl-pds">"</span></span>,
					<span class="pl-s"><span class="pl-pds">"</span>LastTime<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2012-01-02 16:44:53<span class="pl-pds">"</span></span>
				},
				{
					<span class="pl-s"><span class="pl-pds">"</span>Data<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>ns66.worldnic.com<span class="pl-pds">"</span></span>,
					<span class="pl-s"><span class="pl-pds">"</span>LastTime<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-10-28 20:43:59<span class="pl-pds">"</span></span>
				},
				{
					<span class="pl-s"><span class="pl-pds">"</span>Data<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>69.172.200.235<span class="pl-pds">"</span></span>,
					<span class="pl-s"><span class="pl-pds">"</span>LastTime<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-10-29 22:50:34<span class="pl-pds">"</span></span>
				}
			],
			<span class="pl-s"><span class="pl-pds">"</span>Value<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>test.com<span class="pl-pds">"</span></span>
		}
	]
}</pre>
</div>
<h3 id="h_327258507361546439902765">2. Get SSL certificate history for IP addresses or CIDR blocks</h3>
<hr>
<p>Query IP address or CIDR blocks (/32 up to /23) for SSL certificates history.</p>
<h5>Base Command</h5>
<p><code>circl-ssl-list-certificates</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 245px;"><strong>Argument Name</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
<th style="width: 141px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 245px;">queryValue</td>
<td style="width: 354px;">IP address or CIDR block</td>
<td style="width: 141px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 340px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 342px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 340px;">CIRCLssl.IPAddress.Value</td>
<td style="width: 58px;">string</td>
<td style="width: 342px;">IP address</td>
</tr>
<tr>
<td style="width: 340px;">CIRCLssl.IPAddress.Certificate.SHA1</td>
<td style="width: 58px;">string</td>
<td style="width: 342px;">The SHA-1 fingerprint of the certificate</td>
</tr>
<tr>
<td style="width: 340px;">CIRCLssl.IPAddress.Certificate.Subjects</td>
<td style="width: 58px;">string</td>
<td style="width: 342px;">Certificate subjects</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!circl-ssl-list-certificates queryValue=172.228.24.0/28</code></p>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
	<span class="pl-s"><span class="pl-pds">"</span>Certificate<span class="pl-pds">"</span></span>: [
		{
			<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>780a06f6e9b4061cad0c6502710606eb535f1c26<span class="pl-pds">"</span></span>,
			<span class="pl-s"><span class="pl-pds">"</span>Subjects<span class="pl-pds">"</span></span>: [
				<span class="pl-s"><span class="pl-pds">"</span>C=US, O=GeoTrust, Inc., CN=GeoTrust SSL CA<span class="pl-pds">"</span></span>
			]
		},
		{
			<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>b47dcd32bcc997f769a008365b3ae418ae613c5b<span class="pl-pds">"</span></span>,
			<span class="pl-s"><span class="pl-pds">"</span>Subjects<span class="pl-pds">"</span></span>: [
				<span class="pl-s"><span class="pl-pds">"</span>serialNumber=NhYqVrM6jc9PtOjjwTmeTWpc5G6L9yq8, C=KR, ST=Gyeonggi-Do, L=Seongnam-City, O=NAVER Business Platform Corp., OU=NAVER Business Platform Corp., CN=mail.naver.com<span class="pl-pds">"</span></span>
			]
		},
		{
			<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2d33eb5931c47f5bcec037658e77b7d0988ea3b9<span class="pl-pds">"</span></span>,
			<span class="pl-s"><span class="pl-pds">"</span>Subjects<span class="pl-pds">"</span></span>: [
				<span class="pl-s"><span class="pl-pds">"</span>C=KR, ST=Gyeonggi, L=Seongnam-City, O=NAVER Business Platform Corp., OU=NAVER Business Platform Corp., CN=mail.naver.com<span class="pl-pds">"</span></span>
			]
		},
		{
			<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>6c624f520f6fd75d4e05672806cfd384f35bbda1<span class="pl-pds">"</span></span>,
			<span class="pl-s"><span class="pl-pds">"</span>Subjects<span class="pl-pds">"</span></span>: [
				<span class="pl-s"><span class="pl-pds">"</span>C=KR, ST=Gyeonggi-Do, L=Seongnam-Si, O=NAVER Business Platform Corp., OU=NAVER Business Platform Corp., CN=mail.naver.com<span class="pl-pds">"</span></span>
			]
		},
		{
			<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>4f56644858829ffb85a770171accf9f8407a137b<span class="pl-pds">"</span></span>,
			<span class="pl-s"><span class="pl-pds">"</span>Subjects<span class="pl-pds">"</span></span>: [
				<span class="pl-s"><span class="pl-pds">"</span>C=US, O=GeoTrust Inc., CN=GeoTrust SSL CA - G2<span class="pl-pds">"</span></span>
			]
		}
	],
	<span class="pl-s"><span class="pl-pds">"</span>Value<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>172.228.24.209<span class="pl-pds">"</span></span>
}</pre>
</div>
<h3 id="h_418653939671546439908013">3. Get IP addresses associated with an SSL certificate</h3>
<hr>
<p>Query a certificate value to get all associated addresses.</p>
<h5>Base Command</h5>
<p><code>circl-ssl-query-certificate</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">certificate</td>
<td style="width: 510px;">SHA-1 fingerprint of a certificate</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">limitResults</td>
<td style="width: 510px;">Limit the results number (Increasing number can cause browser slowdowns).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 217px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 471px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 217px;">CIRCLssl.Certificate.SHA1</td>
<td style="width: 52px;">string</td>
<td style="width: 471px;">The SHA-1 fingerprint of the certificate</td>
</tr>
<tr>
<td style="width: 217px;">CIRCLssl.Certificate.Hits</td>
<td style="width: 52px;">number</td>
<td style="width: 471px;">Number of hits for the certificate (number of associated addresses)</td>
</tr>
<tr>
<td style="width: 217px;">CIRCLssl.Certificate.IPAddress</td>
<td style="width: 52px;">string</td>
<td style="width: 471px;">IP address associated to the certificate</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!circl-ssl-query-certificate certificate=c46fed822dadac3f31f9bb4d1a78a1d9eae4567b limitResults=10</code></p>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
	<span class="pl-s"><span class="pl-pds">"</span>Hits<span class="pl-pds">"</span></span>: <span class="pl-c1">1066</span>,
	<span class="pl-s"><span class="pl-pds">"</span>IPAddress<span class="pl-pds">"</span></span>: [
		<span class="pl-s"><span class="pl-pds">"</span>172.231.209.35<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>222.163.206.206<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>104.98.248.71<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>23.212.29.129<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>23.7.44.197<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>104.67.128.36<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>96.16.84.130<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>172.233.131.187<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>23.197.219.175<span class="pl-pds">"</span></span>,
		<span class="pl-s"><span class="pl-pds">"</span>173.222.24.202<span class="pl-pds">"</span></span>
	],
	<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>c46fed822dadac3f31f9bb4d1a78a1d9eae4567b<span class="pl-pds">"</span></span>
}</pre>
</div>
<h3 id="h_677391388971546439913147">4. Get information for an SSL certificate</h3>
<hr>
<p>Get the raw certificate and related information.</p>
<h5>Base Command</h5>
<p><code>circl-ssl-get-certificate</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Argument Name</strong></th>
<th style="width: 398px;"><strong>Description</strong></th>
<th style="width: 124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">certificate</td>
<td style="width: 398px;">SHA-1 fingerprint of a certificate</td>
<td style="width: 124px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 285px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 377px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.SHA1</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">The SHA-1 fingerprint of the certificate</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Usage</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">Extended key usage</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Distribution</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">CRL distribution points</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Issuer</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">Certificate issuer</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Time</td>
<td style="width: 78px;">date</td>
<td style="width: 377px;">Certificate issued time (***not_before)</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Subject</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">Certificate subject</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Key</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">Certificate public key</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Pem</td>
<td style="width: 78px;">string</td>
<td style="width: 377px;">Certificate in PEM format</td>
</tr>
<tr>
<td style="width: 285px;">CIRCLssl.Certificate.Seen</td>
<td style="width: 78px;">number</td>
<td style="width: 377px;">Number of times the certificate was seen</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!circl-ssl-get-certificate certificate=37221925980c05deefac014f9a72b4765e716341</code></p>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
	<span class="pl-s"><span class="pl-pds">"</span>Distribution<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-cce">\n</span>Full Name:<span class="pl-cce">\n</span>  URI:http://vassg142.crl.omniroot.com/vassg142.crl<span class="pl-cce">\n</span><span class="pl-pds">"</span></span>,
	<span class="pl-s"><span class="pl-pds">"</span>Issuer<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>C=NL, L=Amsterdam, O=Verizon Enterprise Solutions, OU=Cybertrust, CN=Verizon Akamai SureServer CA G14-SHA2<span class="pl-pds">"</span></span>,
	<span class="pl-s"><span class="pl-pds">"</span>Key<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>-----BEGIN PUBLIC KEY-----<span class="pl-cce">\n</span>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtp19/XP3H9LNDAt7PUF/<span class="pl-cce">\n</span>K8ug35VTcMM6HJt+bIqzKMKdTogXLv2gI24k/pS/T0y19H80dlg3PpJDyuISUvHf<span class="pl-cce">\n</span>33nKT1ad+Z3cddFvo/FJU1gJZulAuovqc5bF6tSP7IKMGIyY9By1R4PsqftUYSu0<span class="pl-cce">\n</span>lnfwGc8JDbt6BPGzyOnrk+UFgv7BidKKhlvW3nbKN2ydvFhOWQeFTsNaxkp+PzA1<span class="pl-cce">\n</span>m/MwEiCetorBuVFWi5wTo0CFko9cFCFyWUp5eEaNUcVxAHwxnqWu0B9Cwsli9ei7<span class="pl-cce">\n</span>gcIDUgPIkAbuo+GSLc8tRyb+pvBe6TPq4qlN0LdPDcMjodM+wUNrA4ojTNmzjRFb<span class="pl-cce">\n</span>EwIDAQAB<span class="pl-cce">\n</span>-----END PUBLIC KEY-----<span class="pl-cce">\n</span><span class="pl-pds">"</span></span>,
	"Pem": "-----BEGIN CERTIFICATE-----\nMIIFkDCCBHigAwIBAgIUdIcF/AeOFgHhxbQhFzBZ+1ye94EwDQYJKoZIhvcNAQEL\nBQAwgY0xCzAJBgNVBAYTAk5MMRIwEAYDVQQHEwlBbXN0ZXJkYW0xJTAjBgNVBAoT\nHFZlcml6b24gRW50ZXJwcmlzZSBTb2x1dGlvbnMxEzARBgNVBAsTCkN5YmVydHJ1\nc3QxLjAsBgNVBAMTJVZlcml6b24gQWthbWFpIFN1cmVTZXJ2ZXIgQ0EgRzE0LVNI\nQTIwHhcNMTUwNDIzMTY1ODAzWhcNMTYwNDIzMTY1NzU5WjCBhDELMAkGA1UEBhMC\nSlAxDjAMBgNVBAgTBVRva3lvMRIwEAYDVQQHEwlNaW5hdG8ta3UxGTAXBgNVBAoT\nEFNvbnkgY29ycG9yYXRpb24xDDAKBgNVBAsTA05QUzEoMCYGA1UEAxMfcHNuLXJz\nYy5wcm9kLmRsLnBsYXlzdGF0aW9uLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBALadff1z9x/SzQwLez1BfyvLoN+VU3DDOhybfmyKsyjCnU6IFy79\noCNuJP6Uv09MtfR/NHZYNz6SQ8riElLx3995yk9Wnfmd3HXRb6PxSVNYCWbpQLqL\n6nOWxerUj+yCjBiMmPQctUeD7Kn7VGErtJZ38BnPCQ27egTxs8jp65PlBYL+wYnS\nioZb1t52yjdsnbxYTlkHhU7DWsZKfj8wNZvzMBIgnraKwblRVoucE6NAhZKPXBQh\ncllKeXhGjVHFcQB8MZ6lrtAfQsLJYvXou4HCA1IDyJAG7qPhki3PLUcm/qbwXukz\n6uKpTdC3Tw3DI6HTPsFDawOKI0zZs40RWxMCAwEAAaOCAe0wggHpMAwGA1UdEwEB\n/wQCMAAwTAYDVR0gBEUwQzBBBgkrBgEEAbE+ATIwNDAyBggrBgEFBQcCARYmaHR0\ncHM6Ly9zZWN1cmUub21uaXJvb3QuY29tL3JlcG9zaXRvcnkwga8GCCsGAQUFBwEB\nBIGiMIGfMC0GCCsGAQUFBzABhiFodHRwOi8vdmFzc2cxNDIub2NzcC5vbW5pcm9v\ndC5jb20wNgYIKwYBBQUHMAKGKmh0dHBzOi8vY2FjZXJ0LmEub21uaXJvb3QuY29t\nL3Zhc3NnMTQyLmNydDA2BggrBgEFBQcwAoYqaHR0cHM6Ly9jYWNlcnQuYS5vbW5p\ncm9vdC5jb20vdmFzc2cxNDIuZGVyMCoGA1UdEQQjMCGCH3Bzbi1yc2MucHJvZC5k\nbC5wbGF5c3RhdGlvbi5uZXQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\nAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBT4vfqvc3fGxxv5S00Rp9Ezr69y\nETA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vdmFzc2cxNDIuY3JsLm9tbmlyb290\nLmNvbS92YXNzZzE0Mi5jcmwwHQYDVR0OBBYEFECotIoqM/RYjCUGFD97O9KzLnrA\nMA0GCSqGSIb3DQEBCwUAA4IBAQAtdu6/cFEzzP3NxTLG0Zidap+g4id4gTru1593\nXOc/RFobetN1/z6PYDR0l1tivaA8q1PU7swF8anK9m2+3Tn/MD9CONhaWHNuE3OY\nJlFreviSUih4EnUB2GKF78ac5I3VgNZwaOT6khsIqvNkFVEX4s0r1BweoTU75/mn\nm22SlEuGYWsree/ltMjYw08k2B/6aBFuwIaFbv57/1V/IBjufqLUNBcp01Rz62gE\nWstynBavGrQQPXInqRUxMSiuhHUQEZNgff5yesowMk4e7A0Q8DUo1VlqSXM4T27X\n5pS20KmmlWetKd5WTjpQYzjetHf6TYRy8+E8eebww2A7uO3A\n-----END CERTIFICATE-----\n",
	<span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>37221925980c05deefac014f9a72b4765e716341<span class="pl-pds">"</span></span>,
	<span class="pl-s"><span class="pl-pds">"</span>Seen<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>16<span class="pl-pds">"</span></span>,
	<span class="pl-s"><span class="pl-pds">"</span>Subject<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>C=JP, ST=Tokyo, L=Minato-ku, O=Sony corporation, OU=NPS, CN=psn-rsc.prod.dl.playstation.net<span class="pl-pds">"</span></span>,
	<span class="pl-s"><span class="pl-pds">"</span>Time<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2015-04-23T16:58:03+00:00<span class="pl-pds">"</span></span>,
	<span class="pl-s"><span class="pl-pds">"</span>Usage<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>TLS Web Server Authentication, TLS Web Client Authentication<span class="pl-pds">"</span></span>
}</pre>
</div>