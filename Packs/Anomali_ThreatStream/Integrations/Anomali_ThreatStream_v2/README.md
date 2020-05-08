<!-- HTML_DOC -->
<p>Use the Anomali ThreatStream integration to query and submit threats.</p>
<h2>Anomali ThreatStream v2 Playbook</h2>
<ul>
<li>Detonate File - ThreatStream</li>
<li>Detonate URL - ThreatStream</li>
</ul>
<h2>Use Cases</h2>
<ol>
<li>Get threat intelligence from the ThreatStream platform.</li>
<li>Create and manage threat models.</li>
<li>Import indicators to ThreatStream platform.</li>
<li>Submit file or URL to sandbox and receive an analysis report.</li>
</ol>
<h2>Configure Anomali ThreatStream v2 on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Anomali ThreatStream v2.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span><a href="https://www.test.com/" rel="nofollow">https://www.test.com</a>)</strong></li>
<li><strong>Username</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Threshold of the indicator.</strong></li>
<li><strong>Trust any certificate (insecure)</strong></li>
<li><strong>Use system proxy</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_f1f947a5-6e97-439c-9e1a-912581a47729" target="_self">Get the reputation of an IP address: ip</a></li>
<li><a href="#h_c5ddcd8b-b5cf-4bd3-8e08-ad0ce732448d" target="_self">Get the reputation of a domain name: domain</a></li>
<li><a href="#h_d93298a2-414a-4705-9a55-249e425508de" target="_self">Get the reputation of a file: file</a></li>
<li><a href="#h_7aea5e1f-dd82-4456-b3ce-bd4ba9ede500" target="_self">Get the reputation of a URL: url</a></li>
<li><a href="#h_07be9617-2153-4596-9461-1a64cfa82c41" target="_self">Get the reputation of an email address: threatstream-email-reputation</a></li>
<li><a href="#h_f39323ba-05fe-48a7-9fa8-43c1a536f4fc" target="_self">Get enrichment data for a domain or IP address: threatstream-get-passive-dns</a></li>
<li><a href="#h_3e5b000a-a5eb-4b6e-bddc-ba2edde7c7af" target="_self">Import indicators: threatstream-import-indicator-with-approval</a></li>
<li><a href="#h_873f28ef-3a19-4c48-8305-bd156bcfb9ce" target="_self">Get a list of threat models: threatstream-get-model-list</a></li>
<li><a href="#h_7bfb43d7-8e55-44c5-9b2b-d290eee42e51" target="_self">Get a description of a threat model: threatstream-get-model-description</a></li>
<li><a href="#h_b000ad9b-2be2-4a00-b4b8-c55400058188" target="_self">Get a list of indicators for a threat model: threatstream-get-indicators-by-model</a></li>
<li><a href="#h_6a77675f-f6aa-4aeb-9abf-4dd78318b177" target="_self">Submit a file or URL for detonation: threatstream-submit-to-sandbox</a></li>
<li><a href="#h_d322b0f1-3684-43f6-9bee-46edb2713f41" target="_self">Get the status of a report: threatstream-get-analysis-status</a></li>
<li><a href="#h_224b4581-0ceb-4b95-a7e3-d8a59c7e9967" target="_self">Get the report of a submitted file or URL: threatstream-analysis-report</a></li>
<li><a href="#h_3d94a1ac-b756-4b52-86f2-f309d633d18c" target="_self">Get a list of filtered indicators: threatstream-get-indicators</a></li>
<li><a href="#h_789d66ed-a1e0-42c2-934a-18f3c34f7022" target="_self">Add tags to a threat model: threatstream-add-tag-to-model</a></li>
<li><a href="#h_073ab7a3-58c7-48a5-9e01-55c78a9f6788" target="_self">Create a threat model: threatstream-create-model</a></li>
<li><a href="#h_6e714d0f-5ef9-4788-a5bb-e0e9498cb0f5" target="_self">Update a threat model: threatstream-update-model</a></li>
<li><a href="#h_36bf4b62-235a-4fb1-8dd2-1e5a67f1e5fd" target="_self">Get a list of supported platforms: threatstream-supported-platforms</a></li>
</ol>
<h3 id="h_f1f947a5-6e97-439c-9e1a-912581a47729">1. Get the reputation for an IP address</h3>
<hr>
<p>Checks for and returns the reputation of the given IP address.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">ip</td>
<td style="width: 538px;">The IP to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">threshold</td>
<td style="width: 538px;">If the severity is greater than or equal to the threshold, then the IP address will be considered malicious. This argument will override the default threshold defined as a parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">include_inactive</td>
<td style="width: 538px;">Whether to include results with the status "Inactive". Default is "True".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 209px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 209px;">DBotScore.Indicator</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 209px;">DBotScore.Type</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 209px;">DBotScore.Vendor</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 209px;">IP.ASN</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Autonomous System (AS) number associated with the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">IP.Address</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">IP.Geo.Country</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Country associated with the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">IP.Geo.Location</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Longitude and latitude of the IP address.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.ASN</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Autonomous System (AS) number associated with the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Address</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">IP address of the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Country</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Country associated with the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Type</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Modified</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Severity</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">The indicator severity ("very-high", "high", "medium", or "low".</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Confidence</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Status</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Status assigned to the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Organization</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Name of the business that owns the IP address associated with the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">ThreatStream.IP.Source</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 209px;">DBotScore.Score</td>
<td style="width: 58px;">Number</td>
<td style="width: 473px;">The actual score.</td>
</tr>
<tr>
<td style="width: 209px;">IP.Malicious.Vendor</td>
<td style="width: 58px;">String</td>
<td style="width: 473px;">Vendor that reported the indicator as malicious.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>ip ip=39.41.26.166 using-brand="Anomali ThreatStream v2"</pre>
<h5>Context Example</h5>
<pre>{
    "IP": {
        "Geo": {
            "Country": "PK", 
            "Location": "33.6007,73.0679"
        }, 
        "ASN": "45595", 
        "Address": "39.41.26.166"
    }, 
    "DBotScore": {
        "Vendor": "TOR Exit Nodes", 
        "Indicator": "39.41.26.166", 
        "Score": 2, 
        "Type": "ip"
    }, 
    "ThreatStream.IP": {
        "Status": "active", 
        "Confidence": 96, 
        "Severity": "low", 
        "Country": "PK", 
        "Modified": "2019-06-24T10:10:12.289Z", 
        "Source": "TOR Exit Nodes", 
        "Address": "39.41.26.166", 
        "Organization": "PTCL", 
        "Type": "ip", 
        "ASN": "45595"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>IP reputation for: 39.41.26.166</h3>
<table style="width: 768px;" border="2">
<thead>
<tr>
<th style="width: 86px;">Address</th>
<th style="width: 98px;">Confidence</th>
<th style="width: 55px;">Source</th>
<th style="width: 38px;">Type</th>
<th style="width: 51px;">Status</th>
<th style="width: 134px;">Modified</th>
<th style="width: 102px;">Organization</th>
<th style="width: 45px;">ASN</th>
<th style="width: 54px;">Country</th>
<th style="width: 74px;">Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 86px;">39.41.26.166</td>
<td style="width: 98px;">96</td>
<td style="width: 55px;">TOR Exit Nodes</td>
<td style="width: 38px;">ip</td>
<td style="width: 51px;">active</td>
<td style="width: 134px;">2019-06-24T10:10:12.289Z</td>
<td style="width: 102px;">PTCL</td>
<td style="width: 45px;">45595</td>
<td style="width: 54px;">PK</td>
<td style="width: 74px;">low</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_c5ddcd8b-b5cf-4bd3-8e08-ad0ce732448d">2. Get the reputation of a domain name</h3>
<hr>
<p>Checks for and returns the reputation of the given domain name. </p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">domain</td>
<td style="width: 518px;">The domain name to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">threshold</td>
<td style="width: 518px;">If severity is greater than or equal to the threshold, then the IP address will be considered malicious. This argument will override the default threshold defined as a parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">include_inactive</td>
<td style="width: 518px;">Whether to include results with status of "Inactive". Default is "True".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 255px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">Domain.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The domain name.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.DNS</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">IPs resolved by DNS.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.WHOIS.CreationDate</td>
<td style="width: 53px;">Date</td>
<td style="width: 432px;">Date the domain was created. The date format is: YYYYMMDDThhmmss. Where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.WHOIS.UpdatedDate</td>
<td style="width: 53px;">Date</td>
<td style="width: 432px;">Date the domain was last updated. The date format is: YYYYMMDDThhmmss. Where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.WHOIS.Registrant.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Name of the registrant.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.WHOIS.Registrant.Email</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Email address of the registrant.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.WHOIS.Registrant.Phone</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Phone number of the registrant.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.ASN</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Autonomous System (AS) number associated with the indicator.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Address</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The domain name of the indicator.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Country</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Country associated with the indicator.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Modified</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value</td>
</tr>
<tr>
<td style="width: 255px;">for time, in UTC time.</td>
<td style="width: 53px;"> </td>
<td style="width: 432px;"> </td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Severity</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The indicator severity ("very-high", "high", "medium", "low").</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Confidence</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Status</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Status assigned to the indicator.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Organization</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Name of the business that owns the IP address associated with the indicator.</td>
</tr>
<tr>
<td style="width: 255px;">ThreatStream.Domain.Source</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 255px;">Domain.Malicious.Vendor</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Vendor that reported the indicator as malicious.</td>
</tr>
<tr>
<td style="width: 255px;">DBotScore.Indicator</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 255px;">DBotScore.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 255px;">DBotScore.Vendor</td>
<td style="width: 53px;">String</td>
<td style="width: 432px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 255px;">DBotScore.Score</td>
<td style="width: 53px;">Number</td>
<td style="width: 432px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example </h5>
<pre>domain domain="microsoftfaq.com" using-brand="Anomali ThreatStream v2" </pre>
<h5>Context Example </h5>
<pre>{
    "ThreatStream.Domain": {
        "Status": "active", 
        "Confidence": 38, 
        "Severity": "high", 
        "Country": null, 
        "Modified": "2019-06-24T08:39:04.644Z", 
        "Source": "Analyst", 
        "Address": "microsoftfaq.com", 
        "Organization": "", 
        "Type": "domain", 
        "ASN": ""
    }, 
    "Domain": {
        "Malicious": {
            "Vendor": "ThreatStream"
        }, 
        "Name": "microsoftfaq.com", 
        "DNS": "127.0.0.1", 
        "WHOIS": {
            "UpdatedDate": "2019-06-24T08:39:04.644Z", 
            "CreationDate": "2019-06-24T08:38:53.246Z", 
            "Registrant": {
                "Phone": "", 
                "Email": "", 
                "Name": "Registrant City:"
            }
        }
    }, 
    "DBotScore": {
        "Vendor": "Analyst", 
        "Indicator": "microsoftfaq.com", 
        "Score": 3, 
        "Type": "domain"
    }
}</pre>
<h5>Human Readable Output </h5>
<h3>Domain reputation for: microsoftfaq.com</h3>
<table border="2">
<thead>
<tr>
<th>Address</th>
<th>Confidence</th>
<th>Source</th>
<th>Type</th>
<th>Status</th>
<th>Modified</th>
<th>Organization</th>
<th>ASN</th>
<th>Country</th>
<th>Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td>microsoftfaq.com</td>
<td>38</td>
<td>Analyst</td>
<td>domain</td>
<td>active</td>
<td>2019-06-24T08:39:04.644Z</td>
<td> </td>
<td> </td>
<td> </td>
<td>high</td>
</tr>
</tbody>
</table>
<p>  </p>
<h3 id="h_d93298a2-414a-4705-9a55-249e425508de">3. Get the reputation of a file</h3>
<hr>
<p>Checks for and returns the reputation of the given MD5 hash of the file. </p>
<h5>Base Command </h5>
<p><code>file</code> </p>
<h5>Input </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 537px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">file</td>
<td style="width: 537px;">The MD5 hash of file to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 132px;">threshold</td>
<td style="width: 537px;">If severity is greater than or equal to the threshold, then the MD5 hash of file will be considered malicious. This argument will override the default threshold defined as a parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">include_inactive</td>
<td style="width: 537px;">Whether to include results with the status "Inactive". Default is "True".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 212px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 475px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 212px;">File.MD5</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 212px;">File.Malicious.Vendor</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">Vendor that reported the indicator as malicious.</td>
</tr>
<tr>
<td style="width: 212px;">DBotScore.Indicator</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 212px;">DBotScore.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 212px;">DBotScore.Vendor</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 212px;">DBotScore.Score</td>
<td style="width: 53px;">Number</td>
<td style="width: 475px;">The actual score.</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.Severity</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">The indicator severity ("very-high", "high", "medium", "low").</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.Confidence</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence.</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.Status</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">Status assigned to the indicator.</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.MD5</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">The MD5 hash of the indicator.</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.Modified</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
<tr>
<td style="width: 212px;">ThreatStream.File.Source</td>
<td style="width: 53px;">String</td>
<td style="width: 475px;">The source of the indicator.</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Command Example</h5>
<pre>file file=07df6c1d9a76d81f191be288d463784b using-brand="Anomali ThreatStream v2"
</pre>
<h5>Context Example</h5>
<pre>{
    "DBotScore": {
        "Vendor": "URLHaus Hashes", 
        "Indicator": "07df6c1d9a76d81f191be288d463784b", 
        "Score": 2, 
        "Type": "md5"
    }, 
    "ThreatStream.File": {
        "Status": "active", 
        "Confidence": 75, 
        "Severity": "medium", 
        "Modified": "2019-06-24T10:13:27.284Z", 
        "Source": "URLHaus Hashes", 
        "Type": "md5", 
        "MD5": "07df6c1d9a76d81f191be288d463784b"
    }, 
    "File": {
        "MD5": "07df6c1d9a76d81f191be288d463784b"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>MD5 reputation for: 07df6c1d9a76d81f191be288d463784b</h3>
<table border="2">
<thead>
<tr>
<th>Confidence</th>
<th>Source</th>
<th>Type</th>
<th>Status</th>
<th>Modified</th>
<th>Severity</th>
<th>MD5</th>
</tr>
</thead>
<tbody>
<tr>
<td>75</td>
<td>URLHaus Hashes</td>
<td>md5</td>
<td>active</td>
<td>2019-06-24T10:13:27.284Z</td>
<td>medium</td>
<td>07df6c1d9a76d81f191be288d463784b</td>
</tr>
</tbody>
</table>
<p>  </p>
<h3 id="h_7aea5e1f-dd82-4456-b3ce-bd4ba9ede500">4. Get the reputation of a URL</h3>
<hr>
<p>Checks for and returns the reputation of the given URL. </p>
<h5>Base Command </h5>
<p><code>url</code> </p>
<h5>Input </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">url</td>
<td style="width: 526px;">The URL to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">threshold</td>
<td style="width: 526px;">If the severity is greater than or equal to the threshold, then the URL will be considered malicious. This argument will override the default threshold defined as a parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">include_inactive</td>
<td style="width: 526px;">Whether to include results with the status "Inactive". Default is "True".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 229px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 459px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 229px;">DBotScore.Indicator</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Type</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Vendor</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 229px;">DBotScore.Score</td>
<td style="width: 52px;">Number</td>
<td style="width: 459px;">The actual score.</td>
</tr>
<tr>
<td style="width: 229px;">URL.Data</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The URL of the indicator.</td>
</tr>
<tr>
<td style="width: 229px;">URL.Malicious.Vendor</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">Vendor that reported the indicator as malicious.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Modified</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Confidence</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Status</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The status of the indicator.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Organization</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">Name of the business that owns the IP address associated with the indicator.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Address</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">URL of the indicator.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Country</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">Country associated with the indicator.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Type</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Source</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 229px;">ThreatStream.URL.Severity</td>
<td style="width: 52px;">String</td>
<td style="width: 459px;">The indicator severity ("very-high", "high", "medium", or "low").</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Command Example</h5>
<pre>url url=http://194.147.35.172/mikey.mpsl using-brand="Anomali ThreatStream v2"
</pre>
<h5>Context Example</h5>
<pre>{
    "URL": {
        "Malicious": {
            "Vendor": "ThreatStream"
        }, 
        "Data": "http://194.147.35.172/mikey.mpsl"
    }, 
    "ThreatStream.URL": {
        "Status": "active", 
        "Confidence": 90, 
        "Severity": "very-high", 
        "Country": "RU", 
        "Modified": "2019-06-24T10:10:05.890Z", 
        "Source": "H3X Tracker", 
        "Address": "http://194.147.35.172/mikey.mpsl", 
        "Organization": "LLC Baxet", 
        "Type": "url"
    }, 
    "DBotScore": {
        "Vendor": "H3X Tracker", 
        "Indicator": "http://194.147.35.172/mikey.mpsl", 
        "Score": 3, 
        "Type": "url"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>URL reputation for:<span> </span>http://194.147.35.172/mikey.mpsl</h3>
<table style="width: 869px;" border="2">
<thead>
<tr>
<th style="width: 247px;">Address</th>
<th style="width: 88px;">Confidence</th>
<th style="width: 55px;">Source</th>
<th style="width: 38px;">Type</th>
<th style="width: 51px;">Status</th>
<th style="width: 134px;">Modified</th>
<th style="width: 102px;">Organization</th>
<th style="width: 63px;">Country</th>
<th style="width: 63px;">Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 247px;">http://194.147.35.172/mikey.mpsl</td>
<td style="width: 88px;">90</td>
<td style="width: 55px;">H3X Tracker</td>
<td style="width: 38px;">url</td>
<td style="width: 51px;">active</td>
<td style="width: 134px;">2019-06-24T10:10:05.890Z</td>
<td style="width: 102px;">LLC Baxet</td>
<td style="width: 63px;">RU</td>
<td style="width: 63px;">very-high</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_07be9617-2153-4596-9461-1a64cfa82c41">5. Get the reputation of an email address</h3>
<hr>
<p>Checks for and returns the reputation of the given email address. </p>
<h5>Base Command </h5>
<p><code>threatstream-email-reputation</code> </p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">email</td>
<td style="width: 534px;">The email address to check.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 135px;">threshold</td>
<td style="width: 534px;">If the severity is greater or equal than the threshold, then the IP address will be considered malicious. This argument will override the default threshold defined as a parameter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 135px;">include_inactive</td>
<td style="width: 534px;">Whether to include results with the status "Inactive". Default is "True".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 303px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 384px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 303px;">DBotScore.Indicator</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">The tested indicator.</td>
</tr>
<tr>
<td style="width: 303px;">DBotScore.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 303px;">DBotScore.Vendor</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">Vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 303px;">DBotScore.Score</td>
<td style="width: 53px;">Number</td>
<td style="width: 384px;">The actual score.</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Severity</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">The indicator severity ("very-high", "high", "medium", "low").</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Confidence</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">Level of certainty that an observable is of the reported indicator type. Confidence score can range from 0-100, in increasing order of confidence.</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Status</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">Status assigned to the indicator.</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Email</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">The email address of the indicator.</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Source</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 303px;">ThreatStream.EmailReputation.Modified</td>
<td style="width: 53px;">String</td>
<td style="width: 384px;">Date and time when the indicator was last updated. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Command Example</h5>
<pre>threatstream-email-reputation email=svellis@sault.com
</pre>
<h5>Context Example</h5>
<pre>{
    "DBotScore": {
        "Vendor": "Anomali Labs Compromised Credentials", 
        "Indicator": "svellis@sault.com", 
        "Score": 2, 
        "Type": "email"
    }, 
    "ThreatStream.EmailReputation": {
        "Status": "active", 
        "Confidence": 100, 
        "Severity": "low", 
        "Modified": "2019-06-24T09:50:23.810Z", 
        "Source": "Anomali Labs Compromised Credentials", 
        "Type": "email", 
        "Email": "svellis@sault.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Email reputation for:<span> </span>sveis@ault.com</h3>
<table style="width: 698px;" border="2">
<thead>
<tr>
<th style="width: 88px;">Confidence</th>
<th style="width: 174px;">Source</th>
<th style="width: 43px;">Type</th>
<th style="width: 51px;">Status</th>
<th style="width: 144px;">Modified</th>
<th style="width: 65px;">Severity</th>
<th style="width: 111px;">Email</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 88px;">100</td>
<td style="width: 174px;">Anomali Labs Compromised Credentials</td>
<td style="width: 43px;">email</td>
<td style="width: 51px;">active</td>
<td style="width: 144px;">2019-06-24T09:50:23.810Z</td>
<td style="width: 65px;">low</td>
<td style="width: 111px;">sveis@ault.com</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_f39323ba-05fe-48a7-9fa8-43c1a536f4fc">6. Get enrichment data for a domain or IP address</h3>
<hr>
<p>Returns enrichment data for a domain or an IP address, for available observables. </p>
<h5>Base Command</h5>
<p><code>threatstream-get-passive-dns</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 485px;"><strong>Description</strong></th>
<th style="width: 93px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">type</td>
<td style="width: 485px;">The type of passive DNS search ("ip", "domain").</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">value</td>
<td style="width: 485px;">Possible values are "IP" or "Domain".</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">limit</td>
<td style="width: 485px;">Maximum number of results to return. Default is 50.</td>
<td style="width: 93px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 261px;"><strong>Path</strong></th>
<th style="width: 38px;"><strong>Type</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">ThreatStream.PassiveDNS.Domain</td>
<td style="width: 38px;">String</td>
<td style="width: 441px;">The domain value.</td>
</tr>
<tr>
<td style="width: 261px;">ThreatStream.PassiveDNS.Ip</td>
<td style="width: 38px;">String</td>
<td style="width: 441px;">The IP value.</td>
</tr>
<tr>
<td style="width: 261px;">ThreatStream.PassiveDNS.Rrtype</td>
<td style="width: 38px;">String</td>
<td style="width: 441px;">The Rrtype value.</td>
</tr>
<tr>
<td style="width: 261px;">ThreatStream.PassiveDNS.Source</td>
<td style="width: 38px;">String</td>
<td style="width: 441px;">The source value.</td>
</tr>
<tr>
<td style="width: 261px;">ThreatStream.PassiveDNS.FirstSeen</td>
<td style="width: 38px;">String</td>
<td style="width: 441px;">The first seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
<tr>
<td style="width: 261px;">ThreatStream.PassiveDNS.LastSeen</td>
<td style="width: 38px;">String</td>
<td style="width: 441px;">The last seen date. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-get-passive-dns type=domain value=discoverer.blog</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream.PassiveDNS": [
        {
            "Domain": "discoverer.blog", 
            "Ip": "184.168.221.52", 
            "Rrtype": "A", 
            "Source": "Spamhaus", 
            "LastSeen": "2019-06-23T08:09:54", 
            "FirstSeen": "2019-06-23T08:09:54"
        }, 
        {
            "Domain": "discoverer.blog", 
            "Ip": "50.63.202.51", 
            "Rrtype": "A", 
            "Source": "Spamhaus", 
            "LastSeen": "2019-06-21T10:33:54", 
            "FirstSeen": "2019-06-21T10:33:54"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Passive DNS enrichment data for: discoverer.blog</h3>
<table border="2">
<thead>
<tr>
<th>Domain</th>
<th>Ip</th>
<th>Rrtype</th>
<th>Source</th>
<th>FirstSeen</th>
<th>LastSeen</th>
</tr>
</thead>
<tbody>
<tr>
<td>discoverer.blog</td>
<td>184.168.221.52</td>
<td>A</td>
<td>Spamhaus</td>
<td>2019-06-23T08:09:54</td>
<td>2019-06-23T08:09:54</td>
</tr>
<tr>
<td>discoverer.blog</td>
<td>50.63.202.51</td>
<td>A</td>
<td>Spamhaus</td>
<td>2019-06-21T10:33:54</td>
<td>2019-06-21T10:33:54</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3e5b000a-a5eb-4b6e-bddc-ba2edde7c7af">7. Import indicators</h3>
<hr>
<p>Imports indicators (observables) into ThreatStream. Approval of the imported data is required, using the ThreatStream UI. The data can be imported using one of three methods: plain-text, file, or URL. Only one argument can be used.</p>
<h5>Base Command</h5>
<p><code>threatstream-import-indicator-with-approval</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 130px;"><strong>Argument Name</strong></th>
<th style="width: 539px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 130px;">confidence</td>
<td style="width: 539px;">The level of certainty that an observable is of the reported indicator type. Default is 50.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 130px;">classification</td>
<td style="width: 539px;">Denotes whether the indicator data is public or private to the organization. Default is "private".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 130px;">threat_type</td>
<td style="width: 539px;">Type of threat associated with the imported observables. Default is "exploit".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 130px;">severity</td>
<td style="width: 539px;">Gauges the potential impact of the indicator type the observable is thought to be associated with. Default is "low".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 130px;">import_type</td>
<td style="width: 539px;">The import type of the indicator.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 130px;">import_value</td>
<td style="width: 539px;">The source of imported data. Can be one of the following: url, data text of file-id of uploaded file to the War Rroom. Supported formats in case of file-id are: CSV, HTML, IOC, JSON, PDF, TXT.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 353px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 353px;">ThreatStream.Import.ImportID</td>
<td style="width: 65px;">String</td>
<td style="width: 322px;">The ID of the imported data.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-import-indicator-with-approval import_type="file-id" import_value=5403@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0</pre>
<h5>Context Example</h5>
<pre>{
    "File": {
        "EntryID": "5403@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
        "Extension": "csv",
        "Info": "text/csv; charset=utf-8",
        "MD5": "5b7ed7973e4deb3c98ee3a4bd6d911af",
        "Name": "input.csv",
        "SHA1": "055c5002eb5a4d4abe2eb1768e925bfc3a1a763e",
        "SHA256": "fd16220852b39e2c8fa51766750e3991670766512836212c799c5a0537e3ef8c",
        "SSDeep": "3:Wg8oEIjOH9+KS3qvRBTdRi690oVqzBUGyT0/n:Vx0HgKnTdE6eoVafY8",
        "Size": 102,
        "Type": "UTF-8 Unicode (with BOM) text, with CRLF line terminators\n"
    },
    "ThreatStream": {
        "Import": {
            "ImportID": "894516"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>The data was imported successfully. The ID of imported job is: 894514</p>
<h3 id="h_873f28ef-3a19-4c48-8305-bd156bcfb9ce">8. Get a list of threat models</h3>
<hr>
<p>Returns a list of threat models.</p>
<h5>Base Command</h5>
<p><code>threatstream-get-model-list</code></p>
<h5>Input</h5>
<table style="width: 747px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">model</td>
<td style="width: 532px;">Threat model of the returned list.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">limit</td>
<td style="width: 532px;">Limits the list of models size. Specifying limit=0 will return up to a maximum of 1,000 models. In case  limit=0 the output won't be set in the context.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 228px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 475px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 228px;">ThreatStream.List.Type</td>
<td style="width: 37px;">String</td>
<td style="width: 475px;">The type of threat model.</td>
</tr>
<tr>
<td style="width: 228px;">ThreatStream.List.Name</td>
<td style="width: 37px;">String</td>
<td style="width: 475px;">The name of the threat model.</td>
</tr>
<tr>
<td style="width: 228px;">ThreatStream.List.ID</td>
<td style="width: 37px;">String</td>
<td style="width: 475px;">The ID of the threat model.</td>
</tr>
<tr>
<td style="width: 228px;">ThreatStream.List.CreatedTime</td>
<td style="width: 37px;">String</td>
<td style="width: 475px;">Date and time of threat model creation. The date format is: YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-get-model-list model=actor limit=10</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream.List": [
        {
            "CreatedTime": "2015-06-29T17:02:01.885011", 
            "Type": "Actor", 
            "ID": 2, 
            "Name": "Pirpi"
        }, 
        {
            "CreatedTime": "2015-06-30T19:20:05.930697", 
            "Type": "Actor", 
            "ID": 3, 
            "Name": "TeamCyberGhost"
        }, 
        {
            "CreatedTime": "2015-07-01T18:10:53.241301", 
            "Type": "Actor", 
            "ID": 4, 
            "Name": "Wekby"
        }, 
        {
            "CreatedTime": "2015-07-01T19:27:06.180602", 
            "Type": "Actor", 
            "ID": 5, 
            "Name": "Axiom"
        }, 
        {
            "CreatedTime": "2015-07-01T19:52:56.019862", 
            "Type": "Actor", 
            "ID": 7, 
            "Name": "Peace (Group) a/k/a C0d0s0"
        }, 
        {
            "CreatedTime": "2015-07-01T19:58:50.741202", 
            "Type": "Actor", 
            "ID": 8, 
            "Name": "Nitro"
        }, 
        {
            "CreatedTime": "2015-07-06T16:06:12.123839", 
            "Type": "Actor", 
            "ID": 9, 
            "Name": "Comment Crew"
        }, 
        {
            "CreatedTime": "2015-07-07T17:40:04.920012", 
            "Type": "Actor", 
            "ID": 10, 
            "Name": "Comfoo"
        }, 
        {
            "CreatedTime": "2015-07-07T18:53:12.331221", 
            "Type": "Actor", 
            "ID": 11, 
            "Name": "Syrian Electronic Army"
        }, 
        {
            "CreatedTime": "2015-07-08T20:59:29.751919", 
            "Type": "Actor", 
            "ID": 12, 
            "Name": "DD4BC"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>List of Actors</h3>
<table border="2">
<thead>
<tr>
<th>CreatedTime</th>
<th>ID</th>
<th>Name</th>
<th>Type</th>
</tr>
</thead>
<tbody>
<tr>
<td>2015-06-29T17:02:01.885011</td>
<td>2</td>
<td>Pirpi</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-06-30T19:20:05.930697</td>
<td>3</td>
<td>TeamCyberGhost</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-01T18:10:53.241301</td>
<td>4</td>
<td>Wekby</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-01T19:27:06.180602</td>
<td>5</td>
<td>Axiom</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-01T19:52:56.019862</td>
<td>7</td>
<td>Peace (Group) a/k/a C0d0s0</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-01T19:58:50.741202</td>
<td>8</td>
<td>Nitro</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-06T16:06:12.123839</td>
<td>9</td>
<td>Comment Crew</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-07T17:40:04.920012</td>
<td>10</td>
<td>Comfoo</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-07T18:53:12.331221</td>
<td>11</td>
<td>Syrian Electronic Army</td>
<td>Actor</td>
</tr>
<tr>
<td>2015-07-08T20:59:29.751919</td>
<td>12</td>
<td>DD4BC</td>
<td>Actor</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7bfb43d7-8e55-44c5-9b2b-d290eee42e51">9. Get a description of a threat model</h3>
<hr>
<p>Returns an HTML file with a description of the threat model.</p>
<h5>Base Command</h5>
<p><code>threatstream-get-model-description</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 248px;"><strong>Argument Name</strong></th>
<th style="width: 357px;"><strong>Description</strong></th>
<th style="width: 135px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 248px;">model</td>
<td style="width: 357px;">The threat model.</td>
<td style="width: 135px;">Required</td>
</tr>
<tr>
<td style="width: 248px;">id</td>
<td style="width: 357px;">The ID of the threat model.</td>
<td style="width: 135px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Path</strong></th>
<th style="width: 85px;"><strong>Type</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">File.Name</td>
<td style="width: 85px;">String</td>
<td style="width: 501px;">The file name of the model description.</td>
</tr>
<tr>
<td style="width: 154px;">File.EntryID</td>
<td style="width: 85px;">String</td>
<td style="width: 501px;">The entry ID of the model description.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-get-model-description model=campaign id=1406</pre>
<h5>Context Example</h5>
<pre>{
    "File": {
        "EntryID": "5384@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
        "Extension": "html",
        "Info": "text/html; charset=utf-8",
        "MD5": "66eabc1c704fdac429939eb09bc5346f",
        "Name": "campaign_1406.html",
        "SHA1": "69f3dfe8ae037253e782dd201904aa583d83bcd7",
        "SHA256": "49635483962b38a2fd5d50ebbb51b7002ecab3fd23e0f9f99e915f7b33d3f739",
        "SSDeep": "96:XZcBqz4xqHC2AwALc+nvJN7GBoBGK1IW7h:XC40W/tixmoLTh",
        "Size": 3686,
        "Type": "HTML document text, ASCII text, with very long lines, with no line terminators\n"
    }
}
</pre>
<h3 id="h_b000ad9b-2be2-4a00-b4b8-c55400058188">10. Get a list of indicators for a threat model</h3>
<hr>
<p>Returns a list of indicators associated with the specified model and ID of the model. </p>
<h5>Base Command</h5>
<p><code>threatstream-get-indicators-by-model</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 175px;"><strong>Argument Name</strong></th>
<th style="width: 472px;"><strong>Description</strong></th>
<th style="width: 93px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">model</td>
<td style="width: 472px;">The threat model.</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 175px;">id</td>
<td style="width: 472px;">The ID of the model.</td>
<td style="width: 93px;">Required</td>
</tr>
<tr>
<td style="width: 175px;">limit</td>
<td style="width: 472px;">Maximum number of results to return. Default is 20.</td>
<td style="width: 93px;">Optional</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 319px;"><strong>Path</strong></th>
<th style="width: 38px;"><strong>Type</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 319px;">ThreatStream.Model.ModelType</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The type of the threat model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.ModelID</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The ID of the threat model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Value</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The value of indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.ID</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The ID of indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.IType</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The iType of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Severity</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The severity of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Confidence</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The confidence of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Country</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The country of the indicator associated with the specified model</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Organization</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The organization of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.ASN</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The ASN of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Status</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The status of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Tags</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The tags of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Modified</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The date and time the indicator was last modified.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Source</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 319px;">ThreatStream.Model.Indicators.Type</td>
<td style="width: 38px;">String</td>
<td style="width: 383px;">The type of the indicator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-get-indicators-by-model id=11885 model=incident</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream.Model": {
        "Indicators": [
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.446", 
                "Value": "417072b246af74647897978902f7d903562e0f6f", 
                "ID": "50117813617", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.455", 
                "Value": "d3c65377d39e97ab019f7f00458036ee0c7509a7", 
                "ID": "50117813616", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.462", 
                "Value": "5f51084a4b81b40a8fcf485b0808f97ba3b0f6af", 
                "ID": "50117813615", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.469", 
                "Value": "220a8eacd212ecc5a55d538cb964e742acf039c6", 
                "ID": "50117813614", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.477", 
                "Value": "a16ef7d96a72a24e2a645d5e3758c7d8e6469a55", 
                "ID": "50117813612", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.485", 
                "Value": "275e76fc462b865fe1af32f5f15b41a37496dd97", 
                "ID": "50117813611", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.493", 
                "Value": "df4b8c4b485d916c3cadd963f91f7fa9f509723f", 
                "ID": "50117813610", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.500", 
                "Value": "66eccea3e8901f6d5151b49bca53c126f086e437", 
                "ID": "50117813609", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.507", 
                "Value": "3d90630ff6c151fc2659a579de8d204d1c2f841a", 
                "ID": "50117813608", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.513", 
                "Value": "a6d14b104744188f80c6c6b368b589e0bd361607", 
                "ID": "50117813607", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.520", 
                "Value": "e3f183e67c818f4e693b69748962eecda53f7f88", 
                "ID": "50117813606", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.527", 
                "Value": "f326479a4aacc2aaf86b364b78ed5b1b0def1fbe", 
                "ID": "50117813605", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.534", 
                "Value": "c4d1fb784fcd252d13058dbb947645a902fc8935", 
                "ID": "50117813604", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.541", 
                "Value": "fb4a4143d4f32b0af4c2f6f59c8d91504d670b41", 
                "ID": "50117813603", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.548", 
                "Value": "400e4f843ff93df95145554b2d574a9abf24653f", 
                "ID": "50117813602", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.555", 
                "Value": "f82d18656341793c0a6b9204a68605232f0c39e7", 
                "ID": "50117813601", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.562", 
                "Value": "c33fe4c286845a175ee0d83db6d234fe24dd2864", 
                "ID": "50117813600", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.569", 
                "Value": "d9294b86b3976ddf89b66b8051ccf98cfae2e312", 
                "ID": "50117813599", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.576", 
                "Value": "9fc71853d3e6ac843bd36ce9297e398507e5b2bd", 
                "ID": "50117813597", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }, 
            {
                "Status": "active", 
                "Confidence": 100, 
                "IType": "mal_md5", 
                "Severity": "very-high", 
                "Tags": "FINSPY,FinSpy,community-threat-briefing,Weaponization", 
                "Country": null, 
                "Modified": "2017-09-25T11:43:54.583", 
                "Value": "c0ad9c242c533effd50b51e94874514a5b9f2219", 
                "ID": "50117813596", 
                "Source": "ThreatStream", 
                "Organization": "", 
                "Type": "md5", 
                "ASN": ""
            }
        ], 
        "ModelType": "Incident", 
        "ModelID": "11885"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Indicators list for Threat Model Incident with id 11885</h3>
<table border="2">
<thead>
<tr>
<th>IType</th>
<th>Value</th>
<th>ID</th>
<th>Confidence</th>
<th>Source</th>
<th>Type</th>
<th>Status</th>
<th>Tags</th>
<th>Modified</th>
<th>Organization</th>
<th>ASN</th>
<th>Country</th>
<th>Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td>mal_md5</td>
<td>417072b246af74647897978902f7d903562e0f6f</td>
<td>50117813617</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.446</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>d3c65377d39e97ab019f7f00458036ee0c7509a7</td>
<td>50117813616</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.455</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>5f51084a4b81b40a8fcf485b0808f97ba3b0f6af</td>
<td>50117813615</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.462</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>220a8eacd212ecc5a55d538cb964e742acf039c6</td>
<td>50117813614</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.469</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>a16ef7d96a72a24e2a645d5e3758c7d8e6469a55</td>
<td>50117813612</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.477</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>275e76fc462b865fe1af32f5f15b41a37496dd97</td>
<td>50117813611</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.485</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>df4b8c4b485d916c3cadd963f91f7fa9f509723f</td>
<td>50117813610</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.493</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>66eccea3e8901f6d5151b49bca53c126f086e437</td>
<td>50117813609</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.500</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>3d90630ff6c151fc2659a579de8d204d1c2f841a</td>
<td>50117813608</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.507</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>a6d14b104744188f80c6c6b368b589e0bd361607</td>
<td>50117813607</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.513</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>e3f183e67c818f4e693b69748962eecda53f7f88</td>
<td>50117813606</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.520</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>f326479a4aacc2aaf86b364b78ed5b1b0def1fbe</td>
<td>50117813605</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.527</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>c4d1fb784fcd252d13058dbb947645a902fc8935</td>
<td>50117813604</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.534</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>fb4a4143d4f32b0af4c2f6f59c8d91504d670b41</td>
<td>50117813603</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.541</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>400e4f843ff93df95145554b2d574a9abf24653f</td>
<td>50117813602</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.548</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>f82d18656341793c0a6b9204a68605232f0c39e7</td>
<td>50117813601</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.555</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>c33fe4c286845a175ee0d83db6d234fe24dd2864</td>
<td>50117813600</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.562</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>d9294b86b3976ddf89b66b8051ccf98cfae2e312</td>
<td>50117813599</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.569</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>9fc71853d3e6ac843bd36ce9297e398507e5b2bd</td>
<td>50117813597</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.576</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
<tr>
<td>mal_md5</td>
<td>c0ad9c242c533effd50b51e94874514a5b9f2219</td>
<td>50117813596</td>
<td>100</td>
<td>ThreatStream</td>
<td>md5</td>
<td>active</td>
<td>FINSPY,FinSpy,community-threat-briefing,Weaponization</td>
<td>2017-09-25T11:43:54.583</td>
<td> </td>
<td> </td>
<td> </td>
<td>very-high</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_6a77675f-f6aa-4aeb-9abf-4dd78318b177">11. Submit a file or URL for detonation</h3>
<hr>
<p>Submits a file or URL to the ThreatStream-hosted Sandbox for detonation. </p>
<h5>Base Command</h5>
<p><code>threatstream-submit-to-sandbox</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 185px;"><strong>Argument Name</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">submission_classification</td>
<td style="width: 484px;">Classification of the sandbox submission.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">report_platform</td>
<td style="width: 484px;">Platform on which the submitted URL or file will be run. To obtain a list supported platforms run the threatstream-get-sandbox-platforms command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">submission_type</td>
<td style="width: 484px;">The detonation type ("file" or "url").</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 185px;">submission_value</td>
<td style="width: 484px;">The submission value. Possible values are a valid URL or a file ID that was uploaded to the War Room to detonate.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 185px;">premium_sandbox</td>
<td style="width: 484px;">Specifies whether the premium sandbox should be used for detonation. Default is "false".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 185px;">detail</td>
<td style="width: 484px;">A CSV list of additional details for the indicator. This information is displayed in the Tag column of the ThreatStream UI.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 244px;"><strong>Path</strong></th>
<th style="width: 50px;"><strong>Type</strong></th>
<th style="width: 446px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 244px;">ThreatStream.Analysis.ReportID</td>
<td style="width: 50px;">String</td>
<td style="width: 446px;">The report ID that was submitted to the sandbox.</td>
</tr>
<tr>
<td style="width: 244px;">ThreatStream.Analysis.Status</td>
<td style="width: 50px;">String</td>
<td style="width: 446px;">The analysis status.</td>
</tr>
<tr>
<td style="width: 244px;">ThreatStream.Analysis.Platform</td>
<td style="width: 50px;">String</td>
<td style="width: 446px;">The platform of the submission submitted to the sandbox.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-submit-to-sandbox submission_type=file submission_value=5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0 premium_sandbox=false report_platform=WINDOWS7</pre>
<h5>Context Example</h5>
<pre>{
    "File": {
        "EntryID": "5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0",
        "Extension": "png",
        "Info": "image/png",
        "MD5": "a36544c75d1253d8dd32070908adebd0",
        "Name": "input_file.png",
        "SHA1": "15868fbe28e34f601b4e07b0f356ecb1f3a14876",
        "SHA256": "5126eb938b3c2dc53837d4805df01c8522a3bd4e5e77e9bc4f825b9ee178e6ab",
        "SSDeep": "98304:pKOjdLh3d35gcNMjnN+FOLEdhVb2t6lLPP9nuyxJ4iQzxKxOduLT/GzxS3UvtT:pHhhvglN+F+GwUlLPP9PxnQzxKxOdEUR",
        "Size": 4938234,
        "Type": "PNG image data, 2572 x 1309, 8-bit/color RGBA, non-interlaced\n"
    },
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": 422662,
            "Status": "processing"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>The submission info for 5358@6cf3881e-1cfd-48b5-8fc3-0b9fcfb791f0</h3>
<table border="2">
<thead>
<tr>
<th>ReportID</th>
<th>Status</th>
<th>Platform</th>
</tr>
</thead>
<tbody>
<tr>
<td>422662</td>
<td>processing</td>
<td>WINDOWS7</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_d322b0f1-3684-43f6-9bee-46edb2713f41">12. Get the status of a report</h3>
<hr>
<p>Returns the current status of the report that was submitted to the sandbox. The report ID is returned from the<span> </span><code>threatstream-submit-to-sandbox</code><span> </span>command.</p>
<h5>Base Command</h5>
<p><code>threatstream-get-analysis-status</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 199px;"><strong>Argument Name</strong></th>
<th style="width: 431px;"><strong>Description</strong></th>
<th style="width: 110px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 199px;">report_id</td>
<td style="width: 431px;">Report ID for which to check the status.</td>
<td style="width: 110px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 231px;"><strong>Path</strong></th>
<th style="width: 40px;"><strong>Type</strong></th>
<th style="width: 469px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 231px;">ThreatStream.Analysis.ReportID</td>
<td style="width: 40px;">String</td>
<td style="width: 469px;">The report ID of the file or URL that was detonated to sandbox.</td>
</tr>
<tr>
<td style="width: 231px;">ThreatStream.Analysis.Status</td>
<td style="width: 40px;">String</td>
<td style="width: 469px;">The report status of the file or URL that was detonated in the sandbox.</td>
</tr>
<tr>
<td style="width: 231px;">ThreatStream.Analysis.Platform</td>
<td style="width: 40px;">String</td>
<td style="width: 469px;">The platform that was used for detonation.</td>
</tr>
<tr>
<td style="width: 231px;">ThreatStream.Analysis.Verdict</td>
<td style="width: 40px;">String</td>
<td style="width: 469px;">The report verdict of the file or URL that was detonated in the sandbox. The verdict will remain "benign" until detonation is complete.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-get-analysis-status report_id=422662</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream": {
        "Analysis": {
            "Platform": "WINDOWS7",
            "ReportID": "422662",
            "Status": "processing",
            "Verdict": "Benign"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>The analysis status for id 422662</h3>
<table border="2">
<thead>
<tr>
<th>ReportID</th>
<th>Status</th>
<th>Platform</th>
<th>Verdict</th>
</tr>
</thead>
<tbody>
<tr>
<td>422662</td>
<td>processing</td>
<td>WINDOWS7</td>
<td>Benign</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_224b4581-0ceb-4b95-a7e3-d8a59c7e9967">13. Get the report of a submitted file or URL</h3>
<hr>
<p>Returns the report of a file or URL that was submitted to the sandbox. </p>
<h5>Base Command</h5>
<p><code>threatstream-analysis-report</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 275px;"><strong>Argument Name</strong></th>
<th style="width: 309px;"><strong>Description</strong></th>
<th style="width: 156px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 275px;">report_id</td>
<td style="width: 309px;">Report ID to return.</td>
<td style="width: 156px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 342px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 337px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.ReportID</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The ID of the report submitted to the sandbox.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Category</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The report category.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Started</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">Detonation start time.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Completed</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">Detonation completion time.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Duration</td>
<td style="width: 61px;">Number</td>
<td style="width: 337px;">Duration of the detonation (in seconds).</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.VmName</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The name of the VM.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.VmID</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The ID of the VM.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.UdpSource</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The source of UDP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.UdpDestination</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The destination of UDP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.UdpPort</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The port of the UDP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.IcmpSource</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The ICMP source.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.IcmpDestination</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The destination of ICMP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.IcmpPort</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The port of the ICMP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.TcpSource</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The source of TCP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.TcpDestination</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The destination of TCP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.TcpPort</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The port of TCP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.HttpSource</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The source of HTTP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.HttpDestinaton</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The destination of HTTP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.HttpPort</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The port of HTTP.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.HttpsSource</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The source of HTTPS.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.HttpsDestinaton</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The destination of HTTPS.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.HttpsPort</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The port of HTTPS.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Network.Hosts</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The hosts of network analysis.</td>
</tr>
<tr>
<td style="width: 342px;">ThreatStream.Analysis.Verdict</td>
<td style="width: 61px;">String</td>
<td style="width: 337px;">The verdict of the sandbox detonation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-analysis-report report_id=413336</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream": {
        "Analysis": {
            "Category": "File",
            "Completed": "2019-05-30 14:06:33",
            "Duration": 68,
            "Network": [
                {
                    "UdpDestination": "8.8.8.8",
                    "UdpPort": 53,
                    "UdpSource": "192.168.2.4"
                },
                {
                    "UdpDestination": "192.168.2.4",
                    "UdpPort": 65324,
                    "UdpSource": "8.8.8.8"
                },
                {
                    "UdpDestination": "192.168.2.4",
                    "UdpPort": 54896,
                    "UdpSource": "8.8.8.8"
                }
            ],
            "ReportID": "413336",
            "Started": "2019-05-30 14:05:25",
            "Verdict": "Benign",
            "VmID": "",
            "VmName": ""
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Report 413336 analysis results</h3>
<table border="2">
<thead>
<tr>
<th>Category</th>
<th>Started</th>
<th>Completed</th>
<th>Duration</th>
<th>VmName</th>
<th>VmID</th>
<th>ReportID</th>
<th>Verdict</th>
</tr>
</thead>
<tbody>
<tr>
<td>File</td>
<td>2019-05-30 14:05:25</td>
<td>2019-05-30 14:06:33</td>
<td>68</td>
<td> </td>
<td> </td>
<td>413336</td>
<td>Benign</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3d94a1ac-b756-4b52-86f2-f309d633d18c">14. Get a list of filtered indicators</h3>
<hr>
<p>Return filtered indicators from ThreatStream. If a query is defined, it overrides all of the arguments that were passed to the command.</p>
<h5>Base Command</h5>
<p><code>threatstream-get-indicators</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">query</td>
<td style="width: 518px;">Anomali Observable Search Filter Language query to filter indicators results. If a query is passed as an argument, it overrides all other arguments.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">asn</td>
<td style="width: 518px;">Autonomous System (AS) number associated with the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">confidence</td>
<td style="width: 518px;">Level of certainty that an observable<br> is of the reported indicator type. Confidence scores range from 0-100, in increasing order of confidence, and is assigned by ThreatStream based on several factors.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">country</td>
<td style="width: 518px;">Country associated with the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">created_ts</td>
<td style="width: 518px;">When the indicator was first seen on<br> the ThreatStream cloud platform. Date must be specified in this format:<br> YYYYMMDDThhmmss, where "T" denotes the start of the value for time, in UTC time.<br> For example, 2014-10-02T20:44:35.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">id</td>
<td style="width: 518px;">Unique ID for the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">is_public</td>
<td style="width: 518px;">Classification of the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">indicator_severity</td>
<td style="width: 518px;">Severity assigned to the indicator by ThreatStream.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">org</td>
<td style="width: 518px;">Registered owner (organization) of the IP address associated with the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">status</td>
<td style="width: 518px;">Status assigned to the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">tags_name</td>
<td style="width: 518px;">Tag assigned to the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">type</td>
<td style="width: 518px;">Type of indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">indicator_value</td>
<td style="width: 518px;">Value of the indicator.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">limit</td>
<td style="width: 518px;">Maximum number of results to return from ThreatStream. Default is 20.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 273px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.IType</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">The indicator type.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Modified</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">Date and time when the indicator was last updated on the ThreatStream. Format: YYYYMMDDThhmmss, where T denotes the start of the value</td>
</tr>
<tr>
<td style="width: 273px;">for time, in UTC time.</td>
<td style="width: 37px;"> </td>
<td style="width: 430px;"> </td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Confidence</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">Level of certainty that an observable is of the reported indicator type.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Value</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">The indicator value.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Status</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">The indicator status.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Organization</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">Registered owner (organization) of the IP address associated with the indicator.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Country</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">Country associated with the indicator.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Tags</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">Tag assigned to the indicator.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Source</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.ID</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">The ID of the indicator.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.ASN</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">Autonomous System (AS) number associated with the indicator.</td>
</tr>
<tr>
<td style="width: 273px;">ThreatStream.Indicators.Severity</td>
<td style="width: 37px;">String</td>
<td style="width: 430px;">The severity assigned to the indicator.</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Command Example</h5>
<pre>threatstream-get-indicators type=ip status=active asn=4837 country=CN confidence=84 indicator_severity=medium org="China Unicom Guangxi" limit=5</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream.Indicators": [
        {
            "Status": "active", 
            "Confidence": 84, 
            "IType": "scan_ip", 
            "Severity": "medium", 
            "Tags": null, 
            "Country": "CN", 
            "Modified": "2019-06-24T10:19:52.077Z", 
            "Value": "121.31.166.99", 
            "ID": 53042398831, 
            "Source": "Anomali Labs MHN", 
            "Organization": "China Unicom Guangxi", 
            "Type": "ip", 
            "ASN": "4837"
        }, 
        {
            "Status": "active", 
            "Confidence": 84, 
            "IType": "scan_ip", 
            "Severity": "medium", 
            "Tags": "port-1433,suricata,TCP", 
            "Country": "CN", 
            "Modified": "2019-06-24T09:51:04.804Z", 
            "Value": "121.31.166.99", 
            "ID": 53042253345, 
            "Source": "Anomali Labs MHN Tagged", 
            "Organization": "China Unicom Guangxi", 
            "Type": "ip", 
            "ASN": "4837"
        }, 
        {
            "Status": "active", 
            "Confidence": 84, 
            "IType": "scan_ip", 
            "Severity": "medium", 
            "Tags": null, 
            "Country": "CN", 
            "Modified": "2019-06-24T06:08:12.585Z", 
            "Value": "182.88.27.168", 
            "ID": 53016547378, 
            "Source": "DShield Scanning IPs", 
            "Organization": "China Unicom Guangxi", 
            "Type": "ip", 
            "ASN": "4837"
        }, 
        {
            "Status": "active", 
            "Confidence": 84, 
            "IType": "scan_ip", 
            "Severity": "medium", 
            "Tags": "AlienVault,OTX", 
            "Country": "CN", 
            "Modified": "2019-06-23T19:38:05.782Z", 
            "Value": "182.91.129.165", 
            "ID": 53038621037, 
            "Source": "Alien Vault OTX Malicious IPs", 
            "Organization": "China Unicom Guangxi", 
            "Type": "ip", 
            "ASN": "4837"
        }, 
        {
            "Status": "active", 
            "Confidence": 84, 
            "IType": "scan_ip", 
            "Severity": "medium", 
            "Tags": null, 
            "Country": "CN", 
            "Modified": "2019-06-23T17:52:51.165Z", 
            "Value": "182.91.129.207", 
            "ID": 52970998522, 
            "Source": "DShield Scanning IPs", 
            "Organization": "China Unicom Guangxi", 
            "Type": "ip", 
            "ASN": "4837"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>The indicators results</h3>
<table border="2">
<thead>
<tr>
<th>IType</th>
<th>Value</th>
<th>Confidence</th>
<th>ID</th>
<th>Source</th>
<th>Type</th>
<th>Status</th>
<th>Tags</th>
<th>Modified</th>
<th>Organization</th>
<th>ASN</th>
<th>Country</th>
<th>Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td>scan_ip</td>
<td>121.31.166.99</td>
<td>84</td>
<td>53042398831</td>
<td>Anomali Labs MHN</td>
<td>ip</td>
<td>active</td>
<td> </td>
<td>2019-06-24T10:19:52.077Z</td>
<td>China Unicom Guangxi</td>
<td>4837</td>
<td>CN</td>
<td>medium</td>
</tr>
<tr>
<td>scan_ip</td>
<td>121.31.166.99</td>
<td>84</td>
<td>53042253345</td>
<td>Anomali Labs MHN Tagged</td>
<td>ip</td>
<td>active</td>
<td>port-1433,suricata,TCP</td>
<td>2019-06-24T09:51:04.804Z</td>
<td>China Unicom Guangxi</td>
<td>4837</td>
<td>CN</td>
<td>medium</td>
</tr>
<tr>
<td>scan_ip</td>
<td>182.88.27.168</td>
<td>84</td>
<td>53016547378</td>
<td>DShield Scanning IPs</td>
<td>ip</td>
<td>active</td>
<td> </td>
<td>2019-06-24T06:08:12.585Z</td>
<td>China Unicom Guangxi</td>
<td>4837</td>
<td>CN</td>
<td>medium</td>
</tr>
<tr>
<td>scan_ip</td>
<td>182.91.129.165</td>
<td>84</td>
<td>53038621037</td>
<td>Alien Vault OTX Malicious IPs</td>
<td>ip</td>
<td>active</td>
<td>AlienVault,OTX</td>
<td>2019-06-23T19:38:05.782Z</td>
<td>China Unicom Guangxi</td>
<td>4837</td>
<td>CN</td>
<td>medium</td>
</tr>
<tr>
<td>scan_ip</td>
<td>182.91.129.207</td>
<td>84</td>
<td>52970998522</td>
<td>DShield Scanning IPs</td>
<td>ip</td>
<td>active</td>
<td> </td>
<td>2019-06-23T17:52:51.165Z</td>
<td>China Unicom Guangxi</td>
<td>4837</td>
<td>CN</td>
<td>medium</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_789d66ed-a1e0-42c2-934a-18f3c34f7022">15. Add tags to a threat model</h3>
<hr>
<p>Add tags to intelligence for purposes of filtering for related entities.</p>
<h5>Base Command</h5>
<p><code>threatstream-add-tag-to-model</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 163px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163px;">model</td>
<td style="width: 506px;">The type of threat model entity on which to add the tag. Default is "intelligence" (indicator).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 163px;">tags</td>
<td style="width: 506px;">A CSV list of tags applied to the specified threat model entities or observable.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 163px;">model_id</td>
<td style="width: 506px;">The ID of the model on which to add the tag.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Output </h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>threatstream-add-tag-to-model model=intelligence model_id=51375607503 tags="suspicious,not valid"</pre>
<h5>Human Readable Output</h5>
<p>Added successfully tags: ['suspicious', 'not valid'] to intelligence with 51375607503</p>
<h3 id="h_073ab7a3-58c7-48a5-9e01-55c78a9f6788">16. Create a threat model</h3>
<hr>
<p>Creates a threat model with the specified parameters.</p>
<h5>Base Command</h5>
<p><code>threatstream-create-model</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">model</td>
<td style="width: 526px;">The type of threat model to create.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">name</td>
<td style="width: 526px;">The name of the threat model to create.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">is_public</td>
<td style="width: 526px;">The scope of threat model visibility.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">tlp</td>
<td style="width: 526px;">Traffic Light Protocol designation for the threat model.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">tags</td>
<td style="width: 526px;">A CSV list of tags.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">intelligence</td>
<td style="width: 526px;">A CSV list of indicators IDs associated with the threat model on the ThreatStream platform.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">description</td>
<td style="width: 526px;">The description of the threat model.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 320px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 320px;">ThreatStream.Model.ModelType</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The type of the threat model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.ModelID</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The ID of the threat model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Value</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The value of indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.ID</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The ID of indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.IType</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The iType of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Severity</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The severity of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Confidence</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The confidence of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Country</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The country of the indicator associated with the specified model</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Organization</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The organization of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.ASN</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The ASN of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Status</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The status of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Tags</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The tags of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Modified</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The date and time the indicator was last modified.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Source</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The source of the indicator.</td>
</tr>
<tr>
<td style="width: 320px;">ThreatStream.Model.Indicators.Type</td>
<td style="width: 37px;">String</td>
<td style="width: 383px;">The indicator type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-create-model model=actor name="New_Created_Actor" description="Description of the actor threat model" intelligence=53042425466,53042425532,53042425520 tags="new actor,test" tlp=red</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream.Model": {
        "Indicators": [
            {
                "Status": "active", 
                "Confidence": 86, 
                "IType": "suspicious_domain", 
                "Severity": "high", 
                "Tags": "Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech", 
                "Country": "US", 
                "Modified": "2019-06-24T10:51:16.384", 
                "Value": "chatbotshq.com", 
                "ID": "53042425532", 
                "Source": "Analyst", 
                "Organization": "Hostinger International Limited", 
                "Type": "domain", 
                "ASN": "12769"
            }, 
            {
                "Status": "active", 
                "Confidence": 85, 
                "IType": "suspicious_domain", 
                "Severity": "high", 
                "Tags": "Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech", 
                "Country": "US", 
                "Modified": "2019-06-24T10:51:16.589", 
                "Value": "marketshq.com", 
                "ID": "53042425520", 
                "Source": "Analyst", 
                "Organization": "GoDaddy.com, LLC", 
                "Type": "domain", 
                "ASN": "26496"
            }, 
            {
                "Status": "active", 
                "Confidence": 77, 
                "IType": "suspicious_domain", 
                "Severity": "high", 
                "Tags": "Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech", 
                "Country": "US", 
                "Modified": "2019-06-24T10:54:31.318", 
                "Value": "leanomalie.com", 
                "ID": "53042425466", 
                "Source": "Analyst", 
                "Organization": "GoDaddy.com, LLC", 
                "Type": "domain", 
                "ASN": "26496"
            }
        ], 
        "ModelType": "Actor", 
        "ModelID": 26697
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Indicators list for Threat Model Actor with id 26697</h3>
<table border="2">
<thead>
<tr>
<th>IType</th>
<th>Value</th>
<th>ID</th>
<th>Confidence</th>
<th>Source</th>
<th>Type</th>
<th>Status</th>
<th>Tags</th>
<th>Modified</th>
<th>Organization</th>
<th>ASN</th>
<th>Country</th>
<th>Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td>suspicious_domain</td>
<td>chatbotshq.com</td>
<td>53042425532</td>
<td>86</td>
<td>Analyst</td>
<td>domain</td>
<td>active</td>
<td>Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech</td>
<td>2019-06-24T10:51:16.384</td>
<td>Hostinger International Limited</td>
<td>12769</td>
<td>US</td>
<td>high</td>
</tr>
<tr>
<td>suspicious_domain</td>
<td>marketshq.com</td>
<td>53042425520</td>
<td>85</td>
<td>Analyst</td>
<td>domain</td>
<td>active</td>
<td>Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech</td>
<td>2019-06-24T10:51:16.589</td>
<td>GoDaddy.com, LLC</td>
<td>26496</td>
<td>US</td>
<td>high</td>
</tr>
<tr>
<td>suspicious_domain</td>
<td>leanomalie.com</td>
<td>53042425466</td>
<td>77</td>
<td>Analyst</td>
<td>domain</td>
<td>active</td>
<td>Suspicious-Domain-Registration,TSLABS,victim-Hi-Tech</td>
<td>2019-06-24T10:54:31.318</td>
<td>GoDaddy.com, LLC</td>
<td>26496</td>
<td>US</td>
<td>high</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_6e714d0f-5ef9-4788-a5bb-e0e9498cb0f5">17. Update a threat model</h3>
<hr>
<p>Updates a threat model with specific parameters. If one or more optional parameters are defined, the command overrides previous data stored in ThreatStream.</p>
<h5>Base Command</h5>
<p><code>threatstream-update-model</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">model</td>
<td style="width: 538px;">The type of threat model to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">model_id</td>
<td style="width: 538px;">The ID of the threat model to update.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">name</td>
<td style="width: 538px;">The name of the threat model to update.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">is_public</td>
<td style="width: 538px;">The scope of threat model visibility.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">tlp</td>
<td style="width: 538px;">Traffic Light Protocol designation for the threat model.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">tags</td>
<td style="width: 538px;">A CSV list of tags.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">intelligence</td>
<td style="width: 538px;">A CSV list of indicators IDs associated with the threat model on the ThreatStream platform.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">description</td>
<td style="width: 538px;">The description of the threat model.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output </h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 307px;"><strong>Path</strong></th>
<th style="width: 50px;"><strong>Type</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">ThreatStream.Model.ModelType</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The type of threat model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.ModelID</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The ID of the threat model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Value</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The value of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.ID</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The ID of indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.IType</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The iType of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Severity</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The severity of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Confidence</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The confidence of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Country</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The country of the indicator associated with the specified model</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Organization</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The organization of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.ASN</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The ASN of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Status</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The status of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Tags</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The tags of the indicator associated with the specified model.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Modified</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The date and time the indicator was last modified.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Source</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The source of the inidicator.</td>
</tr>
<tr>
<td style="width: 307px;">ThreatStream.Model.Indicators.Type</td>
<td style="width: 50px;">String</td>
<td style="width: 383px;">The type of the inidicator.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-update-model model=actor model_id=26697 intelligence=53042694591 tags="updated tag,gone"</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream": {
        "Model": {
            "Indicators": [
                {
                    "ASN": "",
                    "Confidence": 36,
                    "Country": "CA",
                    "ID": "53042694591",
                    "IType": "exploit_ip",
                    "Modified": "2019-06-24T11:28:31.185",
                    "Organization": "OVH Hosting",
                    "Severity": "high",
                    "Source": "Analyst",
                    "Status": "active",
                    "Tags": "HoneyDB",
                    "Type": "ip",
                    "Value": "54.39.20.14"
                }
            ],
            "ModelID": "26697",
            "ModelType": "Actor"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Indicators list for Threat Model Actor with id 26697</h3>
<table border="2">
<thead>
<tr>
<th>IType</th>
<th>Value</th>
<th>ID</th>
<th>Confidence</th>
<th>Source</th>
<th>Type</th>
<th>Status</th>
<th>Tags</th>
<th>Modified</th>
<th>Organization</th>
<th>ASN</th>
<th>Country</th>
<th>Severity</th>
</tr>
</thead>
<tbody>
<tr>
<td>exploit_ip</td>
<td>54.39.20.14</td>
<td>53042694591</td>
<td>36</td>
<td>Analyst</td>
<td>ip</td>
<td>active</td>
<td>HoneyDB</td>
<td>2019-06-24T11:28:31.185</td>
<td>OVH Hosting</td>
<td> </td>
<td>CA</td>
<td>high</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_36bf4b62-235a-4fb1-8dd2-1e5a67f1e5fd">18. Get a list of supported platforms</h3>
<hr>
<p>Returns list of supported platforms for default or premium sandbox </p>
<h5>Base Command</h5>
<p><code>threatstream-supported-platforms</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 177px;"><strong>Argument Name</strong></th>
<th style="width: 462px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">sandbox_type</td>
<td style="width: 462px;">The type of sandbox ("default" or "premium").</td>
<td style="width: 101px;">Optional</td>
</tr>
</tbody>
</table>
<p>  </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 280px;"><strong>Path</strong></th>
<th style="width: 41px;"><strong>Type</strong></th>
<th style="width: 419px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280px;">ThreatStream.PremiumPlatforms.Name</td>
<td style="width: 41px;">String</td>
<td style="width: 419px;">Name of the supported platform for premium sandbox.</td>
</tr>
<tr>
<td style="width: 280px;">ThreatStream.PremiumPlatforms.Types</td>
<td style="width: 41px;">String</td>
<td style="width: 419px;">Type of supported submissions for premium sandbox.</td>
</tr>
<tr>
<td style="width: 280px;">ThreatStream.PremiumPlatforms.Label</td>
<td style="width: 41px;">String</td>
<td style="width: 419px;">The display name of the supported platform of premium sandbox.</td>
</tr>
<tr>
<td style="width: 280px;">ThreatStream.DefaultPlatforms.Name</td>
<td style="width: 41px;">String</td>
<td style="width: 419px;">Name of the supported platform for standard sandbox.</td>
</tr>
<tr>
<td style="width: 280px;">ThreatStream.DefaultPlatforms.Types</td>
<td style="width: 41px;">String</td>
<td style="width: 419px;">Type of supported submissions for standard sandbox.</td>
</tr>
<tr>
<td style="width: 280px;">ThreatStream.DefaultPlatforms.Label</td>
<td style="width: 41px;">String</td>
<td style="width: 419px;">The display name of the supported platform of standard sandbox.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>threatstream-supported-platforms sandbox_type=default</pre>
<h5>Context Example</h5>
<pre>{
    "ThreatStream.DefaultPlatforms": [
        {
            "Name": "WINDOWSXP", 
            "Types": [
                "file", 
                "url"
            ], 
            "Label": "Windows XP"
        }, 
        {
            "Name": "WINDOWS7", 
            "Types": [
                "file", 
                "url"
            ], 
            "Label": "Windows 7"
        }, 
        {
            "Name": "ALL", 
            "Types": [
                "file", 
                "url"
            ], 
            "Label": "All"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Supported platforms for default sandbox</h3>
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>Types</th>
<th>Label</th>
</tr>
</thead>
<tbody>
<tr>
<td>WINDOWSXP</td>
<td>file,<br> url</td>
<td>Windows XP</td>
</tr>
<tr>
<td>WINDOWS7</td>
<td>file,<br> url</td>
<td>Windows 7</td>
</tr>
<tr>
<td>ALL</td>
<td>file,<br> url</td>
<td>All</td>
</tr>
</tbody>
</table>