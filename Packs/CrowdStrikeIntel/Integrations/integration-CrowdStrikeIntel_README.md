<!-- HTML_DOC -->
<p>Deprecated. Use the CrowdStrike Falcon Intelligence v2 integration instead.</p>
<p>This integration was integrated and tested with CrowdStrike Falcon Intel v2.</p>
<h2>Use Cases</h2>
<ul>
<li>Search files, URLs, domains, and IP addresses, for malware.</li>
<li>Create indicator based reports.</li>
</ul>
<h2>Configure CrowdStrike Falcon Intelligence v2 on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Falcon Intel v2.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: URL of Falcon Intel server.</li>
<li><strong>API ID</strong></li>
<li><strong>API Key</strong></li>
<li>
<strong>Threshold</strong>: Minimum malicious confidence from Falcon Intel to consider the indicator malicious (low, medium, or high). Default is high.</li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Allow self-signed SSL certificates</strong></li>
<li><strong>Indicator API V2</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_27836259351531206474006">Check file for malware: file</a></li>
<li><a href="#h_929507814711531206482007">Check URL for malware: url</a></li>
<li><a href="#h_5808759781361531206490489">Check domain for malware: domain</a></li>
<li><a href="#h_8762868482001531206502745">Check IP address for malware: ip</a></li>
<li><a href="#h_3748526322631531206511556">Search for actors: cs-actors</a></li>
<li><a href="#h_486742413251531206521157">Indicator based report: cs-indicators</a></li>
<li><a href="#h_3309100193861531206534035">Search summary and ID of Intelligence Reports: cs-reports</a></li>
<li><a href="#h_3467486824461531206549615">Get report in PDF format:cs-report-pdf</a></li>
</ol>
<hr>
<h3 id="h_27836259351531206474006">1. Check file for malware</h3>
<p>Returns malware report for specified file.</p>
<h5>Base Command</h5>
<p><code>file</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>file </td>
<td>MD5, SHA-1, or SHA-256 hash of the file to check</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>File.MD5</td>
<td>Malicious MD5 hash file</td>
</tr>
<tr>
<td>File.SHA1</td>
<td>Malicious SHA-1 hash file</td>
</tr>
<tr>
<td>File.SHA256</td>
<td>Malicious SHA-256 hash file</td>
</tr>
<tr>
<td>File.Malicious.Vendor</td>
<td>For malicious files, the vendor that made the decision</td>
</tr>
<tr>
<td>File.Malicious.Description</td>
<td>For malicious files, the reason that the vendor made the decision</td>
</tr>
<tr>
<td>DBotScore.Indicator</td>
<td>The indicator tested</td>
</tr>
<tr>
<td>DBotScore.Type</td>
<td>Type of indicator tested</td>
</tr>
<tr>
<td>DBotScore.Vendor</td>
<td>Vendor used to calculate the score</td>
</tr>
<tr>
<td>DBotScore.Score</td>
<td>The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!file file=369c8fc6532ba547d7ef5985bb5e880a using-brand="FalconIntel V2"</code></p>
<h5>Raw Output</h5>
<pre>DBotScore
{  
   "Indicator":"369c8fc6532ba547d7ef5985bb5e880a",
   "Score":3,
   "Type":"hash",
   "Vendor":"CrowdStrike"
}<br>
File
{  
   "MD5":"369c8fc6532ba547d7ef5985bb5e880a",
   "Malicious":{  
      "Description":"High confidence",
      "Vendor":"CrowdStrike"
   }
}</pre>
<h5>Context Example</h5>
<pre>DBotScore:[] 2 items
1:{} 4 items
Indicator:369c8fc6532ba547d7ef5985bb5e880a
Score:3
Type:hash
Vendor:CrowdStrike
File:{} 2 items
MD5:369c8fc6532ba547d7ef5985bb5e880a
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
</pre>
<hr>
<h3 id="h_929507814711531206482007">2. Check URL for malware</h3>
<p>Returns a malware report for the specified URL.</p>
<h5>Base Command</h5>
<p><code>url</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>url</td>
<td>URL to check</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>URL.Data</td>
<td>Malicious URL</td>
</tr>
<tr>
<td>URL.Malicious.Vendor</td>
<td>For malicious URLs, the vendor that made the decision</td>
</tr>
<tr>
<td>URL.Malicious.Description</td>
<td>For malicious URLs, the reason that the vendor made that decision</td>
</tr>
<tr>
<td>DBotScore.Indicator</td>
<td>The indicator tested</td>
</tr>
<tr>
<td>DBotScore.Type</td>
<td>Type of indicator tested</td>
</tr>
<tr>
<td>DBotScore.Vendor</td>
<td>Vendor used to calculate the score</td>
</tr>
<tr>
<td>DBotScore.Score</td>
<td>The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!url url="http://8.8.8.8/google.doc" using="FalconIntel V2_instance_1"</code></p>
<h5>Raw Output</h5>
<pre> 
DBotScore
{  
   "Indicator":"http://8.8.8.8/google.doc",
   "Score":3,
   "Type":"url",
   "Vendor":"CrowdStrike"
}
<br>URL
{
   "Data": "http://8.8.8.8/google.doc",
   "Malicious": {
   "Description": "High confidence",
   "Vendor": "CrowdStrike"
    }
}
</pre>
<h5>Context Example</h5>
<pre>DBotScore:[] 3 items 2:{} 4 items
Indicator:http://8.8.8.8/google.doc
Score:3
Type:url
Vendor:CrowdStrike
URL:{} 2 items
Data:http://8.8.8.8/google.doc
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
 </pre>
<hr>
<h3 id="h_5808759781361531206490489">3. Check Domain for malware</h3>
<p>Returns malware report for specified domain.</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>domain </td>
<td>Domain to check</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>Domain.Name</td>
<td>Malicious domain</td>
</tr>
<tr>
<td>Domain.Malicious.Vendor</td>
<td>For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td>Domain.Malicious.Description</td>
<td>For malicious domains, the reason that the vendor to made that decision</td>
</tr>
<tr>
<td>DBotScore.Indicator</td>
<td>The indicator tested</td>
</tr>
<tr>
<td>DBotScore.Type</td>
<td>Type of indicator tested</td>
</tr>
<tr>
<td>DBotScore.Vendor</td>
<td>Vendor used to calculate the score</td>
</tr>
<tr>
<td>DBotScore.Score</td>
<td>The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!domain domain="dns02.hpupdat.net" using="FalconIntel V2_instance_1"</code></p>
<h5>Raw Output</h5>
<pre>DBotScore
{
"Indicator": "dns02.hpupdat.net",
"Score": 3,
"Type": "domain",
"Vendor": "CrowdStrike"
}
Domain
{
"Malicious": {
"Description": "High confidence",
"Vendor": "CrowdStrike"
},
"Name": "dns02.hpupdat.net"
}
 </pre>
<h5>Context Example</h5>
<pre> 
DBotScore:[] 4 items 3:{} 4 items
Indicator:dns02.hpupdat.net
Score:3
Type:domain
Vendor:CrowdStrike
Domain:{} 2 items
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
Name:dns02.hpupdat.net
</pre>
<hr>
<h3 id="h_8762868482001531206502745">4. Check IP address for malware</h3>
<p>Returns malware report for specified file.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>ip </td>
<td>IP address to check</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>IP.Address</td>
<td>Malicious IP address</td>
</tr>
<tr>
<td>IP.Malicious.Vendor</td>
<td>For malicious IP addresses, the vendor that made the decision</td>
</tr>
<tr>
<td>IP.Malicious.Description</td>
<td>For malicious IP addresses, the reason that the vendor made that decision</td>
</tr>
<tr>
<td>DBotScore.Indicator</td>
<td>The indicator tested</td>
</tr>
<tr>
<td>DBotScore.Type</td>
<td>Type of indicator tested</td>
</tr>
<tr>
<td>DBotScore.Vendor</td>
<td>Vendor used to calculate the score</td>
</tr>
<tr>
<td>DBotScore.Score</td>
<td>The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>ip ip="4.4.4.4" using="FalconIntel V2_instance_1"</code></p>
<h5>Raw Output</h5>
<pre>DBotScore
{
   "Indicator": "4.4.4.4",
   "Score": 1,
   "Type": "ip",
   "Vendor": "CrowdStrike"
} </pre>
<h5>Context Example</h5>
<pre>DBotScore:{} 4 items
Indicator:4.4.4.4
Score:1
Type:ip
Vendor:CrowdStrike </pre>
<hr>
<h3 id="h_3748526322631531206511556">5. Search for actors</h3>
<p>Searches for actors.</p>
<h5>Base Command</h5>
<p><code>cs-actors</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>q</td>
<td>Search all fields for the specified data.</td>
</tr>
<tr>
<td>name</td>
<td>Search based on actor name.</td>
</tr>
<tr>
<td>desc</td>
<td>Search based on description.</td>
</tr>
<tr>
<td>minLastModifiedDate</td>
<td>
<p>Search range starts at modified date.</p>
<p>Dates are formatted as YYYY-MM-DD.</p>
</td>
</tr>
<tr>
<td>maxLastModifiedDate</td>
<td>
<p>Search range ends at modified date.</p>
<p>Dates are formatted as YYYY-MM-DD.</p>
</td>
</tr>
<tr>
<td>minLastActivityDate</td>
<td>
<p>Search range starts at activity date.</p>
<p>Dates are formatted as YYYY-MM-DD.</p>
</td>
</tr>
<tr>
<td>maxLastActivityDate</td>
<td>
<p>Search range ends at activity date.</p>
<p>Dates are formatted as YYYY-MM-DD.</p>
</td>
</tr>
<tr>
<td>origins</td>
<td>Search by comma-separated list of origins.</td>
</tr>
<tr>
<td>targetCountries</td>
<td>Search by comma-separated list of target countries.</td>
</tr>
<tr>
<td>targetIndustries</td>
<td>Search by comma-separated list of target industries.</td>
</tr>
<tr>
<td>motivations</td>
<td>Search by comma-separated list of motivations.</td>
</tr>
<tr>
<td>offset</td>
<td>Which page of the results to retrieve. It is 0 based.</td>
</tr>
<tr>
<td>limit</td>
<td>Number of results displayed in the page.</td>
</tr>
<tr>
<td>sort</td>
<td>
<p>Sort is field_name.order, field_name.order.</p>
<p><strong>order</strong> is either <strong>asc</strong> or <strong>desc</strong>.</p>
</td>
</tr>
<tr>
<td>slug</td>
<td>
<p>Search by 'slug' or short descriptive name.</p>
<p>Example: "anchor-panda"</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!cs-actors q="google" limit="2"</code></p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h5>Context Example</h5>
<p>There is no context example for this command.</p>
<hr>
<h3 id="h_486742413251531206521157">6. Indicator based report</h3>
<p>Generates a report according to specified indicators.</p>
<h5>Base Command</h5>
<p><code>cs-indicators</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>parameter</td>
<td>
<p>What parameter to search.</p>
<p>See CrowdStrike documentation for details. &lt;hyperlink&gt;</p>
<p>Valid values are:</p>
<ul>
<li>indicator</li>
<li>type</li>
<li>report</li>
<li>actor</li>
<li>malicious_confidence</li>
<li>published_date</li>
<li>last_updated</li>
<li>malware_family</li>
<li>kill_chain</li>
<li>labels</li>
<li>DomainType</li>
<li>EmailAddressType</li>
<li>IntelNews</li>
<li>IPAddressType</li>
<li>Malware</li>
<li>Status</li>
<li>Target</li>
<li>ThreatType</li>
<li>Vulnerability</li>
</ul>
</td>
</tr>
<tr>
<td>filter</td>
<td>
<p>Valid values are:</p>
<ul>
<li>match</li>
<li>equal</li>
<li>gt(e)</li>
<li>lt(e)</li>
</ul>
</td>
</tr>
<tr>
<td>value</td>
<td>The value for the given parameter</td>
</tr>
<tr>
<td>sort</td>
<td>
<p>Sort by a field in the format of field_name.order.</p>
<p><strong>order</strong> is either <strong>asc</strong> or <strong>desc</strong>.</p>
<p>Valid values for fields are:</p>
<ul>
<li>indicator</li>
<li>type</li>
<li>report</li>
<li>actor</li>
<li>malicious_confidence</li>
<li>published_date</li>
<li>last_updated</li>
</ul>
</td>
</tr>
<tr>
<td>page</td>
<td>The page to retrieve - 1 based</td>
</tr>
<tr>
<td>pageSize</td>
<td>The size of the page to retrieve</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>File.MD5</td>
<td>Malicious MD5 hash file</td>
</tr>
<tr>
<td>File.SHA1</td>
<td>Malicious SHA-1 hash file</td>
</tr>
<tr>
<td>File.SHA256</td>
<td>Malicious SHA-256 hash file</td>
</tr>
<tr>
<td>Malicious.Vendor</td>
<td>For malicious files, the vendor that made the decision</td>
</tr>
<tr>
<td>File.Malicious.Description</td>
<td>For malicious files, the reason that the vendor made that decision</td>
</tr>
<tr>
<td>File.Reports</td>
<td>For malicious files, the associated reports describing the hash</td>
</tr>
<tr>
<td>File.Actors</td>
<td>For malicious files, the associated actors</td>
</tr>
<tr>
<td>File.MalwareFamilies</td>
<td>For malicious files, the associated malware family</td>
</tr>
<tr>
<td>File.KillChains</td>
<td>For malicious files, the associated kill chain</td>
</tr>
<tr>
<td>URL.Data</td>
<td>Malicious URL</td>
</tr>
<tr>
<td>URL.Malicious.Vendor</td>
<td>For malicious URLs, the vendor that made the decision</td>
</tr>
<tr>
<td>URL.Malicious.Description</td>
<td>For malicious URLs, the reason that the vendor made that decision</td>
</tr>
<tr>
<td>URL.Reports</td>
<td>For malicious URLs, the associated reports describing the URL</td>
</tr>
<tr>
<td>URL.Actors</td>
<td>For malicious URLs, the associated actors</td>
</tr>
<tr>
<td>URL.MalwareFamilies</td>
<td>For malicious URLs, the associated malware family</td>
</tr>
<tr>
<td>URL.KillChains</td>
<td>For malicious URLs, the associated kill chain</td>
</tr>
<tr>
<td>Domain.Name</td>
<td>Malicious domain</td>
</tr>
<tr>
<td>Domain.Malicious.Vendor</td>
<td>For malicious domains, the vendor that made the decision</td>
</tr>
<tr>
<td>Domain.Malicious.Description</td>
<td>For malicious domains, the reason that the vendor made that decision</td>
</tr>
<tr>
<td>Domain.Reports</td>
<td>For malicious domains, the associated reports describing the domain</td>
</tr>
<tr>
<td>Domain.Actors</td>
<td>For malicious domains, the associated actors</td>
</tr>
<tr>
<td>Domain.MalwareFamilies</td>
<td>For malicious domains, the associated malware family</td>
</tr>
<tr>
<td>Domain.KillChains</td>
<td>For malicious domains, the associated kill chain</td>
</tr>
<tr>
<td>IP.Address</td>
<td>IP Indicators</td>
</tr>
<tr>
<td>IP.Malicious.Vendor</td>
<td>For malicious IP addresses, the vendor that made the decision</td>
</tr>
<tr>
<td>IP.Malicious.Description</td>
<td>For malicious IP addresses, the reason that the vendor made that decision</td>
</tr>
<tr>
<td>IP.Reports</td>
<td>For malicious IP addresses, the associated reports describing the IP</td>
</tr>
<tr>
<td>IP.Actors</td>
<td>For malicious IP addresses, the associated actors</td>
</tr>
<tr>
<td>IP.MalwareFamilies</td>
<td>For malicious IP addresses, the associated malware family</td>
</tr>
<tr>
<td>IP.KillChains</td>
<td>For malicious IP addresses, the associated kill chain</td>
</tr>
<tr>
<td>DBotScore.Indicator</td>
<td>The indicator tested</td>
</tr>
<tr>
<td>DBotScore.Type</td>
<td>Type of indicator tested</td>
</tr>
<tr>
<td>DBotScore.Vendor</td>
<td>Vendor used to calculate the score</td>
</tr>
<tr>
<td>DBotScore.Score</td>
<td>The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cs-indicators filter=match parameter=indicator value="panda"</code></p>
<h5>Raw Output</h5>
<pre> DBotScore
[  
   {  
      "Indicator":"nadazpanda.publicvm.com",
      "Score":3,
      "Type":"domain",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"pandadefender.com",
      "Score":3,
      "Type":"domain",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"http://panda.tech/tw.com/panda.rtf",
      "Score":3,
      "Type":"url",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"panda1.hopto.org",
      "Score":3,
      "Type":"domain",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"http://suliparwarda.com/includes/panda.php?c=",
      "Score":3,
      "Type":"url",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"http://azmwn.suliparwarda.com/wp-content/plugins/wpdatatables/panda.php?c=",
      "Score":3,
      "Type":"url",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"balvinnew.pandabearsunited.xyz",
      "Score":3,
      "Type":"domain",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"panda3.ddns.net",
      "Score":3,
      "Type":"domain",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"panda.tech-tw.com",
      "Score":2,
      "Type":"domain",
      "Vendor":"CrowdStrike"
   },
   {  
      "Indicator":"http://panda.tech-tw.com/panda.rtf",
      "Score":3,
      "Type":"url",
      "Vendor":"CrowdStrike"
   }
]

Domain
[  
   {  
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "njRAT"
      ],
      "Name":"nadazpanda.publicvm.com"
   },
   {  
      "Actors":[  
         "FANCYBEAR"
      ],
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "X-Agent"
      ],
      "Name":"pandadefender.com",
      "Reports":[  
         "CSIR-17010"
      ]
   },
   {  
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "CybergateRAT"
      ],
      "Name":"panda1.hopto.org"
   },
   {  
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "XtremeRAT"
      ],
      "Name":"balvinnew.pandabearsunited.xyz"
   },
   {  
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "njRAT"
      ],
      "Name":"panda3.ddns.net"
   },
   {  
      "KillChains":[  
         "Delivery"
      ],
      "Name":"panda.tech-tw.com"
   }
]

URL
[  
   {  
      "Data":"http://panda.tech/tw.com/panda.rtf",
      "KillChains":[  
         "Delivery"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      }
   },
   {  
      "Actors":[  
         "STATICKITTEN"
      ],
      "Data":"http://suliparwarda.com/includes/panda.php?c=",
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "NTSTATS"
      ],
      "Reports":[  
         "CSIR-18002"
      ]
   },
   {  
      "Actors":[  
         "STATICKITTEN"
      ],
      "Data":"http://azmwn.suliparwarda.com/wp-content/plugins/wpdatatables/panda.php?c=",
      "KillChains":[  
         "C2"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      },
      "MalwareFamilies":[  
         "NTSTATS"
      ],
      "Reports":[  
         "CSIR-18002"
      ]
   },
   {  
      "Data":"http://panda.tech-tw.com/panda.rtf",
      "KillChains":[  
         "Delivery"
      ],
      "Malicious":{  
         "Description":"High confidence",
         "Vendor":"CrowdStrike"
      }
   }
]
</pre>
<h5>Context Example</h5>
<pre>DBotScore:[] 10 items
0:{} 4 items
Indicator:nadazpanda.publicvm.com
Score:3
Type:domain
Vendor:CrowdStrike
1:{} 4 items
Indicator:pandadefender.com
Score:3
Type:domain
Vendor:CrowdStrike
2:{} 4 items
Indicator:http://panda.tech/tw.com/panda.rtf
Score:3
Type:url
Vendor:CrowdStrike
3:{} 4 items
Indicator:panda1.hopto.org
Score:3
Type:domain
Vendor:CrowdStrike
4:{} 4 items
Indicator:http://suliparwarda.com/includes/panda.php?c=
Score:3
Type:url
Vendor:CrowdStrike
5:{} 4 items
Indicator:http://azmwn.suliparwarda.com/wp-content/plugins/wpdatatables/panda.php?c=
Score:3
Type:url
Vendor:CrowdStrike
6:{} 4 items
Indicator:balvinnew.pandabearsunited.xyz
Score:3
Type:domain
Vendor:CrowdStrike
7:{} 4 items
Indicator:panda3.ddns.net
Score:3
Type:domain
Vendor:CrowdStrike
8:{} 4 items
Indicator:panda.tech-tw.com
Score:2
Type:domain
Vendor:CrowdStrike
9:{} 4 items
Indicator:http://panda.tech-tw.com/panda.rtf
Score:3
Type:url
Vendor:CrowdStrike
Domain:[] 6 items
0:{} 4 items
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:njRAT
Name:nadazpanda.publicvm.com
1:{} 6 items
Actors:[] 1 item
0:FANCYBEAR
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:X-Agent
Name:pandadefender.com
Reports:[] 1 item
0:CSIR-17010
2:{} 4 items
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:CybergateRAT
Name:panda1.hopto.org
3:{} 4 items
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:XtremeRAT
Name:balvinnew.pandabearsunited.xyz
4:{} 4 items
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:njRAT
Name:panda3.ddns.net
5:{} 2 items
KillChains:[] 1 item
0:Delivery
Name:panda.tech-tw.com
URL:[] 4 items
0:{} 3 items
Data:http://panda.tech/tw.com/panda.rtf
KillChains:[] 1 item
0:Delivery
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
1:{} 6 items
Actors:[] 1 item
0:STATICKITTEN
Data:http://suliparwarda.com/includes/panda.php?c=
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:NTSTATS
Reports:[] 1 item
0:CSIR-18002
2:{} 6 items
Actors:[] 1 item
0:STATICKITTEN
Data:http://azmwn.suliparwarda.com/wp-content/plugins/wpdatatables/panda.php?c=
KillChains:[] 1 item
0:C2
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike
MalwareFamilies:[] 1 item
0:NTSTATS
Reports:[] 1 item
0:CSIR-18002
3:{} 3 items
Data:http://panda.tech-tw.com/panda.rtf
KillChains:[] 1 item
0:Delivery
Malicious:{} 2 items
Description:High confidence
Vendor:CrowdStrike </pre>
<hr>
<h3 id="h_3309100193861531206534035">7. Search summary and ID of Intelligence Reports</h3>
<p>Searches for summary and ID of Intelligence Reports.</p>
<h5>Base Command</h5>
<p><code>cs-reports</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>q</td>
<td>Performs a generic substring search across all fields in a report.</td>
</tr>
<tr>
<td>name</td>
<td>Search for keywords across report names (for example, the report’s title).</td>
</tr>
<tr>
<td>actor</td>
<td>
<p>Search for a report related to a specified actor.</p>
<p>For a list of actors, refer to the Intel Actors API. &lt;hyperlink&gt;</p>
</td>
</tr>
<tr>
<td>targetCountries</td>
<td>Search reports by targeted country or countries.</td>
</tr>
<tr>
<td>targetIndustries</td>
<td>Search reports by targeted industry or industries.</td>
</tr>
<tr>
<td>motivations</td>
<td>Search reports by motivation.</td>
</tr>
<tr>
<td>slug</td>
<td>Search reports by report 'slug' or short descriptive name.</td>
</tr>
<tr>
<td>description</td>
<td>Search the body of the report.</td>
</tr>
<tr>
<td>type</td>
<td>The type of object to search for.</td>
</tr>
<tr>
<td>subType</td>
<td>The sub-type of object to search for.</td>
</tr>
<tr>
<td>tags</td>
<td>Tags associated with a report (managed internally by CrowdStrike).</td>
</tr>
<tr>
<td>minLastModifiedDate</td>
<td>
<p>Search range starts at modified date.</p>
<p>Dates are formatted as YYYY-MM-DD.</p>
</td>
</tr>
<tr>
<td>maxLastModifiedDate</td>
<td>
<p>Search range ends at modified date.</p>
<p>Dates are formatted as YYYY-MM-DD.</p>
</td>
</tr>
<tr>
<td>offset</td>
<td>
<p>Used to number the responses.</p>
<p>You can then use limit to set the number of results for the next page.</p>
</td>
</tr>
<tr>
<td>limit</td>
<td>Limits the number of results to return</td>
</tr>
<tr>
<td>sort</td>
<td>
<p>The field and direction to sort results on in the format of: . or ..</p>
<p>Valid values are:</p>
<ul>
<li>name</li>
<li>target_countries</li>
<li>target_industries</li>
<li>type</li>
<li>created_date</li>
<li>last_modified_date</li>
</ul>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output. </p>
<h5>Command Example</h5>
<p><code>!cs-reports actor=panda limit=10</code></p>
<h5>Raw Output</h5>
<p>There is no raw output.</p>
<h5>Context Example</h5>
<p>There is no context example.</p>
<hr>
<h3 id="h_3467486824461531206549615">8. Get report in PDF format</h3>
<p>Returns a full summary of a specified report in PDF format.</p>
<h5>Base Command</h5>
<p><code>cs-report-pdf</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
</tr>
<tr>
<td>id</td>
<td>The ID of the report to return</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!cs-report-pdf id=588</code></p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h5>Context Example</h5>
<p>There is no context example for this command.</p>