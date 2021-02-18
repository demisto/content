<!-- HTML_DOC -->
<p class="has-line-data" data-line-start="3" data-line-end="5">Use the iDefense integration to manage cyber threats and security issues in the iDefense security platform.<br> </p>
<h2 class="code-line" data-line-start="11" data-line-end="12">Configure iDefense on Demisto</h2>
<ol>
<li class="has-line-data" data-line-start="14" data-line-end="15">Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li class="has-line-data" data-line-start="15" data-line-end="16">Search for iDefense.</li>
<li class="has-line-data" data-line-start="16" data-line-end="22">Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li class="has-line-data" data-line-start="17" data-line-end="18">
<strong>Name</strong>: a textual name for the integration instance.</li>
<li class="has-line-data" data-line-start="18" data-line-end="19"><strong>URL</strong></li>
<li class="has-line-data" data-line-start="19" data-line-end="20"><strong>API Token</strong></li>
<li class="has-line-data" data-line-start="20" data-line-end="21"><strong>Trust any certificate (not secure)</strong></li>
<li class="has-line-data" data-line-start="21" data-line-end="22"><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li class="has-line-data" data-line-start="22" data-line-end="23">Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<hr>
<h2 class="code-line" data-line-start="26" data-line-end="27">Commands</h2>
<p class="has-line-data" data-line-start="28" data-line-end="30">You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li class="has-line-data" data-line-start="30" data-line-end="31"><a href="#h_1841b53d-16d5-42bd-954b-1012407df8b0" target="_self">Check IP address: ip</a></li>
<li class="has-line-data" data-line-start="31" data-line-end="32"><a href="#h_4a9b6a96-3203-4228-a8f7-8900956ffc51" target="_self">Check a domain: domain</a></li>
<li class="has-line-data" data-line-start="32" data-line-end="33"><a href="#h_97f7f5ab-f28a-47e1-9d0f-613c9515ce7a" target="_self">Check a URL: url</a></li>
<li class="has-line-data" data-line-start="33" data-line-end="34"><a href="#h_772bfa15-fd06-4971-ad90-5329199ecc4a" target="_self">Get threats from the iDefense database: idefence-general</a></li>
<li class="has-line-data" data-line-start="34" data-line-end="35"><a href="#h_590a86dc-c02d-46d8-9c4c-ad3d403bb41f" target="_self">Get the reputation of an indicator: uuid</a></li>
</ol>
<h3 id="h_1841b53d-16d5-42bd-954b-1012407df8b0" class="code-line" data-line-start="35" data-line-end="36">1. Check an IP address</h3>
<hr>
<p class="has-line-data" data-line-start="37" data-line-end="38">Checks the reputation of an IP address.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5 class="code-line" data-line-start="43" data-line-end="44">Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 324px;"><strong>Argument Name</strong></th>
<th style="width: 233px;"><strong>Description</strong></th>
<th style="width: 184px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 324px;">ip</td>
<td style="width: 233px;">The IP address to check.</td>
<td style="width: 184px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="50" data-line-end="51">Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 167px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">IP.Address</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">The address of the bad IP.</td>
</tr>
<tr>
<td style="width: 167px;">IP.Malicious.Vendor</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">For malicious IPs, the name of the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 167px;">IP.Malicious.Description</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">For malicious IPs, the reason that the vendor to made the decision.</td>
</tr>
<tr>
<td style="width: 167px;">DBotScore.Indicator</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 167px;">DBotScore.Type</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">The type of indicator.</td>
</tr>
<tr>
<td style="width: 167px;">DBotScore.Vendor</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 167px;">DBotScore.Score</td>
<td style="width: 73px;">unknown</td>
<td style="width: 500px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="63" data-line-end="64">
<a id="Command_Example_63"></a>Command Example</h5>
<pre>  !ip ip=256.256.256.256 using=iDefense_instance_1
</pre>
<h5 class="code-line" data-line-start="66" data-line-end="67">
<a id="Context_Example_66"></a>Context Example</h5>
<pre>{
    "IP": [
        {
            "Malicious": {
                "Vendor": "iDefense", 
                "Description": "last seen as MALWARE_C2"
            }, 
            "Address": "256.256.256.256"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "iDefense", 
            "Indicator": "256.256.256.256", 
            "Score": 2, 
            "Type": "ip"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="89" data-line-end="90">Human Readable Output</h5>
<h3 class="code-line" data-line-start="90" data-line-end="91">iDefense IP Reputation</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Dbot Reputation</th>
<th>Name</th>
<th>Threat Types</th>
<th>confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td>Suspicious</td>
<td>256.256.256.256</td>
<td>Cyber Espionage</td>
<td>50</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4a9b6a96-3203-4228-a8f7-8900956ffc51" class="code-line" data-line-start="96" data-line-end="97">2. Check a domain</h3>
<hr>
<p class="has-line-data" data-line-start="98" data-line-end="99">Checks the reputation of a domain.</p>
<h5 class="code-line" data-line-start="101" data-line-end="102">Base Command</h5>
<p><code>domain</code></p>
<h5 class="code-line" data-line-start="104" data-line-end="105">Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 295.333px;"><strong>Argument Name</strong></th>
<th style="width: 276.667px;"><strong>Description</strong></th>
<th style="width: 168px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 295.333px;">domain</td>
<td style="width: 276.667px;">The name of the domain to check.</td>
<td style="width: 168px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="111" data-line-end="112">
<a id="Context_Output_111"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 203px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 203px;">Domain.Name</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">The name of the bad domain.</td>
</tr>
<tr>
<td style="width: 203px;">Domain.Malicious.Vendor</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">For malicious domains, the name of the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 203px;">Domain.Malicious.Description</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">For malicious domains, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 203px;">DBotScore.Indicator</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 203px;">DBotScore.Type</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">The type of the indicator.</td>
</tr>
<tr>
<td style="width: 203px;">DBotScore.Vendor</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 203px;">DBotScore.Score</td>
<td style="width: 68px;">unknown</td>
<td style="width: 470px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="124" data-line-end="125">
<a id="Command_Example_124"></a>Command Example</h5>
<pre>!domain domain=example.com using=iDefense_instance_1</pre>
<h5 class="code-line" data-line-start="127" data-line-end="128">
<a id="Context_Example_127"></a>Context Example</h5>
<pre>{
    "Domain": [
        {
            "Malicious": {
                "Vendor": "iDefense", 
                "Description": "last seen as MALWARE_DOWNLOAD"
            }, 
            "Name": "example.com"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "iDefense", 
            "Indicator": "example.com", 
            "Score": 2, 
            "Type": "domain"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="150" data-line-end="151">
<a id="Human_Readable_Output_150"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="151" data-line-end="152">
<a id="iDefense_Domain_Reputation_151"></a>iDefense Domain Reputation</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Dbot Reputation</th>
<th>Name</th>
<th>Threat Types</th>
<th>confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td>Suspicious</td>
<td>example.com</td>
<td>Cyber Espionage</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_97f7f5ab-f28a-47e1-9d0f-613c9515ce7a" class="code-line" data-line-start="157" data-line-end="158">3. Check a URL </h3>
<hr>
<p class="has-line-data" data-line-start="159" data-line-end="160">Checks the reputation of a URL.</p>
<h5 class="code-line" data-line-start="162" data-line-end="163">Base Command</h5>
<p class="has-line-data" data-line-start="164" data-line-end="165"><code>url</code></p>
<h5 class="code-line" data-line-start="165" data-line-end="166">Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 198.333px;"><strong>Argument Name</strong></th>
<th style="width: 429.667px;"><strong>Description</strong></th>
<th style="width: 112px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198.333px;">url</td>
<td style="width: 429.667px;">The name of the URL to check (must start with http://).</td>
<td style="width: 112px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="172" data-line-end="173">Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 183.333px;"><strong>Path</strong></th>
<th style="width: 68.6667px;"><strong>Type</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183.333px;">URL.Data</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">The name of the bad URL.</td>
</tr>
<tr>
<td style="width: 183.333px;">URL.Malicious.Vendor</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 183.333px;">URL.Malicious.Description</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 183.333px;">DBotScore.Indicator</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 183.333px;">DBotScore.Type</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">The type of indicator.</td>
</tr>
<tr>
<td style="width: 183.333px;">DBotScore.Vendor</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 183.333px;">DBotScore.Score</td>
<td style="width: 68.6667px;">unknown</td>
<td style="width: 488px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="185" data-line-end="186">Command Example</h5>
<pre>  !url url=http://example.com using=iDefense_instance_1
</pre>
<h5 class="code-line" data-line-start="188" data-line-end="189">Context Example</h5>
<pre>{
    "URL": [
        {
            "Malicious": {
                "Vendor": "iDefense", 
                "Description": "last seen as MALWARE_C2"
            }, 
            "Data": "http://example.com"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "iDefense", 
            "Indicator": "http://example.com", 
            "Score": 2, 
            "Type": "url"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="211" data-line-end="212">Human Readable Output</h5>
<h3 class="code-line" data-line-start="212" data-line-end="213">iDefense URL Reputation</h3>
<table class="table table-striped table-bordered" style="width: 750px;" border="2">
<thead>
<tr>
<th>Dbot Reputation</th>
<th>Name</th>
<th>Threat Types</th>
<th>confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td>Suspicious</td>
<td>http://example.com</td>
<td>Cyber Crime</td>
<td>50</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_772bfa15-fd06-4971-ad90-5329199ecc4a" class="code-line" data-line-start="218" data-line-end="219">4. Get threats from the iDefense database</h3>
<hr>
<p class="has-line-data" data-line-start="220" data-line-end="221">Returns threat information, such as IP address, URL and domain from the iDefense database. </p>
<h5 class="code-line" data-line-start="223" data-line-end="224">Base Command</h5>
<p class="has-line-data" data-line-start="225" data-line-end="226"><code>idefense-general</code></p>
<h5 class="code-line" data-line-start="226" data-line-end="227">Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 233px;"><strong>Argument Name</strong></th>
<th style="width: 373px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">max_result</td>
<td style="width: 373px;">The maximum amount of results to return.</td>
<td style="width: 134px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="233" data-line-end="234">Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 202px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 202px;">IP.Address</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The name of the bad IP Address.</td>
</tr>
<tr>
<td style="width: 202px;">IP.Malicious.Vendor</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">For malicious IPs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 202px;">IP.Malicious.Description</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">For malicious IPs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 202px;">Domain.Name</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The name of the bad domain.</td>
</tr>
<tr>
<td style="width: 202px;">Domain.Malicious.Vendor</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 202px;">Domain.Malicious.Description</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">For malicious domains, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 202px;">URL.Data</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The bad URL found.</td>
</tr>
<tr>
<td style="width: 202px;">URL.Malicious.Vendor</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 202px;">URL.Malicious.Description</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 202px;">DBotScore.Indicator</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 202px;">DBotScore.Type</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The type of indicator.</td>
</tr>
<tr>
<td style="width: 202px;">DBotScore.Vendor</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 202px;">DBotScore.Score</td>
<td style="width: 69px;">unknown</td>
<td style="width: 470px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="252" data-line-end="253">
<a id="Command_Example_252"></a>Command Example</h5>
<pre>!idefense-general max_result=1</pre>
<h5 class="code-line" data-line-start="255" data-line-end="256">
<a id="Context_Example_255"></a>Context Example</h5>
<pre>{
    "URL": [
        {
            "Malicious": {
                "Vendor": "iDefense", 
                "Description": "last seen as MALWARE_DOWNLOAD"
            }, 
            "Data": "http://example.com/malicious_file.exe"
        }, 
        {
            "Vendor": "iDefense", 
            "Indicator": "http://example.com/suspicious_file.exe", 
            "Score": 2, 
            "Type": "url"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="276" data-line-end="277">
<a id="Human_Readable_Output_276"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="277" data-line-end="278">
<a id="iDefense_Reputations_277"></a>iDefense Reputations</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Dbot Reputation</th>
<th>Name</th>
<th>Threat Types</th>
<th>confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td>Malicious</td>
<td>http://example.com/malicious_file.exe</td>
<td>Cyber Crime</td>
<td>100</td>
</tr>
<tr>
<td>Suspicious</td>
<td>http://example.com/suspicious_file.exe</td>
<td>Cyber Crime</td>
<td>50</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_590a86dc-c02d-46d8-9c4c-ad3d403bb41f" class="code-line" data-line-start="285" data-line-end="286">5. Get the reputation of an indicator</h3>
<hr>
<p class="has-line-data" data-line-start="287" data-line-end="288">Returns the reputation of a specific indicator.</p>
<h5 class="code-line" data-line-start="290" data-line-end="291">Base Command</h5>
<p class="has-line-data" data-line-start="292" data-line-end="293"><code>uuid</code></p>
<h5 class="code-line" data-line-start="293" data-line-end="294">Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 305px;"><strong>Argument Name</strong></th>
<th style="width: 262px;"><strong>Description</strong></th>
<th style="width: 173px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 305px;">uuid</td>
<td style="width: 262px;">The unique ID of the user.</td>
<td style="width: 173px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="300" data-line-end="301">
<a id="Context_Output_300"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 698px;">
<thead>
<tr>
<th style="width: 195px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 195px;">IP.Address</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The name of the bad IP Address.</td>
</tr>
<tr>
<td style="width: 195px;">IP.Malicious.Vendor</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">For malicious IPs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 195px;">IP.Malicious.Description</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">For malicious IPs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 195px;">Domain.Name</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The name of the bad domain.</td>
</tr>
<tr>
<td style="width: 195px;">Domain.Malicious.Vendor</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">For malicious domains, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 195px;">Domain.Malicious.Description</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">For malicious domains, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 195px;">URL.Data</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The name of the bad URL.</td>
</tr>
<tr>
<td style="width: 195px;">URL.Malicious.Vendor</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">For malicious URLs, the vendor that made the decision.</td>
</tr>
<tr>
<td style="width: 195px;">URL.Malicious.Description</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">For malicious URLs, the reason that the vendor made the decision.</td>
</tr>
<tr>
<td style="width: 195px;">DBotScore.Indicator</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The indicator that was tested.</td>
</tr>
<tr>
<td style="width: 195px;">DBotScore.Type</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The type of indicator.</td>
</tr>
<tr>
<td style="width: 195px;">DBotScore.Vendor</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The vendor used to calculate the score.</td>
</tr>
<tr>
<td style="width: 195px;">DBotScore.Score</td>
<td style="width: 76px;">unknown</td>
<td style="width: 420px;">The actual score.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="319" data-line-end="320">
<a id="Command_Example_319"></a>Command Example</h5>
<pre>!uuid uuid=44a7d565-a260-9oc6-b7f4-2368dc3a4a67 using=iDefense_instance_1</pre>
<h5 class="code-line" data-line-start="322" data-line-end="323">
<a id="Context_Example_322"></a>Context Example</h5>
<pre>{
    "Domain": [
        {
            "Malicious": {
                "Vendor": "iDefense", 
                "Description": "last seen as MALWARE_C2"
            }, 
            "Name": "example.com"
        }
    ], 
    "DBotScore": [
        {
            "Vendor": "iDefense", 
            "Indicator": "example.com", 
            "Score": 2, 
            "Type": "domain"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="345" data-line-end="346">
<a id="Human_Readable_Output_345"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="346" data-line-end="347">
<a id="iDefense_Reputations_346"></a>iDefense Reputations</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Dbot Reputation</th>
<th>Name</th>
<th>Threat Types</th>
<th>confidence</th>
</tr>
</thead>
<tbody>
<tr>
<td>Suspicious</td>
<td>example.com</td>
<td>Cyber Espionage</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>