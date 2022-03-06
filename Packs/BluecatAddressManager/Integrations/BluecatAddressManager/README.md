<!-- HTML_DOC -->
<p><b>This integration supports Bluecat Address Manager version 9.1, Newer versions might fail to run.</b></p>
<p>Use the BlueCat integration to enrich IP addresses and manage response policies.</p>
<h2>Configure BluecatAddressManager on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for BluecatAddressManager.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Incident type</strong></li>
<li><strong>Server URL (e.g.,<span> </span><a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (insecure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>Configuration Name</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_ad8eee3b-a87d-41c0-b040-3f294b59e922" target="_self">Enrich an IP address: bluecat-am-query-ip</a></li>
<li><a href="#h_859247e3-9b45-4b4b-850e-3295e96c2f98" target="_self">Get all response policies: bluecat-am-get-response-policies</a></li>
<li><a href="#h_e903027d-e30c-4d2b-8b1c-044ae5068495" target="_self">Search response policies by domain: bluecat-am-search-response-policies-by-domain</a></li>
<li><a href="#h_d14f7a3e-ee37-439a-918f-8ca79cebb056" target="_self">Add a domain to a response policy: bluecat-am-response-policy-add-domain</a></li>
<li><a href="#h_489c45fb-a61f-4aef-88d0-6d9f07798955" target="_self">Remove a domain from a response policy: bluecat-am-response-policy-remove-domain</a></li>
<li><a href="#h_0457fa2f-abac-46f1-9091-f56b52cb50be" target="_self">Get an IPv4 block containing an IPv4 address: bluecat-am-get-range-by-ip</a></li>
</ol>
<h3 id="h_ad8eee3b-a87d-41c0-b040-3f294b59e922">1. Enrich an IP address</h3>
<hr>
<p>Enriches an IP address with data about IP networks and blocks to which it belongs, linked IPs, MAC addresses, and so on.</p>
<h5>Base Command</h5>
<p><code>bluecat-am-query-ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 260px;"><strong>Argument Name</strong></th>
<th style="width: 337px;"><strong>Description</strong></th>
<th style="width: 143px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">ip</td>
<td style="width: 337px;">The IP to get data for.</td>
<td style="width: 143px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 327px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 345px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.ID</td>
<td style="width: 68px;">Number</td>
<td style="width: 345px;">The address manager ID of the IP address.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Name</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Name of the IP address.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.MacAddress</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Corresponding MAC address.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Parents.ID</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">ID of the parent IP address.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Parents.Type</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Type of the parent IP address.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Parents.Name</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Name of the parent IP address.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Parents.CIDR</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Classless Inter-Domain Routing.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Type</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Type of IP address.</td>
</tr>
<tr>
<td style="width: 327px;">IP.Address</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Address of IP.</td>
</tr>
<tr>
<td style="width: 327px;">BlueCat.AddressManager.IP.Parents.Prefix</td>
<td style="width: 68px;">String</td>
<td style="width: 345px;">Prefix of the IP address.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>bluecat-am-query-ip ip="10.0.0.10"</pre>
<h5>Context Example</h5>
<pre>{
    "IP": {
        "Address": "10.0.0.10"
    }, 
    "BlueCat.AddressManager.IP": {
        "Name": null, 
        "LocationInherited": "true", 
        "State": "STATIC", 
        "Parents": [
            {
                "InheritPingBeforeAssign": "true", 
                "InheritDNSRestrictions": "true", 
                "LocationInherited": "true", 
                "PingBeforeAssign": "disable", 
                "AllowDuplicateHost": "disable", 
                "ID": 100913, 
                "InheritAllowDuplicateHost": "true", 
                "InheritDefaultView": "true", 
                "CIDR": "10.0.0.0/24", 
                "DefaultView": "100907", 
                "Type": "IP4Network", 
                "Gateway": "10.0.0.1", 
                "InheritDefaultDomains": "true", 
                "Name": "East Office"
            }, 
            {
                "InheritPingBeforeAssign": "true", 
                "InheritDNSRestrictions": "true", 
                "LocationInherited": "true", 
                "PingBeforeAssign": "disable", 
                "AllowDuplicateHost": "disable", 
                "InheritAllowDuplicateHost": "true", 
                "InheritDefaultView": "true", 
                "CIDR": "10.0.0.0/21", 
                "DefaultView": "100907", 
                "Type": "IP4Block", 
                "ID": 100912, 
                "InheritDefaultDomains": "true", 
                "Name": "Tampa"
            }, 
            {
                "InheritPingBeforeAssign": "true", 
                "InheritDNSRestrictions": "true", 
                "LocationInherited": "true", 
                "PingBeforeAssign": "disable", 
                "AllowDuplicateHost": "disable", 
                "InheritAllowDuplicateHost": "true", 
                "InheritDefaultView": "true", 
                "CIDR": "10.0.0.0/19", 
                "DefaultView": "100907", 
                "Type": "IP4Block", 
                "ID": 100911, 
                "InheritDefaultDomains": "true", 
                "Name": "Florida"
            }, 
            {
                "InheritPingBeforeAssign": "true", 
                "InheritDNSRestrictions": "true", 
                "LocationInherited": "true", 
                "PingBeforeAssign": "disable", 
                "AllowDuplicateHost": "disable", 
                "InheritAllowDuplicateHost": "true", 
                "InheritDefaultView": "true", 
                "CIDR": "10.0.0.0/16", 
                "DefaultView": "100907", 
                "Type": "IP4Block", 
                "ID": 100910, 
                "InheritDefaultDomains": "true", 
                "Name": "North America"
            }, 
            {
                "InheritPingBeforeAssign": "false", 
                "InheritDNSRestrictions": "true", 
                "LocationInherited": "true", 
                "PingBeforeAssign": "disable", 
                "AllowDuplicateHost": "disable", 
                "InheritAllowDuplicateHost": "false", 
                "InheritDefaultView": "false", 
                "CIDR": "10.0.0.0/8", 
                "DefaultView": "100907", 
                "Type": "IP4Block", 
                "ID": 100909, 
                "InheritDefaultDomains": "true", 
                "Name": "global"
            }
        ], 
        "Address": "10.0.0.10", 
        "Type": "IPv4", 
        "ID": 100923
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>10.0.0.10 IP Result:</h3>
<table style="width: 456px;" border="2">
<thead>
<tr>
<th style="width: 53px;">ID</th>
<th style="width: 47px;">Name</th>
<th style="width: 38px;">Type</th>
<th style="width: 69px;">Address</th>
<th style="width: 51px;">State</th>
<th style="width: 183px;">Location Inherited</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 53px;">100923</td>
<td style="width: 47px;"> </td>
<td style="width: 38px;">IPv4</td>
<td style="width: 69px;">10.0.0.10</td>
<td style="width: 51px;">STATIC</td>
<td style="width: 183px;">true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Parents Details:</h3>
<table style="width: 934px;" border="2">
<thead>
<tr>
<th style="width: 54px;">ID</th>
<th style="width: 82px;">Type</th>
<th style="width: 58px;">Name</th>
<th style="width: 84px;">CIDR</th>
<th style="width: 75px;">Allow Duplicate Host</th>
<th style="width: 75px;">Inherit Allow Duplicate Host</th>
<th style="width: 53px;">Ping Before Assign</th>
<th style="width: 56px;">Inherit Ping Before Assign</th>
<th style="width: 75px;">Location Inherited</th>
<th style="width: 69px;">Inherit Default Domains</th>
<th style="width: 58px;">Default View</th>
<th style="width: 58px;">Inherit Default View</th>
<th style="width: 97px;">Inherit DNS Restrictions</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 54px;">100909</td>
<td style="width: 82px;">IP4Block</td>
<td style="width: 58px;">global</td>
<td style="width: 84px;">10.0.0.0/8</td>
<td style="width: 75px;">disable</td>
<td style="width: 75px;">false</td>
<td style="width: 53px;">disable</td>
<td style="width: 56px;">false</td>
<td style="width: 75px;">true</td>
<td style="width: 69px;">true</td>
<td style="width: 58px;">100907</td>
<td style="width: 58px;">false</td>
<td style="width: 97px;">true</td>
</tr>
<tr>
<td style="width: 54px;">100910</td>
<td style="width: 82px;">IP4Block</td>
<td style="width: 58px;">North America</td>
<td style="width: 84px;">10.0.0.0/16</td>
<td style="width: 75px;">disable</td>
<td style="width: 75px;">true</td>
<td style="width: 53px;">disable</td>
<td style="width: 56px;">true</td>
<td style="width: 75px;">true</td>
<td style="width: 69px;">true</td>
<td style="width: 58px;">100907</td>
<td style="width: 58px;">true</td>
<td style="width: 97px;">true</td>
</tr>
<tr>
<td style="width: 54px;">100911</td>
<td style="width: 82px;">IP4Block</td>
<td style="width: 58px;">Florida</td>
<td style="width: 84px;">10.0.0.0/19</td>
<td style="width: 75px;">disable</td>
<td style="width: 75px;">true</td>
<td style="width: 53px;">disable</td>
<td style="width: 56px;">true</td>
<td style="width: 75px;">true</td>
<td style="width: 69px;">true</td>
<td style="width: 58px;">100907</td>
<td style="width: 58px;">true</td>
<td style="width: 97px;">true</td>
</tr>
<tr>
<td style="width: 54px;">100912</td>
<td style="width: 82px;">IP4Block</td>
<td style="width: 58px;">Tampa</td>
<td style="width: 84px;">10.0.0.0/21</td>
<td style="width: 75px;">disable</td>
<td style="width: 75px;">true</td>
<td style="width: 53px;">disable</td>
<td style="width: 56px;">true</td>
<td style="width: 75px;">true</td>
<td style="width: 69px;">true</td>
<td style="width: 58px;">100907</td>
<td style="width: 58px;">true</td>
<td style="width: 97px;">true</td>
</tr>
<tr>
<td style="width: 54px;">100913</td>
<td style="width: 82px;">IP4Network</td>
<td style="width: 58px;">East Office</td>
<td style="width: 84px;">10.0.0.0/24</td>
<td style="width: 75px;">disable</td>
<td style="width: 75px;">true</td>
<td style="width: 53px;">disable</td>
<td style="width: 56px;">true</td>
<td style="width: 75px;">true</td>
<td style="width: 69px;">true</td>
<td style="width: 58px;">100907</td>
<td style="width: 58px;">true</td>
<td style="width: 97px;">true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_859247e3-9b45-4b4b-850e-3295e96c2f98">2. Get all response policies</h3>
<hr>
<p>Returns all response policies.</p>
<h5>Base Command</h5>
<p><code>bluecat-am-get-response-policies</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">start</td>
<td style="width: 506px;">Start index from which to get the response policies. Default is 0.</td>
<td style="width: 81px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">count</td>
<td style="width: 506px;">Maximum number of response policies to return.</td>
<td style="width: 81px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 404px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 266px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 404px;">BlueCat.AddressManager.ResponsePolicies.ID</td>
<td style="width: 70px;">Number</td>
<td style="width: 266px;">ID of the response policy.</td>
</tr>
<tr>
<td style="width: 404px;">BlueCat.AddressManager.ResponsePolicies.Name</td>
<td style="width: 70px;">String</td>
<td style="width: 266px;">Name of the response policy.</td>
</tr>
<tr>
<td style="width: 404px;">BlueCat.AddressManager.ResponsePolicies.Ttl</td>
<td style="width: 70px;">Unknown</td>
<td style="width: 266px;">Time to live (TTL) of the response policy.</td>
</tr>
<tr>
<td style="width: 404px;">BlueCat.AddressManager.ResponsePolicies.Type</td>
<td style="width: 70px;">String</td>
<td style="width: 266px;">Type of the response policy (BLACKLIST, BLACKHOLE, WHITELIST, or REDIRECT).</td>
</tr>
<tr>
<td style="width: 404px;">BlueCat.AddressManager.ResponsePolicies.RedirectTarget</td>
<td style="width: 70px;">String</td>
<td style="width: 266px;">Target of redirect, in case of REDIRECT policy type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>bluecat-am-get-response-policies start="0" count="30"</pre>
<h5>Context Example</h5>
<pre>{
    "BlueCat.AddressManager.ResponsePolicies": [
        {
            "RedirectTarget": "foo.com", 
            "ResponsePolicyType": "REDIRECT", 
            "Ttl": "30", 
            "Type": "ResponsePolicy", 
            "ID": 100930, 
            "Name": "Malware Trap"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h2>Response Policies:</h2>
<h3>Malware Trap</h3>
<table style="width: 578px;" border="2">
<thead>
<tr>
<th style="width: 54px;">ID</th>
<th style="width: 94px;">Name</th>
<th style="width: 107px;">Type</th>
<th style="width: 21px;">Ttl</th>
<th style="width: 161px;">ResponsePolicyType</th>
<th style="width: 122px;">RedirectTarget</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 54px;">100930</td>
<td style="width: 94px;">Malware Trap</td>
<td style="width: 107px;">ResponsePolicy</td>
<td style="width: 21px;">30</td>
<td style="width: 161px;">REDIRECT</td>
<td style="width: 122px;">foo.com</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_e903027d-e30c-4d2b-8b1c-044ae5068495">3. Search response policies by domain</h3>
<hr>
<p>Searches all response policies in which the given domain is included.</p>
<h5>Base Command</h5>
<p><code>bluecat-am-search-response-policies-by-domain</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Argument Name</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
<th style="width: 121px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">domain</td>
<td style="width: 401px;">Domain name by which to search.</td>
<td style="width: 121px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 409px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 270px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 409px;">BlueCat.AddressManager.ResponsePolicies.ID</td>
<td style="width: 61px;">Number</td>
<td style="width: 270px;">ID of the response policy.</td>
</tr>
<tr>
<td style="width: 409px;">BlueCat.AddressManager.ResponsePolicies.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 270px;">Name of the response policy.</td>
</tr>
<tr>
<td style="width: 409px;">BlueCat.AddressManager.ResponsePolicies.Ttl</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 270px;">Time to live (TTL) of the response policy</td>
</tr>
<tr>
<td style="width: 409px;">BlueCat.AddressManager.ResponsePolicies.Type</td>
<td style="width: 61px;">String</td>
<td style="width: 270px;">Type of the responce policy ( BLACKLIST, BLACKHOLE, WHITELIST, or REDIRECT).</td>
</tr>
<tr>
<td style="width: 409px;">BlueCat.AddressManager.ResponsePolicies.RedirectTarget</td>
<td style="width: 61px;">String</td>
<td style="width: 270px;">Target of redirect, in case of REDIRECT policy type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>bluecat-am-search-response-policies-by-domain domain="demisto.com"</pre>
<h5>Human Readable Output</h5>
<p>Could not find any response policy</p>
<h3 id="h_d14f7a3e-ee37-439a-918f-8ca79cebb056">4. Add a domain to a response policy</h3>
<hr>
<p>Adds a domain to the given response policy.</p>
<h5>Base Command</h5>
<p><code>bluecat-am-response-policy-add-domain</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 208px;"><strong>Argument Name</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
<th style="width: 114px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 208px;">policy_id</td>
<td style="width: 418px;">ID of the response policy to edit.</td>
<td style="width: 114px;">Required</td>
</tr>
<tr>
<td style="width: 208px;">domain</td>
<td style="width: 418px;">Domain to add to the response policy.</td>
<td style="width: 114px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>bluecat-am-response-policy-add-domain policy_id="100930" domain="demisto.com"</pre>
<h5>Human Readable Output</h5>
<p>Successfully added demisto.com to response policy 100930</p>
<h3 id="h_489c45fb-a61f-4aef-88d0-6d9f07798955">5. Remove a domain from a response policy</h3>
<hr>
<p>Removes a domain from the given response policy.</p>
<h5>Base Command</h5>
<p><code>bluecat-am-response-policy-remove-domain</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 201px;"><strong>Argument Name</strong></th>
<th style="width: 436px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">policy_id</td>
<td style="width: 436px;">ID of the response policy to edit.</td>
<td style="width: 103px;">Required</td>
</tr>
<tr>
<td style="width: 201px;">domain</td>
<td style="width: 436px;">Domain to remove from the response policy.</td>
<td style="width: 103px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>bluecat-am-response-policy-remove-domain policy_id="100930" domain="demisto.com"</pre>
<h5>Human Readable Output</h5>
<p>Successfully removed demisto.com from response policy 100930</p>
<h3 id="h_0457fa2f-abac-46f1-9091-f56b52cb50be">6. Get an IPv4 block containing an IPv4 address</h3>
<hr>
<p>Gets an IPv4 block, which contains a specified IPv4 address.</p>
<h5>Base Command</h5>
<p><code>bluecat-am-get-range-by-ip</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 189px;"><strong>Argument Name</strong></th>
<th style="width: 444px;"><strong>Description</strong></th>
<th style="width: 107px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 189px;">ip</td>
<td style="width: 444px;">The IP address for which to get the range.</td>
<td style="width: 107px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 372px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 316px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.ID</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">The address manager ID of the Range.</td>
</tr>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.Name</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">Name of the Range.</td>
</tr>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.Type</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">Type of the Range.</td>
</tr>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.Parents.ID</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">ID of the parent Range.</td>
</tr>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.Parents.Type</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">Type of the parent Range.</td>
</tr>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.Parents.Name</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">Name of the parent Range.</td>
</tr>
<tr>
<td style="width: 372px;">BlueCat.AddressManager.Range.Parents.CIDR</td>
<td style="width: 52px;">String</td>
<td style="width: 316px;">Classless Inter-Domain Routing.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !bluecat-am-get-range-by-ip ip=10.0.0.11
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/62834322-13159600-bc53-11e9-9fc4-25b30714114b.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/62834322-13159600-bc53-11e9-9fc4-25b30714114b.png" alt="Screen Shot 2019-08-08 at 15 44 51"></a></p>