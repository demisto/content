<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Retrieve and analyze network access controls across Tufin-managed firewalls, SDN, and public cloud to identify vulnerable access paths of an attack.</p>
</div>
<div class="cl-preview-section">
<p>This integration was integrated and tested with version 17-2 through 18-3 of the Tufin Orchestration Suite.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Enrich investigations with network policy information.</li>
<li>Run routine or on-demand policy searches.</li>
<li>Understand the full topology of a network event.</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-tufin-on-demisto">Configure Tufin on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Tufin.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>SecureTrack IP or FQDN</strong></li>
<li><strong>SecureTrack User Credentials</strong></li>
<li><strong>Trust any certificate (unsecure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Maximum number of rules returned for a device during a policy search</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#search-the-tufin-topology-map" target="_self">Search the Tufin topology: tufin-search-topology</a></li>
<li><a href="#search-the-tufin-topology-map-and-return-an-image" target="_self">Search the Tufin topology map: tufin-search-topology-image</a></li>
<li><a href="#resolve-an-ip-address-to-a-network-object" target="_self">Resolve an IP address to a network object: tufin-object-resolve</a></li>
<li><a href="#search-all-tufin-managed-devices" target="_self">Search all Tufin-managed devices: tufin-policy-search</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="search-the-tufin-topology-map">1. Search the Tufin topology map</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Executes a search in the Tufin Topology Map.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>tufin-search-topology</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 144.5px;"><strong>Argument Name</strong></th>
<th style="width: 524.5px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144.5px;">source</td>
<td style="width: 524.5px;">A CSV list of source addresses, for example: “192.168.100.32” or “192.168.100.32/32,192.168.100.33”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144.5px;">destination</td>
<td style="width: 524.5px;">A CSV list of destination addresses, for example: “192.168.100.32” or “192.168.100.32/32,192.168.100.33”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144.5px;">service</td>
<td style="width: 524.5px;">A port or an application. “Port” example: “tcp:80”, “any”. “Application” example: “Skype”, “Facebook”.</td>
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
<th style="width: 327.5px;"><strong>Path</strong></th>
<th style="width: 92.5px;"><strong>Type</strong></th>
<th style="width: 320px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 327.5px;">Tufin.Topology.TrafficAllowed</td>
<td style="width: 92.5px;">boolean</td>
<td style="width: 320px;">Whether traffic is permitted.</td>
</tr>
<tr>
<td style="width: 327.5px;">Tufin.Topology.TrafficDevices</td>
<td style="width: 92.5px;">string</td>
<td style="width: 320px;">A list of devices in the path.</td>
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
<pre>tufin-search-topology source=172.16.20.1 destination=172.16.90.1</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Tufin.Topology.TrafficDevices": [
        "StoneSoft-NG VF", 
        "RTR3", 
        "Pe_1", 
        "RTR2", 
        "SRX", 
        "NSX-Edge-01", 
        "NSX-Distributed-Router"
    ], 
    "Tufin.Topology.TrafficAllowed": false
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="tufin-topology-search-for-172.16.20.1-to-172.16.90.1-via-service-any.-traffic-is-denied">Tufin Topology Search for 172.16.20.1 to 172.16.90.1 via Service Any. Traffic is <strong>Denied</strong>
</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Start</th>
<th>Devices in Path</th>
<th>End</th>
</tr>
</thead>
<tbody>
<tr>
<td>172.16.20.1</td>
<td>
<strong>StoneSoft-NG VF</strong> (Stonesoft SMC)–&gt;<strong>RTR3</strong> (Cisco)–&gt;<strong>Pe_1</strong> (Cisco)–&gt;<strong>RTR2</strong>(Cisco)–&gt;<strong>SRX</strong> (Juniper)–&gt;<strong>NSX-Edge-01</strong> (VMware)–&gt;<strong>NSX-Distributed-Router</strong>(VMware)</td>
<td>172.16.90.1</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="search-the-tufin-topology-map-and-return-an-image">2. Search the Tufin topology map and return an image</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Executes a search in the Tufin Topology Map, returning an image.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>tufin-search-topology-image</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 142.5px;"><strong>Argument Name</strong></th>
<th style="width: 526.5px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142.5px;">source</td>
<td style="width: 526.5px;">A CSV list of source addresses, for example: “192.168.100.32” or “192.168.100.32/32,192.168.100.33”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142.5px;">destination</td>
<td style="width: 526.5px;">A CSV list of destination addresses, for example: “192.168.100.32” or “192.168.100.32/32,192.168.100.33”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142.5px;">service</td>
<td style="width: 526.5px;">A port or an application. “Port” example: “tcp:80”, “any”. “Application” example: “Skype”, “Facebook”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>tufin-search-topology-image source=172.16.20.1 destination=172.16.90.1</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><img src="https://stackedit.io/topo.png" alt="Topology Image"></p>
</div>
<div class="cl-preview-section">
<h3 id="resolve-an-ip-address-to-a-network-object">3. Resolve an IP address to a network object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Resolves an IP address to a Network Object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>tufin-object-resolve</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170.5px;"><strong>Argument Name</strong></th>
<th style="width: 471.5px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170.5px;">ip</td>
<td style="width: 471.5px;">The IP address to resolve to the network object.</td>
<td style="width: 98px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 268.5px;"><strong>Path</strong></th>
<th style="width: 57.5px;"><strong>Type</strong></th>
<th style="width: 414px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 268.5px;">Tufin.ObjectResolve.NumberOfObjects</td>
<td style="width: 57.5px;">number</td>
<td style="width: 414px;">The number of objects that resolve to the given IP address.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>tufin-object-resolve ip="1.1.1.2"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Tufin.ObjectResolve.NumberOfObjects": 20
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="object-lookup-for-1.1.1.2">Object Lookup for 1.1.1.2</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ObjectName</th>
<th>Device</th>
</tr>
</thead>
<tbody>
<tr>
<td>1.1.1.2/32</td>
<td>Cisco ACI -Reg_18-1 (Cisco aci_tenant)</td>
</tr>
<tr>
<td>1.1.1.2</td>
<td>Cisco Firepower (Cisco fmc)</td>
</tr>
<tr>
<td>Host_1.1.1.1</td>
<td>Cisco Firepower (Cisco fmc)</td>
</tr>
<tr>
<td>1.1.1.2</td>
<td>Domain_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>H_1.1.1.2</td>
<td>Domain_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1</td>
<td>Domain_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1_1</td>
<td>Domain_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>1.1.1.2</td>
<td>Domain_1_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>1.1.1.2</td>
<td>Domain_1_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>H_1.1.1.2</td>
<td>Domain_1_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1</td>
<td>Domain_1_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1_1</td>
<td>Domain_1_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1_2</td>
<td>Domain_1_1 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>1.1.1.2</td>
<td>Domain_2 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1</td>
<td>Domain_2 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>1.1.1.2</td>
<td>Domain_2_2 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.1</td>
<td>Domain_2_2 (Cisco fmc_domain)</td>
</tr>
<tr>
<td>Host_1.1.1.2</td>
<td>Palo FW 02 Migrated (PaloAltoNetworks Panorama_device)</td>
</tr>
<tr>
<td>test2</td>
<td>Panorama - old client (PaloAltoNetworks Panorama)</td>
</tr>
<tr>
<td>test2</td>
<td>San Francisco DG (PaloAltoNetworks Panorama_device_group)</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="search-all-tufin-managed-devices">4. Search all Tufin-managed devices</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Searches the policies of all devices managed by Tufin.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>tufin-policy-search</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 241.5px;"><strong>Argument Name</strong></th>
<th style="width: 361.5px;"><strong>Description</strong></th>
<th style="width: 137px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241.5px;">search</td>
<td style="width: 361.5px;">The text format for a field.</td>
<td style="width: 137px;"> Required</td>
</tr>
</tbody>
</table>
</div>
<p> </p>
<pre>"source:192.168.1.1", or bareword for a free-text search. For more information about search, see the SecureTrack Policy Browser page. | Required | 
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 319.5px;"><strong>Path</strong></th>
<th style="width: 70.5px;"><strong>Type</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 319.5px;">Tufin.Policysearch.NumberRulesFound</td>
<td style="width: 70.5px;">number</td>
<td style="width: 350px;">The number of rules found in the search.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>tufin-policy-search search="action: deny shadowed: true"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Tufin.Policysearch.NumberRulesFound": 7
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="policy-search-results-for-action-deny-shadowed-true">Policy Search Results for action: deny shadowed: true</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Device</th>
<th>Source</th>
<th>Destination</th>
<th>Destination Service</th>
<th>Action</th>
</tr>
</thead>
<tbody>
<tr>
<td>Palo FW 02 Migrated (PaloAltoNetworks Panorama_device)</td>
<td>A_192.168.3.5</td>
<td>A_172.16.40.80</td>
<td>roi-ftp</td>
<td>Deny</td>
</tr>
<tr>
<td>San Francisco DG (PaloAltoNetworks Panorama_device_group)</td>
<td>A_192.168.3.5</td>
<td>A_172.16.40.80</td>
<td>roi-ftp</td>
<td>Deny</td>
</tr>
<tr>
<td>NSX-Distributed Firewall (VMware nsx_fw)</td>
<td>Web01</td>
<td>App-Tier-01</td>
<td>HTTPS</td>
<td>Reject</td>
</tr>
<tr>
<td>NSX-Distributed Firewall (VMware nsx_fw)</td>
<td>Any</td>
<td>Any</td>
<td>Any</td>
<td>Drop</td>
</tr>
<tr>
<td>StoneSoft-NG VF (Stonesoft virtual_fw)</td>
<td>h_172.16.20.50,<br> h_172.16.20.51</td>
<td>Amsterdam Users</td>
<td>POP2,<br> POP3</td>
<td>Reject</td>
</tr>
<tr>
<td>StoneSoft-NG VF (Stonesoft virtual_fw)</td>
<td>Toronto Users</td>
<td>h_172.16.20.170,<br> h_172.16.20.171</td>
<td>DNS (TCP),<br> Echo (TCP)</td>
<td>Reject</td>
</tr>
<tr>
<td>Palo-Usage Collector (PaloAltoNetworks PaloAltoFW)</td>
<td>192.168.0.0-192.168.255.255,<br> H_10.100.19.72</td>
<td>H_10.100.200.160,<br> Net_10.108.151.0</td>
<td>service-http,<br> service-https</td>
<td>Deny</td>
</tr>
</tbody>
</table>
</div>
</div>