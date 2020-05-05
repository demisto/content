<!-- HTML_DOC -->
<p class="has-line-data" data-line-start="0" data-line-end="1">Use the CounterTack integration to get information for endpoints and behaviors, manage tags, quarantine endpoints, and manage files.</p>
<h2 class="code-line" data-line-start="1" data-line-end="2">
<a id="Configure_CounterTack_on_Demisto_1"></a>Configure CounterTack on Demisto</h2>
<ol>
<li class="has-line-data" data-line-start="2" data-line-end="3">Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li class="has-line-data" data-line-start="3" data-line-end="4">Search for CounterTack.</li>
<li class="has-line-data" data-line-start="4" data-line-end="15">Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li class="has-line-data" data-line-start="5" data-line-end="6">
<strong>Name</strong>: a textual name for the integration instance.</li>
<li class="has-line-data" data-line-start="6" data-line-end="7"><strong>Server URL (e.g.<span> </span>https://democloud.countertack.com)</strong></li>
<li class="has-line-data" data-line-start="7" data-line-end="8"><strong>User Name</strong></li>
<li class="has-line-data" data-line-start="8" data-line-end="9"><strong>Use system proxy settings</strong></li>
<li class="has-line-data" data-line-start="9" data-line-end="10"><strong>Trust any certificate (not secure)</strong></li>
<li class="has-line-data" data-line-start="10" data-line-end="11"><strong>Fetch incidents</strong></li>
<li class="has-line-data" data-line-start="11" data-line-end="12"><strong>Incident type</strong></li>
<li class="has-line-data" data-line-start="12" data-line-end="13"><strong>First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year)</strong></li>
<li class="has-line-data" data-line-start="13" data-line-end="14"><strong>Fetch notifications incidents</strong></li>
<li class="has-line-data" data-line-start="14" data-line-end="15"><strong>Fetch behviors incidents</strong></li>
</ul>
</li>
<li class="has-line-data" data-line-start="15" data-line-end="16">Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2 class="code-line" data-line-start="16" data-line-end="17">
<a id="Commands_16"></a>Commands</h2>
<p class="has-line-data" data-line-start="17" data-line-end="18">You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li class="has-line-data" data-line-start="18" data-line-end="19"><a href="#h_4f9ab19e-a19d-421f-b2ce-7f462093c882" target="_self"> Get information for multiple endpoints: countertack-get-endpoints </a></li>
<li class="has-line-data" data-line-start="19" data-line-end="20"><a href="#h_fecf6c35-3d41-47eb-be29-a37ea46cc153" target="_self"> Get information for all behaviors: countertack-get-behaviors </a></li>
<li class="has-line-data" data-line-start="20" data-line-end="21"><a href="#h_a10fe1d1-c126-4eb6-a1e4-37c14da55edf" target="_self"> Get information for a single endpoint: countertack-get-endpoint </a></li>
<li class="has-line-data" data-line-start="21" data-line-end="22"><a href="#h_56d50a38-d9dc-4855-b579-7834fa778f80" target="_self"> Get information for a single behavior: countertack-get-behavior </a></li>
<li class="has-line-data" data-line-start="22" data-line-end="23"><a href="#h_c3ef9fd9-59ed-48ad-9b11-c9135fc177d3" target="_self">Get the tags for an endpoint: countertack-get-endpoint-tags</a></li>
<li class="has-line-data" data-line-start="23" data-line-end="24"><a href="#h_177d1ab3-5105-4165-946c-cfbe1315a683" target="_self">Add tags to an endpoint: countertack-add-tags</a></li>
<li class="has-line-data" data-line-start="24" data-line-end="25"><a href="#h_71aac75c-b0ec-4c7b-8566-cbec9ad4e3c1" target="_self">Delete tags from an endpoint: countertack-delete-tags</a></li>
<li class="has-line-data" data-line-start="25" data-line-end="26"><a href="#h_fcef2152-d35f-4924-8174-8e0d02400a40" target="_self">Add tags to a behavior: countertack-add-behavior-tags</a></li>
<li class="has-line-data" data-line-start="26" data-line-end="27"><a href="#h_247ffe89-0f7c-4ad7-b622-7099a0eed512" target="_self"> Delete tags from a behavior: countertack-delete-behavior-tags </a></li>
<li class="has-line-data" data-line-start="27" data-line-end="28"><a href="#h_f1616c2b-bfdf-45eb-8598-a6b0f0709c94" target="_self">Quarantine an endpoint: countertack-endpoint-quarantine</a></li>
<li class="has-line-data" data-line-start="28" data-line-end="29"><a href="#h_2fbd1d96-6eef-46d9-8ecc-8e48708f5b99" target="_self"> Remove an endpoint from quarantine: countertack-disable-quarantine </a></li>
<li class="has-line-data" data-line-start="29" data-line-end="30"><a href="#h_bd041638-3f1c-4ec9-afa7-85a643ff8485" target="_self">Extract a file from an endpoint: countertack-extract-file</a></li>
<li class="has-line-data" data-line-start="30" data-line-end="31"><a href="#h_1cd3a62b-87a6-4f55-80a3-fc8307880bb2" target="_self">Delete a file from an endpoint: countertack-delete-file</a></li>
<li class="has-line-data" data-line-start="31" data-line-end="32"><a href="#h_6a331519-1fc4-4db3-be4c-f0021d2c97f7" target="_self">Get all files for all endpoints: countertack-get-all-files</a></li>
<li class="has-line-data" data-line-start="32" data-line-end="33"><a href="#h_e7fa7578-3437-492c-be6b-df5e96038ccc" target="_self"> Return all files for a single endpoint: countertack-get-endpoint-files </a></li>
<li class="has-line-data" data-line-start="33" data-line-end="34"><a href="#h_5297485a-7812-4f0e-ae74-4a69969523a9" target="_self"> Get information for a file: countertack-get-file-information </a></li>
<li class="has-line-data" data-line-start="34" data-line-end="35"><a href="#h_ede8dfd7-4676-4399-bb38-18c85b427933" target="_self">Download a file: countertack-download-file</a></li>
<li class="has-line-data" data-line-start="35" data-line-end="36"><a href="#h_764a00dc-9381-4197-a411-b474dec45638" target="_self">Search for events: countertack-search-events</a></li>
<li class="has-line-data" data-line-start="36" data-line-end="37"><a href="#h_7180250f-9c10-4a6f-8d5e-dfc37a0b2cbb" target="_self"> Terminate all instances of a process: countertack-kill-process </a></li>
<li class="has-line-data" data-line-start="37" data-line-end="38"><a href="#h_97ba610b-549f-48d1-84e4-2e801caa0004" target="_self">Search for file hashes: countertack-search-hashes</a></li>
<li class="has-line-data" data-line-start="38" data-line-end="39"><a href="#h_04015056-544a-47e4-aa6c-28bc645d5c19" target="_self">Search for endpoints: countertack-search-endpoints</a></li>
<li class="has-line-data" data-line-start="39" data-line-end="41"><a href="#h_f499a204-8783-4238-bfcc-f8070b8e3cc3" target="_self">Search for behaviors: countertack-search-behaviors</a></li>
</ol>
<h3 id="h_4f9ab19e-a19d-421f-b2ce-7f462093c882" class="code-line" data-line-start="41" data-line-end="42">
<a id="1_Get_information_for_endpoints_41"></a>1. Get information for endpoints</h3>
<hr>
<p class="has-line-data" data-line-start="43" data-line-end="44">Returns information for endpoints.</p>
<p class="has-line-data" data-line-start="45" data-line-end="46"> </p>
<h5 class="code-line" data-line-start="46" data-line-end="47">
<a id="Base_Command_46"></a>Base Command</h5>
<p class="has-line-data" data-line-start="48" data-line-end="49"><code>countertack-get-endpoints</code></p>
<h5 class="code-line" data-line-start="49" data-line-end="50">
<a id="Input_49"></a>Input</h5>
<p>There are no arguments for this command.</p>
<h5 class="code-line" data-line-start="55" data-line-end="56">
<a id="Context_Output_55"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 323.4px;"><strong>Path</strong></th>
<th style="width: 58.6px;"><strong>Type</strong></th>
<th style="width: 357px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.IsQuarantined</td>
<td style="width: 58.6px;">boolean</td>
<td style="width: 357px;">Whether the endpoint currently quarantined.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.MaxImpact</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">Impact of the highest scoring behavior.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Memory</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">The RAM of the endpoint (in megabytes).</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.DriverVersion</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Endpoint sensor version.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.ProfileVersion</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Version of the current profile used for collection.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.BehaviorCount</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">Number of behaviors detected.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.CurrentProfile</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Currently active analysis profile.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Domain</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">DNS suffix for the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.NumCpus</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">Number of CPUs.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Macs</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">MAC addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.WinRdpPort</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">RDP port used by the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Ip</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">IP address used to connect to the analysis cluster.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.ClusterHosts</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The list of hosts that the endpoint tries to connect through (in order).</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Vendor</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">OS vendor.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.SensorMode</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Specifies the sensor mode of the driver.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Identifier</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">OS identifier.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.CurrentResponsePolicy</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Currently active response policy.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Tenant</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Tenant ID set at the time of KM installation.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Name</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.ImpactLevel</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Threat level of the endpoint (LOW, MEDIUM, HIGH, CRITICAL).</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Ips</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">IP addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.ClusterConnectionRoute</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">List of hosts through which the endpoint is currently connected.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.LastActive</td>
<td style="width: 58.6px;">date</td>
<td style="width: 357px;">Time of last event captured on the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.TimeStarted</td>
<td style="width: 58.6px;">date</td>
<td style="width: 357px;">Time kernel module collection last engaged.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Mac</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The endpoint MAC address.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.EventStartTime</td>
<td style="width: 58.6px;">date</td>
<td style="width: 357px;">The time that the event was captured.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.CpuType</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Bit length of the CPU architecture.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Status</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Collection status of the endpoint (ON, PAUSE, OFF, INIT).</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.OsType</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">OS type.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Version</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">OS version.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Tags</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">List of user-assigned tags.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Threat</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Threat level associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.Id</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Endpoints ID</td>
</tr>
<tr>
<td style="width: 323.4px;">CounterTack.Endpoint.ProductName</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.Memory</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">Endpoint RAM (in megabytes).</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.Processors</td>
<td style="width: 58.6px;">number</td>
<td style="width: 357px;">Number of CPUs.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.Domain</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">DNS suffix for the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.OS</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">Product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.MACAddress</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.Model</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The analysis profile that is currently active.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.IPAddress</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The IP addresses that are associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.OSVersion</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The endpoint sensor version.</td>
</tr>
<tr>
<td style="width: 323.4px;">Endpoint.ID</td>
<td style="width: 58.6px;">string</td>
<td style="width: 357px;">The IDs of the endpoints.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="104" data-line-end="105">
<a id="Command_Example_104"></a>Command Example</h5>
<pre>!countertack-get-endpoints</pre>
<h5 class="code-line" data-line-start="107" data-line-end="108">
<a id="Context_Example_107"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": [
        {
            "IsQuarantined": false, 
            "ImpactLevel": "CRITICAL", 
            "CurrentResponsePolicy": "policy-1541066935463560", 
            "ResponsePolicyVersion": "bf9df735239fc4509ec31f982bca87a0", 
            "Version": "10 v1607 x64", 
            "BehaviorCount": 35, 
            "Memory": 2008, 
            "MaxImpact": 100, 
            "Status": "UNINSTALL", 
            "ClusterHosts": [
                "trialcloud.countertack.com"
            ], 
            "Macs": [
                "06:DD:7F:80:00:1A", 
                "NULL"
            ], 
            "TimeStarted": "2019-03-14T21:02:10.130+0000", 
            "Tags": [
                "Test", 
                "check", 
                "demisto", 
                "test1"
            ], 
            "EventStartTime": "2019-03-14T21:01:39.595+0000", 
            "DriverVersion": "5.8.4.17", 
            "SensorMode": "basic", 
            "Mac": "06:DD:7F:80:00:1A", 
            "OsType": 1, 
            "CpuType": "64", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "EC2AMAZ-D6LF2KI", 
            "WinRdpPort": 3389, 
            "ProfileVersion": "d761152277565ff7b20af5d3002d94f1", 
            "CurrentProfile": "Default-Windows-Profile", 
            "Threat": "CRITICAL", 
            "Vendor": "Microsoft", 
            "Identifier": "Windows", 
            "Domain": "eu-central-1.compute.internal", 
            "Ip": "172.31.36.196", 
            "ProductName": "Windows Server 2016 Datacenter", 
            "Ips": [
                "172.31.36.196", 
                "fe80:0000:0000:0000:91ba:7558:26d3:acde", 
                "2001:0000:9d38:6ab8:2811:397d:53e0:db3b", 
                "fe80:0000:0000:0000:2811:397d:53e0:db3b", 
                "fe80:0000:0000:0000:0000:5efe:ac1f:24c4"
            ], 
            "ClusterConnectionRoute": [
                "democloud-collector01.us-west2b.countertack.com", 
                "democloud.countertack.com"
            ], 
            "LastActive": "2019-03-18T17:33:02.406+0000", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "NumCpus": 2
        }, 
        {
            "IsQuarantined": false, 
            "ImpactLevel": "HIGH", 
            "MaxImpact": 90, 
            "Version": "Enterprise Linux 3.10.0-862 x86_64", 
            "BehaviorCount": 5, 
            "Memory": 1800, 
            "Status": "UNINSTALL", 
            "ClusterHosts": [
                "trialcloud.countertack.com"
            ], 
            "Macs": [
                "06:F9:DE:36:DD:B0"
            ], 
            "TimeStarted": "2019-03-14T21:02:10.113+0000", 
            "Tags": [
                "test2", 
                "test1"
            ], 
            "EventStartTime": "2019-03-14T21:01:39.180+0000", 
            "DriverVersion": "5.8.4.61", 
            "SensorMode": "advanced", 
            "Mac": "06:F9:DE:36:DD:B0", 
            "OsType": 2, 
            "CpuType": "64", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "ip-172-31-36-134.eu-central-1.compute.internal", 
            "WinRdpPort": 0, 
            "ProfileVersion": "cda8c4825cfc60025ae42ee74eab00e3", 
            "CurrentProfile": "Default-Linux-Profile", 
            "Threat": "HIGH", 
            "Vendor": "CentOS", 
            "Identifier": "Linux", 
            "Domain": "", 
            "Ip": "172.31.36.134", 
            "ProductName": "CentOS Linux release 7.5.1804 (Core)", 
            "Ips": [
                "172.31.36.134", 
                "fe80:0000:0000:0000:04f9:deff:fe36:ddb0"
            ], 
            "ClusterConnectionRoute": [
                "democloud-collector01.us-west2b.countertack.com", 
                "democloud.countertack.com"
            ], 
            "LastActive": "2019-03-18T17:33:02.406+0000", 
            "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "NumCpus": 2
        }, 
        {
            "ImpactLevel": "HIGH", 
            "CurrentResponsePolicy": "policy-1541066914070800", 
            "ResponsePolicyVersion": "29f9f82456c0fa377c37bd8a5a85ccf4", 
            "Version": "Darwin 18.5.0 x86_64", 
            "GroupIds": [
                "groups-builtin-outdated-km"
            ], 
            "BehaviorCount": 42315, 
            "Memory": 16384, 
            "MaxImpact": 90, 
            "Status": "OFF", 
            "ClusterHosts": [
                "trialcloud.countertack.com"
            ], 
            "Macs": [
                "00:00:00:00:00:00", 
                "AC:DE:48:00:11:22"
            ], 
            "TimeStarted": "2019-05-21T09:03:49.591+0000", 
            "EventStartTime": "2019-05-21T09:03:47.578+0000", 
            "DriverVersion": "5.8.4.64", 
            "SensorMode": "advanced", 
            "Mac": "", 
            "OsType": 2, 
            "CpuType": "64", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "TLVMAC30YCJG5H", 
            "WinRdpPort": 0, 
            "ProfileVersion": "b95032b028b3417dc7c09e19c9d7e326", 
            "CurrentProfile": "Default-Mac-Profile", 
            "Threat": "HIGH", 
            "Vendor": "Apple", 
            "Identifier": "macOS", 
            "Domain": "", 
            "Ip": "172.22.100.85", 
            "ProductName": "macOS 10.14.4 Mojave", 
            "Ips": [
                "fe80:0008:0000:0000:aede:48ff:fe00:1122"
            ], 
            "ClusterConnectionRoute": [
                "democloud-collector02.us-west2c.countertack.com", 
                "democloud.countertack.com"
            ], 
            "LastActive": "2019-05-21T09:03:49.591+0000", 
            "Id": "8ce40b54-154e-ccd9-3ae5-46011c1b6b50", 
            "NumCpus": 12
        }
    ], 
    "Endpoint": [
        {
            "MACAddress": "06:DD:7F:80:00:1A", 
            "Domain": "eu-central-1.compute.internal", 
            "Processors": 2, 
            "OS": "Windows Server 2016 Datacenter", 
            "Memory": 2008, 
            "Model": "Default-Windows-Profile", 
            "OSVersion": "5.8.4.17", 
            "IPAddress": [
                "172.31.36.196", 
                "fe80:0000:0000:0000:91ba:7558:26d3:acde", 
                "2001:0000:9d38:6ab8:2811:397d:53e0:db3b", 
                "fe80:0000:0000:0000:2811:397d:53e0:db3b", 
                "fe80:0000:0000:0000:0000:5efe:ac1f:24c4"
            ], 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567"
        }, 
        {
            "MACAddress": "06:F9:DE:36:DD:B0", 
            "Domain": "", 
            "Processors": 2, 
            "OS": "CentOS Linux release 7.5.1804 (Core)", 
            "Memory": 1800, 
            "Model": "Default-Linux-Profile", 
            "OSVersion": "5.8.4.61", 
            "IPAddress": [
                "172.31.36.134", 
                "fe80:0000:0000:0000:04f9:deff:fe36:ddb0"
            ], 
            "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62"
        }, 
        {
            "MACAddress": "", 
            "Domain": "", 
            "Processors": 12, 
            "OS": "macOS 10.14.4 Mojave", 
            "Memory": 16384, 
            "Model": "Default-Mac-Profile", 
            "OSVersion": "5.8.4.64", 
            "IPAddress": [
                "fe80:0008:0000:0000:aede:48ff:fe00:1122"
            ], 
            "Id": "8ce40b54-154e-ccd9-3ae5-46011c1b6b50"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="313" data-line-end="314">
<a id="Human_Readable_Output_313"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="314" data-line-end="315">
<a id="CounterTack_Endpoints_314"></a>CounterTack Endpoints</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>OS</th>
<th>Name</th>
<th>Threat</th>
<th>Status</th>
<th>Id</th>
<th>IP</th>
</tr>
</thead>
<tbody>
<tr>
<td>Windows Server 2016 Datacenter</td>
<td>EC2AMAZ-D6LF2KI</td>
<td>CRITICAL</td>
<td>UNINSTALL</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>172.31.36.196,&lt;br&gt;fe80:0000:0000:0000:91ba:7558:26d3:acde,&lt;br&gt;2001:0000:9d38:6ab8:2811:397d:53e0:db3b,&lt;br&gt;fe80:0000:0000:0000:2811:397d:53e0:db3b,&lt;br&gt;fe80:0000:0000:0000:0000:5efe:ac1f:24c4</td>
</tr>
<tr>
<td>CentOS Linux release 7.5.1804 (Core)</td>
<td>ip-172-31-36-134.eu-central-1.compute.internal</td>
<td>HIGH</td>
<td>UNINSTALL</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>172.31.36.134,&lt;br&gt;fe80:0000:0000:0000:04f9:deff:fe36:ddb0</td>
</tr>
<tr>
<td>macOS 10.14.4 Mojave</td>
<td>TLVMAC30YCJG5H</td>
<td>HIGH</td>
<td>OFF</td>
<td>8ce40b54-154e-ccd9-3ae5-46011c1b6b50</td>
<td>fe80:0008:0000:0000:aede:48ff:fe00:1122</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_fecf6c35-3d41-47eb-be29-a37ea46cc153" class="code-line" data-line-start="322" data-line-end="323">2. Get information for all behaviors</h3>
<hr>
<p class="has-line-data" data-line-start="324" data-line-end="325">Returns information for all behaviors.</p>
<p class="has-line-data" data-line-start="326" data-line-end="327"> </p>
<h5 class="code-line" data-line-start="327" data-line-end="328">
<a id="Base_Command_327"></a>Base Command</h5>
<p class="has-line-data" data-line-start="329" data-line-end="330"><code>countertack-get-behaviors</code></p>
<h5 class="code-line" data-line-start="330" data-line-end="331">
<a id="Input_330"></a>Input</h5>
<p>There are no arguments for this command.</p>
<h5 class="code-line" data-line-start="336" data-line-end="337">
<a id="Context_Output_336"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 250px;"><strong>Path</strong></th>
<th style="width: 64.4px;"><strong>Type</strong></th>
<th style="width: 424.6px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 250px;">CounterTack.Behavior.MaxImpact</td>
<td style="width: 64.4px;">number</td>
<td style="width: 424.6px;">The impact of the highest scoring event (0-100).</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.EndpointId</td>
<td style="width: 64.4px;">string</td>
<td style="width: 424.6px;">The ID of the endpoint, based on the UUID of the last installed endpoint sensor.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.Tenant</td>
<td style="width: 64.4px;">string</td>
<td style="width: 424.6px;">The tenant of the behavior.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.EventCount</td>
<td style="width: 64.4px;">number</td>
<td style="width: 424.6px;">The number of events detected.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.Name</td>
<td style="width: 64.4px;">string</td>
<td style="width: 424.6px;">The name of the condition that triggered the behavior.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.ImpactLevel</td>
<td style="width: 64.4px;">string</td>
<td style="width: 424.6px;">The threat level of the behavior (LOW, MEDIUM, HIGH, CRITICAL).</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.LastActive</td>
<td style="width: 64.4px;">date</td>
<td style="width: 424.6px;">The time that the behavior was last active.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.FirstEventId</td>
<td style="width: 64.4px;">date</td>
<td style="width: 424.6px;">The ID of the first event.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.TimeStamp</td>
<td style="width: 64.4px;">date</td>
<td style="width: 424.6px;">The start time for the behavior.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.Type</td>
<td style="width: 64.4px;">string</td>
<td style="width: 424.6px;">The type of behavior (CLASSIFICATION, TRACE).</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.Id</td>
<td style="width: 64.4px;">string</td>
<td style="width: 424.6px;">The ID of the behaviors.</td>
</tr>
<tr>
<td style="width: 250px;">CounterTack.Behavior.LastReported</td>
<td style="width: 64.4px;">date</td>
<td style="width: 424.6px;">The time that the behavior was last seen.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="354" data-line-end="355">
<a id="Command_Example_354"></a>Command Example</h5>
<pre>!countertack-get-behaviors</pre>
<h5 class="code-line" data-line-start="357" data-line-end="358">
<a id="Context_Example_357"></a>Context Example</h5>
<pre>{
    "CounterTack.Behavior": [
        {
            "MaxImpact": 50, 
            "EventCount": 7, 
            "ReportedOn": "2019-02-07T05:27:35.143+0000", 
            "TimeStamp": "2019-02-07T05:27:35.532+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p_AkQh065M", 
            "LastActive": "2019-02-07T05:27:37.535+0000", 
            "LastReported": "2019-02-07T05:27:35.194+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7673854781711167052", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "Tags": [], 
            "MaxImpact": 100, 
            "EventCount": 1339, 
            "ReportedOn": "2019-02-03T08:51:52.067+0000", 
            "TimeStamp": "2019-02-03T08:51:53.271+0000", 
            "ImpactLevel": "CRITICAL", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2qAMXCdfte4", 
            "LastActive": "2019-02-07T08:53:18.023+0000", 
            "LastReported": "2019-02-07T08:53:10.087+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7674188124787759032", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Sponsor process started"
        }, 
        {
            "MaxImpact": 10, 
            "EventCount": 6, 
            "ReportedOn": "2019-02-11T13:34:20.790+0000", 
            "TimeStamp": "2019-02-11T13:34:32.502+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p9rWHjbnaE", 
            "LastActive": "2019-02-11T13:34:32.530+0000", 
            "LastReported": "2019-02-11T13:34:20.806+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "SciId": "176349c6-7642-3601-0dcb-b225bd95c567!windows_service_manager_1", 
            "Type": "classification", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!9223370486962703305!newService.WindowsServiceManager", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "newService.WindowsServiceManager"
        }, 
        {
            "Tags": [], 
            "MaxImpact": 10, 
            "EventCount": 1, 
            "ReportedOn": "2019-01-29T12:45:45.500+0000", 
            "TimeStamp": "2019-01-29T12:45:46.483+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "tc0yqKrFWGKu7piLpyuKYmqBrZQKOJox", 
            "LastActive": "2019-01-29T12:45:46.484+0000", 
            "LastReported": "2019-01-29T12:45:45.500+0000", 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "Type": "trace", 
            "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606091354282545", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Unix: Credentials lift to superuser"
        }, 
        {
            "Tags": [], 
            "MaxImpact": 75, 
            "EventCount": 1, 
            "ReportedOn": "2019-02-03T08:22:42.688+0000", 
            "TimeStamp": "2019-02-03T08:22:46.483+0000", 
            "ImpactLevel": "HIGH", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2qAMwfsjU-2", 
            "LastActive": "2019-02-03T08:22:46.485+0000", 
            "LastReported": "2019-02-03T08:22:42.688+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7674189874165796790", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Powershell: System.Management.Automation.dll file read"
        }, 
        {
            "Tags": [], 
            "MaxImpact": 10, 
            "EventCount": 1, 
            "ReportedOn": "2019-01-29T12:45:27.979+0000", 
            "TimeStamp": "2019-01-29T12:45:28.473+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "tc0yqKrFWGKu7piLpyuKYmqBrZgehzkV", 
            "LastActive": "2019-01-29T12:45:28.474+0000", 
            "LastReported": "2019-01-29T12:45:27.979+0000", 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "Type": "trace", 
            "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606108874848533", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Unix: Credentials lift to superuser"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 24, 
            "ReportedOn": "2019-02-18T05:26:56.053+0000", 
            "TimeStamp": "2019-02-18T05:26:56.861+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7oer9XUcD", 
            "LastActive": "2019-02-18T06:00:05.895+0000", 
            "LastReported": "2019-02-18T06:00:00.873+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672904420800939779", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 17, 
            "ReportedOn": "2019-02-19T05:27:07.092+0000", 
            "TimeStamp": "2019-02-19T05:27:07.926+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7U1PaH_e-", 
            "LastActive": "2019-02-19T11:40:07.401+0000", 
            "LastReported": "2019-02-19T11:40:06.648+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672818009762691006", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "MaxImpact": 15, 
            "EventCount": 19, 
            "ReportedOn": "2019-02-18T15:36:12.782+0000", 
            "TimeStamp": "2019-02-18T15:36:15.024+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7gKt2hpET", 
            "LastActive": "2019-02-19T13:55:41.749+0000", 
            "LastReported": "2019-02-19T13:55:39.356+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672867864072065299", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Sponsor process started"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 46, 
            "ReportedOn": "2019-02-20T05:27:24.057+0000", 
            "TimeStamp": "2019-02-20T05:27:24.744+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7BLtVk609", 
            "LastActive": "2019-02-20T11:40:38.774+0000", 
            "LastReported": "2019-02-20T11:40:36.549+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672731592796908861", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="520" data-line-end="521">
<a id="Human_Readable_Output_520"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="521" data-line-end="522">
<a id="CounterTack_Endpoints_Behaviors_521"></a>CounterTack Endpoints Behaviors</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Name</th>
<th>Id</th>
<th>Type</th>
<th>ImpactLevel</th>
<th>EndpointId</th>
<th>lastReported</th>
</tr>
</thead>
<tbody>
<tr>
<td>Commandline Utility Process Created</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7673854781711167052</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-07T05:27:35.194+0000</td>
</tr>
<tr>
<td>Sponsor process started</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7674188124787759032</td>
<td>trace</td>
<td>CRITICAL</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-07T08:53:10.087+0000</td>
</tr>
<tr>
<td>newService.WindowsServiceManager</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!9223370486962703305!newService.WindowsServiceManager</td>
<td>classification</td>
<td>LOW</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-11T13:34:20.806+0000</td>
</tr>
<tr>
<td>Unix: Credentials lift to superuser</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606091354282545</td>
<td>trace</td>
<td>LOW</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-01-29T12:45:45.500+0000</td>
</tr>
<tr>
<td>Powershell: System.Management.Automation.dll file read</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7674189874165796790</td>
<td>trace</td>
<td>HIGH</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-03T08:22:42.688+0000</td>
</tr>
<tr>
<td>Unix: Credentials lift to superuser</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606108874848533</td>
<td>trace</td>
<td>LOW</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-01-29T12:45:27.979+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672904420800939779</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-18T06:00:00.873+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672818009762691006</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-19T11:40:06.648+0000</td>
</tr>
<tr>
<td>Sponsor process started</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672867864072065299</td>
<td>trace</td>
<td>LOW</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-19T13:55:39.356+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672731592796908861</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-20T11:40:36.549+0000</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a10fe1d1-c126-4eb6-a1e4-37c14da55edf" class="code-line" data-line-start="536" data-line-end="537">
<a id="3_Get_information_for_a_single_endpoint_536"></a>3. Get information for a single endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="538" data-line-end="539">Returns information for a single endpoint.</p>
<h5 class="code-line" data-line-start="541" data-line-end="542">
<a id="Base_Command_541"></a>Base Command</h5>
<p class="has-line-data" data-line-start="543" data-line-end="544"><code>countertack-get-endpoint</code></p>
<h5 class="code-line" data-line-start="544" data-line-end="545">
<a id="Input_544"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 519px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">endpoint_id</td>
<td style="width: 519px;">The ID of the endpoint. To get the “endpoint_id”, run the<span> </span><code>get-endpoints</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="551" data-line-end="552">
<br> <a id="Context_Output_551"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 321px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 356px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.MaxImpact</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The impact of the highest scoring behavior.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Memory</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The RAM of the endpoint (in megabytes).</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.DriverVersion</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The sensor version of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.ProfileVersion</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The version of the current profile used for collection.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.BehaviorCount</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The number of behaviors that were detected.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.CurrentProfile</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The analysis profile that is currently active.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Domain</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">DNS suffix for the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.NumCpus</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The number of CPUs for the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.WinRdpPort</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The RDP port used by the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Macs</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The MAC addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Ip</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The IP address used to connect to the analysis cluster.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.ClusterHosts</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The list of hosts that the endpoint tries to connect through (in order).</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Vendor</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">OS vendor.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.SensorMode</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The sensor mode of the driver.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Identifier</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The identifier of the OS.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Tenant</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The tenant ID that was set at the time of KM installation.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The machine name of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.ImpactLevel</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The threat level of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Ips</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The IP addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.ClusterConnectionRoute</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The list of hosts that the endpoint is currently connected through.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.LastActive</td>
<td style="width: 63px;">date</td>
<td style="width: 356px;">The time of the last event that was captured on the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.TimeStarted</td>
<td style="width: 63px;">date</td>
<td style="width: 356px;">The first time that the endpoint started to work.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Mac</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.EventStartTime</td>
<td style="width: 63px;">date</td>
<td style="width: 356px;">The time that the event was captured.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.CpuType</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The bit length of the CPU architecture.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Status</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The collection status of the endpoint (ON, PAUSE, OFF, INIT).</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.OsType</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The OS type.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Version</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The version of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Threat</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The threat level associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Id</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.ProductName</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.Tags</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The list of user-assigned tags.</td>
</tr>
<tr>
<td style="width: 321px;">CounterTack.Endpoint.IsQuarantined</td>
<td style="width: 63px;">boolean</td>
<td style="width: 356px;">Whether the endpoint is currently quarantined.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.Memory</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The RAM of the endpoint (in megabytes).</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.Processors</td>
<td style="width: 63px;">number</td>
<td style="width: 356px;">The number of CPUs.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.Domain</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The DNS suffix for the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.OS</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.MACAddress</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.Model</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The analysis profile that is currently active.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.IPAddress</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The IP addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 321px;">Endpoint.OSVersion</td>
<td style="width: 63px;">string</td>
<td style="width: 356px;">The version of the endpoint sensor.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="598" data-line-end="599">
<a id="Command_Example_598"></a>Command Example</h5>
<pre>!countertack-get-endpoint endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567</pre>
<h5 class="code-line" data-line-start="601" data-line-end="602">
<a id="Context_Example_601"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": {
        "IsQuarantined": false, 
        "ImpactLevel": "CRITICAL", 
        "CurrentResponsePolicy": "policy-1541066935463560", 
        "ResponsePolicyVersion": "bf9df735239fc4509ec31f982bca87a0", 
        "Version": "10 v1607 x64", 
        "BehaviorCount": 35, 
        "Memory": 2008, 
        "MaxImpact": 100, 
        "Status": "UNINSTALL", 
        "ClusterHosts": [
            "trialcloud.countertack.com"
        ], 
        "Macs": [
            "06:DD:7F:80:00:1A", 
            "NULL"
        ], 
        "TimeStarted": "2019-03-14T21:02:10.130+0000", 
        "Tags": [
            "Test", 
            "check", 
            "demisto", 
            "test1"
        ], 
        "EventStartTime": "2019-03-14T21:01:39.595+0000", 
        "DriverVersion": "5.8.4.17", 
        "SensorMode": "basic", 
        "Mac": "06:DD:7F:80:00:1A", 
        "OsType": 1, 
        "CpuType": "64", 
        "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
        "Name": "EC2AMAZ-D6LF2KI", 
        "WinRdpPort": 3389, 
        "ProfileVersion": "d761152277565ff7b20af5d3002d94f1", 
        "CurrentProfile": "Default-Windows-Profile", 
        "Threat": "CRITICAL", 
        "Vendor": "Microsoft", 
        "Identifier": "Windows", 
        "Domain": "eu-central-1.compute.internal", 
        "Ip": "172.31.36.196", 
        "ProductName": "Windows Server 2016 Datacenter", 
        "Ips": [
            "172.31.36.196", 
            "fe80:0000:0000:0000:91ba:7558:26d3:acde", 
            "2001:0000:9d38:6ab8:2811:397d:53e0:db3b", 
            "fe80:0000:0000:0000:2811:397d:53e0:db3b", 
            "fe80:0000:0000:0000:0000:5efe:ac1f:24c4"
        ], 
        "ClusterConnectionRoute": [
            "democloud-collector01.us-west2b.countertack.com", 
            "democloud.countertack.com"
        ], 
        "LastActive": "2019-03-18T17:33:02.406+0000", 
        "Id": "176349c6-7642-3601-0dcb-b225bd95c567", 
        "NumCpus": 2
    }, 
    "Endpoint": {
        "MACAddress": "06:DD:7F:80:00:1A", 
        "Domain": "eu-central-1.compute.internal", 
        "Processors": 2, 
        "OS": "Windows Server 2016 Datacenter", 
        "Memory": 2008, 
        "Model": "Default-Windows-Profile", 
        "OSVersion": "5.8.4.17", 
        "IPAddress": [
            "172.31.36.196", 
            "fe80:0000:0000:0000:91ba:7558:26d3:acde", 
            "2001:0000:9d38:6ab8:2811:397d:53e0:db3b", 
            "fe80:0000:0000:0000:2811:397d:53e0:db3b", 
            "fe80:0000:0000:0000:0000:5efe:ac1f:24c4"
        ], 
        "Id": "176349c6-7642-3601-0dcb-b225bd95c567"
    }
}
</pre>
<h5 class="code-line" data-line-start="680" data-line-end="681">
<a id="Human_Readable_Output_680"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="681" data-line-end="682">
<a id="CounterTack_Endpoint_information_681"></a>CounterTack Endpoint information:</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>OS</th>
<th>Domain</th>
<th>IP</th>
<th>Threat</th>
<th>MaxImpact</th>
<th>TenantID</th>
<th>IsQuarantined</th>
<th>Profile</th>
<th>Tags</th>
<th>Status</th>
</tr>
</thead>
<tbody>
<tr>
<td>Windows Server 2016 Datacenter</td>
<td>eu-central-1.compute.internal</td>
<td>172.31.36.196</td>
<td>CRITICAL</td>
<td>100</td>
<td>fc35572e-0171-4bd3-9117-044188832e9e</td>
<td>false</td>
<td>Default-Windows-Profile</td>
<td>Test,&lt;br&gt;check,&lt;br&gt;demisto,&lt;br&gt;test1</td>
<td>UNINSTALL</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_56d50a38-d9dc-4855-b579-7834fa778f80" class="code-line" data-line-start="687" data-line-end="688">
<a id="4_Get_information_for_a_single_behavior_687"></a>4. Get information for a single behavior</h3>
<hr>
<p class="has-line-data" data-line-start="689" data-line-end="690">Returns information for a single behavior.</p>
<h5 class="code-line" data-line-start="690" data-line-end="691">
<a id="Required_Permissions_690"></a>Required Permissions</h5>
<p class="has-line-data" data-line-start="691" data-line-end="692"><strong>FILL IN REQUIRED PERMISSIONS HERE</strong></p>
<h5 class="code-line" data-line-start="692" data-line-end="693">
<a id="Base_Command_692"></a>Base Command</h5>
<p class="has-line-data" data-line-start="694" data-line-end="695"><code>countertack-get-behavior</code></p>
<p><a id="Input_695"></a>Input</p>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 256px;"><strong>Argument Name</strong></th>
<th style="width: 337px;"><strong>Description</strong></th>
<th style="width: 147px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256px;">behavior_id</td>
<td style="width: 337px;">The ID of the behavior.</td>
<td style="width: 147px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="702" data-line-end="703">
<a id="Context_Output_702"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 308px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 369px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 308px;">CounterTack.Behavior.MaxImpact</td>
<td style="width: 63px;">number</td>
<td style="width: 369px;">The maximum impact of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.EndpointId</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.Tenant</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The tenant of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.EventCount</td>
<td style="width: 63px;">number</td>
<td style="width: 369px;">The event count of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.ReportedOn</td>
<td style="width: 63px;">date</td>
<td style="width: 369px;">The time that the behavior was first seen.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The name of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.ImpactLevel</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The impact level of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.LastActive</td>
<td style="width: 63px;">date</td>
<td style="width: 369px;">The last time that the behavior was active.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.TimeStamp</td>
<td style="width: 63px;">date</td>
<td style="width: 369px;">The time stamp of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.FirstEventId</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The ID of the first event.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.Type</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The type of behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.Id</td>
<td style="width: 63px;">string</td>
<td style="width: 369px;">The ID of the behavior.</td>
</tr>
<tr>
<td style="width: 308px;">CounterTack.Behavior.LastReported</td>
<td style="width: 63px;">date</td>
<td style="width: 369px;">The time that the behavior was last seen.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="721" data-line-end="722">
<a id="Command_Example_721"></a>Command Example</h5>
<pre>!countertack-get-behavior behavior_id=b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428</pre>
<h5 class="code-line" data-line-start="724" data-line-end="725">
<a id="Context_Example_724"></a>Context Example</h5>
<pre>{
    "CounterTack.Behavior": {
        "Tags": [
            "test1"
        ], 
        "MaxImpact": 90, 
        "EventCount": 1, 
        "ReportedOn": "2019-01-29T12:46:10.642+0000", 
        "TimeStamp": "2019-01-29T12:46:11.501+0000", 
        "ImpactLevel": "HIGH", 
        "FirstEventId": "tc0yqKrFWGKu7piLpyuKYmqBrY4vna_M", 
        "LastActive": "2019-01-29T12:46:11.502+0000", 
        "LastReported": "2019-01-29T12:46:10.642+0000", 
        "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
        "Type": "trace", 
        "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428", 
        "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
        "Name": "Linux: bash history file modified"
    }
}
</pre>
<h5 class="code-line" data-line-start="748" data-line-end="749">
<a id="Human_Readable_Output_748"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="749" data-line-end="750">
<a id="CounterTack_Behavior_information_749"></a>CounterTack Behavior information</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Name</th>
<th>Id</th>
<th>ImpactLevel</th>
<th>MaxImpact</th>
<th>EventCount</th>
<th>Type</th>
<th>EndpointId</th>
<th>LastActive</th>
</tr>
</thead>
<tbody>
<tr>
<td>Linux: bash history file modified</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428</td>
<td>HIGH</td>
<td>90</td>
<td>1</td>
<td>trace</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-01-29T12:46:11.502+0000</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_c3ef9fd9-59ed-48ad-9b11-c9135fc177d3" class="code-line" data-line-start="755" data-line-end="756">
<a id="5_Get_the_tags_for_an_endpoint_755"></a>5. Get the tags for an endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="757" data-line-end="758">Returns the tags for the specified endpoint.</p>
<p class="has-line-data" data-line-start="759" data-line-end="760"> </p>
<h5 class="code-line" data-line-start="760" data-line-end="761">
<a id="Base_Command_760"></a>Base Command</h5>
<p class="has-line-data" data-line-start="762" data-line-end="763"><code>countertack-get-endpoint-tags</code></p>
<h5 class="code-line" data-line-start="763" data-line-end="764">
<a id="Input_763"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 189px;"><strong>Argument Name</strong></th>
<th style="width: 448px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 189px;">endpoint_id</td>
<td style="width: 448px;">The ID of the endpoint for which to get tags.</td>
<td style="width: 103px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="770" data-line-end="771">
<a id="Context_Output_770"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 359px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 359px;">CounterTack.Endpoint.Tags</td>
<td style="width: 59px;">string</td>
<td style="width: 322px;">The list of user-assigned tags.</td>
</tr>
<tr>
<td style="width: 359px;">CounterTack.Endpoint.EndpointId</td>
<td style="width: 59px;">string</td>
<td style="width: 322px;">The ID of the endpoints.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="778" data-line-end="779">
<a id="Command_Example_778"></a>Command Example</h5>
<pre>!countertack-get-endpoint-tags endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567</pre>
<h5 class="code-line" data-line-start="781" data-line-end="782">
<a id="Context_Example_781"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": {
        "Id": "176349c6-7642-3601-0dcb-b225bd95c567", 
        "Tags": {
            "tags": [
                "Test", 
                "check", 
                "demisto", 
                "test1"
            ]
        }
    }
}
</pre>
<h5 class="code-line" data-line-start="798" data-line-end="799">
<a id="Human_Readable_Output_798"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="799" data-line-end="800">
<a id="CounterTack_tags_for_the_specified_endpoint_799"></a>CounterTack tags for the specified endpoint:</h3>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th>tags</th>
</tr>
</thead>
<tbody>
<tr>
<td>Test,&lt;br&gt;check,&lt;br&gt;demisto,&lt;br&gt;test1</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_177d1ab3-5105-4165-946c-cfbe1315a683" class="code-line" data-line-start="805" data-line-end="806">
<a id="6_Add_tags_to_an_endpoint_805"></a>6. Add tags to an endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="807" data-line-end="808">Adds tags to the specified endpoint.</p>
<p class="has-line-data" data-line-start="809" data-line-end="810"> </p>
<h5 class="code-line" data-line-start="810" data-line-end="811">
<a id="Base_Command_810"></a>Base Command</h5>
<p class="has-line-data" data-line-start="812" data-line-end="813"><code>countertack-add-tags</code></p>
<h5 class="code-line" data-line-start="813" data-line-end="814">
<a id="Input_813"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 525px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">endpoint_id</td>
<td style="width: 525px;">The ID of the endpoint. To get the "<em>endpoint_id</em>", run the<span> </span><code>get-endpoints</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">tags</td>
<td style="width: 525px;">A CSV list of tags you want to add to the endpoint, for example, “test1,test2”.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="821" data-line-end="822">
<a id="Context_Output_821"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 384px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">CounterTack.Endpoint.EndpointId</td>
<td style="width: 52px;">string</td>
<td style="width: 384px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 304px;">CounterTack.Endpoint.Tags</td>
<td style="width: 52px;">string</td>
<td style="width: 384px;">The tags that were added to the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="829" data-line-end="830">
<a id="Command_Example_829"></a>Command Example</h5>
<pre>!countertack-add-tags endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567 tags=test2</pre>
<h5 class="code-line" data-line-start="832" data-line-end="833">
<a id="Context_Example_832"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": {
        "Id": "176349c6-7642-3601-0dcb-b225bd95c567", 
        "Tags": [
            "Test", 
            "check", 
            "demisto", 
            "test1"
        ]
    }
}
</pre>
<h5 class="code-line" data-line-start="847" data-line-end="848">
<a id="Human_Readable_Output_847"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="848" data-line-end="849">
<a id="Endpoint_tags_were_added_successfully_848"></a>Endpoint tags were added successfully</h3>
<table class="table table-striped table-bordered" style="width: 600px;" border="2">
<thead>
<tr>
<th style="width: 304px;">Id</th>
<th style="width: 289px;">tags</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">176349c6-7642-3601-0dcb-b225bd95c567</td>
<td style="width: 289px;">Test,&lt;br&gt;check,&lt;br&gt;demisto,&lt;br&gt;test1</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_71aac75c-b0ec-4c7b-8566-cbec9ad4e3c1" class="code-line" data-line-start="854" data-line-end="855">
<a id="7_Delete_tags_from_an_endpoint_854"></a>7. Delete tags from an endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="856" data-line-end="857">Deletes the supplied tags from the specified endpoint.</p>
<h5 class="code-line" data-line-start="859" data-line-end="860">
<a id="Base_Command_859"></a>Base Command</h5>
<p class="has-line-data" data-line-start="861" data-line-end="862"><code>countertack-delete-tags</code></p>
<h5 class="code-line" data-line-start="862" data-line-end="863">
<a id="Input_862"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 508px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">tags</td>
<td style="width: 508px;">A CSV list of tags to delete from the specified endpoint. </td>
<td style="width: 81px;">Required</td>
</tr>
<tr>
<td style="width: 151px;">endpoint_id</td>
<td style="width: 508px;">The endpoint ID. Get the ID from the “get-endpoints” command.</td>
<td style="width: 81px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="870" data-line-end="871">
<a id="Context_Output_870"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 296px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">CounterTack.Endpoint.Id</td>
<td style="width: 63px;">string</td>
<td style="width: 381px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 296px;">CounterTack.Endpoint.Tags</td>
<td style="width: 63px;">string</td>
<td style="width: 381px;">The tags of the specified endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="878" data-line-end="879">
<a id="Command_Example_878"></a>Command Example</h5>
<pre>!countertack-delete-tags endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567 tags=demisto</pre>
<h5 class="code-line" data-line-start="881" data-line-end="882">
<a id="Context_Example_881"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": {
        "Id": "176349c6-7642-3601-0dcb-b225bd95c567", 
        "Tags": [
            "test2", 
            "Test", 
            "check", 
            "demisto", 
            "test1"
        ]
    }
}
</pre>
<h5 class="code-line" data-line-start="897" data-line-end="898">
<a id="Human_Readable_Output_897"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="898" data-line-end="899">
<a id="Endpoint_tags_were_deleted_successfully_898"></a>Endpoint tags were deleted successfully</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Id</th>
<th>tags</th>
</tr>
</thead>
<tbody>
<tr>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>test2,&lt;br&gt;Test,&lt;br&gt;check,&lt;br&gt;demisto,&lt;br&gt;test1</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_fcef2152-d35f-4924-8174-8e0d02400a40" class="code-line" data-line-start="904" data-line-end="905">
<a id="8_Add_tags_to_a_behavior_904"></a>8. Add tags to a behavior</h3>
<hr>
<p class="has-line-data" data-line-start="906" data-line-end="907">Adds tags to a given behavior.</p>
<h5 class="code-line" data-line-start="909" data-line-end="910">
<a id="Base_Command_909"></a>Base Command</h5>
<p class="has-line-data" data-line-start="911" data-line-end="912"><code>countertack-add-behavior-tags</code></p>
<h5 class="code-line" data-line-start="912" data-line-end="913">
<a id="Input_912"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 515px;"><strong>Description</strong></th>
<th style="width: 78px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">behaviour_id</td>
<td style="width: 515px;">The ID of the behavior.</td>
<td style="width: 78px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">tags</td>
<td style="width: 515px;">A CSV list of tags to add to the behavior, for example, “test1,test2”.</td>
<td style="width: 78px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="920" data-line-end="921">
<a id="Context_Output_920"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 346px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 321px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 346px;">CounterTack.Behavior.Id</td>
<td style="width: 73px;">string</td>
<td style="width: 321px;">The ID of the behavior.</td>
</tr>
<tr>
<td style="width: 346px;">CounterTack.Behavior.Tags</td>
<td style="width: 73px;">string</td>
<td style="width: 321px;">The tags of the behavior.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="928" data-line-end="929">
<a id="Command_Example_928"></a>Command Example</h5>
<pre>!countertack-add-behavior-tags behaviour_id=b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428 tags=test2</pre>
<h5 class="code-line" data-line-start="931" data-line-end="932">
<a id="Context_Example_931"></a>Context Example</h5>
<pre>{
    "CounterTack.Behavior": {
        "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428", 
        "Tags": [
            "test2", 
            "test1"
        ]
    }
}
</pre>
<h5 class="code-line" data-line-start="944" data-line-end="945">
<a id="Human_Readable_Output_944"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="945" data-line-end="946">
<a id="Behavior_tags_were_added_successfully_945"></a>Behavior tags were added successfully</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Id</th>
<th>tags</th>
</tr>
</thead>
<tbody>
<tr>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428</td>
<td>test2,&lt;br&gt;test1</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_247ffe89-0f7c-4ad7-b622-7099a0eed512" class="code-line" data-line-start="951" data-line-end="952">
<a id="9_Delete_tags_from_a_behavior_951"></a>9. Delete tags from a behavior</h3>
<hr>
<p class="has-line-data" data-line-start="953" data-line-end="954">Deletes the supplied tags from the specified behavior.</p>
<p class="has-line-data" data-line-start="955" data-line-end="956"> </p>
<h5 class="code-line" data-line-start="956" data-line-end="957">
<a id="Base_Command_956"></a>Base Command</h5>
<p class="has-line-data" data-line-start="958" data-line-end="959"><code>countertack-delete-behavior-tags</code></p>
<h5 class="code-line" data-line-start="959" data-line-end="960">
<a id="Input_959"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 190px;"><strong>Argument Name</strong></th>
<th style="width: 447px;"><strong>Description</strong></th>
<th style="width: 103px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 190px;">behaviour_id</td>
<td style="width: 447px;">The behavior ID.</td>
<td style="width: 103px;">Required</td>
</tr>
<tr>
<td style="width: 190px;">tags</td>
<td style="width: 447px;">A CSV list of tags to delete from a behavior. </td>
<td style="width: 103px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="967" data-line-end="968">
<a id="Context_Output_967"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 330px;"><strong>Path</strong></th>
<th style="width: 107px;"><strong>Type</strong></th>
<th style="width: 303px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330px;">CounterTack.Behavior.Id</td>
<td style="width: 107px;">string</td>
<td style="width: 303px;">The ID of the behavior.</td>
</tr>
<tr>
<td style="width: 330px;">CounterTack.Behavior.Tags</td>
<td style="width: 107px;">Unknown</td>
<td style="width: 303px;">The tags of the behavior.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="975" data-line-end="976">
<a id="Command_Example_975"></a>Command Example</h5>
<pre>!countertack-delete-behavior-tags behaviour_id=b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428 tags=test1</pre>
<h5 class="code-line" data-line-start="978" data-line-end="979">
<a id="Context_Example_978"></a>Context Example</h5>
<pre>{
    "CounterTack.Behavior": {
        "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428", 
        "Tags": [
            "test2"
        ]
    }
}
</pre>
<h5 class="code-line" data-line-start="990" data-line-end="991">
<a id="Human_Readable_Output_990"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="991" data-line-end="992">
<a id="Endpoint_tags_were_deleted_successfully_991"></a>Endpoint tags were deleted successfully</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Id</th>
<th>tags</th>
</tr>
</thead>
<tbody>
<tr>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606066211860428</td>
<td>test2</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_f1616c2b-bfdf-45eb-8598-a6b0f0709c94" class="code-line" data-line-start="997" data-line-end="998">
<a id="10_Quarantine_an_endpoint_997"></a>10. Quarantine an endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="999" data-line-end="1000">Quarantines a given endpoint.</p>
<p class="has-line-data" data-line-start="1001" data-line-end="1002"> </p>
<h5 class="code-line" data-line-start="1002" data-line-end="1003">
<a id="Base_Command_1002"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1004" data-line-end="1005"><code>countertack-endpoint-quarantine</code></p>
<h5 class="code-line" data-line-start="1005" data-line-end="1006">
<a id="Input_1005"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 210px;"><strong>Argument Name</strong></th>
<th style="width: 415px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 210px;">endpoint_id</td>
<td style="width: 415px;">The ID of the endpoint to quarantine.</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1012" data-line-end="1013">
<a id="Context_Output_1012"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 324px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 348px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 324px;">CounterTack.Endpoint.Id</td>
<td style="width: 68px;">string</td>
<td style="width: 348px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 324px;">CounterTack.Endpoint.IsQuarantine</td>
<td style="width: 68px;">boolean</td>
<td style="width: 348px;">Is the endpoint currently quarantined.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1020" data-line-end="1021">
<a id="Command_Example_1020"></a>Command Example</h5>
<pre>!countertack-endpoint-quarantine endpoint_id=b5cd32a8-aac5-5862-aeee-988ba72b8a62</pre>
<h5 class="code-line" data-line-start="1023" data-line-end="1024">
<a id="Context_Example_1023"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": {
        "IsQuarantine": true, 
        "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62"
    }
}
</pre>
<h5 class="code-line" data-line-start="1033" data-line-end="1034">
<a id="Human_Readable_Output_1033"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1034" data-line-end="1035">
<a id="The_command_has_been_applied_successfully_1034"></a>The command has been applied successfully:</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Id</th>
<th>command name</th>
<th>endpoint ID</th>
<th>request time</th>
<th>status</th>
<th>user name</th>
</tr>
</thead>
<tbody>
<tr>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62-0000001565175405639-v</td>
<td>quarantine</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-08-07T10:56:45.639+0000</td>
<td>initial</td>
<td>kelvis.com@local</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_2fbd1d96-6eef-46d9-8ecc-8e48708f5b99" class="code-line" data-line-start="1040" data-line-end="1041">
<a id="11_Remove_an_endpoint_from_quarantine_1040"></a>11. Remove an endpoint from quarantine</h3>
<hr>
<p class="has-line-data" data-line-start="1042" data-line-end="1043">Removes a given endpoint from quarantine.</p>
<p class="has-line-data" data-line-start="1044" data-line-end="1045"> </p>
<h5 class="code-line" data-line-start="1045" data-line-end="1046">
<a id="Base_Command_1045"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1047" data-line-end="1048"><code>countertack-disable-quarantine</code></p>
<h5 class="code-line" data-line-start="1048" data-line-end="1049">
<a id="Input_1048"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 472px;"><strong>Description</strong></th>
<th style="width: 95px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">endpoint_id</td>
<td style="width: 472px;">The ID of the endpoint to remove from quarantine.</td>
<td style="width: 95px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1055" data-line-end="1056">
<a id="Context_Output_1055"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 260px;"><strong>Path</strong></th>
<th style="width: 45px;"><strong>Type</strong></th>
<th style="width: 435px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">CounterTack.Endpoint.Id</td>
<td style="width: 45px;">string</td>
<td style="width: 435px;">The ID of the endpoint that was removed from quarantine.</td>
</tr>
<tr>
<td style="width: 260px;">CounterTack.Endpoint.IsQuarantine</td>
<td style="width: 45px;">string</td>
<td style="width: 435px;">Is the endpoint is currently quarantined.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1063" data-line-end="1064">
<a id="Command_Example_1063"></a>Command Example</h5>
<pre>!countertack-disable-quarantine endpoint_id=b5cd32a8-aac5-5862-aeee-988ba72b8a62</pre>
<h5 class="code-line" data-line-start="1066" data-line-end="1067">
<a id="Context_Example_1066"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": {
        "IsQuarantine": false, 
        "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62"
    }
}
</pre>
<h5 class="code-line" data-line-start="1076" data-line-end="1077">
<a id="Human_Readable_Output_1076"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1077" data-line-end="1078">
<a id="The_command_has_been_applied_successfully_1077"></a>The command has been applied successfully:</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Id</th>
<th>command name</th>
<th>endpoint ID</th>
<th>request time</th>
<th>status</th>
<th>user name</th>
</tr>
</thead>
<tbody>
<tr>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62-0000001565175407931-Y</td>
<td>lift_quarantine</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-08-07T10:56:47.931+0000</td>
<td>initial</td>
<td>ks.com@local</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_bd041638-3f1c-4ec9-afa7-85a643ff8485" class="code-line" data-line-start="1083" data-line-end="1084">
<a id="12_Extract_a_file_from_an_endpoint_1083"></a>12. Extract a file from an endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="1085" data-line-end="1086">Extracts a file from the specified endpoint.</p>
<p class="has-line-data" data-line-start="1087" data-line-end="1088"> </p>
<h5 class="code-line" data-line-start="1088" data-line-end="1089">
<a id="Base_Command_1088"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1090" data-line-end="1091"><code>countertack-extract-file</code></p>
<h5 class="code-line" data-line-start="1091" data-line-end="1092">
<a id="Input_1091"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 498px;"><strong>Description</strong></th>
<th style="width: 87px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">endpoint_id</td>
<td style="width: 498px;">The ID of the endpoint to extract a file from.</td>
<td style="width: 87px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">file_path</td>
<td style="width: 498px;">The path of the file to extract, for example, “C:\test1.txt”.</td>
<td style="width: 87px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1099" data-line-end="1100">
<a id="Context_Output_1099"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 319px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 357px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg.contents</td>
<td style="width: 64px;">boolean</td>
<td style="width: 357px;">The contents of the extracted file.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg.extracted_ids</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The IDs of the extracted file.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg.md5</td>
<td style="width: 64px;">boolean</td>
<td style="width: 357px;">The MD5 hash of the extracted file.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg.paths</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The path of the extracted file.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg.sha256</td>
<td style="width: 64px;">boolean</td>
<td style="width: 357px;">The SHA256 has of teh extracted file.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg.ssdeep</td>
<td style="width: 64px;">boolean</td>
<td style="width: 357px;">The ssdeep hash of the extracted file.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandArg</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 357px;">The command arguments.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.CommandName</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The name of the command that is sent.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.Username</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The username of the user that requested the command.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.TargetType</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The type of resource or collection this command is being sent to.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.Status</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The status of the command (initial, pending, complete, error).</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.RequestTime</td>
<td style="width: 64px;">date</td>
<td style="width: 357px;">The time at which the client requested the command.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.Id</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The ID of the commands.</td>
</tr>
<tr>
<td style="width: 319px;">CounterTack.File.EndpointIds</td>
<td style="width: 64px;">string</td>
<td style="width: 357px;">The ID of the source this command is being sent to.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1119" data-line-end="1120">
<a id="Command_Example_1119"></a>Command Example</h5>
<pre>!countertack-extract-file endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567 file_path=C:\\test1.txt</pre>
<h5 class="code-line" data-line-start="1122" data-line-end="1123">
<a id="Context_Example_1122"></a>Context Example</h5>
<pre>{
    "CounterTack.File": {
        "Status": "initial", 
        "TargetType": "endpoints", 
        "RequestTime": "2019-08-07T10:56:40.286+0000", 
        "EndpointIds": [
            "176349c6-7642-3601-0dcb-b225bd95c567"
        ], 
        "CommandName": "extract_files", 
        "CommandArg": {
            "paths": "C:\\\\test1.txt", 
            "contents": true, 
            "ssdeep": true, 
            "sha256": true, 
            "extracted_ids": "extracted_files-0000001565175400289-0709747298", 
            "md5": true
        }, 
        "Username": "kelvint@dbs.com@local", 
        "Id": "176349c6-7642-3601-0dcb-b225bd95c567-0000001565175400286-5"
    }
}
</pre>
<h5 class="code-line" data-line-start="1147" data-line-end="1148">
<a id="Human_Readable_Output_1147"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1148" data-line-end="1149">
<a id="The_file_has_been_extracted_successfully_1148"></a>The file has been extracted successfully:</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Id</th>
<th>User Name</th>
<th>Request Time</th>
<th>Endpoint ID</th>
<th>Command Name</th>
<th>Command Arguments</th>
<th>Status</th>
</tr>
</thead>
<tbody>
<tr>
<td>176349c6-7642-3601-0dcb-b225bd95c567-0000001565175400286-5</td>
<td>kelvis.com@local</td>
<td>2019-08-07T10:56:40.286+0000</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>extract_files</td>
<td>paths: C:\test1.txt&lt;br&gt;contents: true&lt;br&gt;ssdeep: true&lt;br&gt;sha256: true&lt;br&gt;extracted_ids: extracted_files-0000001565175400289-0709747298&lt;br&gt;md5: true</td>
<td>initial</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1cd3a62b-87a6-4f55-80a3-fc8307880bb2" class="code-line" data-line-start="1154" data-line-end="1155">
<a id="13_Delete_a_file_from_an_endpoint_1154"></a>13. Delete a file from an endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="1156" data-line-end="1157">Deletes a file from the given endpoint.</p>
<p class="has-line-data" data-line-start="1158" data-line-end="1159"> </p>
<h5 class="code-line" data-line-start="1159" data-line-end="1160">
<a id="Base_Command_1159"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1161" data-line-end="1162"><code>countertack-delete-file</code></p>
<h5 class="code-line" data-line-start="1162" data-line-end="1163">
<a id="Input_1162"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 182px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 182px;">endpoint_id</td>
<td style="width: 453px;">The ID of the endpoint to delete a file from.</td>
<td style="width: 105px;">Required</td>
</tr>
<tr>
<td style="width: 182px;">file_path</td>
<td style="width: 453px;">The path of the file to delete.</td>
<td style="width: 105px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1170" data-line-end="1171">
<a id="Context_Output_1170"></a>Context Output</h5>
<p> </p>
<p class="has-line-data" data-line-start="1172" data-line-end="1173">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="1174" data-line-end="1175">
<a id="Command_Example_1174"></a>Command Example</h5>
<pre>!countertack-delete-file endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567 file_path=C:\\test2.txt</pre>
<h5 class="code-line" data-line-start="1177" data-line-end="1178">
<a id="Human_Readable_Output_1177"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="1178" data-line-end="1179">The file has been deleted successfully</p>
<h3 id="h_6a331519-1fc4-4db3-be4c-f0021d2c97f7" class="code-line" data-line-start="1180" data-line-end="1181">
<a id="14_Get_all_files_for_all_endpoints_1180"></a>14. Get all files for all endpoints</h3>
<hr>
<p class="has-line-data" data-line-start="1182" data-line-end="1183">Gets all extracted files for all endpoints.</p>
<p class="has-line-data" data-line-start="1184" data-line-end="1185"> </p>
<h5 class="code-line" data-line-start="1185" data-line-end="1186">
<a id="Base_Command_1185"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1187" data-line-end="1188"><code>countertack-get-all-files</code></p>
<h5 class="code-line" data-line-start="1188" data-line-end="1189">
<a id="Input_1188"></a>Input</h5>
<p>There are no arguments for this command.</p>
<h5 class="code-line" data-line-start="1194" data-line-end="1195">
<a id="Context_Output_1194"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 246px;"><strong>Path</strong></th>
<th style="width: 51px;"><strong>Type</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 246px;">CounterTack.File.Size</td>
<td style="width: 51px;">number</td>
<td style="width: 443px;">The size of the extracted file (in bytes).</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.EndpointId</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The ID of the endpoint that contains the extracted file.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.ExtractionTime</td>
<td style="width: 51px;">date</td>
<td style="width: 443px;">The time that the file was extracted.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Path</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The full file system path of the extracted file, including the filename, as seen on the endpoint.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Sha256</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Tenant</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The tenant ID for the endpoint.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.User</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The name of the user requesting the file.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Ssdeep</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.EndpointIp</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The IP address of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.AvCoverage</td>
<td style="width: 51px;">number</td>
<td style="width: 443px;">The percentage of AV engines that determined that the hash is malicious.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Status</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The status of the contents.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.VtStatus</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The VirusTotal report status.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.EndpointName</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The name of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Id</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The file ID of the extracted file.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.Md5</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 246px;">CounterTack.File.VtReportLocation</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The VirusTotal report location path.</td>
</tr>
<tr>
<td style="width: 246px;">File.MD5</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 246px;">File.Path</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The full file system path of the extracted file, including the filename, as seen on the endpoint.</td>
</tr>
<tr>
<td style="width: 246px;">File.SHA256</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 246px;">File.SSDeep</td>
<td style="width: 51px;">string</td>
<td style="width: 443px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 246px;">File.Size</td>
<td style="width: 51px;">number</td>
<td style="width: 443px;">The size of the extracted file (in bytes).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1221" data-line-end="1222">
<a id="Command_Example_1221"></a>Command Example</h5>
<pre>!countertack-get-all-files</pre>
<h5 class="code-line" data-line-start="1224" data-line-end="1225">
<a id="Context_Example_1224"></a>Context Example</h5>
<pre>{
    "CounterTack.File": [
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-11T10:12:31.203+0000", 
            "VtReportLocation": "https://www.virustotal.com/file/a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3/analysis/1549506642/", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 66560, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "AvCoverage": 0, 
            "Ssdeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "Sha256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "VtStatus": "completed_benign", 
            "Id": "extracted_files-0000001549879951203-1015199282", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-11T10:10:02.041+0000", 
            "VtReportLocation": "https://www.virustotal.com/file/a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3/analysis/1549506642/", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 66560, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "AvCoverage": 0, 
            "Ssdeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "Sha256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "VtStatus": "completed_benign", 
            "Id": "extracted_files-0000001549879802041-2034430182", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-11T14:13:34.257+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test1.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549894414258-1792972434", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-07T13:28:48.120+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549546128120-0552910285", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-10T10:39:35.382+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549795175382-1873919773", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-10T13:38:48.568+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549805928568-1898066936", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-10T18:31:03.691+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549823463691-0424848883", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-12T10:50:14.802+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test1.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549968614802-0265949112", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-12T10:58:35.930+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test1.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549969115931-0820123773", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-12T10:58:35.933+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test2.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549969115933-0777596748", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }
    ], 
    "File": [
        {
            "Size": 66560, 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "SSDeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "SHA256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "MD5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Size": 66560, 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "SSDeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "SHA256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "MD5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test1.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test1.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test1.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test2.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="1440" data-line-end="1441">
<a id="Human_Readable_Output_1440"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1441" data-line-end="1442">
<a id="CounterTack_Endpoints_Files_1441"></a>CounterTack Endpoints Files</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Status</th>
<th>Id</th>
<th>path</th>
<th>endpoint_id</th>
<th>extraction_time</th>
<th>user</th>
</tr>
</thead>
<tbody>
<tr>
<td>complete</td>
<td>extracted_files-0000001549879951203-1015199282</td>
<td>??\C:\Windows\twain_32.dll</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-11T10:12:31.203+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549879802041-2034430182</td>
<td>??\C:\Windows\twain_32.dll</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-11T10:10:02.041+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549894414258-1792972434</td>
<td>??\C:\test1.txt</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-11T14:13:34.257+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549546128120-0552910285</td>
<td>??\C:\Windows wain_32.dll</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-07T13:28:48.120+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549795175382-1873919773</td>
<td>??\C:\Windows wain_32.dll</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-10T10:39:35.382+0000</td>
<td>kelvins.com@local</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549805928568-1898066936</td>
<td>??\C:\Windows wain_32.dll</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-10T13:38:48.568+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549823463691-0424848883</td>
<td>??\C:\Windows wain_32.dll</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-10T18:31:03.691+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549968614802-0265949112</td>
<td>??\C:\test1.txt</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-12T10:50:14.802+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549969115931-0820123773</td>
<td>??\C:\test1.txt</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-12T10:58:35.930+0000</td>
<td>kelvis.com@local</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549969115933-0777596748</td>
<td>??\C:\test2.txt</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-12T10:58:35.933+0000</td>
<td>kelvis.com@local</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_e7fa7578-3437-492c-be6b-df5e96038ccc" class="code-line" data-line-start="1456" data-line-end="1457">
<a id="15_Return_all_files_for_a_single_endpoint_1456"></a>15. Return all files for a single endpoint</h3>
<hr>
<p class="has-line-data" data-line-start="1458" data-line-end="1459">Returns all extracted files from a single endpoint.</p>
<h5 class="code-line" data-line-start="1461" data-line-end="1462">
<a id="Base_Command_1461"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1463" data-line-end="1464"><code>countertack-get-endpoint-files</code></p>
<h5 class="code-line" data-line-start="1464" data-line-end="1465">
<a id="Input_1464"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">endpoint_id</td>
<td style="width: 524px;">The ID of the endpoint. To get the endpoint_id, run the<span> </span><code>get-endpoints</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1471" data-line-end="1472">
<a id="Context_Output_1471"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 245px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 245px;">CounterTack.File.Id</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The file ID of the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Status</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The status of the contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.EndpointId</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ID of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.ExtractionTime</td>
<td style="width: 52px;">date</td>
<td style="width: 443px;">The time that the file was extracted.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Tenant</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The tenant ID for the endpoint.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.User</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The name of the user requesting the file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Path</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The full file system path of the extracted file, including the filename, as seen on the endpoint.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Sha256</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Ssdeep</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.EndpointIp</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The IP address of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.VtStatus</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The VirusTotal report status.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.VtReportLocation</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The location path of the VirusTotal report.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Size</td>
<td style="width: 52px;">number</td>
<td style="width: 443px;">The size of the extracted file (in bytes).</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.EndpointName</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The name of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Md5</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.MD5</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.Path</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The full file system path of the extracted file, including the filename, as seen on the endpoint.</td>
</tr>
<tr>
<td style="width: 245px;">File.SHA256</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.SSDeep</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.Size</td>
<td style="width: 52px;">number</td>
<td style="width: 443px;">The size of the extracted file (bytes).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1497" data-line-end="1498">
<a id="Command_Example_1497"></a>Command Example</h5>
<pre>!countertack-get-endpoint-files endpoint_id=176349c6-7642-3601-0dcb-b225bd95c567</pre>
<h5 class="code-line" data-line-start="1500" data-line-end="1501">
<a id="Context_Example_1500"></a>Context Example</h5>
<pre>{
    "CounterTack.File": [
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-11T10:12:31.203+0000", 
            "VtReportLocation": "https://www.virustotal.com/file/a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3/analysis/1549506642/", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 66560, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "AvCoverage": 0, 
            "Ssdeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "Sha256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "VtStatus": "completed_benign", 
            "Id": "extracted_files-0000001549879951203-1015199282", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-11T10:10:02.041+0000", 
            "VtReportLocation": "https://www.virustotal.com/file/a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3/analysis/1549506642/", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 66560, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "AvCoverage": 0, 
            "Ssdeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "Sha256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "VtStatus": "completed_benign", 
            "Id": "extracted_files-0000001549879802041-2034430182", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-11T14:13:34.257+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test1.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549894414258-1792972434", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-07T13:28:48.120+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549546128120-0552910285", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-10T10:39:35.382+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549795175382-1873919773", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-10T13:38:48.568+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549805928568-1898066936", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "initial", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "User": "kelvint@dbs.com@local", 
            "ExtractionTime": "2019-02-10T18:31:03.691+0000", 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "Id": "extracted_files-0000001549823463691-0424848883", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e"
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-12T10:50:14.802+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test1.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549968614802-0265949112", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-12T10:58:35.930+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test1.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549969115931-0820123773", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }, 
        {
            "Status": "complete", 
            "EndpointIp": "172.31.36.196", 
            "ExtractionTime": "2019-02-12T10:58:35.933+0000", 
            "EndpointName": "EC2AMAZ-D6LF2KI", 
            "Size": 0, 
            "User": "kelvint@dbs.com@local", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Path": "\\??\\C:\\test2.txt", 
            "Ssdeep": "", 
            "Sha256": "", 
            "VtStatus": "initial", 
            "Id": "extracted_files-0000001549969115933-0777596748", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Md5": ""
        }
    ], 
    "File": [
        {
            "Size": 66560, 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "SSDeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "SHA256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "MD5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Size": 66560, 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "SSDeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "SHA256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "MD5": "21f91141b4796108a50733b14850cdf2"
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test1.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": null, 
            "Path": "\\??\\C:\\Windows\twain_32.dll", 
            "SSDeep": null, 
            "SHA256": null, 
            "MD5": null
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test1.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test1.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }, 
        {
            "Size": 0, 
            "Path": "\\??\\C:\\test2.txt", 
            "SSDeep": "", 
            "SHA256": "", 
            "MD5": ""
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="1716" data-line-end="1717">
<a id="Human_Readable_Output_1716"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1717" data-line-end="1718">
<a id="The_extracted_files_from_the_endpoint_1717"></a>The extracted files from the endpoint:</h3>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th>Status</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>complete</td>
<td>extracted_files-0000001549879951203-1015199282</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549879802041-2034430182</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549894414258-1792972434</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549546128120-0552910285</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549795175382-1873919773</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549805928568-1898066936</td>
</tr>
<tr>
<td>initial</td>
<td>extracted_files-0000001549823463691-0424848883</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549968614802-0265949112</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549969115931-0820123773</td>
</tr>
<tr>
<td>complete</td>
<td>extracted_files-0000001549969115933-0777596748</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_5297485a-7812-4f0e-ae74-4a69969523a9" class="code-line" data-line-start="1732" data-line-end="1733">
<a id="16_Get_information_for_a_file_1732"></a>16. Get information for a file</h3>
<hr>
<p class="has-line-data" data-line-start="1734" data-line-end="1735">Returns the information of a given file.</p>
<p class="has-line-data" data-line-start="1736" data-line-end="1737"> </p>
<h5 class="code-line" data-line-start="1737" data-line-end="1738">
<a id="Base_Command_1737"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1739" data-line-end="1740"><code>countertack-get-file-information</code></p>
<h5 class="code-line" data-line-start="1740" data-line-end="1741">
<a id="Input_1740"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">file_id</td>
<td style="width: 526px;">The ID of the requested file. To get the "file_id"m run the<span> </span><code>get-all-files</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1747" data-line-end="1748">
<a id="Context_Output_1747"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 245px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 245px;">CounterTack.File.Size</td>
<td style="width: 52px;">number</td>
<td style="width: 443px;">The size of the extracted file (in bytes).</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.EndpointId</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ID of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.ExtractionTime</td>
<td style="width: 52px;">date</td>
<td style="width: 443px;">The time that the file was extracted.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Path</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">Full file system path of the extracted file, including the filename, as seen on the endpoint.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Sha256</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Tenant</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The tenant ID for the endpoint.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.User</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The name of the user requesting the file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Ssdeep</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.EndpointIp</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The IP address of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.AvCoverage</td>
<td style="width: 52px;">number</td>
<td style="width: 443px;">The percentage of AV engines that determined that the hash is malicious.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Status</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The status of the contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.VtStatus</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The status of the VirusTotal report.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.EndpointName</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The name of the endpoint with the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Id</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ID of the extracted file.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.Md5</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">CounterTack.File.VtReportLocation</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The location path of the VirusTotal report.</td>
</tr>
<tr>
<td style="width: 245px;">File.MD5</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.Path</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The full file system path of the extracted file, including the filename, as seen on the endpoint.</td>
</tr>
<tr>
<td style="width: 245px;">File.SHA256</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.SSDeep</td>
<td style="width: 52px;">string</td>
<td style="width: 443px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 245px;">File.Size</td>
<td style="width: 52px;">number</td>
<td style="width: 443px;">The size of the extracted file (in bytes).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1774" data-line-end="1775">
<a id="Command_Example_1774"></a>Command Example</h5>
<pre>!countertack-get-file-information file_id=extracted_files-0000001549879951203-1015199282</pre>
<h5 class="code-line" data-line-start="1777" data-line-end="1778">
<a id="Context_Example_1777"></a>Context Example</h5>
<pre>{
    "CounterTack.File": {
        "Status": "complete", 
        "EndpointIp": "172.31.36.196", 
        "ExtractionTime": "2019-02-11T10:12:31.203+0000", 
        "VtReportLocation": "https://www.virustotal.com/file/a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3/analysis/1549506642/", 
        "EndpointName": "EC2AMAZ-D6LF2KI", 
        "Size": 66560, 
        "User": "kelvint@dbs.com@local", 
        "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
        "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
        "AvCoverage": 0, 
        "Ssdeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
        "Sha256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
        "VtStatus": "completed_benign", 
        "Id": "extracted_files-0000001549879951203-1015199282", 
        "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
        "Md5": "21f91141b4796108a50733b14850cdf2"
    }, 
    "File": [
        {
            "Size": 66560, 
            "Path": "\\??\\C:\\\\Windows\\twain_32.dll", 
            "SSDeep": "1536:DO0xgmx8rbNZ95Q19JN91jugybPOM3U3zBp:i0rx+9mJNbWPOM3Ujn", 
            "SHA256": "a3f8a1b8dae8566c6be400eb35bed86440de26e29e9b599ec8ca90dec9cdc8c3", 
            "MD5": "21f91141b4796108a50733b14850cdf2"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="1810" data-line-end="1811">
<a id="Human_Readable_Output_1810"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1811" data-line-end="1812">
<a id="CounterTack_File_Information_1811"></a>CounterTack File Information:</h3>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th>endpoint_name</th>
<th>path</th>
<th>size</th>
<th>status</th>
<th>extraction_time</th>
</tr>
</thead>
<tbody>
<tr>
<td>EC2AMAZ-D6LF2KI</td>
<td>??\C:\Windows\twain_32.dll</td>
<td>66560</td>
<td>complete</td>
<td>2019-02-11T10:12:31.203+0000</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_ede8dfd7-4676-4399-bb38-18c85b427933" class="code-line" data-line-start="1817" data-line-end="1818">
<a id="17_Download_a_file_1817"></a>17. Download a file</h3>
<hr>
<p class="has-line-data" data-line-start="1819" data-line-end="1820">Downloads an extracted file in ZIP format. The password to unlock the ZIP file is<span> </span><code>sentinel</code>.</p>
<h5 class="code-line" data-line-start="1820" data-line-end="1821">
<a id="Required_Permissions_1820"></a>Required Permissions</h5>
<p class="has-line-data" data-line-start="1821" data-line-end="1822"><strong>FILL IN REQUIRED PERMISSIONS HERE</strong></p>
<h5 class="code-line" data-line-start="1822" data-line-end="1823">
<a id="Base_Command_1822"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1824" data-line-end="1825"><code>countertack-download-file</code></p>
<h5 class="code-line" data-line-start="1825" data-line-end="1826">
<a id="Input_1825"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 698px;">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 479px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">file_id</td>
<td style="width: 479px;">The ID of the extracted file. To get the “file_id”, run the<span> </span><code>get-all-files</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1832" data-line-end="1833">
<a id="Context_Output_1832"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 173px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 477px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">File.Size</td>
<td style="width: 90px;">number</td>
<td style="width: 477px;">The size of the extracted file (in bytes).</td>
</tr>
<tr>
<td style="width: 173px;">File.SHA1</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The SHA1 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 173px;">File.SHA256</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The SHA256 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 173px;">File.Name</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The name of the file.</td>
</tr>
<tr>
<td style="width: 173px;">File.SSDeep</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The ssdeep digest of the file contents.</td>
</tr>
<tr>
<td style="width: 173px;">File.EntryID</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The EntryID of the file.</td>
</tr>
<tr>
<td style="width: 173px;">File.Info</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The file information.</td>
</tr>
<tr>
<td style="width: 173px;">File.Type</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The file type.</td>
</tr>
<tr>
<td style="width: 173px;">File.MD5</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The MD5 digest of the file contents.</td>
</tr>
<tr>
<td style="width: 173px;">File.Extension</td>
<td style="width: 90px;">string</td>
<td style="width: 477px;">The extension of the file (.zip).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1848" data-line-end="1849">
<a id="Command_Example_1848"></a>Command Example</h5>
<pre>!countertack-download-file file_id=extracted_files-0000001549894414258-1792972434</pre>
<h5 class="code-line" data-line-start="1851" data-line-end="1852">
<a id="Human_Readable_Output_1851"></a>Human Readable Output</h5>
<ul>
<li class="has-line-data" data-line-start="1852" data-line-end="1854">Return the file to download</li>
</ul>
<h3 id="h_764a00dc-9381-4197-a411-b474dec45638" class="code-line" data-line-start="1854" data-line-end="1855">
<a id="18_Search_for_events_1854"></a>18. Search for events</h3>
<hr>
<p class="has-line-data" data-line-start="1856" data-line-end="1857">Searches for events, using CQL expression.</p>
<h5 class="code-line" data-line-start="1859" data-line-end="1860">
<a id="Base_Command_1859"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1861" data-line-end="1862"><code>countertack-search-events</code></p>
<h5 class="code-line" data-line-start="1862" data-line-end="1863">
<a id="Input_1862"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">expression</td>
<td style="width: 526px;">The CQL expression to use for the search, for example, “events.event_type=basic”.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1869" data-line-end="1870">
<a id="Context_Output_1869"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 407px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 270px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceProcessTimeStarted</td>
<td style="width: 63px;">date</td>
<td style="width: 270px;">The start time for the source process.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadProcessPid</td>
<td style="width: 63px;">number</td>
<td style="width: 270px;">The process PID of the source thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.IsTaintTransfer</td>
<td style="width: 63px;">boolean</td>
<td style="width: 270px;">Is the event a malignant transfer.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.IsBasic</td>
<td style="width: 63px;">boolean</td>
<td style="width: 270px;">Is the event a basic event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadTimeFinished</td>
<td style="width: 63px;">date</td>
<td style="width: 270px;">The exit time of the source thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadTid</td>
<td style="width: 63px;">number</td>
<td style="width: 270px;">The TID of the source thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.Tenant</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The tenant of the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadProcessTimeStarted</td>
<td style="width: 63px;">date</td>
<td style="width: 270px;">The start time of the parent process for the source thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.TargetType</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The system object type that was target of the event (PROCESS, THREAD, REGISTRY, DRIVER, TCPIP,FILE, MUTEX, MEMORY_REGION).</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.ConditionNames</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 270px;">The names of the condition triggered by the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.IsOrigin</td>
<td style="width: 63px;">boolean</td>
<td style="width: 270px;">Is the event an origin for a trace.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.endpoint_id</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The endpoint ID, based on the UUID of the last installed endpoint sensor.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.TargetFilePath</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The path of the target file.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Events.SourceThreadProcessBackingFilePath</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The backing file of the source thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.EventType</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The type of event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.IsKey</td>
<td style="width: 63px;">boolean</td>
<td style="width: 270px;">Is the event a key event in a trace.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceType</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The system object that was the source of the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadProcessName</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The name of the parent process for the source thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadProcessUser</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The user associated with the process of the thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.TimeStamp</td>
<td style="width: 63px;">date</td>
<td style="width: 270px;">The time that the event was collected.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.Action</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The system interaction that characterizes the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.IsTainted</td>
<td style="width: 63px;">boolean</td>
<td style="width: 270px;">Whether objects in the event are tainted.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadProcessParentPid</td>
<td style="width: 63px;">number</td>
<td style="width: 270px;">The parent PID of the source thread process.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceProcessPid</td>
<td style="width: 63px;">number</td>
<td style="width: 270px;">The PID of the source process.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceThreadStartAddress</td>
<td style="width: 63px;">number</td>
<td style="width: 270px;">The start address of the thread.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceProcessSid</td>
<td style="width: 63px;">number</td>
<td style="width: 270px;">The user SIDs associated with the process.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.Id</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The ID of the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.ConditionIds</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 270px;">The IDs of the condition triggered by the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceProcessName</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The name of the process that was the source of the event.</td>
</tr>
<tr>
<td style="width: 407px;">CounterTack.Event.SourceProcessUser</td>
<td style="width: 63px;">string</td>
<td style="width: 270px;">The user associated with the process</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1905" data-line-end="1906">
<a id="Command_Example_1905"></a>Command Example</h5>
<pre>!countertack-search-events expression=events.event_type=basic</pre>
<h5 class="code-line" data-line-start="1908" data-line-end="1909">
<a id="Context_Example_1908"></a>Context Example</h5>
<pre>{
    "CounterTack.Event": [
        {
            "Impact": 0, 
            "TargetType": "process", 
            "SourceThreadStartAddress": 0, 
            "IsKey": false, 
            "SourceThreadProcessUser": "root", 
            "SourceThreadTimeStarted": "2019-01-29T12:41:06.776+0000", 
            "SourceProcessPid": 1232, 
            "SourceThreadProcessTimeStarted": "2019-01-29T12:41:06.776+0000", 
            "TargetProcessName": "sshd", 
            "SourceProcessTimeStarted": "2019-01-29T12:41:06.776+0000", 
            "SourceProcessName": "sshd", 
            "InsertionTimeStamp": "2019-03-01T17:27:01.037+0000", 
            "SourceProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceProcessSid": "0", 
            "TargetProcessSid": "0", 
            "SourceThreadProcessSid": "0", 
            "EventType": "basic", 
            "TargetProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "TargetProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceThreadTimeFinished": "1970-01-01T00:00:00.000+0000", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "TargetProcessCommandLine": "/usr/sbin/sshd -D -R", 
            "Action": "PROCESS_CREATE", 
            "IsTainted": false, 
            "TimeStamp": "2019-03-01T17:26:59.071+0000", 
            "SourceThreadProcessPid": 1232, 
            "IsTaintTransfer": false, 
            "SourceThreadProcessParentPid": 1, 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "SourceThreadProcessBackingFilePath": "/usr/sbin/sshd", 
            "TargetProcessBackingFileMd5": "56f6d9e73cfb3e36a0e321880589e830", 
            "SourceProcessUser": "root", 
            "ConditionIds": [
                "countertack:observable-9e6a62ae-3927-4e59-8885-7a5a783e1e26"
            ], 
            "TargetProcessUser": "root", 
            "TargetProcessParentPid": 1232, 
            "SourceType": "thread", 
            "IsOrigin": false, 
            "TargetProcessPid": 15608, 
            "SourceThreadTid": 1232, 
            "SourceThreadProcessName": "sshd", 
            "ConditionNames": [
                "Process Created"
            ], 
            "Id": "tc0yqKrFWGKu7piLpyuKYmp4Gj3CeUiA"
        }, 
        {
            "Impact": 0, 
            "TargetType": "file", 
            "SourceThreadStartAddress": 0, 
            "TargetFilePath": "/proc/15608/oom_score_adj", 
            "IsKey": false, 
            "SourceThreadProcessUser": "root", 
            "SourceThreadTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessPid": 15608, 
            "SourceThreadProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessName": "sshd", 
            "InsertionTimeStamp": "2019-03-01T17:27:01.037+0000", 
            "SourceProcessBackingFilePath": "/usr/sbin/sshd", 
            "TargetFileMd5": "d41d8cd98f00b204e9800998ecf8427e", 
            "SourceProcessSid": "0", 
            "SourceThreadProcessSid": "0", 
            "EventType": "basic", 
            "SourceThreadTimeFinished": "1970-01-01T00:00:00.000+0000", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Action": "FILE_CREATE", 
            "IsTainted": false, 
            "TimeStamp": "2019-03-01T17:26:59.071+0000", 
            "SourceThreadProcessPid": 15608, 
            "IsTaintTransfer": false, 
            "SourceThreadProcessParentPid": 1232, 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "SourceThreadProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceProcessUser": "root", 
            "ConditionIds": [
                "countertack:observable-42213560-1DC2-4865-9A45-FDFC71776B84"
            ], 
            "SourceType": "thread", 
            "IsOrigin": false, 
            "SourceThreadTid": 15608, 
            "SourceThreadProcessName": "sshd", 
            "ConditionNames": [
                "File Created"
            ], 
            "Id": "tc0yqKrFWGKu7piLpyuKYmp4Gj3Cd3WT"
        }, 
        {
            "Impact": 0, 
            "TargetType": "process", 
            "SourceThreadStartAddress": 0, 
            "IsKey": false, 
            "SourceThreadProcessUser": "root", 
            "SourceThreadTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessPid": 15608, 
            "SourceThreadProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "TargetProcessName": "sshd", 
            "SourceProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessName": "sshd", 
            "InsertionTimeStamp": "2019-03-01T17:27:01.038+0000", 
            "SourceProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceProcessSid": "0", 
            "TargetProcessSid": "0", 
            "SourceThreadProcessSid": "0", 
            "EventType": "basic", 
            "TargetProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "TargetProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceThreadTimeFinished": "1970-01-01T00:00:00.000+0000", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "TargetProcessCommandLine": "/usr/sbin/sshd -D -R", 
            "Action": "PROCESS_CREATE", 
            "IsTainted": false, 
            "TimeStamp": "2019-03-01T17:26:59.071+0000", 
            "SourceThreadProcessPid": 15608, 
            "IsTaintTransfer": false, 
            "SourceThreadProcessParentPid": 1232, 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "SourceThreadProcessBackingFilePath": "/usr/sbin/sshd", 
            "TargetProcessBackingFileMd5": "56f6d9e73cfb3e36a0e321880589e830", 
            "SourceProcessUser": "root", 
            "ConditionIds": [
                "countertack:observable-9e6a62ae-3927-4e59-8885-7a5a783e1e26"
            ], 
            "TargetProcessUser": "root", 
            "TargetProcessParentPid": 1232, 
            "SourceType": "thread", 
            "IsOrigin": false, 
            "TargetProcessPid": 15608, 
            "SourceThreadTid": 15608, 
            "SourceThreadProcessName": "sshd", 
            "ConditionNames": [
                "Process Created"
            ], 
            "Id": "tc0yqKrFWGKu7piLpyuKYmp4Gj3CbLH8"
        }, 
        {
            "Impact": 0, 
            "TargetType": "process", 
            "SourceThreadStartAddress": 0, 
            "IsKey": false, 
            "SourceThreadProcessUser": "sshd", 
            "SourceThreadTimeStarted": "2019-03-01T17:26:59.362+0000", 
            "SourceProcessPid": 15609, 
            "SourceThreadProcessTimeStarted": "2019-03-01T17:26:59.362+0000", 
            "TargetProcessName": "sshd", 
            "SourceProcessTimeStarted": "2019-03-01T17:26:59.362+0000", 
            "SourceProcessName": "sshd", 
            "InsertionTimeStamp": "2019-03-01T17:27:05.037+0000", 
            "SourceProcessSid": "74", 
            "TargetProcessSid": "74", 
            "SourceThreadProcessSid": "74", 
            "EventType": "basic", 
            "TargetProcessTimeStarted": "2019-03-01T17:26:59.362+0000", 
            "SourceThreadTimeFinished": "1970-01-01T00:00:00.000+0000", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "IsTainted": false, 
            "TimeStamp": "2019-03-01T17:27:01.054+0000", 
            "SourceThreadProcessPid": 15609, 
            "IsTaintTransfer": false, 
            "SourceThreadProcessParentPid": 15608, 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "Action": "PROCESS_TERMINATE", 
            "SourceProcessUser": "sshd", 
            "ConditionIds": [
                "countertack:observable-45AE9331-FDE4-401E-9522-C87DD18AE437"
            ], 
            "TargetProcessUser": "sshd", 
            "TargetProcessParentPid": 15608, 
            "SourceType": "thread", 
            "IsOrigin": false, 
            "TargetProcessPid": 15609, 
            "SourceThreadTid": 15609, 
            "SourceThreadProcessName": "sshd", 
            "ConditionNames": [
                "Process termination"
            ], 
            "Id": "tc0yqKrFWGKu7piLpyuKYmp4Gj1MOf7c"
        }, 
        {
            "Impact": 0, 
            "TargetType": "process", 
            "SourceThreadStartAddress": 0, 
            "IsKey": false, 
            "SourceThreadProcessUser": "root", 
            "SourceThreadTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessPid": 15608, 
            "SourceThreadProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "TargetProcessName": "sshd", 
            "SourceProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "SourceProcessName": "sshd", 
            "InsertionTimeStamp": "2019-03-01T17:27:07.043+0000", 
            "SourceProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceProcessSid": "0", 
            "TargetProcessSid": "0", 
            "SourceThreadProcessSid": "0", 
            "EventType": "basic", 
            "TargetProcessTimeStarted": "2019-03-01T17:26:59.070+0000", 
            "TargetProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceThreadTimeFinished": "1970-01-01T00:00:00.000+0000", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Action": "PROCESS_TERMINATE", 
            "IsTainted": false, 
            "TimeStamp": "2019-03-01T17:27:01.057+0000", 
            "SourceThreadProcessPid": 15608, 
            "IsTaintTransfer": false, 
            "SourceThreadProcessParentPid": 1232, 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "SourceThreadProcessBackingFilePath": "/usr/sbin/sshd", 
            "SourceProcessUser": "root", 
            "ConditionIds": [
                "countertack:observable-45AE9331-FDE4-401E-9522-C87DD18AE437"
            ], 
            "TargetProcessUser": "root", 
            "TargetProcessParentPid": 1232, 
            "SourceType": "thread", 
            "IsOrigin": false, 
            "TargetProcessPid": 15608, 
            "SourceThreadTid": 15608, 
            "SourceThreadProcessName": "sshd", 
            "ConditionNames": [
                "Process termination"
            ], 
            "Id": "tc0yqKrFWGKu7piLpyuKYmp4Gj1MGhIj"
        }, 
        {
            "Impact": 0, 
            "TargetType": "dns", 
            "IsKey": false, 
            "SourceProcessBackingFileDeviceName": "\\Device\\HarddiskVolume1", 
            "SourceProcessPid": 1240, 
            "SourceProcessTimeStarted": "2019-02-11T11:28:58.067+0000", 
            "SourceProcessName": "svchost.exe", 
            "InsertionTimeStamp": "2019-03-01T17:55:44.158+0000", 
            "SourceProcessBackingFilePath": "C:\\Windows\\System32\\svchost.exe", 
            "SourceProcessSid": "S-1-5-20", 
            "EventType": "basic", 
            "SourceProcessParentPid": 596, 
            "SourceProcessBackingFileReferenceNumber": -46171748948768, 
            "TargetDnsQueryName": "wpad.us-east-1.ec2-utilities.amazonaws.com", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "IsTainted": false, 
            "SourceProcessBackingFileDriveLetter": "C:", 
            "TimeStamp": "2019-03-01T17:55:42.854+0000", 
            "IsTaintTransfer": false, 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Action": "DNS_QUERY", 
            "SourceProcessUser": "WORKGROUP\\EC2AMAZ-D6LF2KI$", 
            "ConditionIds": [
                "countertack:observable-D0A10636-B5F7-48B1-A338-280AEA504D58"
            ], 
            "SourceType": "process", 
            "IsOrigin": false, 
            "ConditionNames": [
                "DNS request sent"
            ], 
            "Id": "F2NJxnZCNgENy7IlvZXFZ2p4GKxo-uo5"
        }, 
        {
            "Impact": 0, 
            "TargetType": "dns", 
            "IsKey": false, 
            "SourceProcessBackingFileDeviceName": "\\Device\\HarddiskVolume1", 
            "SourceProcessPid": 1240, 
            "SourceProcessTimeStarted": "2019-02-11T11:28:58.067+0000", 
            "SourceProcessName": "svchost.exe", 
            "InsertionTimeStamp": "2019-03-01T17:55:44.158+0000", 
            "SourceProcessBackingFilePath": "C:\\Windows\\System32\\svchost.exe", 
            "SourceProcessSid": "S-1-5-20", 
            "EventType": "basic", 
            "SourceProcessParentPid": 596, 
            "SourceProcessBackingFileReferenceNumber": -46171748948768, 
            "TargetDnsQueryName": "wpad.eu-central-1.ec2-utilities.amazonaws.com", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "IsTainted": false, 
            "SourceProcessBackingFileDriveLetter": "C:", 
            "TimeStamp": "2019-03-01T17:55:42.854+0000", 
            "IsTaintTransfer": false, 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Action": "DNS_QUERY", 
            "SourceProcessUser": "WORKGROUP\\EC2AMAZ-D6LF2KI$", 
            "ConditionIds": [
                "countertack:observable-D0A10636-B5F7-48B1-A338-280AEA504D58"
            ], 
            "SourceType": "process", 
            "IsOrigin": false, 
            "ConditionNames": [
                "DNS request sent"
            ], 
            "Id": "F2NJxnZCNgENy7IlvZXFZ2p4GKxo-0cG"
        }, 
        {
            "Impact": 0, 
            "TargetType": "dns", 
            "IsKey": false, 
            "SourceProcessBackingFileDeviceName": "\\Device\\HarddiskVolume1", 
            "SourceProcessPid": 1240, 
            "SourceProcessTimeStarted": "2019-02-11T11:28:58.067+0000", 
            "SourceProcessName": "svchost.exe", 
            "InsertionTimeStamp": "2019-03-01T17:55:44.159+0000", 
            "SourceProcessBackingFilePath": "C:\\Windows\\System32\\svchost.exe", 
            "SourceProcessSid": "S-1-5-20", 
            "EventType": "basic", 
            "SourceProcessParentPid": 596, 
            "SourceProcessBackingFileReferenceNumber": -46171748948768, 
            "TargetDnsQueryName": "wpad.eu-central-1.compute.internal", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "IsTainted": false, 
            "SourceProcessBackingFileDriveLetter": "C:", 
            "TimeStamp": "2019-03-01T17:55:42.854+0000", 
            "IsTaintTransfer": false, 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Action": "DNS_QUERY", 
            "SourceProcessUser": "WORKGROUP\\EC2AMAZ-D6LF2KI$", 
            "ConditionIds": [
                "countertack:observable-D0A10636-B5F7-48B1-A338-280AEA504D58"
            ], 
            "SourceType": "process", 
            "IsOrigin": false, 
            "ConditionNames": [
                "DNS request sent"
            ], 
            "Id": "F2NJxnZCNgENy7IlvZXFZ2p4GKxo-sCf"
        }, 
        {
            "Impact": 0, 
            "TargetType": "process", 
            "SourceThreadStartAddress": 0, 
            "IsKey": false, 
            "SourceThreadProcessUser": "root", 
            "SourceThreadTimeStarted": "2019-03-01T14:01:02.177+0000", 
            "SourceProcessPid": 14946, 
            "SourceThreadProcessTimeStarted": "2019-03-01T14:01:02.177+0000", 
            "TargetProcessName": "kworker/0:0", 
            "SourceProcessTimeStarted": "2019-03-01T14:01:02.177+0000", 
            "SourceProcessName": "kworker/0:0", 
            "InsertionTimeStamp": "2019-03-01T18:06:05.990+0000", 
            "SourceProcessSid": "0", 
            "TargetProcessSid": "0", 
            "SourceThreadProcessSid": "0", 
            "EventType": "basic", 
            "TargetProcessTimeStarted": "2019-03-01T14:01:02.177+0000", 
            "SourceThreadTimeFinished": "1970-01-01T00:00:00.000+0000", 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "IsTainted": false, 
            "TimeStamp": "2019-03-01T18:06:02.757+0000", 
            "SourceThreadProcessPid": 14946, 
            "IsTaintTransfer": false, 
            "SourceThreadProcessParentPid": 2, 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "Action": "PROCESS_TERMINATE", 
            "SourceProcessUser": "root", 
            "ConditionIds": [
                "countertack:observable-45AE9331-FDE4-401E-9522-C87DD18AE437"
            ], 
            "TargetProcessUser": "root", 
            "TargetProcessParentPid": 2, 
            "SourceType": "thread", 
            "IsOrigin": false, 
            "TargetProcessPid": 14946, 
            "SourceThreadTid": 14946, 
            "SourceThreadProcessName": "kworker/0:0", 
            "ConditionNames": [
                "Process termination"
            ], 
            "Id": "tc0yqKrFWGKu7piLpyuKYmp4GBwT4YcV"
        }, 
        {
            "Impact": 0, 
            "TargetType": "process", 
            "SourceTcpipCountry": "cn", 
            "IsKey": false, 
            "SourceTcpipVersion": 4, 
            "TargetProcessName": "svchost.exe", 
            "TargetProcessBackingFileDeviceName": "\\Device\\HarddiskVolume1", 
            "InsertionTimeStamp": "2019-03-01T16:58:07.219+0000", 
            "SourceTcpipRemotePort": 21435, 
            "SourceTcpipLongitude": "116.995", 
            "TargetProcessSid": "S-1-5-20", 
            "EventType": "basic", 
            "TargetProcessTimeStarted": "2019-02-11T11:28:57.772+0000", 
            "TargetProcessBackingFileDeviceVendorName": "NVMe", 
            "SourceProcessParentPid": 596, 
            "TargetProcessBackingFileDeviceSize": 32210153472, 
            "TargetProcessBackingFileDeviceSerialNumber": "vol0fede9ef64c7b5345_00000001.", 
            "TargetProcessBackingFileReferenceNumber": -46171748948768, 
            "IsBasic": true, 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "TargetProcessUser": "WORKGROUP\\EC2AMAZ-D6LF2KI$", 
            "IsTainted": false, 
            "SourceTcpipLocalHost": "172.31.36.196", 
            "TimeStamp": "2019-03-01T16:58:03.298+0000", 
            "TargetProcessBackingFileDriveLetter": "C:", 
            "IsTaintTransfer": false, 
            "SourceTcpipLocalPort": 3389, 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Action": "TCP_INBOUND", 
            "TargetProcessBackingFilePath": "C:\\Windows\\System32\\svchost.exe", 
            "ConditionIds": [
                "", 
                "countertack:observable-C65B3DDB-0FD8-4C7F-9166-60CE872A50C3"
            ], 
            "SourceTcpipRegion": "37", 
            "TargetProcessParentPid": 596, 
            "SourceType": "tcpip", 
            "IsOrigin": false, 
            "SourceTcpipLatitude": "36.6653", 
            "TargetProcessPid": 904, 
            "Id": "F2NJxnZCNgENy7IlvZXFZ2p4G9Hmjhhg", 
            "TargetProcessBackingFileDeviceProductName": "Amazon Elastic B", 
            "SourceTcpipDirection": "in", 
            "ConditionNames": [
                "", 
                "Inbound connection established"
            ], 
            "SourceTcpipCity": "jinan", 
            "SourceTcpipRemoteHost": "150.242.117.189"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2344" data-line-end="2345">
<a id="Human_Readable_Output_2344"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2345" data-line-end="2346">
<a id="Results_of_the_events_search_2345"></a>Results of the events search</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Event Type</th>
<th>Events Action</th>
<th>Events EndpointID</th>
<th>Events Impact</th>
<th>Collected time</th>
<th>Source process PID</th>
<th>Source process name</th>
</tr>
</thead>
<tbody>
<tr>
<td>basic</td>
<td>PROCESS_CREATE</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>0</td>
<td>2019-03-01T17:26:59.071+0000</td>
<td>1232</td>
<td>sshd</td>
</tr>
<tr>
<td>basic</td>
<td>FILE_CREATE</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>0</td>
<td>2019-03-01T17:26:59.071+0000</td>
<td>15608</td>
<td>sshd</td>
</tr>
<tr>
<td>basic</td>
<td>PROCESS_CREATE</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>0</td>
<td>2019-03-01T17:26:59.071+0000</td>
<td>15608</td>
<td>sshd</td>
</tr>
<tr>
<td>basic</td>
<td>PROCESS_TERMINATE</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>0</td>
<td>2019-03-01T17:27:01.054+0000</td>
<td>15609</td>
<td>sshd</td>
</tr>
<tr>
<td>basic</td>
<td>PROCESS_TERMINATE</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>0</td>
<td>2019-03-01T17:27:01.057+0000</td>
<td>15608</td>
<td>sshd</td>
</tr>
<tr>
<td>basic</td>
<td>DNS_QUERY</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>0</td>
<td>2019-03-01T17:55:42.854+0000</td>
<td>1240</td>
<td>svchost.exe</td>
</tr>
<tr>
<td>basic</td>
<td>DNS_QUERY</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>0</td>
<td>2019-03-01T17:55:42.854+0000</td>
<td>1240</td>
<td>svchost.exe</td>
</tr>
<tr>
<td>basic</td>
<td>DNS_QUERY</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>0</td>
<td>2019-03-01T17:55:42.854+0000</td>
<td>1240</td>
<td>svchost.exe</td>
</tr>
<tr>
<td>basic</td>
<td>PROCESS_TERMINATE</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>0</td>
<td>2019-03-01T18:06:02.757+0000</td>
<td>14946</td>
<td>kworker/0:0</td>
</tr>
<tr>
<td>basic</td>
<td>TCP_INBOUND</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>0</td>
<td>2019-03-01T16:58:03.298+0000</td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7180250f-9c10-4a6f-8d5e-dfc37a0b2cbb" class="code-line" data-line-start="2360" data-line-end="2361">
<a id="19_Terminate_all_instances_of_a_process_2360"></a>19. Terminate all instances of a process</h3>
<hr>
<p class="has-line-data" data-line-start="2362" data-line-end="2363">Terminates all instances of the process identified in the command. Processes can be identified by the PID or process name.</p>
<p class="has-line-data" data-line-start="2364" data-line-end="2365"> </p>
<h5 class="code-line" data-line-start="2365" data-line-end="2366">
<a id="Base_Command_2365"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2367" data-line-end="2368"><code>countertack-kill-process</code></p>
<h5 class="code-line" data-line-start="2368" data-line-end="2369">
<a id="Input_2368"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 525px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">endpoint_id</td>
<td style="width: 525px;">The ID of the endpoint. To get the “endpoint_id”, run the<span> </span><code>get-endpoints</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">process_id</td>
<td style="width: 525px;">The process PID. To get the “process_id”, run the<span> </span><code>search-events</code><span> </span>command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">process_name</td>
<td style="width: 525px;">The name of the process. To get the “process_name”, run the<span> </span><code>search-events</code> command.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2377" data-line-end="2378">
<a id="Context_Output_2377"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 302px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.EndpointIds</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The ID of the source this command is being sent to.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.TargetType</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The type of resource or collection this command is being sent to.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.CommandArg.name</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The name of the process that was terminated.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.CommandArg.pid</td>
<td style="width: 52px;">number</td>
<td style="width: 386px;">The PID of the process that was terminated.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.CommandArg</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The command arguments.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.Status</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The status of the command (initial, pending, complete, error).</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.CommandName</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The name of the command that is sent.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.Username</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The username of the user that requested the command.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.Id</td>
<td style="width: 52px;">string</td>
<td style="width: 386px;">The ID of the commands.</td>
</tr>
<tr>
<td style="width: 302px;">CounterTack.Endpoint.RequestTime</td>
<td style="width: 52px;">date</td>
<td style="width: 386px;">The time at which the client requested the command.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2393" data-line-end="2394">
<a id="Command_Example_2393"></a>Command Example</h5>
<pre>!countertack-kill-process endpoint_id=b5cd32a8-aac5-5862-aeee-988ba72b8a62 process_id=1232</pre>
<h5 class="code-line" data-line-start="2396" data-line-end="2397">Human Readable Output</h5>
<h3 class="code-line" data-line-start="2397" data-line-end="2398">
<a id="The_process_has_been_terminated_2397"></a>The process has been terminated</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Command Name</th>
<th>Endpoint ID</th>
<th>Id</th>
<th>Request Time</th>
<th>Status</th>
<th>User Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>kill_process</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62-0000001565175635953-b</td>
<td>2019-08-07T11:00:35.953+0000</td>
<td>initial</td>
<td>kelvis.com@local</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_97ba610b-549f-48d1-84e4-2e801caa0004" class="code-line" data-line-start="2403" data-line-end="2404">
<a id="20_Search_for_file_hashes_2403"></a>20. Search for file hashes</h3>
<hr>
<p class="has-line-data" data-line-start="2405" data-line-end="2406">Searches for hashes using CQL expressions (Contextual Query Language) to represent queries.</p>
<p class="has-line-data" data-line-start="2407" data-line-end="2408"> </p>
<h5 class="code-line" data-line-start="2408" data-line-end="2409">
<a id="Base_Command_2408"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2410" data-line-end="2411"><code>countertack-search-hashes</code></p>
<h5 class="code-line" data-line-start="2411" data-line-end="2412">
<a id="Input_2411"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 75px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">expression</td>
<td style="width: 523px;">The CQL expression to be used for the search (e.g hashes.type = md5)</td>
<td style="width: 75px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2418" data-line-end="2419">
<a id="Context_Output_2418"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 258px;"><strong>Path</strong></th>
<th style="width: 50px;"><strong>Type</strong></th>
<th style="width: 432px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 258px;">CounterTack.Hash.AvCoverage</td>
<td style="width: 50px;">number</td>
<td style="width: 432px;">The percentage of AV engines that determined that the hash is malicious.</td>
</tr>
<tr>
<td style="width: 258px;">CounterTack.Hash.Id</td>
<td style="width: 50px;">string</td>
<td style="width: 432px;">The ID of the hashes.</td>
</tr>
<tr>
<td style="width: 258px;">CounterTack.Hash.Impact</td>
<td style="width: 50px;">number</td>
<td style="width: 432px;">The impact score for the event in the hash (1-100).</td>
</tr>
<tr>
<td style="width: 258px;">CounterTack.Hash.Type</td>
<td style="width: 50px;">string</td>
<td style="width: 432px;">The type of file hash (sha256, md5, or ssdeep).</td>
</tr>
<tr>
<td style="width: 258px;">CounterTack.Hash.VtReportLocation</td>
<td style="width: 50px;">string</td>
<td style="width: 432px;">The report location for VirusTotal report.</td>
</tr>
<tr>
<td style="width: 258px;">File.MD5</td>
<td style="width: 50px;">string</td>
<td style="width: 432px;">The MD5 of the file</td>
</tr>
<tr>
<td style="width: 258px;">File.SHA256</td>
<td style="width: 50px;">string</td>
<td style="width: 432px;">The SHA256 of the file.</td>
</tr>
<tr>
<td style="width: 258px;">File.SSDeep</td>
<td style="width: 50px;">string</td>
<td style="width: 432px;">The ssdeep of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2432" data-line-end="2433">
<a id="Command_Example_2432"></a>Command Example</h5>
<pre>!countertack-search-hashes expression=hashes.type=md5</pre>
<h5 class="code-line" data-line-start="2435" data-line-end="2436">
<a id="Context_Example_2435"></a>Context Example</h5>
<pre>{
    "CounterTack.Hash": [
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/aa4a82a4623329aaec0c976077504b462bf08f70b95ad3c4900a0a95ae654a97/analysis/1509573407/", 
            "Type": "MD5", 
            "MD5": "28289fa7b8b0cef2aef74f42d448e4ef"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/819287ebc2ee3188385a3bede5b559e999967b227b84f6daf05131abe3fdb650/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "0a081c08592efc5fb3c9d2bda28c0e14"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/dd01d7374babf4c5764bdcc09f38a448b4613690d3573cc7744a538421e8d12f/analysis/1509573408/", 
            "Type": "MD5", 
            "MD5": "8dcb336d9ed101bbf4fa4fda36db3c8b"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/76ea0717d90074785d6a7d6383ae6886ccf8e42ad43aa4ccdc7767f6970cbe64/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "bd1258948a24f845a9a4b077f9473b70"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/f4a7df03656bb42863691804605eb67256933f4ff785c9f521175158907cd5a9/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "31c62407bc3e01942f73ff4e0750ed8d"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/ed0acd46fd9c7a69846cde03bb422d0f16514fa9baeb1bacaa892d912577a43c/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "9e60c9a06741d7f1c034c095b3d82ceb"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/b0d70b4d71a32d9d37664a69e286ebbd43059115c9d6fb0d0e234bafd6b39c67/analysis/1509573404/", 
            "Type": "MD5", 
            "MD5": "9853108de818591776e401896824e221"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/cc3427cce525c40f147061486317d0e70567ac099026ca21db4bb9edbc1fad38/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "7c1a9188b256d85c825676a57afd8bc3"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/40e0e828ed22c0032e2ba668fa989dd3ee7d0bed18b1a3b943c29d5451700a1e/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "e347402e7d117e9cae27b9c8df67756c"
        }, 
        {
            "Impact": 0, 
            "AV Coverage": 0, 
            "VT report location": "https://www.virustotal.com/file/13ccd8d1d4a2afe20a67d76db55057cc5c0f643a7329dc47fdc2df28387b4187/analysis/1509573405/", 
            "Type": "MD5", 
            "MD5": "0ccb661b29f1914fab827f05b33cd4ff"
        }
    ], 
    "File": [
        {
            "MD5": "28289fa7b8b0cef2aef74f42d448e4ef"
        }, 
        {
            "MD5": "0a081c08592efc5fb3c9d2bda28c0e14"
        }, 
        {
            "MD5": "8dcb336d9ed101bbf4fa4fda36db3c8b"
        }, 
        {
            "MD5": "bd1258948a24f845a9a4b077f9473b70"
        }, 
        {
            "MD5": "31c62407bc3e01942f73ff4e0750ed8d"
        }, 
        {
            "MD5": "9e60c9a06741d7f1c034c095b3d82ceb"
        }, 
        {
            "MD5": "9853108de818591776e401896824e221"
        }, 
        {
            "MD5": "7c1a9188b256d85c825676a57afd8bc3"
        }, 
        {
            "MD5": "e347402e7d117e9cae27b9c8df67756c"
        }, 
        {
            "MD5": "0ccb661b29f1914fab827f05b33cd4ff"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2545" data-line-end="2546">
<a id="Human_Readable_Output_2545"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2546" data-line-end="2547">
<a id="Results_of_the_hashes_search_2546"></a>Results of the hashes search:</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>AV Coverage</th>
<th>Impact</th>
<th>MD5</th>
<th>Type</th>
<th>VT report location</th>
</tr>
</thead>
<tbody>
<tr>
<td>0</td>
<td>0</td>
<td>28289fa7b8b0cef2aef74f42d448e4ef</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/aa4a82a4623329aaec0c976077504b462bf08f70b95ad3c4900a0a95ae654a/analysis/1509573407/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>0a081c08592efc5fb3c9d2bda28c0e14</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/819287ebc2ee3188385a3bede5b559e999967b227b84f6daf05131abe3fdb6/analysis/1509573405/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>8dcb336d9ed101bbf4fa4fda36db3c8b</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/dd01d7374babf4c5764bdcc09f38a448b4613690d3573cc7744a538421e82f/analysis/1509573408/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>bd1258948a24f845a9a4b077f9473b70</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/76ea0717d90074785d6a7d6383ae6886ccf8e42ad43aa4ccdc7767f6970e64/analysis/1509573405/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>31c62407bc3e01942f73ff4e0750ed8d</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/f4a7df03656bb42863691804605eb67256933f4ff785c9f521175158907ca9/analysis/1509573405/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>9e60c9a06741d7f1c034c095b3d82ceb</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/ed0acd46fd9c7a69846cde03bb422d0f16514fa9baeb1bacaa89212577a43c/analysis/1509573405/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>9853108de818591776e401896824e221</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/b0d70b4d71a32d9d37664a69e286ebbd43059115c9d6fb0d0ebafd6b39c67/analysis/1509573404/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>7c1a9188b256d85c825676a57afd8bc3</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/cc3427cce525c40f147061486317d0e70567ac099026ca21db4bedbc1fad38/analysis/1509573405/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>e347402e7d117e9cae27b9c8df67756c</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/40e0e828ed22c0032e2ba668fa989dd3ee7d0bed18b1a3b943cd5451700a1e/analysis/1509573405/</td>
</tr>
<tr>
<td>0</td>
<td>0</td>
<td>0ccb661b29f1914fab827f05b33cd4ff</td>
<td>MD5</td>
<td>https://www.virustotal.com/file/13ccd8d1d4a2afe20a67d76db55057cc5c0f643a7329dc47fddf28387b4187/analysis/1509573405/</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_04015056-544a-47e4-aa6c-28bc645d5c19" class="code-line" data-line-start="2561" data-line-end="2562">
<a id="21_Search_for_endpoints_2561"></a>21. Search for endpoints</h3>
<hr>
<p class="has-line-data" data-line-start="2563" data-line-end="2564">Searches for endpoints search using CQL expression (Contextual Query Language) to represent queries.</p>
<p class="has-line-data" data-line-start="2565" data-line-end="2566"> </p>
<h5 class="code-line" data-line-start="2566" data-line-end="2567">
<a id="Base_Command_2566"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2568" data-line-end="2569"><code>countertack-search-endpoints</code></p>
<h5 class="code-line" data-line-start="2569" data-line-end="2570">
<a id="Input_2569"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">expression</td>
<td style="width: 520px;">The CQL expression to be used for the search, for example, endpoints.status=on.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p class="code-line" data-line-start="2576" data-line-end="2577"> </p>
<h5 class="code-line" data-line-start="2576" data-line-end="2577">
<a id="Context_Output_2576"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 331px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 356px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Memory</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">The RAM of the endpoint (in megabytes).</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.CpuType</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">Bit length of the CPU architecture.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.WinRdpPort</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">RDP port used by the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Macs</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">MAC addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Ip</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">IP address used to connect to the analysis cluster.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Vendor</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">OS vendor.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Identifier</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">OS identifier.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Tenant</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Tenant ID set at the time of KM installation.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.MaxImpact</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">Impact of the highest scoring behavior.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Ips</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">IP addresses associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.CurrentResponsePolicy</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Currently active response policy.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.ProfileVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Version of the current profile used for collection.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.CurrentProfile</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Currently active analysis profile.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.DriverVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Endpoint sensor version.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.NumCpus</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">Number of CPUs.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.ClusterConnectionRoute</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">List of hosts the endpoint is currently connected through.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.ClusterHosts</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">The list of hosts that the endpoint tries to connect through (in order).</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Status</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Collection status of the endpoint (ON, PAUSE, OFF, INIT).</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.TimeStarted</td>
<td style="width: 53px;">Date</td>
<td style="width: 356px;">Time kernel module collection last engaged.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.EventStartTime</td>
<td style="width: 53px;">Date</td>
<td style="width: 356px;">The time that the event was captured.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Version</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">OS version.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Threat</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Threat level associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.ProductName</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.Id</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Endpoints ID.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.LastActive</td>
<td style="width: 53px;">Date</td>
<td style="width: 356px;">Time of last event captured on the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.SensorMode</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Specifies the sensor mode of the driver.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.BehaviorCount</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">Number of behaviors detected.</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.ImpactLevel</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Threat level of the endpoint.(LOW, MEDIUM, HIGH, CRITICAL).</td>
</tr>
<tr>
<td style="width: 331px;">CounterTack.Endpoint.OsType</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">The OS type.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.Memory</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">Endpoint RAM (megabytes).</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.Processors</td>
<td style="width: 53px;">Number</td>
<td style="width: 356px;">Number of CPUs.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.Domain</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">DNS suffix for the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.OS</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">Product name of the endpoint OS.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.MACAddress</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.Model</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">The analysis profile that is currently active.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.IPAddress</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">The IP addresses that are associated with the endpoint.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.OSVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">The endpoint sensor version.</td>
</tr>
<tr>
<td style="width: 331px;">Endpoint.Id</td>
<td style="width: 53px;">String</td>
<td style="width: 356px;">The ID of the endpoints.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2621" data-line-end="2622">
<a id="Command_Example_2621"></a>Command Example</h5>
<pre>!countertack-search-endpoints expression=endpoints.status=off</pre>
<h5 class="code-line" data-line-start="2624" data-line-end="2625">
<a id="Context_Example_2624"></a>Context Example</h5>
<pre>{
    "CounterTack.Endpoint": [
        {
            "ImpactLevel": "HIGH", 
            "CurrentResponsePolicy": "policy-1541066914070800", 
            "ResponsePolicyVersion": "29f9f82456c0fa377c37bd8a5a85ccf4", 
            "Version": "Darwin 18.5.0 x86_64", 
            "GroupIds": [
                "groups-builtin-outdated-km"
            ], 
            "BehaviorCount": 42315, 
            "Memory": 16384, 
            "MaxImpact": 90, 
            "Status": "OFF", 
            "ClusterHosts": [
                "trialcloud.countertack.com"
            ], 
            "Macs": [
                "00:00:00:00:00:00", 
                "AC:DE:48:00:11:22"
            ], 
            "TimeStarted": "2019-05-21T09:03:49.591+0000", 
            "EventStartTime": "2019-05-21T09:03:47.578+0000", 
            "DriverVersion": "5.8.4.64", 
            "SensorMode": "advanced", 
            "OsType": 2, 
            "CpuType": "64", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "TLVMAC30YCJG5H", 
            "WinRdpPort": 0, 
            "ProfileVersion": "b95032b028b3417dc7c09e19c9d7e326", 
            "CurrentProfile": "Default-Mac-Profile", 
            "Threat": "HIGH", 
            "Vendor": "Apple", 
            "Identifier": "macOS", 
            "Ip": "172.22.100.85", 
            "ProductName": "macOS 10.14.4 Mojave", 
            "Ips": [
                "fe80:0008:0000:0000:aede:48ff:fe00:1122"
            ], 
            "ClusterConnectionRoute": [
                "democloud-collector02.us-west2c.countertack.com", 
                "democloud.countertack.com"
            ], 
            "LastActive": "2019-05-21T09:03:49.591+0000", 
            "Id": "8ce40b54-154e-ccd9-3ae5-46011c1b6b50", 
            "NumCpus": 12
        }
    ], 
    "Endpoint": [
        {
            "MACAddress": "", 
            "Domain": "", 
            "Processors": 12, 
            "OS": "macOS 10.14.4 Mojave", 
            "Memory": 16384, 
            "Model": "Default-Mac-Profile", 
            "OSVersion": "5.8.4.64", 
            "IPAddress": [
                "fe80:0008:0000:0000:aede:48ff:fe00:1122"
            ], 
            "Id": "8ce40b54-154e-ccd9-3ae5-46011c1b6b50"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2693" data-line-end="2694">
<a id="Human_Readable_Output_2693"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2694" data-line-end="2695">
<a id="Results_of_the_endpoints_search_2694"></a>Results of the endpoints search</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Status</th>
<th>Name</th>
<th>Id</th>
<th>OS</th>
<th>Threat</th>
<th>IP</th>
</tr>
</thead>
<tbody>
<tr>
<td>OFF</td>
<td>TLVMAC30YCJG5H</td>
<td>8ce40b54-154e-ccd9-3ae5-46011c1b6b50</td>
<td>macOS 10.14.4 Mojave</td>
<td>HIGH</td>
<td>fe80:0008:0000:0000:aede:48ff:fe00:1122</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_f499a204-8783-4238-bfcc-f8070b8e3cc3" class="code-line" data-line-start="2700" data-line-end="2701">
<a id="22_Search_for_behaviors_2700"></a>22. Search for behaviors</h3>
<hr>
<p class="has-line-data" data-line-start="2702" data-line-end="2703">Request for behaviors search using CQL expression (Contextual Query Language) to represent queries.</p>
<h5 class="code-line" data-line-start="2705" data-line-end="2706">
<a id="Base_Command_2705"></a>Base Command</h5>
<p class="has-line-data" data-line-start="2707" data-line-end="2708"><code>countertack-search-behaviors</code></p>
<h5 class="code-line" data-line-start="2708" data-line-end="2709">
<a id="Input_2708"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 515px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">expression</td>
<td style="width: 515px;">The CQL expression to be used for the search (e.g.,  behaviors.event_count&lt;60).</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2715" data-line-end="2716">
<a id="Context_Output_2715"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 254px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 434px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 254px;">CounterTack.Behavior.FirstEventId</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The ID of the first event.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.LastReported</td>
<td style="width: 52px;">Date</td>
<td style="width: 434px;">The time that the behavior was last seen.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.Tenant</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The tenant of the behavior.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.MaxImpact</td>
<td style="width: 52px;">Number</td>
<td style="width: 434px;">The impact of the highest scoring event (0-100).</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.Name</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The name of the condition that triggered the behavior.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.EndpointId</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The ID of the endpoint, based on the UUID of the last installed endpoint sensor.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.ReportedOn</td>
<td style="width: 52px;">Date</td>
<td style="width: 434px;">The time that the behavior was first seen.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.EventCount</td>
<td style="width: 52px;">Number</td>
<td style="width: 434px;">The number of events detected.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.TimeStamp</td>
<td style="width: 52px;">Date</td>
<td style="width: 434px;">The start time for the behavior.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.Type</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The type of behavior (CLASSIFICATION, TRACE).</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.Id</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The ID of the behaviors.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.LastActive</td>
<td style="width: 52px;">Date</td>
<td style="width: 434px;">The time that the behavior was last active.</td>
</tr>
<tr>
<td style="width: 254px;">CounterTack.Behavior.ImpactLevel</td>
<td style="width: 52px;">String</td>
<td style="width: 434px;">The threat level of the behavior (LOW, MEDIUM, HIGH, CRITICAL).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2734" data-line-end="2735">
<a id="Command_Example_2734"></a>Command Example</h5>
<pre>!countertack-search-behaviors expression=behaviors.event_count&lt;50</pre>
<h5 class="code-line" data-line-start="2737" data-line-end="2738">
<a id="Context_Example_2737"></a>Context Example</h5>
<pre>{
    "CounterTack.Behavior": [
        {
            "MaxImpact": 50, 
            "EventCount": 7, 
            "ReportedOn": "2019-02-07T05:27:35.143+0000", 
            "TimeStamp": "2019-02-07T05:27:35.532+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p_AkQh065M", 
            "LastActive": "2019-02-07T05:27:37.535+0000", 
            "LastReported": "2019-02-07T05:27:35.194+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7673854781711167052", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "MaxImpact": 10, 
            "EventCount": 6, 
            "ReportedOn": "2019-02-11T13:34:20.790+0000", 
            "TimeStamp": "2019-02-11T13:34:32.502+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p9rWHjbnaE", 
            "LastActive": "2019-02-11T13:34:32.530+0000", 
            "LastReported": "2019-02-11T13:34:20.806+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "SciId": "176349c6-7642-3601-0dcb-b225bd95c567!windows_service_manager_1", 
            "Type": "classification", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!9223370486962703305!newService.WindowsServiceManager", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "newService.WindowsServiceManager"
        }, 
        {
            "MaxImpact": 10, 
            "EventCount": 1, 
            "ReportedOn": "2019-01-29T12:45:45.500+0000", 
            "TimeStamp": "2019-01-29T12:45:46.483+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "tc0yqKrFWGKu7piLpyuKYmqBrZQKOJox", 
            "LastActive": "2019-01-29T12:45:46.484+0000", 
            "LastReported": "2019-01-29T12:45:45.500+0000", 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "Type": "trace", 
            "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606091354282545", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Unix: Credentials lift to superuser"
        }, 
        {
            "MaxImpact": 75, 
            "EventCount": 1, 
            "ReportedOn": "2019-02-03T08:22:42.688+0000", 
            "TimeStamp": "2019-02-03T08:22:46.483+0000", 
            "ImpactLevel": "HIGH", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2qAMwfsjU-2", 
            "LastActive": "2019-02-03T08:22:46.485+0000", 
            "LastReported": "2019-02-03T08:22:42.688+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7674189874165796790", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Powershell: System.Management.Automation.dll file read"
        }, 
        {
            "MaxImpact": 10, 
            "EventCount": 1, 
            "ReportedOn": "2019-01-29T12:45:27.979+0000", 
            "TimeStamp": "2019-01-29T12:45:28.473+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "tc0yqKrFWGKu7piLpyuKYmqBrZgehzkV", 
            "LastActive": "2019-01-29T12:45:28.474+0000", 
            "LastReported": "2019-01-29T12:45:27.979+0000", 
            "EndpointId": "b5cd32a8-aac5-5862-aeee-988ba72b8a62", 
            "Type": "trace", 
            "Id": "b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606108874848533", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Unix: Credentials lift to superuser"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 24, 
            "ReportedOn": "2019-02-18T05:26:56.053+0000", 
            "TimeStamp": "2019-02-18T05:26:56.861+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7oer9XUcD", 
            "LastActive": "2019-02-18T06:00:05.895+0000", 
            "LastReported": "2019-02-18T06:00:00.873+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672904420800939779", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 17, 
            "ReportedOn": "2019-02-19T05:27:07.092+0000", 
            "TimeStamp": "2019-02-19T05:27:07.926+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7U1PaH_e-", 
            "LastActive": "2019-02-19T11:40:07.401+0000", 
            "LastReported": "2019-02-19T11:40:06.648+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672818009762691006", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "MaxImpact": 15, 
            "EventCount": 19, 
            "ReportedOn": "2019-02-18T15:36:12.782+0000", 
            "TimeStamp": "2019-02-18T15:36:15.024+0000", 
            "ImpactLevel": "LOW", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7gKt2hpET", 
            "LastActive": "2019-02-19T13:55:41.749+0000", 
            "LastReported": "2019-02-19T13:55:39.356+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672867864072065299", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Sponsor process started"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 46, 
            "ReportedOn": "2019-02-20T05:27:24.057+0000", 
            "TimeStamp": "2019-02-20T05:27:24.744+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p7BLtVk609", 
            "LastActive": "2019-02-20T11:40:38.774+0000", 
            "LastReported": "2019-02-20T11:40:36.549+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672731592796908861", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }, 
        {
            "MaxImpact": 50, 
            "EventCount": 5, 
            "ReportedOn": "2019-02-22T05:27:18.024+0000", 
            "TimeStamp": "2019-02-22T05:27:19.254+0000", 
            "ImpactLevel": "MEDIUM", 
            "FirstEventId": "F2NJxnZCNgENy7IlvZXFZ2p6Z5Oal5rI", 
            "LastActive": "2019-02-22T05:27:19.267+0000", 
            "LastReported": "2019-02-22T05:27:18.058+0000", 
            "EndpointId": "176349c6-7642-3601-0dcb-b225bd95c567", 
            "Type": "trace", 
            "Id": "176349c6-7642-3601-0dcb-b225bd95c567!7672558798830541512", 
            "Tenant": "fc35572e-0171-4bd3-9117-044188832e9e", 
            "Name": "Commandline Utility Process Created"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2896" data-line-end="2897">
<a id="Human_Readable_Output_2896"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2897" data-line-end="2898">
<a id="Results_of_the_behaviors_search_2897"></a>Results of the behaviors search</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Name</th>
<th>Type</th>
<th>Impact_Level</th>
<th>Id</th>
<th>EndpointID</th>
<th>lastReported</th>
</tr>
</thead>
<tbody>
<tr>
<td>Commandline Utility Process Created</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7673854781711167052</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-07T05:27:35.194+0000</td>
</tr>
<tr>
<td>newService.WindowsServiceManager</td>
<td>classification</td>
<td>LOW</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!9223370486962703305!newService.WindowsServiceManager</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-11T13:34:20.806+0000</td>
</tr>
<tr>
<td>Unix: Credentials lift to superuser</td>
<td>trace</td>
<td>LOW</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606091354282545</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-01-29T12:45:45.500+0000</td>
</tr>
<tr>
<td>Powershell: System.Management.Automation.dll file read</td>
<td>trace</td>
<td>HIGH</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7674189874165796790</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-03T08:22:42.688+0000</td>
</tr>
<tr>
<td>Unix: Credentials lift to superuser</td>
<td>trace</td>
<td>LOW</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62!7674606108874848533</td>
<td>b5cd32a8-aac5-5862-aeee-988ba72b8a62</td>
<td>2019-01-29T12:45:27.979+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672904420800939779</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-18T06:00:00.873+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672818009762691006</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-19T11:40:06.648+0000</td>
</tr>
<tr>
<td>Sponsor process started</td>
<td>trace</td>
<td>LOW</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672867864072065299</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-19T13:55:39.356+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672731592796908861</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-20T11:40:36.549+0000</td>
</tr>
<tr>
<td>Commandline Utility Process Created</td>
<td>trace</td>
<td>MEDIUM</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567!7672558798830541512</td>
<td>176349c6-7642-3601-0dcb-b225bd95c567</td>
<td>2019-02-22T05:27:18.058+0000</td>
</tr>
</tbody>
</table>