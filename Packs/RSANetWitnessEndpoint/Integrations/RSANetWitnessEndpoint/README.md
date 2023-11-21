<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>RSA NetWitness Endpoint provides deep visibility beyond basic endpoint security solutions by monitoring and collecting activity across all of your endpoints—on and off your network.<br>Use this integration to access to information about endpoints, modules, and indicators.</p>
<p>This integration was integrated and tested with RSA NetWitness Endpoint v4.0.</p>
<p> </p>
<h2>Configure RSA NetWitness Endpoint on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for RSA NetWitness Endpoint.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1:30022/" rel="nofollow">https://192.168.0.1:30022</a>)</strong></li>
<li><strong>credentials</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URL and credentials.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br>After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li>Get GUIDs for multiple machines: netwitness-get-machines</li>
<li>Get the GUID for a single machine: netwitness-get-machine</li>
<li>List IOCs for a specific machine: netwitness-get-machine-iocs</li>
<li>Get information for machine modules: netwitness-get-machine-modules</li>
<li>Get information for a single machine module: netwitness-get-machine-module</li>
<li>Blacklist IP addresses: netwitness-blacklist-ips</li>
<li>Blacklist domains: netwitness-blacklist-domains</li>
</ol>
<h3>1. Get GUIDs for multiple machines</h3>
<hr>
<p>Get machine GUID. Search by machine name and more.</p>
<h5>Base Command</h5>
<pre><code>netwitness-get-machines</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>machineName</td>
<td>Hostname to filter results by. Not case sensitive.</td>
<td>Optional</td>
</tr>
<tr>
<td>iocScoreGreaterThan</td>
<td>Filter all machines whose IOC score is greater than or equal to this value. Default = 0.</td>
<td>Optional</td>
</tr>
<tr>
<td>iocScoreLessThan</td>
<td>Filter all machines whose IOC score is less than or equal to this value. Default = 1024. Cannot be zero.</td>
<td>Optional</td>
</tr>
<tr>
<td>ipAdress</td>
<td>Filter all machines based on IP address.</td>
<td>Optional</td>
</tr>
<tr>
<td>macAddress</td>
<td>Filter all machines based on MAC address.</td>
<td>Optional</td>
</tr>
<tr>
<td>limit</td>
<td>Limit the number of results. Default = 100.</td>
<td>Optional</td>
</tr>
<tr>
<td>includeMachineData</td>
<td>Include full machine data</td>
<td>Optional</td>
</tr>
<tr>
<td>includeMachineIOCs</td>
<td>Include machine IOCs</td>
<td>Optional</td>
</tr>
<tr>
<td>includeMachineModules</td>
<td>Include machine modules</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>NetWitness.Machines.MachineGUID</td>
<td>Machine GUID</td>
</tr>
<tr>
<td>NetWitness.Machines.AgentID</td>
<td>Agent ID</td>
</tr>
<tr>
<td>NetWitness.Machines.MachineName</td>
<td>Machine name</td>
</tr>
<tr>
<td>NetWitness.Machines.LocalIP</td>
<td>Local IP</td>
</tr>
<tr>
<td>NetWitness.Machines.RemoteIP</td>
<td>Remote IP</td>
</tr>
<tr>
<td>NetWitness.Machines.MAC</td>
<td>MAC</td>
</tr>
<tr>
<td>NetWitness.Machines.MachineStatus</td>
<td>Machine status</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCScore</td>
<td>IIOC score</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCLevel0</td>
<td>IIOC Level 0</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCLevel1</td>
<td>IIOC Level 1</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCLevel2</td>
<td>IIOC Level 2</td>
</tr>
<tr>
<td>NetWitness.Machine.IIOCLevel3</td>
<td>IIOC Level 3</td>
</tr>
<tr>
<td>NetWitness.Machines.AntiVirusDisabled</td>
<td>Anti-virus disabled</td>
</tr>
<tr>
<td>NetWitness.Machines.Comment</td>
<td>Comment</td>
</tr>
<tr>
<td>NetWitness.Machines.ContainmentStatus</td>
<td>Containment status</td>
</tr>
<tr>
<td>NetWitness.Machines.ContainmentSupported</td>
<td>Containment supported</td>
</tr>
<tr>
<td>NetWitness.Machines.Country</td>
<td>Country</td>
</tr>
<tr>
<td>NetWitness.Machines.DNS</td>
<td>DNS</td>
</tr>
<tr>
<td>NetWitness.Machines.DomainName</td>
<td>Domain name</td>
</tr>
<tr>
<td>NetWitness.Machines.FirewallDisabled</td>
<td>Firewall disabled</td>
</tr>
<tr>
<td>NetWitness.Machines.Gateway</td>
<td>Gateway</td>
</tr>
<tr>
<td>NetWitness.Machines.Group</td>
<td>Group</td>
</tr>
<tr>
<td>NetWitness.Machines.Idle</td>
<td>Idle</td>
</tr>
<tr>
<td>NetWitness.Machines.InstallTime</td>
<td>Install time</td>
</tr>
<tr>
<td>NetWitness.Machines.InstallationFailed</td>
<td>Installation failed</td>
</tr>
<tr>
<td>NetWitness.Machines.LastScan</td>
<td>Last scan</td>
</tr>
<tr>
<td>NetWitness.Machines.LastSeen</td>
<td>Last seen</td>
</tr>
<tr>
<td>NetWitness.Machines.NetworkSegment</td>
<td>Network segment</td>
</tr>
<tr>
<td>NetWitness.Machines.OperatingSystem</td>
<td>Operating system</td>
</tr>
<tr>
<td>NetWitness.Machines.OrganizationUnit</td>
<td>Organization unit</td>
</tr>
<tr>
<td>NetWitness.Machines.Platform</td>
<td>Platform</td>
</tr>
<tr>
<td>NetWitness.Machines.Scanning</td>
<td>Scanning</td>
</tr>
<tr>
<td>NetWitness.Machines.UserName</td>
<td>User name</td>
</tr>
<tr>
<td>NetWitness.Machine.VersionInfo</td>
<td>Version information</td>
</tr>
<tr>
<td>NetWitness.IOCs.Description</td>
<td>Description</td>
</tr>
<tr>
<td>NetWitness.IOCs.Type</td>
<td>Type</td>
</tr>
<tr>
<td>NetWitness.IOCs.MachineCount</td>
<td>Machine count</td>
</tr>
<tr>
<td>NetWitness.IOCs.ModuleCount</td>
<td>Module count</td>
</tr>
<tr>
<td>NetWitness.IOCs.IOCLevel</td>
<td>IOC level</td>
</tr>
<tr>
<td>NetWitness.IOCs.Priority</td>
<td>Priority</td>
</tr>
<tr>
<td>NetWitness.IOCs.Active</td>
<td>Active</td>
</tr>
<tr>
<td>NetWitness.IOCs.LastExecuted</td>
<td>Last executed</td>
</tr>
<tr>
<td>NetWitness.IOCs.Alertable</td>
<td>Alertable</td>
</tr>
<tr>
<td>NetWitness.IOCs.IOCTriggeredOnMachine</td>
<td>IOC Triggered On Machine</td>
</tr>
<tr>
<td>NetWitness.Machines.MachineGUID</td>
<td>Machine GUID</td>
</tr>
<tr>
<td>NetWitness.Modules.ModuleName</td>
<td>Module name</td>
</tr>
<tr>
<td>NetWitness.Modules.ModuleID</td>
<td>Module ID</td>
</tr>
<tr>
<td>NetWitness.Modules.Description</td>
<td>Description</td>
</tr>
<tr>
<td>NetWitness.Modules.IOCScore</td>
<td>IOC score</td>
</tr>
<tr>
<td>NetWitness.Modules.AnalyticsScore</td>
<td>Analytics score</td>
</tr>
<tr>
<td>NetWitness.Modules.GlobalMachineCount</td>
<td>Global machine count</td>
</tr>
<tr>
<td>NetWitness.Modules.MD5</td>
<td>MD5</td>
</tr>
<tr>
<td>NetWitness.Modules.SHA256</td>
<td>SHA-256</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!netwitness-get-machines limit="100" includeMachineData="no" includeMachineIOCs="no" includeMachineModules="no"</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Machines<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>IOCScore<span class="pl-pds">"</span></span>: {
                <span class="pl-s"><span class="pl-pds">"</span>FilterValue<span class="pl-pds">"</span></span>: <span class="pl-c1">71</span>,
                <span class="pl-s"><span class="pl-pds">"</span>FullScore<span class="pl-pds">"</span></span>: <span class="pl-c1">8016</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level<span class="pl-pds">"</span></span>: <span class="pl-c1">3</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level0<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level1<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level2<span class="pl-pds">"</span></span>: <span class="pl-c1">8</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level3<span class="pl-pds">"</span></span>: <span class="pl-c1">16</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Score<span class="pl-pds">"</span></span>: <span class="pl-c1">71</span>,
                <span class="pl-s"><span class="pl-pds">"</span>__type<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Tools.IOCScore, Tools<span class="pl-pds">"</span></span>
            },
            <span class="pl-s"><span class="pl-pds">"</span>LastScan<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>2018-09-12T15:59:48Z<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>LocalIp<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxx.xxx.xxx.xxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MacAddress<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xx:xx:xx:xx:xx:xxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineGUID<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxxxxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>NWE<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Online<span class="pl-pds">"</span></span>: <span class="pl-c1">true</span>,
            <span class="pl-s"><span class="pl-pds">"</span>OperatingSystem<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Microsoft Windows Server 2012 R2 Datacenter<span class="pl-pds">"</span></span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h3>NetWitness Endpoint - Get Machines</h3>
<table>
<thead>
<tr>
<th>MachineName</th>
<th>MachineGUID</th>
<th>Online</th>
<th>OperatingSystem</th>
<th>LastScan</th>
<th>IOCScore</th>
<th>MacAddress</th>
<th>LocalIp</th>
</tr>
</thead>
<tbody>
<tr>
<td>NWE</td>
<td>xxxxxxxx</td>
<td>true</td>
<td>Microsoft Windows Server 2012 R2 Datacenter</td>
<td>2018-09-12T15:59:48Z</td>
<td>FilterValue: 71<br>Level: 3<br>Score: 71<br>Level0: 0<br>Level1: 0<br>Level2: 8<br>Level3: 16<br>__type: Tools.IOCScore, Tools<br>FullScore: 8016</td>
<td>xx:xx:xx:xx:xx:xx</td>
<td>xxx.xxx.xxx.xxx</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>2. Get the GUID for a single machine</h3>
<hr>
<p>Get information on a specific machine.</p>
<h5>Base Command</h5>
<pre><code>netwitness-get-machine</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>machineGUID</td>
<td>GUID of the machine</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>NetWitness.Machines.AgentID</td>
<td>Agent ID</td>
</tr>
<tr>
<td>NetWitness.Machines.MachineName</td>
<td>Machine name</td>
</tr>
<tr>
<td>NetWitness.Machines.LocalIP</td>
<td>Local IP</td>
</tr>
<tr>
<td>NetWitness.Machines.RemoteIP</td>
<td>Remote IP</td>
</tr>
<tr>
<td>NetWitness.Machines.MAC</td>
<td>MAC</td>
</tr>
<tr>
<td>NetWitness.Machines.MachineStatus</td>
<td>Machine status</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCScore</td>
<td>IIOC score</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCLevel0</td>
<td>IIOC Level 0</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCLevel1</td>
<td>IIOC Level 1</td>
</tr>
<tr>
<td>NetWitness.Machines.IIOCLevel2</td>
<td>IIOC Level 2</td>
</tr>
<tr>
<td>NetWitness.Machine.IIOCLevel3</td>
<td>IIOC Level 3</td>
</tr>
<tr>
<td>NetWitness.Machines.AntiVirusDisabled</td>
<td>Anti-virus disabled</td>
</tr>
<tr>
<td>NetWitness.Machines.Comment</td>
<td>Comment</td>
</tr>
<tr>
<td>NetWitness.Machines.ContainmentStatus</td>
<td>Containment status</td>
</tr>
<tr>
<td>NetWitness.Machines.ContainmentSupported</td>
<td>Containment supported</td>
</tr>
<tr>
<td>NetWitness.Machines.Country</td>
<td>Country</td>
</tr>
<tr>
<td>NetWitness.Machines.DNS</td>
<td>DNS</td>
</tr>
<tr>
<td>NetWitness.Machines.DomainName</td>
<td>Domain name</td>
</tr>
<tr>
<td>NetWitness.Machines.FirewallDisabled</td>
<td>Firewall disabled</td>
</tr>
<tr>
<td>NetWitness.Machines.Gateway</td>
<td>Gateway</td>
</tr>
<tr>
<td>NetWitness.Machines.Group</td>
<td>Group</td>
</tr>
<tr>
<td>NetWitness.Machines.Idle</td>
<td>Idle</td>
</tr>
<tr>
<td>NetWitness.Machines.InstallTime</td>
<td>Installation time</td>
</tr>
<tr>
<td>NetWitness.Machines.InstallationFailed</td>
<td>Installation failed</td>
</tr>
<tr>
<td>NetWitness.Machines.LastScan</td>
<td>Last scan</td>
</tr>
<tr>
<td>NetWitness.Machines.LastSeen</td>
<td>Last seen</td>
</tr>
<tr>
<td>NetWitness.Machines.NetworkSegment</td>
<td>Network segment</td>
</tr>
<tr>
<td>NetWitness.Machines.OperatingSystem</td>
<td>Operating system</td>
</tr>
<tr>
<td>NetWitness.Machines.OrganizationUnit</td>
<td>Organization unit</td>
</tr>
<tr>
<td>NetWitness.Machines.Platform</td>
<td>Platform</td>
</tr>
<tr>
<td>NetWitness.Machines.Scanning</td>
<td>Scanning</td>
</tr>
<tr>
<td>NetWitness.Machines.UserName</td>
<td>User name</td>
</tr>
<tr>
<td>NetWitness.Machine.VersionInfo</td>
<td>Version information</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!netwitness-get-machine machineGUID=abc123def456</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Machine<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>AgentID<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxxxxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>AntiVirusDisabled<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>False<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Comment<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>ContainmentStatus<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Not Contained<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>ContainmentSupported<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>True<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Country<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>USA<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>DNS<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>8.8.8.8<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>DomainName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>WORKGROUP<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>FirewallDisabled<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>False<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Gateway<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxx.xxx.xxx.xxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Group<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Default<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel0<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>0<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>0<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel2<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>8<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel3<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>16<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCScore<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>71<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Idle<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>True<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>InstallTime<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>9/3/2018 4:01:03 PM<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>InstallationFailed<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>False<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>LastScan<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>9/12/2018 3:59:48 PM<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>LastSeen<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>9/25/2018 1:27:01 PM<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>LocalIP<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxx.xxx.xxx.xxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MAC<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xx:xx:xx:xx:xx:xx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>NWE<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineStatus<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Online<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>NetworkSegment<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxx.xxx.xxx.xxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>OperatingSystem<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Microsoft Windows Server 2012 R2 Datacenter<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>OrganizationUnit<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Platform<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>64-bit (x64)<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>RemoteIP<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>xxx.xxx.xxx.xxx<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Scanning<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>False<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>UserName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span><span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>VersionInfo<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>4.4.0.6<span class="pl-pds">"</span></span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h3>NetWitness Endpoint - Machine NWE Full Data</h3>
<table>
<thead>
<tr>
<th>AgentID</th>
<th>MachineName</th>
<th>LocalIP</th>
<th>RemoteIP</th>
<th>MAC</th>
<th>MachineStatus</th>
<th>IIOCScore</th>
<th>IIOCLevel0</th>
<th>IIOCLevel1</th>
<th>IIOCLevel2</th>
<th>IIOCLevel3</th>
<th>AntiVirusDisabled</th>
<th>Comment</th>
<th>ContainmentStatus</th>
<th>ContainmentSupported</th>
<th>Country</th>
<th>DNS</th>
<th>DomainName</th>
<th>FirewallDisabled</th>
<th>Gateway</th>
<th>Group</th>
<th>Idle</th>
<th>InstallTime</th>
<th>InstallationFailed</th>
<th>LastScan</th>
<th>LastSeen</th>
<th>NetworkSegment</th>
<th>OperatingSystem</th>
<th>OrganizationUnit</th>
<th>Platform</th>
<th>Scanning</th>
<th>UserName</th>
<th>VersionInfo</th>
</tr>
</thead>
<tbody>
<tr>
<td>xxxxxx</td>
<td>NWE</td>
<td>xxx.xxx.xxx.xxx</td>
<td>xxx.xxx.xxx.xx</td>
<td>xx:xx:xx:xx:xx:xx</td>
<td>Online</td>
<td>71</td>
<td>0</td>
<td>0</td>
<td>8</td>
<td>16</td>
<td>False</td>
<td> </td>
<td>Not Contained</td>
<td>True</td>
<td>USA</td>
<td>8.8.8.8</td>
<td>WORKGROUP</td>
<td>False</td>
<td>xxx.xxx.xxx.xxx</td>
<td>Default</td>
<td>True</td>
<td>9/3/2018 4:01:03 PM</td>
<td>False</td>
<td>9/12/2018 3:59:48 PM</td>
<td>9/25/2018 1:27:01 PM</td>
<td>xxx.xxx.xxx.xxx</td>
<td>Microsoft Windows Server 2012 R2 Datacenter</td>
<td> </td>
<td>64-bit (x64)</td>
<td>False</td>
<td> </td>
<td>4.4.0.6</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>3. List IOCs for a specific machine</h3>
<hr>
<p>List IOCs for a specific machine.</p>
<h5>Base Command</h5>
<pre><code>netwitness-get-machine-iocs</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>machineGUID</td>
<td>The machine GUID</td>
<td>Required</td>
</tr>
<tr>
<td>limit</td>
<td>Limit the number of results. Default = 100.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>NetWitness.Machines.MachineGUID</td>
<td>Machine GUID</td>
</tr>
<tr>
<td>NetWitness.IOCs.Description</td>
<td>Description</td>
</tr>
<tr>
<td>NetWitness.IOCs.Type</td>
<td>Type</td>
</tr>
<tr>
<td>NetWitness.IOCs.MachineCount</td>
<td>Machine count</td>
</tr>
<tr>
<td>NetWitness.IOCs.ModuleCount</td>
<td>Module count</td>
</tr>
<tr>
<td>NetWitness.IOCs.IOCLevel</td>
<td>IOC level</td>
</tr>
<tr>
<td>NetWitness.IOCs.Priority</td>
<td>Priority</td>
</tr>
<tr>
<td>NetWitness.IOCs.Active</td>
<td>Active</td>
</tr>
<tr>
<td>NetWitness.IOCs.LastExecuted</td>
<td>Last executed</td>
</tr>
<tr>
<td>NetWitness.IOCs.Alertable</td>
<td>Alertable</td>
</tr>
<tr>
<td>NetWitness.IOCs.IOCTriggeredOnMachine</td>
<td>IOC Triggered On Machine</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3>4. Get information for machine modules</h3>
<hr>
<p>Get Names and ID's of modules of the machine. Filter by name or IOC score.</p>
<h5>Base Command</h5>
<pre><code>netwitness-get-machine-modules</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>machineGUID</td>
<td>The machine GUID</td>
<td>Required</td>
</tr>
<tr>
<td>moduleName</td>
<td>Module name to filter results by (not case sensitive). Example: ModuleName=".exe "will match all machines which have the word ".exe" in their module name.</td>
<td>Optional</td>
</tr>
<tr>
<td>iocScoreGreaterThan</td>
<td>Filter all modules whose IOC score is greater than or equal to this value. Default = 0.</td>
<td>Optional</td>
</tr>
<tr>
<td>iocScoreLessThan</td>
<td>Filter all modules whose IOC score is less than or equal to this value. Default = 1024. Cannot be zero.</td>
<td>Optional</td>
</tr>
<tr>
<td>limit</td>
<td>Limit the number of results. Default 50.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>NetWitness.Machines.MachineGUID</td>
<td>Machine GUID</td>
</tr>
<tr>
<td>NetWitness.Modules.ModuleName</td>
<td>Module name</td>
</tr>
<tr>
<td>NetWitness.Modules.ModuleID</td>
<td>Module ID</td>
</tr>
<tr>
<td>NetWitness.Modules.Description</td>
<td>Description</td>
</tr>
<tr>
<td>NetWitness.Modules.IOCScore</td>
<td>IOC score</td>
</tr>
<tr>
<td>NetWitness.Modules.AnalyticsScore</td>
<td>Analytics score</td>
</tr>
<tr>
<td>NetWitness.Modules.GlobalMachineCount</td>
<td>Global machine count</td>
</tr>
<tr>
<td>NetWitness.Modules.MD5</td>
<td>MD5</td>
</tr>
<tr>
<td>NetWitness.Modules.SHA256</td>
<td>SHA-256</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!netwitness-get-machine-modules machineGUID= iocScoreGreaterThan="20" limit="50"</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>File<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>MD5<span class="pl-pds">"</span></span>: <span class="pl-ii">XX</span>,
        <span class="pl-s"><span class="pl-pds">"</span>Name<span class="pl-pds">"</span></span>: <span class="pl-ii">AdobeARMHelper.exe</span>
    },
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Modules<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>AnalyticsScore<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Description<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Adobe Reader and Acrobat Manager Helper<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>GlobalMachineCount<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
            <span class="pl-s"><span class="pl-pds">"</span>IOCScore<span class="pl-pds">"</span></span>: {
                <span class="pl-s"><span class="pl-pds">"</span>FilterValue<span class="pl-pds">"</span></span>: <span class="pl-c1">25</span>,
                <span class="pl-s"><span class="pl-pds">"</span>FullScore<span class="pl-pds">"</span></span>: <span class="pl-c1">3001</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level<span class="pl-pds">"</span></span>: <span class="pl-c1">3</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level0<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level1<span class="pl-pds">"</span></span>: <span class="pl-c1">0</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level2<span class="pl-pds">"</span></span>: <span class="pl-c1">3</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Level3<span class="pl-pds">"</span></span>: <span class="pl-c1">1</span>,
                <span class="pl-s"><span class="pl-pds">"</span>Score<span class="pl-pds">"</span></span>: <span class="pl-c1">25</span>,
                <span class="pl-s"><span class="pl-pds">"</span>__type<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>Tools.IOCScore, Tools<span class="pl-pds">"</span></span>
            },
            <span class="pl-s"><span class="pl-pds">"</span>MD5<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>XX<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineGUID<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>XX<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>ModuleID<span class="pl-pds">"</span></span>: <span class="pl-c1">685</span>,
            <span class="pl-s"><span class="pl-pds">"</span>ModuleName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>AdobeARMHelper.exe<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>SHA256<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>XX<span class="pl-pds">"</span></span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h3>NetWitness Endpoint - Get Modules</h3>
<table>
<thead>
<tr>
<th>ModuleName</th>
<th>ModuleID</th>
<th>Description</th>
<th>IOCScore</th>
<th>AnalyticsScore</th>
<th>GlobalMachineCount</th>
<th>MD5</th>
<th>SHA256</th>
</tr>
</thead>
<tbody>
<tr>
<td>AdobeARMHelper.exe</td>
<td>685</td>
<td>Adobe Reader and Acrobat Manager Helper</td>
<td>FilterValue: 25<br>Level: 3<br>Score: 25<br>Level0: 0<br>Level1: 0<br>Level2: 3<br>Level3: 1<br>__type: Tools.IOCScore, Tools<br>FullScore: 3001</td>
<td>1</td>
<td>1</td>
<td>XX</td>
<td>XX</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>5. Get information for a single machine module</h3>
<hr>
<p>Get information for a specific machine module.</p>
<h5>Base Command</h5>
<pre><code>netwitness-get-machine-module</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>machineGUID</td>
<td>The machine GUID</td>
<td>Required</td>
</tr>
<tr>
<td>moduleID</td>
<td>The module ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>NetWitness.Modules.MachineGUID</td>
<td>Machine GUID</td>
</tr>
<tr>
<td>NetWitness.Modules.ModuleID</td>
<td>Module ID</td>
</tr>
<tr>
<td>NetWitness.Modules.FileName</td>
<td>File name</td>
</tr>
<tr>
<td>NetWitness.Modules.FullPath</td>
<td>Full path</td>
</tr>
<tr>
<td>NetWitness.Modules.MD5</td>
<td>MD5</td>
</tr>
<tr>
<td>NetWitness.Modules.RiskScore</td>
<td>Risk score</td>
</tr>
<tr>
<td>NetWitness.Modules.SHA1</td>
<td>SHA-1</td>
</tr>
<tr>
<td>NetWitness.Modules.SHA256</td>
<td>SHA-256</td>
</tr>
<tr>
<td>NetWitness.Modules.IIOCScore</td>
<td>IIOC score</td>
</tr>
<tr>
<td>NetWitness.Modules.Blacklisted</td>
<td>Blacklisted</td>
</tr>
<tr>
<td>NetWitness.Modules.Graylisted</td>
<td>Graylisted</td>
</tr>
<tr>
<td>NetWitness.Modules.Whitelisted</td>
<td>Whitelisted</td>
</tr>
<tr>
<td>NetWitness.Modules.MachineCount</td>
<td>Machine count</td>
</tr>
<tr>
<td>NetWitness.Modules.IIOCLevel0</td>
<td>IIOC Level 0</td>
</tr>
<tr>
<td>NetWitness.Modules.IIOCLevel1</td>
<td>IIOC Level 1</td>
</tr>
<tr>
<td>NetWitness.Modules.IIOCLevel2</td>
<td>IIOC Level 2</td>
</tr>
<tr>
<td>NetWitness.Modules.IIOCLevel3</td>
<td>IIOC Level 3</td>
</tr>
<tr>
<td>NetWitness.Modules.FirstSeenName</td>
<td>First seen name</td>
</tr>
<tr>
<td>NetWitness.Modules.FirstSeenDate</td>
<td>First seen date</td>
</tr>
<tr>
<td>File.Name</td>
<td>The file name</td>
</tr>
<tr>
<td>File.MD5</td>
<td>File MD5</td>
</tr>
<tr>
<td>File.SHA1</td>
<td>File SHA-1</td>
</tr>
<tr>
<td>File.Path</td>
<td>File full path</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!netwitness-get-machine-module machineGUID= moduleID=</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>File<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>MD5<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
        <span class="pl-s"><span class="pl-pds">"</span>Name<span class="pl-pds">"</span></span>: <span class="pl-c1">null</span>,
        <span class="pl-s"><span class="pl-pds">"</span>Path<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>C:<span class="pl-cce">\\</span>Program Files (x86)<span class="pl-cce">\\</span>Common Files<span class="pl-cce">\\</span>Adobe<span class="pl-cce">\\</span>ARM<span class="pl-cce">\\</span>1.0<span class="pl-cce">\\</span>Temp<span class="pl-cce">\\</span>242902160<span class="pl-cce">\\</span>AdobeARMHelper.exe<span class="pl-pds">"</span></span>,
        <span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>7AFB5FDF4FAC3C682877B22B90F3D9C3737271D2<span class="pl-pds">"</span></span>
    },
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Module<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>Blacklisted<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>None<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>FileName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>AdobeARMHelper.exe<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>FirstSeenDate<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>9/18/2018 8:13:02 PM<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>FirstSeenName<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>AdobeARMHelper.exe<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>FullPath<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>C:<span class="pl-cce">\\</span>Program Files (x86)<span class="pl-cce">\\</span>Common Files<span class="pl-cce">\\</span>Adobe<span class="pl-cce">\\</span>ARM<span class="pl-cce">\\</span>1.0<span class="pl-cce">\\</span>Temp<span class="pl-cce">\\</span>242902160<span class="pl-cce">\\</span>AdobeARMHelper.exe<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Graylisted<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>None<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel0<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>0<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>0<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel2<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>3<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCLevel3<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>IIOCScore<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>25<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MD5<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>7182705213142EE4DCF722AA247DD55C<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineCount<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>MachineGUID<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>ea946082-0563-c15e-8128-c5b6e8b2fea9<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>RiskScore<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>1<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>SHA1<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>7AFB5FDF4FAC3C682877B22B90F3D9C3737271D2<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>SHA256<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>F9B595F657589A25F6F247B4CDD0DE7F2BA0319B015D33F000728BFC11D0A1C2<span class="pl-pds">"</span></span>,
            <span class="pl-s"><span class="pl-pds">"</span>Whitelisted<span class="pl-pds">"</span></span>: <span class="pl-s"><span class="pl-pds">"</span>None<span class="pl-pds">"</span></span>
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h3>NetWitness Endpoint - Get Module</h3>
<table>
<thead>
<tr>
<th>ModuleID</th>
<th>ModuleName</th>
<th>FullPath</th>
<th>FirstSeenName</th>
<th>FirstSeenDate</th>
<th>MD5</th>
<th>SHA1</th>
<th>SHA256</th>
<th>IIOCLevel0</th>
<th>IIOCLevel1</th>
<th>IIOCLevel2</th>
<th>IIOCLevel3</th>
<th>IIOCScore</th>
<th>Blacklisted</th>
<th>Graylisted</th>
<th>Whitelisted</th>
<th>MachineCount</th>
<th>RiskScore</th>
<th>AVDefinitionHash</th>
<th>AVDescription</th>
<th>AVFirstThreat</th>
<th>AVScanResult</th>
<th>AccessNetwork</th>
<th>AnalysisTime</th>
<th>AppDataLocal</th>
<th>AppDataRoaming</th>
<th>AutoStartCategory</th>
<th>Autorun</th>
<th>BlacklistCategory</th>
<th>BlockingStatus</th>
<th>Desktop</th>
<th>Downloaded</th>
<th>DownloadedTime</th>
<th>FakeStartAddress</th>
<th>FileAccessDenied</th>
<th>FileAccessTime</th>
<th>FileCreationTime</th>
<th>FileEncrypted</th>
<th>FileHiddenAttributes</th>
<th>FileModificationTime</th>
<th>FileName</th>
<th>FileOccurrences</th>
<th>Floating</th>
<th>HashLookup</th>
<th>Hooking</th>
<th>ImportedDLLCount</th>
<th>ImportedDLLs</th>
<th>LiveConnectRiskEnum</th>
<th>LiveConnectRiskReason</th>
<th>Loaded</th>
<th>OriginalFileName</th>
<th>Packed</th>
<th>Platform</th>
<th>RelativeFileName</th>
<th>RelativePath</th>
<th>RemoteFileName</th>
<th>RemotePath</th>
<th>Signature</th>
<th>SignatureTimeStamp</th>
<th>SizeInBytes</th>
<th>Status</th>
<th>YaraDefinitionHash</th>
<th>YaraScanDescription</th>
<th>YaraScanFirstThreat</th>
<th>YaraScanresult</th>
<th>Windows</th>
<th>WritetoExecutable</th>
<th>SysWOW64</th>
<th>System32</th>
<th>Temporary</th>
<th>TooManyConnections</th>
<th>User</th>
<th>SignatureValid</th>
<th>SignedbyMicrosoft</th>
<th>SignatureExpired</th>
<th>SignaturePresent</th>
<th>RenametoExecutable</th>
<th>ReservedName</th>
<th>ProcessAccessDenied</th>
<th>ProgramData</th>
<th>ProgramFiles</th>
<th>ReadDocument</th>
<th>MD5Collision</th>
<th>InstallerDirectory</th>
<th>LikelyPacked</th>
<th>Listen</th>
<th>ImageHidden</th>
<th>ImageMismatch</th>
<th>FirewallAuthorized</th>
<th>AutorunScheduledTask</th>
<th>Beacon</th>
</tr>
</thead>
<tbody>
<tr>
<td> </td>
<td>AdobeARMHelper.exe</td>
<td>C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\Temp\242902160\AdobeARMHelper.exe</td>
<td>AdobeARMHelper.exe</td>
<td>9/18/2018 8:13:02 PM</td>
<td>XX</td>
<td>XX</td>
<td>XX</td>
<td>0</td>
<td>0</td>
<td>3</td>
<td>1</td>
<td>25</td>
<td>None</td>
<td>None</td>
<td>None</td>
<td>1</td>
<td>1</td>
<td>0</td>
<td> </td>
<td> </td>
<td>Unknown</td>
<td>False</td>
<td>1/1/0001 12:00:00 AM</td>
<td>False</td>
<td>False</td>
<td>None</td>
<td>False</td>
<td>Generic Malware</td>
<td>Unknown</td>
<td>False</td>
<td>False</td>
<td>1/1/0001 12:00:00 AM</td>
<td>False</td>
<td>False</td>
<td>9/18/2018 8:11:45 PM</td>
<td>9/18/2018 8:11:45 PM</td>
<td>False</td>
<td>False</td>
<td>3/21/2018 7:21:48 AM</td>
<td>AdobeARMHelper.exe</td>
<td>10343</td>
<td>False</td>
<td>Good</td>
<td>False</td>
<td>16</td>
<td>PSAPI.DLL; msi.dll; USERENV.dll; KERNEL32.dll; USER32.dll; ADVAPI32.dll; SHELL32.dll; ole32.dll; SHLWAPI.dll; CRYPT32.dll; WINTRUST.dll; OLEACC.dll; GDI32.dll; WINSPOOL.DRV; COMDLG32.dll; OLEAUT32.dll</td>
<td>Unknown</td>
<td>None</td>
<td>True</td>
<td> </td>
<td>False</td>
<td>I386</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
<td>Valid: Adobe Systems, Incorporated</td>
<td>3/21/2018 9:19:15 AM</td>
<td>413.5 kB</td>
<td>Neutral</td>
<td>0</td>
<td> </td>
<td> </td>
<td>Unknown</td>
<td>False</td>
<td>True</td>
<td>False</td>
<td>False</td>
<td>True</td>
<td>False</td>
<td>False</td>
<td>True</td>
<td>False</td>
<td>False</td>
<td>True</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>True</td>
<td>False</td>
<td>False</td>
<td>True</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
<td>False</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>6. Block list IP addresses</h3>
<hr>
<p>Add a list of IP addresses to block list.</p>
<h5>Base Command</h5>
<pre><code>netwitness-blacklist-ips</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ips</td>
<td>Comma separated list of IP addresses</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p>!netwitness-blacklist-ips ips="1.1.1.1,2.2.2.2"</p>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Blacklist<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>IPs<span class="pl-pds">"</span></span>: [
                <span class="pl-s"><span class="pl-pds">"</span>1.2.3.4<span class="pl-pds">"</span></span>
            ]
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h3>IPs Successfully Block listed</h3>
<table>
<thead>
<tr>
<th>IP</th>
</tr>
</thead>
<tbody>
<tr>
<td>1.2.3.4</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>7. Block list domains</h3>
<hr>
<p>Add a list of domain block list.</p>
<h5>Base Command</h5>
<pre><code>netwitness-blacklist-domains</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>domains</td>
<td>Comma separated list of domains</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!netwitness-blacklist-domains domains="<a href="https://www.example2.com%2Chttps//www.example2.com" rel="nofollow">https://www.example2.com,https://www.example2.com</a>"</pre>
<h5>Context Example</h5>
<div class="highlight highlight-source-json">
<pre>{
    <span class="pl-s"><span class="pl-pds">"</span>NetWitness<span class="pl-pds">"</span></span>: {
        <span class="pl-s"><span class="pl-pds">"</span>Blacklist<span class="pl-pds">"</span></span>: {
            <span class="pl-s"><span class="pl-pds">"</span>Domains<span class="pl-pds">"</span></span>: [
                <span class="pl-s"><span class="pl-pds">"</span>www.example.com<span class="pl-pds">"</span></span>
            ]
        }
    }
}</pre>
</div>
<h5>Human Readable Output</h5>
<h3>Domains Successfully Block listed</h3>
<table>
<thead>
<tr>
<th>Domain</th>
</tr>
</thead>
<tbody>
<tr>
<td><a href="http://www.example.com/" rel="nofollow">www.example.com</a></td>
</tr>
</tbody>
</table>