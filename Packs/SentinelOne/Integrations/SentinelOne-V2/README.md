<!-- HTML_DOC -->
<p class="has-line-data" data-line-start="1" data-line-end="3">Use the SentinelOne v2 integration to your organize your company's end points. <br> This integration was integrated and tested with version xx of SentinelOne Beta</p>
<h2 class="code-line" data-line-start="5" data-line-end="6">
<a id="Configure_SentinelOne_Beta_on_Demisto_5"></a>Configure SentinelOne Beta on Demisto</h2>
<ol>
<li class="has-line-data" data-line-start="7" data-line-end="8">Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li class="has-line-data" data-line-start="8" data-line-end="9">Search for SentinelOne Beta.</li>
<li class="has-line-data" data-line-start="9" data-line-end="20">Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li class="has-line-data" data-line-start="10" data-line-end="11">
<strong>Name</strong>: a textual name for the integration instance.</li>
<li class="has-line-data" data-line-start="11" data-line-end="12"><strong>Server URL (e.g., <a href="https://usea1.sentinelone.net">https://usea1.sentinelone.net</a>)</strong></li>
<li class="has-line-data" data-line-start="12" data-line-end="13"><strong>Username</strong></li>
<li class="has-line-data" data-line-start="13" data-line-end="14"><strong>API Token</strong></li>
<li class="has-line-data" data-line-start="14" data-line-end="15"><strong>Trust any certificate (not secure)</strong></li>
<li class="has-line-data" data-line-start="15" data-line-end="16"><strong>Use system proxy</strong></li>
<li class="has-line-data" data-line-start="16" data-line-end="17"><strong>Fetch incidents</strong></li>
<li class="has-line-data" data-line-start="16" data-line-end="17"><strong>Fetch limit</strong></li>
<li class="has-line-data" data-line-start="17" data-line-end="18"><strong>Incident type</strong></li>
<li class="has-line-data" data-line-start="18" data-line-end="19"><strong>First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year)</strong></li>
<li class="has-line-data" data-line-start="19" data-line-end="20"><strong>Minimum risk score for importing incidents (0-10), where 0 is low risk and 10 is high risk</strong></li>
</ul>
</li>
<li class="has-line-data" data-line-start="20" data-line-end="22">Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2 class="code-line" data-line-start="22" data-line-end="23">
<a id="Commands_22"></a>Commands</h2>
<p class="has-line-data" data-line-start="23" data-line-end="24">You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li class="has-line-data" data-line-start="24" data-line-end="25"><a href="#h_64eddee3-2ff2-465a-ad86-4feeebb86c49" target="_self">Get all agents: sentinelone-list-agents</a></li>
<li class="has-line-data" data-line-start="25" data-line-end="26"><a href="#h_c999b144-39d8-40a4-b19a-9488037a2b9f" target="_self">Create an exclusion: sentinelone-create-white-list-item</a></li>
<li class="has-line-data" data-line-start="26" data-line-end="27"><a href="#h_ebc4391a-fe91-4de5-bb54-32003899f5a7" target="_self">Get all exclusion items: sentinelone-get-white-list</a></li>
<li class="has-line-data" data-line-start="27" data-line-end="28"><a href="#h_cfc408e8-75eb-4d20-8cdd-46578930ac37" target="_self">Get the reputation of a hash: sentinelone-get-hash</a></li>
<li class="has-line-data" data-line-start="28" data-line-end="29"><a href="#h_d96a47a0-1874-4ebf-b17b-b6ad265e4833" target="_self">Get a threat list: sentinelone-get-threats</a></li>
<li class="has-line-data" data-line-start="29" data-line-end="30"><a href="#h_0e8d08a7-25b5-469b-ba35-27160350e04f" target="_self">Get a threat summary: sentinelone-threat-summary</a></li>
<li class="has-line-data" data-line-start="30" data-line-end="31"><a href="#h_36d71e47-7c93-47e3-857f-01521ededa58" target="_self">Mark suspicious threats: sentinelone-mark-as-threat</a></li>
<li class="has-line-data" data-line-start="31" data-line-end="32"><a href="#h_6255110c-9ff9-478e-afca-5a982802ac17" target="_self">Mitigate threats: sentinelone-mitigate-threat</a></li>
<li class="has-line-data" data-line-start="32" data-line-end="33"><a href="#9_sentineloneresolvethreat_788" target="_self">Resolve threats: sentinelone-resolve-threat</a></li>
<li class="has-line-data" data-line-start="33" data-line-end="34"><a href="#h_e4744817-ad70-417e-a772-8c2926087277" target="_self">Get agent details: sentinelone-get-agent</a></li>
<li class="has-line-data" data-line-start="34" data-line-end="35"><a href="#h_c5e1149a-ccf8-429d-aaf8-3f55a4f190d8" target="_self">Get a list of sites: sentinelone-get-sites</a></li>
<li class="has-line-data" data-line-start="35" data-line-end="36"><a href="#h_7a21d365-5e9f-4bfc-8244-57f65a169794" target="_self">Get a site list: sentinelone-get-site</a></li>
<li class="has-line-data" data-line-start="36" data-line-end="37"><a href="#h_1d957e18-4716-458e-8b95-7b411878fc6b" target="_self">Reactivate a site: sentinelone-reactivate-site</a></li>
<li class="has-line-data" data-line-start="37" data-line-end="38"><a href="#h_4c49234e-0661-4207-abb2-8b67bc5df039" target="_self">Get a list of activities: sentinelone-get-activities</a></li>
<li class="has-line-data" data-line-start="38" data-line-end="39"><a href="#h_0bcee322-ce58-4884-8f3c-026a45a0f8f3" target="_self">Get group data: sentinelone-get-groups</a></li>
<li class="has-line-data" data-line-start="39" data-line-end="40"><a href="#h_e5eee9ec-5047-4388-a345-df9a434f34fe" target="_self">Move agent: sentinelone-move-agent</a></li>
<li class="has-line-data" data-line-start="40" data-line-end="41"><a href="#h_890e6bba-fb17-4027-9db9-0a5468a7b642" target="_self">Delete a group: sentinelone-delete-group</a></li>
<li class="has-line-data" data-line-start="41" data-line-end="42"><a href="#h_b6361197-f4b1-4477-95b4-1cc5654d0f74" target="_self">Retrieve agent processes: sentinelone-agent-processes</a></li>
<li class="has-line-data" data-line-start="42" data-line-end="43"><a href="#h_62b6458d-750a-4457-9ea3-4cd6cfd566c1" target="_self">Connect an agent: sentinelone-connect-agent</a></li>
<li class="has-line-data" data-line-start="43" data-line-end="44"><a href="#h_491ad0f2-97f3-4124-8884-91eb5c84cabc" target="_self">Disconnect an agent: sentinelone-disconnect-agent</a></li>
<li class="has-line-data" data-line-start="44" data-line-end="45"><a href="#h_790d12ec-b824-437d-9791-6fd705f475dd" target="_self">Broadcast a message to agents: sentinelone-broadcast-message</a></li>
<li class="has-line-data" data-line-start="45" data-line-end="46"><a href="#h_e9fd7e73-2fbe-48e0-8a28-8988b597498a" target="_self">Get Deep Visibility events: sentinelone-get-events</a></li>
<li class="has-line-data" data-line-start="46" data-line-end="47"><a href="#h_7c988327-ccd8-4f2c-a296-097259bf4473" target="_self">Create a Deep Visibility query: sentinelone-create-query</a></li>
<li class="has-line-data" data-line-start="47" data-line-end="48"><a href="#h_837965e2-5e05-4b58-b192-b25e0707c6c0" target="_self">Get a list of Deep Visibility events by process: sentinelone-get-processes</a></li>
<li class="has-line-data" data-line-start="48" data-line-end="49"><a href="#h_3172f88b-fc56-48e7-873d-393e69b11851" target="_self">Shutdown an agent: sentinelone-shutdown-agent</a></li>
<li class="has-line-data" data-line-start="49" data-line-end="50"><a href="#h_72b83efd-8abc-48b4-897e-216cfe7d178e" target="_self">Uninstall an agent: sentinelone-uninstall-agent</a></li>
</ol>
<h3 id="h_64eddee3-2ff2-465a-ad86-4feeebb86c49" class="code-line" data-line-start="50" data-line-end="51">
<a id="1_sentinelonelistagents_50"></a>1. Get all agents</h3>
<hr>
<p>Gets a list of all agents.</p>
<h5>Base Command</h5>
<p><code>sentinelone-list-agents</code></p>
<h5>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 133.667px;"><strong>Argument Name</strong></th>
<th style="width: 536.333px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133.667px;">computer_name</td>
<td style="width: 536.333px;">Filter by computer name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.667px;">scan_status</td>
<td style="width: 536.333px;">CSV list of scan statuses by which to filter the results, for example: “started,aborted”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.667px;">os_type</td>
<td style="width: 536.333px;">Included OS types, for example: “windows”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.667px;">created_at</td>
<td style="width: 536.333px;">Endpoint created at timestamp, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133.667px;">min_active_threats</td>
<td style="width: 536.333px;">Minimum number of threats for an agent.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 350.667px;"><strong>Path</strong></th>
<th style="width: 66.3333px;"><strong>Type</strong></th>
<th style="width: 324px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.NetworkStatus</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">The agent network status.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.ID</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">The agent ID.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.AgentVersion</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">The agent software version.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.IsDecomissioned</td>
<td style="width: 66.3333px;">boolean</td>
<td style="width: 324px;">Whether the agent is decommissioned.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.IsActive</td>
<td style="width: 66.3333px;">boolean</td>
<td style="width: 324px;">Whether the agent is active.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.LastActiveDate</td>
<td style="width: 66.3333px;">date</td>
<td style="width: 324px;">The last active date of the agent</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.RegisteredAt</td>
<td style="width: 66.3333px;">date</td>
<td style="width: 324px;">The registration date of the agent.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.ExternalIP</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">The agent IP address.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.ThreatCount</td>
<td style="width: 66.3333px;">number</td>
<td style="width: 324px;">Number of active threats.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.EncryptedApplications</td>
<td style="width: 66.3333px;">boolean</td>
<td style="width: 324px;">Whether disk encryption is enabled.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.OSName</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">Name of operating system.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.ComputerName</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">Name of agent computer.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.Domain</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">Domain name of the agent.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.CreatedAt</td>
<td style="width: 66.3333px;">date</td>
<td style="width: 324px;">Creation time of the agent.</td>
</tr>
<tr>
<td style="width: 350.667px;">SentinelOne.Agents.SiteName</td>
<td style="width: 66.3333px;">string</td>
<td style="width: 324px;">Site name associated with the agent.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sentinelone-list-agents</pre>
<h5>Context Example</h5>
<pre>{
    "SentinelOne.Agents": [
        {
            "ExternalIP": "73.92.194.57", 
            "Domain": "local", 
            "LastActiveDate": "2019-08-18T10:31:18.675994Z", 
            "NetworkStatus": "connected", 
            "EncryptedApplications": true, 
            "ThreatCount": 0, 
            "ComputerName": "Bills-MacBook-Pro", 
            "IsActive": false, 
            "OSName": "OS X", 
            "SiteName": "demisto", 
            "AgentVersion": "2.6.3.2538", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2018-12-02T08:48:37.785644Z", 
            "ID": "507609079972387179", 
            "CreatedAt": "2018-12-02T08:48:37.792682Z"
        }, 
        {
            "ExternalIP": "3.122.240.42", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-08-18T13:56:50.620408Z", 
            "NetworkStatus": "connected", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-AJ0KANC", 
            "IsActive": true, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.3.38", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-06-27T08:01:05.567249Z", 
            "ID": "657613730168123595", 
            "CreatedAt": "2019-06-27T08:01:05.571895Z"
        }, 
        {
            "ExternalIP": "34.100.71.242", 
            "Domain": "PALOALTONETWORK", 
            "LastActiveDate": "2019-08-16T06:32:48.683437Z", 
            "NetworkStatus": "connecting", 
            "EncryptedApplications": true, 
            "ThreatCount": 0, 
            "ComputerName": "TLVWIN9131Q1V", 
            "IsActive": false, 
            "OSName": "Windows 10", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.3.38", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-06-27T12:09:43.590587Z", 
            "ID": "657738871640371668", 
            "CreatedAt": "2019-06-27T12:09:43.598071Z"
        }, 
        {
            "ExternalIP": "52.49.120.63", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-08-06T07:38:35.677266Z", 
            "NetworkStatus": "connected", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-55LV527", 
            "IsActive": false, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.5.63", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-08-05T11:42:38.644242Z", 
            "ID": "685991494097052188", 
            "CreatedAt": "2019-08-05T11:42:38.648232Z"
        }, 
        {
            "ExternalIP": "18.202.247.204", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-08-06T07:37:05.677281Z", 
            "NetworkStatus": "connecting", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-TR9AE9E", 
            "IsActive": false, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.1.5.63", 
            "IsDecomissioned": false, 
            "RegisteredAt": "2019-08-05T11:46:49.681346Z", 
            "ID": "685993599964815937", 
            "CreatedAt": "2019-08-05T11:46:49.687519Z"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Sentinel One - List of Agents</h3>
<p>Provides summary information and details for all the agents that matched your search criteria.</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Agent Version</th>
<th>Computer Name</th>
<th>Created At</th>
<th>Domain</th>
<th>Encrypted Applications</th>
<th>External IP</th>
<th>ID</th>
<th>Is Active</th>
<th>Is Decomissioned</th>
<th>Last ActiveDate</th>
<th>Network Status</th>
<th>OS Name</th>
<th>Registered At</th>
<th>Site Name</th>
<th>Threat Count</th>
</tr>
</thead>
<tbody>
<tr>
<td>2.6.3.2538</td>
<td>Bills-MacBook-Pro</td>
<td>2018-12-02T08:48:37.792682Z</td>
<td>local</td>
<td>true</td>
<td>73.92.194.57</td>
<td>507609079972387179</td>
<td>false</td>
<td>false</td>
<td>2019-08-18T10:31:18.675994Z</td>
<td>connected</td>
<td>OS X</td>
<td>2018-12-02T08:48:37.785644Z</td>
<td>demisto</td>
<td>0</td>
</tr>
<tr>
<td>3.1.3.38</td>
<td>EC2AMAZ-AJ0KANC</td>
<td>2019-06-27T08:01:05.571895Z</td>
<td>WORKGROUP</td>
<td>false</td>
<td>3.122.240.42</td>
<td>657613730168123595</td>
<td>true</td>
<td>false</td>
<td>2019-08-18T13:56:50.620408Z</td>
<td>connected</td>
<td>Windows Server 2016</td>
<td>2019-06-27T08:01:05.567249Z</td>
<td>demisto</td>
<td>0</td>
</tr>
<tr>
<td>3.1.3.38</td>
<td>TLVWIN9131Q1V</td>
<td>2019-06-27T12:09:43.598071Z</td>
<td>PALOALTONETWORK</td>
<td>true</td>
<td>34.100.71.242</td>
<td>657738871640371668</td>
<td>false</td>
<td>false</td>
<td>2019-08-16T06:32:48.683437Z</td>
<td>connecting</td>
<td>Windows 10</td>
<td>2019-06-27T12:09:43.590587Z</td>
<td>demisto</td>
<td>0</td>
</tr>
<tr>
<td>3.1.5.63</td>
<td>EC2AMAZ-55LV527</td>
<td>2019-08-05T11:42:38.648232Z</td>
<td>WORKGROUP</td>
<td>false</td>
<td>52.49.120.63</td>
<td>685991494097052188</td>
<td>false</td>
<td>false</td>
<td>2019-08-06T07:38:35.677266Z</td>
<td>connected</td>
<td>Windows Server 2016</td>
<td>2019-08-05T11:42:38.644242Z</td>
<td>demisto</td>
<td>0</td>
</tr>
<tr>
<td>3.1.5.63</td>
<td>EC2AMAZ-TR9AE9E</td>
<td>2019-08-05T11:46:49.687519Z</td>
<td>WORKGROUP</td>
<td>false</td>
<td>18.202.247.204</td>
<td>685993599964815937</td>
<td>false</td>
<td>false</td>
<td>2019-08-06T07:37:05.677281Z</td>
<td>connecting</td>
<td>Windows Server 2016</td>
<td>2019-08-05T11:46:49.681346Z</td>
<td>demisto</td>
<td>0</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>2. Create an exclusion</h3>
<hr>
<p>Creates an exclusion item for a white list.</p>
<h5>Base Command</h5>
<p><code>sentinelone-create-white-list-item</code></p>
<h5>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 536px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">exclusion_type</td>
<td style="width: 536px;">Exclusion item type. Can be “file_type”, “path”, “white_hash”, “certificate”, or “browser”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">exclusion_value</td>
<td style="width: 536px;">Value of the exclusion item for the exclusion list.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">os_type</td>
<td style="width: 536px;">OS type. Can be “windows”, “windows_legacy”, “macos”, or “linux”. OS type is required for hash exclusions.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">description</td>
<td style="width: 536px;">Description for adding the item.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">exclusion_mode</td>
<td style="width: 536px;">Exclusion mode (path exclusion only). Can be “suppress”, “disable_in_process_monitor_deep”, “disable_in_process_monitor”, “disable_all_monitors”, or “disable_all_monitors_deep”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">path_exclusion_type</td>
<td style="width: 536px;">Excluded path for a path exclusion list.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">group_ids</td>
<td style="width: 536px;">CSV list of group IDs by which to filter. Can be “site_ids” or “group_ids”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">SentinelOne.Exclusions.ID</td>
<td style="width: 58px;">string</td>
<td style="width: 383px;">The whitelisted entity ID.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Exclusions.Type</td>
<td style="width: 58px;">string</td>
<td style="width: 383px;">The whitelisted item type.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Exclusions.CreatedAt</td>
<td style="width: 58px;">date</td>
<td style="width: 383px;">Time when the whitelist item was created.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !sentinelone-create-white-list-item exclusion_type=browser exclusion_value=Chrome os_type=windows description=test group_ids=475482421375116388
</pre>
<h5 class="code-line" data-line-start="231" data-line-end="232">
<a id="Human_Readable_Output_231"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="232" data-line-end="236">###Sentinel One - Adding an exclusion item<br> ##The provided item was successfully added to the exclusion list<br> |Created At|ID|Type|<br> |2019-08-18T13:50:14.454550Z| 695477800149743550|browser</p>
<h3 id="h_ebc4391a-fe91-4de5-bb54-32003899f5a7" class="code-line" data-line-start="238" data-line-end="239">
<a id="3_sentinelonegetwhitelist_238"></a>3. Get all exclusion items: sentinelone-get-white-list</h3>
<hr>
<p>Gets all exclusion items in a white list.</p>
<h5>Base Command</h5>
<p><code>sentinelone-get-white-list</code></p>
<h5>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>item_ids</td>
<td>List of IDs by which to filter, for example: “225494730938493804,225494730938493915”.</td>
<td>Optional</td>
</tr>
<tr>
<td>os_types</td>
<td>CSV list of OS types by which to filter, for example: “windows, linux”.</td>
<td>Optional</td>
</tr>
<tr>
<td>exclusion_type</td>
<td>Exclusion type. Can be “file_type”, “path”, “white_hash”, “certificate”, “browser”.</td>
<td>Optional</td>
</tr>
<tr>
<td>limit</td>
<td>The maximum number of items to return.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 236.667px;"><strong>Path</strong></th>
<th style="width: 45.3333px;"><strong>Type</strong></th>
<th style="width: 458px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.ID</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">The item ID.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.Type</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">The exclusion item type.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.CreatedAt</td>
<td style="width: 45.3333px;">date</td>
<td style="width: 458px;">Timestamp when the item was added.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.Value</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">Value of the added item.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.Source</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">Source of the added item.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.UserID</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">User ID of the user that added the item.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.UpdatedAt</td>
<td style="width: 45.3333px;">date</td>
<td style="width: 458px;">Timestamp when the item was updated</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.OsType</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">OS type.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.UserName</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">User name of the user that added the item.</td>
</tr>
<tr>
<td style="width: 236.667px;">SentinelOne.Exclusions.Mode</td>
<td style="width: 45.3333px;">string</td>
<td style="width: 458px;">CSV list of modes by which to filter (ath exclusions only), for example: “suppress”.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sentinelone-get-white-list exclusion_type=file_type</pre>
<h5>Context Example</h5>
<pre>{
    "SentinelOne.Exclusions": [
        {
            "UserName": "John Roe", 
            "UserID": "433273625970238486", 
            "Value": "MDF", 
            "Source": "user", 
            "Mode": null, 
            "UpdatedAt": "2018-11-05T18:48:49.070978Z", 
            "OsType": "windows", 
            "Type": "file_type", 
            "ID": "488342219732991235", 
            "CreatedAt": "2018-11-05T18:48:49.072116Z"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Sentinel One - Listing exclusion items</h3>
<p>Provides summary information and details for all the exclusion items that matched your search criteria.</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>CreatedAt</th>
<th>ID</th>
<th>OsType</th>
<th>Source</th>
<th>Type</th>
<th>UpdatedAt</th>
<th>UserID</th>
<th>UserName</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>2018-11-05T18:48:49.072116Z</td>
<td>488342219732991235</td>
<td>windows</td>
<td>user</td>
<td>file_type</td>
<td>2018-11-05T18:48:49.070978Z</td>
<td>433273625970238486</td>
<td>John Roe</td>
<td>MDF</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>4. Get the reputation of a hash</h3>
<hr>
<p>Gets the reputation of a hash.</p>
<h5>Base Command</h5>
<p><code>sentinelone-get-hash</code></p>
<h5>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 285.333px;"><strong>Argument Name</strong></th>
<th style="width: 291.667px;"><strong>Description</strong></th>
<th style="width: 163px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 285.333px;">hash</td>
<td style="width: 291.667px;">The content hash.</td>
<td style="width: 163px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 369px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 369px;">SentinelOne.Hash.Rank</td>
<td style="width: 80px;">Number</td>
<td style="width: 291px;">The hash reputation (1-10).</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Hash.Hash</td>
<td style="width: 80px;">String</td>
<td style="width: 291px;">The content hash.</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Hash.Classification</td>
<td style="width: 80px;">String</td>
<td style="width: 291px;">The hash classification.</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Hash.Classification Source</td>
<td style="width: 80px;">String</td>
<td style="width: 291px;">The hash classification source.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sentinelone-get-hash hash=3aacf35d3ff2e15288851e8afe8026576f7110eb</pre>
<h5>Context Example</h5>
<pre>{
    "SentinelOne.Hash": {
        "ClassificationSource": "Cloud", 
        "Hash": "3aacf35d3ff2e15288851e8afe8026576f7110eb", 
        "Rank": "6", 
        "Classification": "PUA"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Sentinel One - Hash Reputation and Classification</h3>
<p class="has-line-data" data-line-start="345" data-line-end="346">Provides hash reputation (rank from 0 to 10):</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Hash</th>
<th>Rank</th>
<th>ClassificationSource</th>
<th>Classification</th>
</tr>
</thead>
<tbody>
<tr>
<td>3aacf35d3ff2e15288851e8afe8026576f7110eb</td>
<td>6</td>
<td>Cloud</td>
<td>PUA</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>5. Get a threat list</h3>
<hr>
<p>Gets a list of threats.</p>
<h5>Base Command</h5>
<p><code>sentinelone-get-threats</code></p>
<h5>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 113.333px;"><strong>Argument Name</strong></th>
<th style="width: 554.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 113.333px;">content_hash</td>
<td style="width: 554.667px;">The content hash of the threat.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">mitigation_status</td>
<td style="width: 554.667px;">CSV list of mitigation statuses. Can be “mitigated”, “active”, “blocked”, “suspicious”, “pending”, or “suspicious_resolved”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">created_before</td>
<td style="width: 554.667px;">Searches for threats created before this date, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">created_after</td>
<td style="width: 554.667px;">Searches for threats created after this date, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">created_until</td>
<td style="width: 554.667px;">Searches for threats created on or before this date, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">created_from</td>
<td style="width: 554.667px;">Search for threats created on or after this date, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">resolved</td>
<td style="width: 554.667px;">Whether to only return resolved threats.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">display_name</td>
<td style="width: 554.667px;">Threat display name. Can be a partial display name, not an exact match.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">limit</td>
<td style="width: 554.667px;">The maximum number of threats to return. Default is 20.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">query</td>
<td style="width: 554.667px;">Full free-text search for fields. Can be “content_hash”, “file_display_name”, “file_path”, “computer_name”, or “uuid”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">threat_ids</td>
<td style="width: 554.667px;">CSV list of threat IDs, for example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">classifications</td>
<td style="width: 554.667px;">CSV list of threat classifications to search, for example: “Malware”, “Network”, “Benign”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 113.333px;">rank</td>
<td style="width: 554.667px;">Risk level threshold to retrieve (1-10).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 313px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 358px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 313px;">SentinelOne.Threat.ID</td>
<td style="width: 70px;">String</td>
<td style="width: 358px;">The threat ID.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.AgentComputerName</td>
<td style="width: 70px;">String</td>
<td style="width: 358px;">The agent computer name.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.CreatedDate</td>
<td style="width: 70px;">Date</td>
<td style="width: 358px;">File created date.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.SiteID</td>
<td style="width: 70px;">String</td>
<td style="width: 358px;">The site ID.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.Classification</td>
<td style="width: 70px;">string</td>
<td style="width: 358px;">Classification name.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.MitigationStatus</td>
<td style="width: 70px;">String</td>
<td style="width: 358px;">The agent status.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.AgentID</td>
<td style="width: 70px;">String</td>
<td style="width: 358px;">The agent ID.</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.Rank</td>
<td style="width: 70px;">Number</td>
<td style="width: 358px;">Number representing cloud reputation (1-10).</td>
</tr>
<tr>
<td style="width: 313px;">SentinelOne.Threat.MarkedAsBenign</td>
<td style="width: 70px;">Boolean</td>
<td style="width: 358px;">Whether the threat is marked as benign.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sentinelone-get-threats</pre>
<h5>Context Example</h5>
<pre>{
    "SentinelOne.Threat": [
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com.txt", 
            "Description": "static-check-on-write", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/eicar.com.txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "513526418089756174", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-10T12:45:19.325000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com.txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com", 
            "Description": "static-check-on-write", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/eicar.com", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "513526832755426837", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-10T12:46:08.771000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "totally_not_a_virus.txt", 
            "Description": "static-check-on-write", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "513529274335282723", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-10T12:50:59.855000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "totally_not_a_virus.txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com (1).txt", 
            "Description": "scanner", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/eicar.com (1).txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "523732151490265554", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-24T14:42:17.533000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com (1).txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com (4).txt", 
            "Description": "scanner", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/eicar.com (4).txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "523732178744852953", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-24T14:42:20.792000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com (4).txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com (3).txt", 
            "Description": "scanner", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/eicar.com (3).txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "523732180305134048", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-24T14:42:20.972000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com (3).txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com (2).txt", 
            "Description": "scanner", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/Downloads/eicar.com (2).txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "523732207828156907", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2018-12-24T14:42:24.275000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com (2).txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "", 
            "FileSha256": null, 
            "ThreatName": "Fusion.dll", 
            "Description": "malware detected - not mitigated yet (static engine)", 
            "Classification": "PUA", 
            "FilePath": "\\Device\\HarddiskVolume3\\Users\\Mayag\\AppData\\Local\\Temp\\nsi483E.tmp\\Fusion.dll", 
            "InQuarantine": null, 
            "Rank": 6, 
            "ID": "579478682051177175", 
            "MarkedAsBenign": null, 
            "FileContentHash": "42361f19d4b3db3a3af96b3e7dba7bce8a5df265", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2019-03-11T12:40:42.717000Z", 
            "AgentOsType": "windows", 
            "AgentID": "523685228116918098", 
            "AgentComputerName": "LAPTOP-MAYA", 
            "FileDisplayName": "Fusion.dll", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "", 
            "FileSha256": null, 
            "ThreatName": "BAFABC52CDF342A08CC06EFFE79F3D11.MAL", 
            "Description": "malware detected - not mitigated yet (static engine)", 
            "Classification": "PUA", 
            "FilePath": "\\Device\\HarddiskVolume3\\ProgramData\\Sentinel\\Quarantine\\BAFABC52CDF342A08CC06EFFE79F3D11.MAL", 
            "InQuarantine": null, 
            "Rank": 6, 
            "ID": "580921365667955680", 
            "MarkedAsBenign": null, 
            "FileContentHash": "42361f19d4b3db3a3af96b3e7dba7bce8a5df265", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2019-03-13T12:26:28.919000Z", 
            "AgentOsType": "windows", 
            "AgentID": "523685228116918098", 
            "AgentComputerName": "LAPTOP-MAYA", 
            "FileDisplayName": "BAFABC52CDF342A08CC06EFFE79F3D11.MAL", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "", 
            "FileSha256": null, 
            "ThreatName": "f_004dba", 
            "Description": "malware detected - not mitigated yet (static engine)", 
            "Classification": "PUA", 
            "FilePath": "\\Device\\HarddiskVolume3\\Users\\Mayag\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\f_004dba", 
            "InQuarantine": null, 
            "Rank": 6, 
            "ID": "582523025838244347", 
            "MarkedAsBenign": null, 
            "FileContentHash": "3aacf35d3ff2e15288851e8afe8026576f7110eb", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2019-03-15T17:29:17.973000Z", 
            "AgentOsType": "windows", 
            "AgentID": "523685228116918098", 
            "AgentComputerName": "LAPTOP-MAYA", 
            "FileDisplayName": "f_004dba", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }, 
        {
            "Username": "root", 
            "FileSha256": null, 
            "ThreatName": "eicar.com.txt", 
            "Description": "static-check-on-write", 
            "Classification": "Malware", 
            "FilePath": "/Users/yardensade/.Trash/eicar.com.txt", 
            "InQuarantine": null, 
            "Rank": 7, 
            "ID": "593894834529633491", 
            "MarkedAsBenign": false, 
            "FileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "SiteID": "475482421366727779", 
            "CreatedDate": "2019-03-31T10:03:01.109000Z", 
            "AgentOsType": "macos", 
            "AgentID": "513505756159722818", 
            "AgentComputerName": "Yardens-MacBook-Pro", 
            "FileDisplayName": "eicar.com.txt", 
            "MitigationStatus": "mitigated", 
            "FileMaliciousContent": null
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="635" data-line-end="636">
<a id="Human_Readable_Output_635"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="636" data-line-end="637">
<a id="Sentinel_One__Getting_Threat_List_636"></a>Sentinel One - Getting Threat List</h3>
<p class="has-line-data" data-line-start="637" data-line-end="638">Provides summary information and details for all the threats that matched your search criteria.</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Agent Computer Name</th>
<th>Agent ID</th>
<th>Classification</th>
<th>Created Date</th>
<th>File Content Hash</th>
<th>ID</th>
<th>Marked As Benign</th>
<th>Mitigation Status</th>
<th>Rank</th>
<th>Site ID</th>
<th>Site Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-10T12:45:19.325000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>513526418089756174</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-10T12:46:08.771000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>513526832755426837</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-10T12:50:59.855000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>513529274335282723</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-24T14:42:17.533000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>523732151490265554</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-24T14:42:20.792000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>523732178744852953</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-24T14:42:20.972000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>523732180305134048</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2018-12-24T14:42:24.275000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>523732207828156907</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>LAPTOP-MAYA</td>
<td>523685228116918098</td>
<td>PUA</td>
<td>2019-03-11T12:40:42.717000Z</td>
<td>42361f19d4b3db3a3af96b3e7dba7bce8a5df265</td>
<td>579478682051177175</td>
<td> </td>
<td>mitigated</td>
<td>6</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>LAPTOP-MAYA</td>
<td>523685228116918098</td>
<td>PUA</td>
<td>2019-03-13T12:26:28.919000Z</td>
<td>42361f19d4b3db3a3af96b3e7dba7bce8a5df265</td>
<td>580921365667955680</td>
<td> </td>
<td>mitigated</td>
<td>6</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>LAPTOP-MAYA</td>
<td>523685228116918098</td>
<td>PUA</td>
<td>2019-03-15T17:29:17.973000Z</td>
<td>3aacf35d3ff2e15288851e8afe8026576f7110eb</td>
<td>582523025838244347</td>
<td> </td>
<td>mitigated</td>
<td>6</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
<tr>
<td>Yardens-MacBook-Pro</td>
<td>513505756159722818</td>
<td>Malware</td>
<td>2019-03-31T10:03:01.109000Z</td>
<td>3395856ce81f2b7382dee72602f798b642f14140</td>
<td>593894834529633491</td>
<td>false</td>
<td>mitigated</td>
<td>7</td>
<td>475482421366727779</td>
<td>demisto</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>6. Get a threat summary</h3>
<hr>
<p>Gets a threat summary.</p>
<h5 class="code-line" data-line-start="658" data-line-end="659">
<a id="Base_Command_658"></a>Base Command</h5>
<p class="has-line-data" data-line-start="660" data-line-end="661"><code>sentinelone-threat-summary</code></p>
<h5 class="code-line" data-line-start="661" data-line-end="662">
<a id="Input_661"></a>Input</h5>
<table class="table table-striped table-bordered">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>group_ids</td>
<td>CSV list of group IDs by which to filter, for example: “225494730938493804,225494730938493915”.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="668" data-line-end="669">
<a id="Context_Output_668"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 270.667px;"><strong>Path</strong></th>
<th style="width: 74.3333px;"><strong>Type</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 270.667px;">SentinelOne.Threat.Active</td>
<td style="width: 74.3333px;">Number</td>
<td style="width: 396px;">Number of active threats in the system.</td>
</tr>
<tr>
<td style="width: 270.667px;">SentinelOne.Threat.Total</td>
<td style="width: 74.3333px;">Number</td>
<td style="width: 396px;">Total number of threats in the system.</td>
</tr>
<tr>
<td style="width: 270.667px;">SentinelOne.Threat.Mitigated</td>
<td style="width: 74.3333px;">Number</td>
<td style="width: 396px;">Number of mitigated threats in the system.</td>
</tr>
<tr>
<td style="width: 270.667px;">SentinelOne.Threat.Suspicious</td>
<td style="width: 74.3333px;">Number</td>
<td style="width: 396px;">Number of suspicious threats in the system.</td>
</tr>
<tr>
<td style="width: 270.667px;">SentinelOne.Threat.Blocked</td>
<td style="width: 74.3333px;">Number</td>
<td style="width: 396px;">Number of blocked threats in the system.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="679" data-line-end="680">
<a id="Command_Example_679"></a>Command Example</h5>
<pre>!sentinelone-threat-summary</pre>
<h5 class="code-line" data-line-start="682" data-line-end="683">
<a id="Context_Example_682"></a>Context Example</h5>
<pre>{
    "SentinelOne.Threat": {
        "Active": 0, 
        "Suspicious": 0, 
        "Mitigated": 11, 
        "Total": 11, 
        "Blocked": 0
    }
}
</pre>
<h5 class="code-line" data-line-start="695" data-line-end="696">
<a id="Human_Readable_Output_695"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="696" data-line-end="697">
<a id="Sentinel_One__Dashboard_Threat_Summary_696"></a>Sentinel One - Dashboard Threat Summary</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Active</th>
<th>Blocked</th>
<th>Mitigated</th>
<th>Suspicious</th>
<th>Total</th>
</tr>
</thead>
<tbody>
<tr>
<td>0</td>
<td>0</td>
<td>11</td>
<td>0</td>
<td>11</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_36d71e47-7c93-47e3-857f-01521ededa58" class="code-line" data-line-start="702" data-line-end="703">
<a id="7_sentinelonemarkasthreat_702"></a>7. Mark suspicious threats</h3>
<hr>
<p>Marks suspicious threats as a threat.</p>
<h5 class="code-line" data-line-start="707" data-line-end="708">
<a id="Base_Command_707"></a>Base Command</h5>
<p><code>sentinelone-mark-as-threat</code></p>
<h5 class="code-line" data-line-start="710" data-line-end="711">
<a id="Input_710"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 158.667px;"><strong>Argument Name</strong></th>
<th style="width: 489.333px;"><strong>Description</strong></th>
<th style="width: 92px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158.667px;">threat_ids</td>
<td style="width: 489.333px;">CSV list of threat IDs.</td>
<td style="width: 92px;">Optional</td>
</tr>
<tr>
<td style="width: 158.667px;">target_scope</td>
<td style="width: 489.333px;">Scope to use for exclusions. Can be “site” or “tenant”.</td>
<td style="width: 92px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="718" data-line-end="719">
<a id="Context_Output_718"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 249px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">SentinelOne.Threat.ID</td>
<td style="width: 62px;">String</td>
<td style="width: 429px;">The threat ID.</td>
</tr>
<tr>
<td style="width: 249px;">SentinelOne.Threat.MarkedAsThreat</td>
<td style="width: 62px;">Boolean</td>
<td style="width: 429px;">Whether the suspicious threat was successfully marked as a threat.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="726" data-line-end="727">
<a id="Command_Example_726"></a>Command Example</h5>
<pre>!sentinelone-mark-as-threat target_scope=site threat_ids=50925977558296070</pre>
<h5 class="code-line" data-line-start="729" data-line-end="730">
<a id="Human_Readable_Output_729"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="730" data-line-end="731">
<a id="Sentinel_One__Marking_suspicious_threats_as_threats_730"></a>Sentinel One - Marking suspicious threats as threats</h3>
<h3 class="code-line" data-line-start="731" data-line-end="732">
<a id="Total_of_1_provided_threats_were_marked_successfully_731"></a>Total of 1 provided threats were marked successfully</h3>
<p class="has-line-data" data-line-start="733" data-line-end="735">|ID|Marked As Threat|<br> |509259775582960700|true</p>
<h3>8. Mitigate threats</h3>
<hr>
<p class="has-line-data" data-line-start="739" data-line-end="740">Applies a mitigation action to a group of threats.</p>
<h5>Base Command</h5>
<p><code>sentinelone-mitigate-threat</code></p>
<h5 class="code-line" data-line-start="745" data-line-end="746">
<a id="Input_745"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 101px;"><strong>Argument Name</strong></th>
<th style="width: 568px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 101px;">action</td>
<td style="width: 568px;">Mitigation action. Can be “kill”, “quarantine”, “un-quarantine”, “remediate”, or “rollback-remediation”.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 101px;">threat_ids</td>
<td style="width: 568px;">CSV list of threat IDs.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="753" data-line-end="754">
<a id="Context_Output_753"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 292.667px;"><strong>Path</strong></th>
<th style="width: 67.3333px;"><strong>Type</strong></th>
<th style="width: 380px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 292.667px;">SentinelOne.Threat.ID</td>
<td style="width: 67.3333px;">String</td>
<td style="width: 380px;">The threat ID.</td>
</tr>
<tr>
<td style="width: 292.667px;">SentinelOne.Threat.Mitigated</td>
<td style="width: 67.3333px;">Boolean</td>
<td style="width: 380px;">Whether the threat was successfully mitigated.</td>
</tr>
<tr>
<td style="width: 292.667px;">SentinelOne.Threat.Mitigation.Action</td>
<td style="width: 67.3333px;">Number</td>
<td style="width: 380px;">Number of threats affected.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="762" data-line-end="763">
<a id="Command_Example_762"></a>Command Example</h5>
<pre>!sentinelone-mitigate-threat action=quarantine threat_ids=509259775582960700</pre>
<h5 class="code-line" data-line-start="765" data-line-end="766">
<a id="Context_Example_765"></a>Context Example</h5>
<pre>{
    "SentinelOne.Threat": [
        {
            "Mitigated": true, 
            "Mitigation": {
                "Action": "quarantine"
            }, 
            "ID": "509259775582960700"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="780" data-line-end="781">
<a id="Human_Readable_Output_780"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="781" data-line-end="782">
<a id="Sentinel_One__Mitigating_threats_781"></a>Sentinel One - Mitigating threats</h3>
<p class="has-line-data" data-line-start="782" data-line-end="783">Total of 1 provided threats were mitigated successfully</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>ID</th>
<th>Mitigation Action</th>
<th>Mitigated</th>
</tr>
</thead>
<tbody>
<tr>
<td>509259775582960700</td>
<td>quarantine</td>
<td>true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_fa9ce6b7-e9ae-45da-9364-57a42b1d722e" class="code-line" data-line-start="788" data-line-end="789">
<a id="9_sentineloneresolvethreat_788"></a>9. Resolve threats</h3>
<hr>
<p class="has-line-data" data-line-start="790" data-line-end="791">Resolves threats using the threat ID.</p>
<h5>Base Command</h5>
<p><code>sentinelone-resolve-threat</code></p>
<h5 class="code-line" data-line-start="796" data-line-end="797">
<a id="Input_796"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 264.333px;"><strong>Argument Name</strong></th>
<th style="width: 325.667px;"><strong>Description</strong></th>
<th style="width: 150px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 264.333px;">threat_ids</td>
<td style="width: 325.667px;">CSV list of threat IDs.</td>
<td style="width: 150px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="803" data-line-end="804">
<a id="Context_Output_803"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 256.667px;"><strong>Path</strong></th>
<th style="width: 73.3333px;"><strong>Type</strong></th>
<th style="width: 411px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 256.667px;">SentinelOne.Threat.ID</td>
<td style="width: 73.3333px;">String</td>
<td style="width: 411px;">The threat ID.</td>
</tr>
<tr>
<td style="width: 256.667px;">SentinelOne.Threat.Resolved</td>
<td style="width: 73.3333px;">Boolean</td>
<td style="width: 411px;">Whether the threat was successfully resolved.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="811" data-line-end="812">
<a id="Command_Example_811"></a>Command Example</h5>
<pre>!sentinelone-resolve-threat threat_ids=509259775582960700</pre>
<h5 class="code-line" data-line-start="814" data-line-end="815">
<a id="Context_Example_814"></a>Context Example</h5>
<pre>{
    "SentinelOne.Threat": [
        {
            "Resolved": false, 
            "ID": "509259775582960700"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="826" data-line-end="827">
<a id="Human_Readable_Output_826"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="827" data-line-end="828">
<a id="Sentinel_One__Resolving_threats_827"></a>Sentinel One - Resolving threats</h3>
<p class="has-line-data" data-line-start="828" data-line-end="829">No threats were resolved</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>ID</th>
<th>Resolved</th>
</tr>
</thead>
<tbody>
<tr>
<td>509259775582960700</td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_e4744817-ad70-417e-a772-8c2926087277" class="code-line" data-line-start="834" data-line-end="835">
<a id="10_sentinelonegetagent_834"></a>10. Get agent details</h3>
<hr>
<p>Gets details of an agent by agent ID.</p>
<h5 class="code-line" data-line-start="839" data-line-end="840">
<a id="Base_Command_839"></a>Base Command</h5>
<p><code>sentinelone-get-agent</code></p>
<h5 class="code-line" data-line-start="842" data-line-end="843">
<a id="Input_842"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 316px;"><strong>Argument Name</strong></th>
<th style="width: 245px;"><strong>Description</strong></th>
<th style="width: 179px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 316px;">agent_id</td>
<td style="width: 245px;">The agent ID.</td>
<td style="width: 179px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="849" data-line-end="850">
<a id="Context_Output_849"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 343px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 328px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 343px;">SentinelOne.Agent.NetworkStatus</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">The agent network status.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.ID</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">The agent ID.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.AgentVersion</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">The agent software version.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.IsDecomissioned</td>
<td style="width: 70px;">boolean</td>
<td style="width: 328px;">Whether the agent is decommissioned.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.IsActive</td>
<td style="width: 70px;">boolean</td>
<td style="width: 328px;">Whether the agent is active.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.LastActiveDate</td>
<td style="width: 70px;">date</td>
<td style="width: 328px;">The last active date of the agent.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.RegisteredAt</td>
<td style="width: 70px;">date</td>
<td style="width: 328px;">The registration date of the agent.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.ExternalIP</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">The agent IP address.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.ThreatCount</td>
<td style="width: 70px;">number</td>
<td style="width: 328px;">Number of active threats.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.EncryptedApplications</td>
<td style="width: 70px;">boolean</td>
<td style="width: 328px;">Whether disk encryption is enabled.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.OSName</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">Name of the operating system.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.ComputerName</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">Name of the agent computer.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.Domain</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">Domain name of the agent.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.CreatedAt</td>
<td style="width: 70px;">date</td>
<td style="width: 328px;">Agent creation time.</td>
</tr>
<tr>
<td style="width: 343px;">SentinelOne.Agent.SiteName</td>
<td style="width: 70px;">string</td>
<td style="width: 328px;">Site name associated with the agent.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="870" data-line-end="871">
<a id="Command_Example_870"></a>Command Example</h5>
<pre>!sentinelone-get-agent agent_id=661361473466353783</pre>
<h5 class="code-line" data-line-start="873" data-line-end="874">
<a id="Context_Example_873"></a>Context Example</h5>
<pre>{
    "SentinelOne.Agent": [
        {
            "ExternalIP": "99.80.149.227", 
            "Domain": "WORKGROUP", 
            "LastActiveDate": "2019-07-15T22:01:30.896402Z", 
            "NetworkStatus": "connecting", 
            "EncryptedApplications": false, 
            "ThreatCount": 0, 
            "ComputerName": "EC2AMAZ-S5C73AI", 
            "IsActive": false, 
            "OSName": "Windows Server 2016", 
            "SiteName": "demisto", 
            "AgentVersion": "3.2.4.54", 
            "IsDecomissioned": true, 
            "RegisteredAt": "2019-07-02T12:07:11.384037Z", 
            "ID": "661361473466353783", 
            "CreatedAt": "2019-07-02T12:07:11.388038Z"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="898" data-line-end="899">
<a id="Human_Readable_Output_898"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="899" data-line-end="900">
<a id="Sentinel_One__Get_Agent_Details_899"></a>Sentinel One - Get Agent Details</h3>
<p class="has-line-data" data-line-start="900" data-line-end="901">Provides details for the following agent ID : 661361473466353783</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Agent Version</th>
<th>Computer Name</th>
<th>Created At</th>
<th>Domain</th>
<th>Encrypted Applications</th>
<th>External IP</th>
<th>ID</th>
<th>Is Active</th>
<th>Is Decomissioned</th>
<th>Last ActiveDate</th>
<th>Network Status</th>
<th>OS Name</th>
<th>Registered At</th>
<th>Site Name</th>
<th>Threat Count</th>
</tr>
</thead>
<tbody>
<tr>
<td>3.2.4.54</td>
<td>EC2AMAZ-S5C73AI</td>
<td>2019-07-02T12:07:11.388038Z</td>
<td>WORKGROUP</td>
<td>false</td>
<td>99.80.149.227</td>
<td>661361473466353783</td>
<td>false</td>
<td>true</td>
<td>2019-07-15T22:01:30.896402Z</td>
<td>connecting</td>
<td>Windows Server 2016</td>
<td>2019-07-02T12:07:11.384037Z</td>
<td>demisto</td>
<td>0</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_c5e1149a-ccf8-429d-aaf8-3f55a4f190d8" class="code-line" data-line-start="906" data-line-end="907">
<a id="11_sentinelonegetsites_906"></a>11. Get a list of sites</h3>
<hr>
<p>Gets a list of all sites.</p>
<h5 class="code-line" data-line-start="911" data-line-end="912">
<a id="Base_Command_911"></a>Base Command</h5>
<p><code>sentinelone-get-sites</code></p>
<h5 class="code-line" data-line-start="914" data-line-end="915">
<a id="Input_914"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 99px;"><strong>Argument Name</strong></th>
<th style="width: 570px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 99px;">updated_at</td>
<td style="width: 570px;">Timestamp of last update, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">query</td>
<td style="width: 570px;">Full-text search for fields: name, account_name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">site_type</td>
<td style="width: 570px;">Site type. Can be “Trial”, “Paid”, “POC”, “DEV”, or “NFR”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">features</td>
<td style="width: 570px;">Returns sites that support the specified features. Can be “firewall-control”, “device-control”, or “ioc”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">state</td>
<td style="width: 570px;">Site state. Can be “active”, “deleted”, or “expired”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">suite</td>
<td style="width: 570px;">The suite of product features active for this site. Can be “Core” or “Complete”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">admin_only</td>
<td style="width: 570px;">Sites to which the user has Admin privileges.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">account_id</td>
<td style="width: 570px;">Account ID, for example: “225494730938493804”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">site_name</td>
<td style="width: 570px;">Site name, for example: “My Site”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">created_at</td>
<td style="width: 570px;">Timestamp of site creation, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 99px;">limit</td>
<td style="width: 570px;">Maximum number of results to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="931" data-line-end="932">
<a id="Context_Output_931"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 306.667px;"><strong>Path</strong></th>
<th style="width: 77.3333px;"><strong>Type</strong></th>
<th style="width: 357px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.Creator</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">The creator name.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.Name</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">The site name.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.Type</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">The site type.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.AccountName</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">The account name.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.State</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">The site state.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.HealthStatus</td>
<td style="width: 77.3333px;">boolean</td>
<td style="width: 357px;">The health status of the site.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.Suite</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">The suite to which the site belongs.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.ActiveLicenses</td>
<td style="width: 77.3333px;">number</td>
<td style="width: 357px;">Number of active licenses on the site.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.ID</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">ID of the site.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.TotalLicenses</td>
<td style="width: 77.3333px;">number</td>
<td style="width: 357px;">Number of total licenses on the site.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.CreatedAt</td>
<td style="width: 77.3333px;">date</td>
<td style="width: 357px;">Timestamp when the site was created.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.Expiration</td>
<td style="width: 77.3333px;">string</td>
<td style="width: 357px;">Timestamp when the site will expire.</td>
</tr>
<tr>
<td style="width: 306.667px;">SentinelOne.Site.UnlimitedLicenses</td>
<td style="width: 77.3333px;">boolean</td>
<td style="width: 357px;">Whether the site has unlimited licenses.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="950" data-line-end="951">
<a id="Command_Example_950"></a>Command Example</h5>
<pre>!sentinelone-get-sites</pre>
<h5 class="code-line" data-line-start="953" data-line-end="954">
<a id="Context_Example_953"></a>Context Example</h5>
<pre>{
    "SentinelOne.Site": [
        {
            "UnlimitedLicenses": true, 
            "Name": "demisto", 
            "Creator": "John Roe", 
            "AccountName": "SentinelOne", 
            "State": "active", 
            "HealthStatus": true, 
            "Expiration": null, 
            "ActiveLicenses": 5, 
            "Suite": "Complete", 
            "TotalLicenses": 0, 
            "Type": "Paid", 
            "ID": "475482421366727779", 
            "CreatedAt": "2018-10-19T00:58:41.644879Z"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="976" data-line-end="977">
<a id="Human_Readable_Output_976"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="977" data-line-end="978">
<a id="Sentinel_One__Gettin_List_of_Sites_977"></a>Sentinel One - Getting List of Sites</h3>
<p class="has-line-data" data-line-start="978" data-line-end="979">Provides summary information and details for all sites that matched your search criteria.</p>
<table class="table table-striped table-bordered" style="width: 750px;" border="2">
<thead>
<tr>
<th>Account Name</th>
<th>Active Licenses</th>
<th>Created At</th>
<th>Creator</th>
<th>Health Status</th>
<th>ID</th>
<th>Name</th>
<th>State</th>
<th>Suite</th>
<th>Total Licenses</th>
<th>Type</th>
<th>Unlimited Licenses</th>
</tr>
</thead>
<tbody>
<tr>
<td>SentinelOne</td>
<td>5</td>
<td>2018-10-19T00:58:41.644879Z</td>
<td>John Roe</td>
<td>true</td>
<td>475482421366727779</td>
<td>demisto</td>
<td>active</td>
<td>Complete</td>
<td>0</td>
<td>Paid</td>
<td>true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7a21d365-5e9f-4bfc-8244-57f65a169794" class="code-line" data-line-start="984" data-line-end="985">
<a id="12_sentinelonegetsite_984"></a>12. Get a site list</h3>
<hr>
<p>Gets a site list by site ID.</p>
<h5 class="code-line" data-line-start="989" data-line-end="990">
<a id="Base_Command_989"></a>Base Command</h5>
<p><code>sentinelone-get-site</code></p>
<h5 class="code-line" data-line-start="992" data-line-end="993">
<a id="Input_992"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 313.333px;"><strong>Argument Name</strong></th>
<th style="width: 248.667px;"><strong>Description</strong></th>
<th style="width: 178px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 313.333px;">site_id</td>
<td style="width: 248.667px;">ID of the site.</td>
<td style="width: 178px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="999" data-line-end="1000">
<a id="Context_Output_999"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 315px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 350px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 315px;">SentinelOne.Site.Creator</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">The creator name.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.Name</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">The site name.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.Type</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">The site type.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.AccountName</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">The account name.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.State</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">The site state.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.HealthStatus</td>
<td style="width: 75px;">boolean</td>
<td style="width: 350px;">The health status of the site.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.Suite</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">The suite to which the site belongs.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.ActiveLicenses</td>
<td style="width: 75px;">number</td>
<td style="width: 350px;">Number of active licenses on the site.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.ID</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">ID of the site.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.TotalLicenses</td>
<td style="width: 75px;">number</td>
<td style="width: 350px;">Number of total licenses on the site.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.CreatedAt</td>
<td style="width: 75px;">date</td>
<td style="width: 350px;">Timestamp when the site was created.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.Expiration</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">Timestamp when the site will expire.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.UnlimitedLicenses</td>
<td style="width: 75px;">boolean</td>
<td style="width: 350px;">Unlimited licenses boolean.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.AccountID</td>
<td style="width: 75px;">string</td>
<td style="width: 350px;">Account ID.</td>
</tr>
<tr>
<td style="width: 315px;">SentinelOne.Site.IsDefault</td>
<td style="width: 75px;">boolean</td>
<td style="width: 350px;">Whether the site is the default site.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1020" data-line-end="1021">
<a id="Command_Example_1020"></a>Command Example</h5>
<pre>!sentinelone-get-site site_id=475482421366727779</pre>
<h5 class="code-line" data-line-start="1023" data-line-end="1024">
<a id="Context_Example_1023"></a>Context Example</h5>
<pre>{
    "SentinelOne.Site": [
        {
            "IsDefault": false, 
            "UnlimitedLicenses": true, 
            "Name": "demisto", 
            "Creator": "John Roe", 
            "AccountName": "SentinelOne", 
            "State": "active", 
            "HealthStatus": true, 
            "Expiration": null, 
            "ActiveLicenses": 5, 
            "Suite": "Complete", 
            "TotalLicenses": 0, 
            "Type": "Paid", 
            "ID": "475482421366727779", 
            "CreatedAt": "2018-10-19T00:58:41.644879Z", 
            "AccountID": "433241117337583618"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="1048" data-line-end="1049">
<a id="Human_Readable_Output_1048"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1049" data-line-end="1050">
<a id="Sentinel_One__Summary_About_Site_475482421366727779_1049"></a>Sentinel One - Summary About Site: 475482421366727779</h3>
<p class="has-line-data" data-line-start="1050" data-line-end="1051">Provides summary information and details for specific site ID.</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Account Name</th>
<th>AccountID</th>
<th>Active Licenses</th>
<th>Created At</th>
<th>Creator</th>
<th>Health Status</th>
<th>ID</th>
<th>IsDefault</th>
<th>Name</th>
<th>State</th>
<th>Suite</th>
<th>Total Licenses</th>
<th>Type</th>
<th>Unlimited Licenses</th>
</tr>
</thead>
<tbody>
<tr>
<td>SentinelOne</td>
<td>433241117337583618</td>
<td>5</td>
<td>2018-10-19T00:58:41.644879Z</td>
<td>John Roe</td>
<td>true</td>
<td>475482421366727779</td>
<td>false</td>
<td>demisto</td>
<td>active</td>
<td>Complete</td>
<td>0</td>
<td>Paid</td>
<td>true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1d957e18-4716-458e-8b95-7b411878fc6b" class="code-line" data-line-start="1056" data-line-end="1057">
<a id="13_sentinelonereactivatesite_1056"></a>13. Reactivate a site</h3>
<hr>
<p>Reactivates an expired site.</p>
<h5 class="code-line" data-line-start="1061" data-line-end="1062">
<a id="Base_Command_1061"></a>Base Command</h5>
<p><code>sentinelone-reactivate-site</code></p>
<h5 class="code-line" data-line-start="1064" data-line-end="1065">
<a id="Input_1064"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 184.667px;"><strong>Argument Name</strong></th>
<th style="width: 451.333px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184.667px;">site_id</td>
<td style="width: 451.333px;">Site ID. Example: “225494730938493804”.</td>
<td style="width: 105px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1071" data-line-end="1072">
<a id="Context_Output_1071"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 353px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">SentinelOne.Site.ID</td>
<td style="width: 88px;">string</td>
<td style="width: 353px;">Site ID.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Site.Reactivated</td>
<td style="width: 88px;">boolean</td>
<td style="width: 353px;">Whether the site was reactivated.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1079" data-line-end="1080">
<a id="Command_Example_1079"></a>Command Example</h5>
<pre>!sentinelone-reactivate-site site_id=475482421366727779</pre>
<h5 class="code-line" data-line-start="1082" data-line-end="1083">
<a id="Human_Readable_Output_1082"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="1083" data-line-end="1084">
<a id="Sentinel_One__Reactivated_Site_475482421366727779_1083"></a>Sentinel One - Reactivated Site: 475482421366727779</h3>
<p class="has-line-data" data-line-start="1084" data-line-end="1085">##‘Site has been reactivated successfully’</p>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>ID</th>
<th>Reactivated</th>
</tr>
</thead>
<tbody>
<tr>
<td>475482421366727779</td>
<td>success</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4c49234e-0661-4207-abb2-8b67bc5df039" class="code-line" data-line-start="1091" data-line-end="1092">
<a id="14_sentinelonegetactivities_1091"></a>14. Get a list of activities</h3>
<hr>
<p class="has-line-data" data-line-start="1093" data-line-end="1094">Gets a list of activities.</p>
<h5 class="code-line" data-line-start="1096" data-line-end="1097">
<a id="Base_Command_1096"></a>Base Command</h5>
<p class="has-line-data" data-line-start="1098" data-line-end="1099"><code>sentinelone-get-activities</code></p>
<h5 class="code-line" data-line-start="1099" data-line-end="1100">
<a id="Input_1099"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 114px;"><strong>Argument Name</strong></th>
<th style="width: 555px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 114px;">created_after</td>
<td style="width: 555px;">Return activities created after this timestamp, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">user_emails</td>
<td style="width: 555px;">Email address of the user who invoked the activity (if applicable).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">group_ids</td>
<td style="width: 555px;">List of Group IDs by which to filter, for example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">created_until</td>
<td style="width: 555px;">Return activities created on or before this timestamp, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">include_hidden</td>
<td style="width: 555px;">Include internal activities hidden from display, for example: “False”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">activities_ids</td>
<td style="width: 555px;">CSV list of activity IDs by which to filter, for example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">created_before</td>
<td style="width: 555px;">Return activities created before this timestamp, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">threats_ids</td>
<td style="width: 555px;">CSV list of threat IDs for which to return activities, for example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">activity_types</td>
<td style="width: 555px;">CSV of activity codes to return, for example: “52,53,71,72”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">user_ids</td>
<td style="width: 555px;">CSV list of user IDs for users that invoked the activity (if applicable), for example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">created_from</td>
<td style="width: 555px;">Return activities created on or after this timestamp, for example: “2018-02-27T04:49:26.257525Z”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">created_between</td>
<td style="width: 555px;">Return activities created within this range (inclusive), for example: “1514978764288-1514978999999”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">agent_ids</td>
<td style="width: 555px;">Return activities related to specified agents. Example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 114px;">limit</td>
<td style="width: 555px;">Maximum number of items to return (1-100).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1119" data-line-end="1120">
<a id="Context_Output_1119"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 51.6667px;"><strong>Type</strong></th>
<th style="width: 390.333px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">SentinelOne.Activity.AgentID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Related agent (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.AgentUpdatedVersion</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Agent’s new version (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.SiteID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Related site (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.UserID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">The user who invoked the activity (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.SecondaryDescription</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Secondary description.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.OsFamily</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Agent’s OS type (if applicable). Can be “linux”, “macos”, “windows”, or “windows_legacy”.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.ActivityType</td>
<td style="width: 51.6667px;">Number</td>
<td style="width: 390.333px;">Activity type.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.data.SiteID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">The site ID.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.data.SiteName</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">The site name.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.data.username</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">The name of the site creator.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.Hash</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Threat file hash (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.UpdatedAt</td>
<td style="width: 51.6667px;">Date</td>
<td style="width: 390.333px;">Activity last updated time (UTC).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.Comments</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Comments for the activity.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.ThreatID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Related threat (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.PrimaryDescription</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Primary description for the activity.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.GroupID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Related group (if applicable).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.ID</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Activity ID.</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.CreatedAt</td>
<td style="width: 51.6667px;">Date</td>
<td style="width: 390.333px;">Activity creation time (UTC).</td>
</tr>
<tr>
<td style="width: 299px;">SentinelOne.Activity.Description</td>
<td style="width: 51.6667px;">String</td>
<td style="width: 390.333px;">Extra activity information.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="1144" data-line-end="1145">
<a id="Command_Example_1144"></a>Command Example</h5>
<pre>!sentinelone-get-activities</pre>
<h5 class="code-line" data-line-start="1147" data-line-end="1148">
<a id="Context_Example_1147"></a>Context Example</h5>
<pre>{
    "SentinelOne.Activity": [
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 5020, 
            "UserID": "433273625970238486", 
            "Comments": null, 
            "ID": "475482421492556909", 
            "PrimaryDescription": "The management user John Roe created demisto site.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-19T00:58:41.660287Z", 
            "AgentID": null, 
            "Data": {
                "siteName": "demisto", 
                "username": "John Roe", 
                "siteId": 475482421366727800
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-19T00:58:41.660278Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": "John Roe", 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 23, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "475482955955938476", 
            "PrimaryDescription": "The management user John Roe added user Jane Doe as admin.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-19T00:59:45.373592Z", 
            "AgentID": null, 
            "Data": {
                "byUser": "John Roe", 
                "username": "Jane Doe", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-19T00:59:45.373584Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "475553388201878769", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-19T03:19:41.551249Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-19T03:19:41.551236Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "476162850050648822", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-19T23:30:35.062505Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-19T23:30:35.062484Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "476162850092591864", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-19T23:30:35.068827Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-19T23:30:35.068812Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "478078612361294941", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-22T14:56:51.726777Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-22T14:56:51.726762Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "478078815793427551", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-10-22T14:57:15.978615Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-10-22T14:57:15.978605Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "499090543532554580", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-11-20T14:43:49.115665Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-11-20T14:43:49.115657Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "500911232606524037", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-11-23T03:01:12.166753Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-11-23T03:01:12.166743Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "504856083882582151", 
            "PrimaryDescription": "The management user Jane Doe logged into management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-11-28T13:38:55.085497Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-11-28T13:38:55.085488Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": "", 
            "ActivityType": 17, 
            "UserID": null, 
            "Comments": null, 
            "ID": "507609080257599870", 
            "PrimaryDescription": "Bills-MBP subscribed and joined the group Default Group.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-02T08:48:37.826824Z", 
            "AgentID": "507609079972387179", 
            "Data": {
                "computerName": "Bills-MBP", 
                "group": "Default Group", 
                "optionalGroups": []
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-02T08:48:37.826816Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 71, 
            "UserID": null, 
            "Comments": null, 
            "ID": "507609080626698626", 
            "PrimaryDescription": "System initiated a full disk scan to the agent: Bills-MBP (98.234.105.153).", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-02T08:48:37.871144Z", 
            "AgentID": "507609079972387179", 
            "Data": {
                "externalIp": "98.234.105.153", 
                "computerName": "Bills-MBP", 
                "system": true, 
                "uuid": "9A532F6E-0F87-5F8E-B6AB-C0206599C568"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-02T08:48:37.871136Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 90, 
            "UserID": null, 
            "Comments": null, 
            "ID": "507609341168474555", 
            "PrimaryDescription": "Agent Bills-MBP started full disk scan at Sun, 02 Dec 2018, 08:49:08 UTC.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-02T08:49:08.929672Z", 
            "AgentID": "507609079972387179", 
            "Data": {
                "status": "started", 
                "computerName": "Bills-MBP", 
                "createdAt": "2018-12-02T08:49:08.908384Z"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-02T08:49:08.929660Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 92, 
            "UserID": null, 
            "Comments": null, 
            "ID": "508159023422660725", 
            "PrimaryDescription": "Agent Bills-MBP completed full disk scan at Mon, 03 Dec 2018, 03:01:16 UTC.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-03T03:01:16.160715Z", 
            "AgentID": "507609079972387179", 
            "Data": {
                "status": "finished", 
                "computerName": "Bills-MBP", 
                "createdAt": "2018-12-03T03:01:16.153462Z"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-03T03:01:16.160707Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "509259775582960700", 
            "SecondaryDescription": "/Users/bill/.Trash/eicar.com.txt", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "509259775683623999", 
            "PrimaryDescription": "Threat detected, name: eicar.com.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-04T15:28:16.055823Z", 
            "AgentID": "507609079972387179", 
            "Data": {
                "username": null, 
                "computerName": "Bills-MBP", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/bill/.Trash/eicar.com.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-04T15:28:16.055815Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "509259775582960700", 
            "SecondaryDescription": "/Users/bill/.Trash/eicar.com.txt", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "509259776623148097", 
            "PrimaryDescription": "The agent Bills-MBP successfully quarantined the threat: eicar.com.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-04T15:28:16.168238Z", 
            "AgentID": "507609079972387179", 
            "Data": {
                "computerName": "Bills-MBP", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/bill/.Trash/eicar.com.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-04T15:28:16.168216Z"
        }, 
        {
            "OsFamily": "macos", 
            "AgentUpdatedVersion": null, 
            "Hash": "3395856ce81f2b7382dee72602f798b642f14140", 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": "3395856ce81f2b7382dee72602f798b642f14140", 
            "ActivityType": 3006, 
            "UserID": null, 
            "Comments": null, 
            "ID": "509259849436265543", 
            "PrimaryDescription": "Cloud has added macOS black hash.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-04T15:28:24.847663Z", 
            "AgentID": null, 
            "Data": {
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "osFamily": "osx", 
                "description": null
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-04T15:28:24.847654Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "510432832787879335", 
            "PrimaryDescription": "The management user Jane Doe logged into the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-06T06:18:55.360302Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-06T06:18:55.360294Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 33, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "510434401356912041", 
            "PrimaryDescription": "The management user Jane Doe logged out of the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-06T06:22:02.348128Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-06T06:22:02.348116Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "512980043203657099", 
            "PrimaryDescription": "The management user Jane Doe logged into the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-09T18:39:46.504215Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-09T18:39:46.504206Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "513485626755302270", 
            "PrimaryDescription": "The management user Jane Doe logged into the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T11:24:16.759935Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T11:24:16.759925Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": "Jane Doe", 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 23, 
            "UserID": "513488018280334208", 
            "Comments": null, 
            "ID": "513488018364220290", 
            "PrimaryDescription": "The management user Jane Doe added user Yarden Sade as admin.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T11:29:01.861735Z", 
            "AgentID": null, 
            "Data": {
                "byUser": "Jane Doe", 
                "username": "Yarden Sade", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T11:29:01.861727Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 33, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "513489064113259396", 
            "PrimaryDescription": "The management user Jane Doe logged out of the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T11:31:06.525318Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T11:31:06.525307Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "513488018280334208", 
            "Comments": null, 
            "ID": "513489107926958983", 
            "PrimaryDescription": "The management user Yarden Sade logged into the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T11:31:11.748582Z", 
            "AgentID": null, 
            "Data": {
                "username": "Yarden Sade", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T11:31:11.748574Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 5008, 
            "UserID": "513488018280334208", 
            "Comments": null, 
            "ID": "513490499303424908", 
            "PrimaryDescription": "The management user Yarden Sade has created New group Test.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T11:33:57.612933Z", 
            "AgentID": null, 
            "Data": {
                "username": "Yarden Sade", 
                "groupName": "Test", 
                "groupId": "513490499236316042"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T11:33:57.612924Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 33, 
            "UserID": "513488018280334208", 
            "Comments": null, 
            "ID": "513504037921146173", 
            "PrimaryDescription": "The management user Yarden Sade logged out of the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:00:51.541682Z", 
            "AgentID": null, 
            "Data": {
                "username": "Yarden Sade", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T12:00:51.541671Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "513504203889755456", 
            "PrimaryDescription": "The management user Jane Doe logged into the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:01:11.326905Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T12:01:11.326896Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": "", 
            "ActivityType": 17, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513505756310717775", 
            "PrimaryDescription": "164 subscribed and joined the group Default Group.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:04:16.390472Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "group": "Default Group", 
                "optionalGroups": []
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:04:16.390462Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 71, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513505756696593747", 
            "PrimaryDescription": "System initiated a full disk scan to the agent: 164 (94.188.164.68).", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:04:16.436092Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "externalIp": "94.188.164.68", 
                "computerName": "164", 
                "system": true, 
                "uuid": "46DBCBC2-216A-5732-A007-4348BB55B37F"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:04:16.436084Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 90, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513506023588545884", 
            "PrimaryDescription": "Agent 164 started full disk scan at Mon, 10 Dec 2018, 12:04:48 UTC.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:04:48.252701Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "status": "started", 
                "computerName": "164", 
                "createdAt": "2018-12-10T12:04:48.248338Z"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:04:48.252693Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513516799695046076", 
            "SecondaryDescription": "/Users/yardensade/WebstormProjects/content/TestData/EICAR.exe", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513516799787320769", 
            "PrimaryDescription": "Threat detected, name: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:26:12.874792Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "username": null, 
                "computerName": "164", 
                "threatClassificationSource": null, 
                "filePath": "/Users/yardensade/WebstormProjects/content/TestData/EICAR.exe", 
                "threatClassification": null, 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:26:12.874784Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513516799695046076", 
            "SecondaryDescription": "/Users/yardensade/WebstormProjects/content/TestData/EICAR.exe", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513516801297270211", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:26:13.054678Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/WebstormProjects/content/TestData/EICAR.exe", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:26:13.054666Z"
        }, 
        {
            "OsFamily": "macos", 
            "AgentUpdatedVersion": null, 
            "Hash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
            "ActivityType": 3006, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513516852300006858", 
            "PrimaryDescription": "Cloud has added macOS black hash.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:26:19.135226Z", 
            "AgentID": null, 
            "Data": {
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "osFamily": "osx", 
                "description": null
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-10T12:26:19.135218Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513516952292214236", 
            "SecondaryDescription": "/Users/yardensade/dev/demisto/content/TestData/EICAR.exe", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513516952367711710", 
            "PrimaryDescription": "Threat detected, name: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:26:31.064576Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "username": null, 
                "computerName": "164", 
                "threatClassificationSource": "Cloud", 
                "filePath": "/Users/yardensade/dev/demisto/content/TestData/EICAR.exe", 
                "threatClassification": "Malware", 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:26:31.064568Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513516952292214236", 
            "SecondaryDescription": "/Users/yardensade/dev/demisto/content/TestData/EICAR.exe", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513516953818940898", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:26:31.236777Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Cloud", 
                "filePath": "/Users/yardensade/dev/demisto/content/TestData/EICAR.exe", 
                "threatClassification": "Malware", 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:26:31.236769Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513518844384691684", 
            "SecondaryDescription": "/Users/yardensade/Documents/GitHub/content/TestData/EICAR.exe", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513518844460189159", 
            "PrimaryDescription": "Threat detected, name: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:30:16.619432Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "username": null, 
                "computerName": "164", 
                "threatClassificationSource": "Cloud", 
                "filePath": "/Users/yardensade/Documents/GitHub/content/TestData/EICAR.exe", 
                "threatClassification": "Malware", 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:30:16.619423Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513518844384691684", 
            "SecondaryDescription": "/Users/yardensade/Documents/GitHub/content/TestData/EICAR.exe", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513518845877863914", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:30:16.788068Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Cloud", 
                "filePath": "/Users/yardensade/Documents/GitHub/content/TestData/EICAR.exe", 
                "threatClassification": "Malware", 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:30:16.788059Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 92, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513519504073213420", 
            "PrimaryDescription": "Agent 164 completed full disk scan at Mon, 10 Dec 2018, 12:31:35 UTC.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:31:35.251329Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "status": "finished", 
                "computerName": "164", 
                "createdAt": "2018-12-10T12:31:35.248610Z"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:31:35.251320Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513526418089756174", 
            "SecondaryDescription": "/Users/yardensade/Downloads/eicar.com.txt", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513526418156865040", 
            "PrimaryDescription": "Threat detected, name: eicar.com.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:45:19.474339Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "username": null, 
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/eicar.com.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:45:19.474330Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513526418089756174", 
            "SecondaryDescription": "/Users/yardensade/Downloads/eicar.com.txt", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513526419608094227", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: eicar.com.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:45:19.647320Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/eicar.com.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:45:19.647311Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513526832755426837", 
            "SecondaryDescription": "/Users/yardensade/Downloads/eicar.com", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513526832864478743", 
            "PrimaryDescription": "Threat detected, name: eicar.com.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:46:08.910934Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "username": null, 
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/eicar.com", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:46:08.910923Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513526832755426837", 
            "SecondaryDescription": "/Users/yardensade/Downloads/eicar.com", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513526834374428187", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: eicar.com.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:46:09.091198Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/eicar.com", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:46:09.091186Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513526832755426837", 
            "SecondaryDescription": "/Users/yardensade/Downloads/eicar.com", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513526971268122141", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: eicar.com.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:46:25.410362Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/eicar.com", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:46:25.410353Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513526418089756174", 
            "SecondaryDescription": "/Users/yardensade/Downloads/eicar.com.txt", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513528784247637538", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: eicar.com.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:50:01.534329Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/eicar.com.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "eicar.com.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:50:01.534321Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513529274335282723", 
            "SecondaryDescription": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
            "ActivityType": 18, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513529274402391589", 
            "PrimaryDescription": "Threat detected, name: totally_not_a_virus.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:50:59.965549Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "username": null, 
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "totally_not_a_virus.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:50:59.965541Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513529274335282723", 
            "SecondaryDescription": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513529275895563816", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: totally_not_a_virus.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:51:00.143471Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "totally_not_a_virus.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:51:00.143461Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513529274335282723", 
            "SecondaryDescription": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513529459253757483", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: totally_not_a_virus.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:51:22.000536Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "totally_not_a_virus.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:51:22.000526Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513529274335282723", 
            "SecondaryDescription": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
            "ActivityType": 2004, 
            "UserID": null, 
            "Comments": null, 
            "ID": "513533152942409262", 
            "PrimaryDescription": "The agent 164 successfully quarantined the threat: totally_not_a_virus.txt.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-10T12:58:42.323499Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Engine", 
                "filePath": "/Users/yardensade/Downloads/totally_not_a_virus.txt", 
                "threatClassification": "OSX.Malware", 
                "fileContentHash": "3395856ce81f2b7382dee72602f798b642f14140", 
                "fileDisplayName": "totally_not_a_virus.txt"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-10T12:58:42.323491Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": "513516952292214236", 
            "SecondaryDescription": "/Users/yardensade/dev/demisto/content/TestData/EICAR.exe", 
            "ActivityType": 2009, 
            "UserID": null, 
            "Comments": null, 
            "ID": "514190868824249980", 
            "PrimaryDescription": "The agent 164 failed to quarantine the threat: EICAR.exe.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-11T10:45:28.166458Z", 
            "AgentID": "513505756159722818", 
            "Data": {
                "computerName": "164", 
                "threatClassificationSource": "Cloud", 
                "filePath": "/Users/yardensade/dev/demisto/content/TestData/EICAR.exe", 
                "threatClassification": "Malware", 
                "fileContentHash": "cf8bd9dfddff007f75adf4c2be48005cea317c62", 
                "fileDisplayName": "EICAR.exe"
            }, 
            "GroupID": "475482421375116388", 
            "CreatedAt": "2018-12-11T10:45:28.166449Z"
        }, 
        {
            "OsFamily": null, 
            "AgentUpdatedVersion": null, 
            "Hash": null, 
            "Description": null, 
            "ThreatID": null, 
            "SecondaryDescription": null, 
            "ActivityType": 27, 
            "UserID": "475482955872052394", 
            "Comments": null, 
            "ID": "514803118157132740", 
            "PrimaryDescription": "The management user Jane Doe logged into the management console.", 
            "SiteID": "475482421366727779", 
            "UpdatedAt": "2018-12-12T07:01:53.974164Z", 
            "AgentID": null, 
            "Data": {
                "username": "Jane Doe", 
                "source": "mgmt", 
                "role": "admin"
            }, 
            "GroupID": null, 
            "CreatedAt": "2018-12-12T07:01:53.974154Z"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2368" data-line-end="2369">
<a id="Human_Readable_Output_2368"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2369" data-line-end="2370">
<a id="Sentinel_One_Activities_2369"></a>Sentinel One Activities</h3>
<table class="table table-striped table-bordered" style="width: 1648px;" border="2">
<thead>
<tr style="height: 21px;">
<th style="width: 161.667px; height: 21px;">ID</th>
<th style="width: 164.333px; height: 21px;">Primary description</th>
<th style="width: 658px; height: 21px;">Data</th>
<th style="width: 160px; height: 21px;">User ID</th>
<th style="width: 160px; height: 21px;">Created at</th>
<th style="width: 160px; height: 21px;">Updated at</th>
<th style="width: 160px; height: 21px;">Threat ID</th>
</tr>
</thead>
<tbody>
<tr style="height: 65px;">
<td style="width: 161.667px; height: 65px;">475482421492556909</td>
<td style="width: 164.333px; height: 65px;">The management user John Roe created demisto site.</td>
<td style="width: 658px; height: 65px;">siteId: 475482421366727779&lt;br&gt;siteName: demisto&lt;br&gt;username: John Roe</td>
<td style="width: 160px; height: 65px;">433273625970238486</td>
<td style="width: 160px; height: 65px;">2018-10-19T00:58:41.660278Z</td>
<td style="width: 160px; height: 65px;">2018-10-19T00:58:41.660287Z</td>
<td style="width: 160px; height: 65px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">475482955955938476</td>
<td style="width: 164.333px; height: 87px;">The management user John Roe added user Jane Doe as admin.</td>
<td style="width: 658px; height: 87px;">byUser: John Roe&lt;br&gt;role: admin&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-10-19T00:59:45.373584Z</td>
<td style="width: 160px; height: 87px;">2018-10-19T00:59:45.373592Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">475553388201878769</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-10-19T03:19:41.551236Z</td>
<td style="width: 160px; height: 87px;">2018-10-19T03:19:41.551249Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">476162850050648822</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-10-19T23:30:35.062484Z</td>
<td style="width: 160px; height: 87px;">2018-10-19T23:30:35.062505Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">476162850092591864</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-10-19T23:30:35.068812Z</td>
<td style="width: 160px; height: 87px;">2018-10-19T23:30:35.068827Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">478078612361294941</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-10-22T14:56:51.726762Z</td>
<td style="width: 160px; height: 87px;">2018-10-22T14:56:51.726777Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">478078815793427551</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-10-22T14:57:15.978605Z</td>
<td style="width: 160px; height: 87px;">2018-10-22T14:57:15.978615Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">499090543532554580</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-11-20T14:43:49.115657Z</td>
<td style="width: 160px; height: 87px;">2018-11-20T14:43:49.115665Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">500911232606524037</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-11-23T03:01:12.166743Z</td>
<td style="width: 160px; height: 87px;">2018-11-23T03:01:12.166753Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">504856083882582151</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-11-28T13:38:55.085488Z</td>
<td style="width: 160px; height: 87px;">2018-11-28T13:38:55.085497Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">507609080257599870</td>
<td style="width: 164.333px; height: 87px;">Bills-MBP subscribed and joined the group Default Group.</td>
<td style="width: 658px; height: 87px;">computerName: Bills-MBP&lt;br&gt;group: Default Group&lt;br&gt;optionalGroups:</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-02T08:48:37.826816Z</td>
<td style="width: 160px; height: 87px;">2018-12-02T08:48:37.826824Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">507609080626698626</td>
<td style="width: 164.333px; height: 87px;">System initiated a full disk scan to the agent: Bills-MBP (98.234.105.153).</td>
<td style="width: 658px; height: 87px;">computerName: Bills-MBP&lt;br&gt;externalIp: 98.234.105.153&lt;br&gt;system: true&lt;br&gt;uuid: 9A532F6E-0F87-5F8E-B6AB-C0206599C568</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-02T08:48:37.871136Z</td>
<td style="width: 160px; height: 87px;">2018-12-02T08:48:37.871144Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">507609341168474555</td>
<td style="width: 164.333px; height: 87px;">Agent Bills-MBP started full disk scan at Sun, 02 Dec 2018, 08:49:08 UTC.</td>
<td style="width: 658px; height: 87px;">computerName: Bills-MBP&lt;br&gt;createdAt: 2018-12-02T08:49:08.908384Z&lt;br&gt;status: started</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-02T08:49:08.929660Z</td>
<td style="width: 160px; height: 87px;">2018-12-02T08:49:08.929672Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">508159023422660725</td>
<td style="width: 164.333px; height: 87px;">Agent Bills-MBP completed full disk scan at Mon, 03 Dec 2018, 03:01:16 UTC.</td>
<td style="width: 658px; height: 87px;">computerName: Bills-MBP&lt;br&gt;createdAt: 2018-12-03T03:01:16.153462Z&lt;br&gt;status: finished</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-03T03:01:16.160707Z</td>
<td style="width: 160px; height: 87px;">2018-12-03T03:01:16.160715Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">509259775683623999</td>
<td style="width: 164.333px; height: 87px;">Threat detected, name: eicar.com.txt.</td>
<td style="width: 658px; height: 87px;">computerName: Bills-MBP&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com.txt&lt;br&gt;filePath: /Users/bill/.Trash/eicar.com.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine&lt;br&gt;username: null</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-04T15:28:16.055815Z</td>
<td style="width: 160px; height: 87px;">2018-12-04T15:28:16.055823Z</td>
<td style="width: 160px; height: 87px;">509259775582960700</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">509259776623148097</td>
<td style="width: 164.333px; height: 87px;">The agent Bills-MBP successfully quarantined the threat: eicar.com.txt.</td>
<td style="width: 658px; height: 87px;">computerName: Bills-MBP&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com.txt&lt;br&gt;filePath: /Users/bill/.Trash/eicar.com.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-04T15:28:16.168216Z</td>
<td style="width: 160px; height: 87px;">2018-12-04T15:28:16.168238Z</td>
<td style="width: 160px; height: 87px;">509259775582960700</td>
</tr>
<tr style="height: 43px;">
<td style="width: 161.667px; height: 43px;">509259849436265543</td>
<td style="width: 164.333px; height: 43px;">Cloud has added macOS black hash.</td>
<td style="width: 658px; height: 43px;">description: null&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;osFamily: osx</td>
<td style="width: 160px; height: 43px;"> </td>
<td style="width: 160px; height: 43px;">2018-12-04T15:28:24.847654Z</td>
<td style="width: 160px; height: 43px;">2018-12-04T15:28:24.847663Z</td>
<td style="width: 160px; height: 43px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">510432832787879335</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-06T06:18:55.360294Z</td>
<td style="width: 160px; height: 87px;">2018-12-06T06:18:55.360302Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">510434401356912041</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged out of the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-06T06:22:02.348116Z</td>
<td style="width: 160px; height: 87px;">2018-12-06T06:22:02.348128Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">512980043203657099</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-09T18:39:46.504206Z</td>
<td style="width: 160px; height: 87px;">2018-12-09T18:39:46.504215Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513485626755302270</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:24:16.759925Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:24:16.759935Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513488018364220290</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe added user Yarden Sade as admin.</td>
<td style="width: 658px; height: 87px;">byUser: Jane Doe&lt;br&gt;role: admin&lt;br&gt;username: Yarden Sade</td>
<td style="width: 160px; height: 87px;">513488018280334208</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:29:01.861727Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:29:01.861735Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513489064113259396</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged out of the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:31:06.525307Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:31:06.525318Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513489107926958983</td>
<td style="width: 164.333px; height: 87px;">The management user Yarden Sade logged into the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Yarden Sade</td>
<td style="width: 160px; height: 87px;">513488018280334208</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:31:11.748574Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:31:11.748582Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513490499303424908</td>
<td style="width: 164.333px; height: 87px;">The management user Yarden Sade has created New group Test.</td>
<td style="width: 658px; height: 87px;">groupId: 513490499236316042&lt;br&gt;groupName: Test&lt;br&gt;username: Yarden Sade</td>
<td style="width: 160px; height: 87px;">513488018280334208</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:33:57.612924Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T11:33:57.612933Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513504037921146173</td>
<td style="width: 164.333px; height: 87px;">The management user Yarden Sade logged out of the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;username: Yarden Sade</td>
<td style="width: 160px; height: 87px;">513488018280334208</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:00:51.541671Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:00:51.541682Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513504203889755456</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:01:11.326896Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:01:11.326905Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 65px;">
<td style="width: 161.667px; height: 65px;">513505756310717775</td>
<td style="width: 164.333px; height: 65px;">164 subscribed and joined the group Default Group.</td>
<td style="width: 658px; height: 65px;">computerName: 164&lt;br&gt;group: Default Group&lt;br&gt;optionalGroups:</td>
<td style="width: 160px; height: 65px;"> </td>
<td style="width: 160px; height: 65px;">2018-12-10T12:04:16.390462Z</td>
<td style="width: 160px; height: 65px;">2018-12-10T12:04:16.390472Z</td>
<td style="width: 160px; height: 65px;"> </td>
</tr>
<tr style="height: 65px;">
<td style="width: 161.667px; height: 65px;">513505756696593747</td>
<td style="width: 164.333px; height: 65px;">System initiated a full disk scan to the agent: 164 (94.188.164.68).</td>
<td style="width: 658px; height: 65px;">computerName: 164&lt;br&gt;externalIp: 94.188.164.68&lt;br&gt;system: true&lt;br&gt;uuid: 46DBCBC2-216A-5732-A007-4348BB55B37F</td>
<td style="width: 160px; height: 65px;"> </td>
<td style="width: 160px; height: 65px;">2018-12-10T12:04:16.436084Z</td>
<td style="width: 160px; height: 65px;">2018-12-10T12:04:16.436092Z</td>
<td style="width: 160px; height: 65px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513506023588545884</td>
<td style="width: 164.333px; height: 87px;">Agent 164 started full disk scan at Mon, 10 Dec 2018, 12:04:48 UTC.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;createdAt: 2018-12-10T12:04:48.248338Z&lt;br&gt;status: started</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:04:48.252693Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:04:48.252701Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513516799787320769</td>
<td style="width: 164.333px; height: 87px;">Threat detected, name: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/WebstormProjects/content/TestData/EICAR.exe&lt;br&gt;threatClassification: null&lt;br&gt;threatClassificationSource: null&lt;br&gt;username: null</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:12.874784Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:12.874792Z</td>
<td style="width: 160px; height: 87px;">513516799695046076</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513516801297270211</td>
<td style="width: 164.333px; height: 87px;">The agent 164 successfully quarantined the threat: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/WebstormProjects/content/TestData/EICAR.exe&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:13.054666Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:13.054678Z</td>
<td style="width: 160px; height: 87px;">513516799695046076</td>
</tr>
<tr style="height: 43px;">
<td style="width: 161.667px; height: 43px;">513516852300006858</td>
<td style="width: 164.333px; height: 43px;">Cloud has added macOS black hash.</td>
<td style="width: 658px; height: 43px;">description: null&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;osFamily: osx</td>
<td style="width: 160px; height: 43px;"> </td>
<td style="width: 160px; height: 43px;">2018-12-10T12:26:19.135218Z</td>
<td style="width: 160px; height: 43px;">2018-12-10T12:26:19.135226Z</td>
<td style="width: 160px; height: 43px;"> </td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513516952367711710</td>
<td style="width: 164.333px; height: 87px;">Threat detected, name: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/dev/demisto/content/TestData/EICAR.exe&lt;br&gt;threatClassification: Malware&lt;br&gt;threatClassificationSource: Cloud&lt;br&gt;username: null</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:31.064568Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:31.064576Z</td>
<td style="width: 160px; height: 87px;">513516952292214236</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513516953818940898</td>
<td style="width: 164.333px; height: 87px;">The agent 164 successfully quarantined the threat: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/dev/demisto/content/TestData/EICAR.exe&lt;br&gt;threatClassification: Malware&lt;br&gt;threatClassificationSource: Cloud</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:31.236769Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:26:31.236777Z</td>
<td style="width: 160px; height: 87px;">513516952292214236</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513518844460189159</td>
<td style="width: 164.333px; height: 87px;">Threat detected, name: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/Documents/GitHub/content/TestData/EICAR.exe&lt;br&gt;threatClassification: Malware&lt;br&gt;threatClassificationSource: Cloud&lt;br&gt;username: null</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:30:16.619423Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:30:16.619432Z</td>
<td style="width: 160px; height: 87px;">513518844384691684</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513518845877863914</td>
<td style="width: 164.333px; height: 87px;">The agent 164 successfully quarantined the threat: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/Documents/GitHub/content/TestData/EICAR.exe&lt;br&gt;threatClassification: Malware&lt;br&gt;threatClassificationSource: Cloud</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:30:16.788059Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:30:16.788068Z</td>
<td style="width: 160px; height: 87px;">513518844384691684</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513519504073213420</td>
<td style="width: 164.333px; height: 87px;">Agent 164 completed full disk scan at Mon, 10 Dec 2018, 12:31:35 UTC.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;createdAt: 2018-12-10T12:31:35.248610Z&lt;br&gt;status: finished</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:31:35.251320Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:31:35.251329Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513526418156865040</td>
<td style="width: 164.333px; height: 109px;">Threat detected, name: eicar.com.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/eicar.com.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine&lt;br&gt;username: null</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:45:19.474330Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:45:19.474339Z</td>
<td style="width: 160px; height: 109px;">513526418089756174</td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513526419608094227</td>
<td style="width: 164.333px; height: 109px;">The agent 164 successfully quarantined the threat: eicar.com.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/eicar.com.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:45:19.647311Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:45:19.647320Z</td>
<td style="width: 160px; height: 109px;">513526418089756174</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513526832864478743</td>
<td style="width: 164.333px; height: 87px;">Threat detected, name: eicar.com.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com&lt;br&gt;filePath: /Users/yardensade/Downloads/eicar.com&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine&lt;br&gt;username: null</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:46:08.910923Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:46:08.910934Z</td>
<td style="width: 160px; height: 87px;">513526832755426837</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">513526834374428187</td>
<td style="width: 164.333px; height: 87px;">The agent 164 successfully quarantined the threat: eicar.com.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com&lt;br&gt;filePath: /Users/yardensade/Downloads/eicar.com&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-10T12:46:09.091186Z</td>
<td style="width: 160px; height: 87px;">2018-12-10T12:46:09.091198Z</td>
<td style="width: 160px; height: 87px;">513526832755426837</td>
</tr>
<tr style="height: 81.7813px;">
<td style="width: 161.667px; height: 81.7813px;">513526971268122141</td>
<td style="width: 164.333px; height: 81.7813px;">The agent 164 successfully quarantined the threat: eicar.com.</td>
<td style="width: 658px; height: 81.7813px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com&lt;br&gt;filePath: /Users/yardensade/Downloads/eicar.com&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 81.7813px;"> </td>
<td style="width: 160px; height: 81.7813px;">2018-12-10T12:46:25.410353Z</td>
<td style="width: 160px; height: 81.7813px;">2018-12-10T12:46:25.410362Z</td>
<td style="width: 160px; height: 81.7813px;">513526832755426837</td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513528784247637538</td>
<td style="width: 164.333px; height: 109px;">The agent 164 successfully quarantined the threat: eicar.com.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: eicar.com.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/eicar.com.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:50:01.534321Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:50:01.534329Z</td>
<td style="width: 160px; height: 109px;">513526418089756174</td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513529274402391589</td>
<td style="width: 164.333px; height: 109px;">Threat detected, name: totally_not_a_virus.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: totally_not_a_virus.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/totally_not_a_virus.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine&lt;br&gt;username: null</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:50:59.965541Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:50:59.965549Z</td>
<td style="width: 160px; height: 109px;">513529274335282723</td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513529275895563816</td>
<td style="width: 164.333px; height: 109px;">The agent 164 successfully quarantined the threat: totally_not_a_virus.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: totally_not_a_virus.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/totally_not_a_virus.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:51:00.143461Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:51:00.143471Z</td>
<td style="width: 160px; height: 109px;">513529274335282723</td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513529459253757483</td>
<td style="width: 164.333px; height: 109px;">The agent 164 successfully quarantined the threat: totally_not_a_virus.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: totally_not_a_virus.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/totally_not_a_virus.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:51:22.000526Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:51:22.000536Z</td>
<td style="width: 160px; height: 109px;">513529274335282723</td>
</tr>
<tr style="height: 109px;">
<td style="width: 161.667px; height: 109px;">513533152942409262</td>
<td style="width: 164.333px; height: 109px;">The agent 164 successfully quarantined the threat: totally_not_a_virus.txt.</td>
<td style="width: 658px; height: 109px;">computerName: 164&lt;br&gt;fileContentHash: 3395856ce81f2b7382dee72602f798b642f14140&lt;br&gt;fileDisplayName: totally_not_a_virus.txt&lt;br&gt;filePath: /Users/yardensade/Downloads/totally_not_a_virus.txt&lt;br&gt;threatClassification: OSX.Malware&lt;br&gt;threatClassificationSource: Engine</td>
<td style="width: 160px; height: 109px;"> </td>
<td style="width: 160px; height: 109px;">2018-12-10T12:58:42.323491Z</td>
<td style="width: 160px; height: 109px;">2018-12-10T12:58:42.323499Z</td>
<td style="width: 160px; height: 109px;">513529274335282723</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">514190868824249980</td>
<td style="width: 164.333px; height: 87px;">The agent 164 failed to quarantine the threat: EICAR.exe.</td>
<td style="width: 658px; height: 87px;">computerName: 164&lt;br&gt;fileContentHash: cf8bd9dfddff007f75adf4c2be48005cea317c62&lt;br&gt;fileDisplayName: EICAR.exe&lt;br&gt;filePath: /Users/yardensade/dev/demisto/content/TestData/EICAR.exe&lt;br&gt;threatClassification: Malware&lt;br&gt;threatClassificationSource: Cloud</td>
<td style="width: 160px; height: 87px;"> </td>
<td style="width: 160px; height: 87px;">2018-12-11T10:45:28.166449Z</td>
<td style="width: 160px; height: 87px;">2018-12-11T10:45:28.166458Z</td>
<td style="width: 160px; height: 87px;">513516952292214236</td>
</tr>
<tr style="height: 87px;">
<td style="width: 161.667px; height: 87px;">514803118157132740</td>
<td style="width: 164.333px; height: 87px;">The management user Jane Doe logged into the management console.</td>
<td style="width: 658px; height: 87px;">role: admin&lt;br&gt;source: mgmt&lt;br&gt;username: Jane Doe</td>
<td style="width: 160px; height: 87px;">475482955872052394</td>
<td style="width: 160px; height: 87px;">2018-12-12T07:01:53.974154Z</td>
<td style="width: 160px; height: 87px;">2018-12-12T07:01:53.974164Z</td>
<td style="width: 160px; height: 87px;"> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_0bcee322-ce58-4884-8f3c-026a45a0f8f3" class="code-line" data-line-start="2424" data-line-end="2425">
<a id="15_sentinelonegetgroups_2424"></a>15. Get group data</h3>
<hr>
<p>Gets data for the specified group.</p>
<h5 class="code-line" data-line-start="2429" data-line-end="2430">
<a id="Base_Command_2429"></a>Base Command</h5>
<p><code>sentinelone-get-groups</code></p>
<h5 class="code-line" data-line-start="2432" data-line-end="2433">
<a id="Input_2432"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 95px;"><strong>Argument Name</strong></th>
<th style="width: 574px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 95px;">group_type</td>
<td style="width: 574px;">Group type, for example: “static”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">group_ids</td>
<td style="width: 574px;">CSV list of group IDs by which to filter, for example: “225494730938493804,225494730938493915”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">group_id</td>
<td style="width: 574px;">Group ID by which to filter, for example: “225494730938493804”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">is_default</td>
<td style="width: 574px;">Whether this is the default group.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">name</td>
<td style="width: 574px;">The name of the group.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">query</td>
<td style="width: 574px;">Free-text search on fields name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">rank</td>
<td style="width: 574px;">The rank sets the priority of a dynamic group over others, for example, “1”, which is the highest priority.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 95px;">limit</td>
<td style="width: 574px;">Maximum number of items to return (1-200).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2446" data-line-end="2447">
<a id="Context_Output_2446"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 215.333px;"><strong>Path</strong></th>
<th style="width: 58.6667px;"><strong>Type</strong></th>
<th style="width: 466px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.siteId</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">The ID of the site of which this group is a member.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.filterName</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">If the group is dynamic, the name of the filter which is used to associate agents.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.creatorId</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">The ID of the user that created the group.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.name</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.creator</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">The user that created the group.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.rank</td>
<td style="width: 58.6667px;">Number</td>
<td style="width: 466px;">The rank, which sets the priority of a dynamic group over others.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.updatedAt</td>
<td style="width: 58.6667px;">Date</td>
<td style="width: 466px;">Timestamp of the last update.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.totalAgents</td>
<td style="width: 58.6667px;">Number</td>
<td style="width: 466px;">Number of agents in the group.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.filterId</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">If the group is dynamic, the group ID of the filter that is used to associate agents.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.isDefault</td>
<td style="width: 58.6667px;">Boolean</td>
<td style="width: 466px;">Whether the groups is the default group of the site.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.inherits</td>
<td style="width: 58.6667px;">Boolean</td>
<td style="width: 466px;">Whether the policy is inherited from a site. “False” if the group has its own edited policy.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.type</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">Group type. Can be static or dynamic</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.id</td>
<td style="width: 58.6667px;">String</td>
<td style="width: 466px;">The ID of the group.</td>
</tr>
<tr>
<td style="width: 215.333px;">SentinelOne.Group.createdAt</td>
<td style="width: 58.6667px;">Date</td>
<td style="width: 466px;">Timestamp of group creation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2466" data-line-end="2467">
<a id="Command_Example_2466"></a>Command Example</h5>
<pre>!sentinelone-get-groups</pre>
<h5 class="code-line" data-line-start="2469" data-line-end="2470">
<a id="Context_Example_2469"></a>Context Example</h5>
<pre>{
    "SentinelOne.Group": [
        {
            "inherits": true, 
            "name": "Default Group", 
            "creator": "John Roe", 
            "filterName": null, 
            "updatedAt": "2019-07-25T07:23:58.622476Z", 
            "filterId": null, 
            "rank": null, 
            "registrationToken": "eyJ1cmwiOiAiaHR0cHM6Ly91c2VhMS1wYXJ0bmVycy5zZW50aW5lbG9uZS5uZXQiLCAic2l0ZV9rZXkiOiAiZ184NjJiYWQzNTIwN2ZmNTJmIn0=", 
            "siteId": "475482421366727779", 
            "isDefault": true, 
            "creatorId": "433273625970238486", 
            "totalAgents": 5, 
            "type": "static", 
            "id": "475482421375116388", 
            "createdAt": "2018-10-19T00:58:41.646045Z"
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2494" data-line-end="2495">
<a id="Human_Readable_Output_2494"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2495" data-line-end="2496">
<a id="Sentinel_One_Groups_2495"></a>Sentinel One Groups</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>Type</th>
<th>Creator</th>
<th>Creator ID</th>
<th>Created at</th>
</tr>
</thead>
<tbody>
<tr>
<td>475482421375116388</td>
<td>Default Group</td>
<td>static</td>
<td>John Roe</td>
<td>433273625970238486</td>
<td>2018-10-19T00:58:41.646045Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_e5eee9ec-5047-4388-a345-df9a434f34fe" class="code-line" data-line-start="2501" data-line-end="2502">
<a id="16_sentinelonemoveagent_2501"></a>16. Move agent</h3>
<hr>
<p>Moves agents to a new group.</p>
<h5 class="code-line" data-line-start="2506" data-line-end="2507">
<a id="Base_Command_2506"></a>Base Command</h5>
<p><code>sentinelone-move-agent</code></p>
<h5 class="code-line" data-line-start="2509" data-line-end="2510">
<a id="Input_2509"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 187px;"><strong>Argument Name</strong></th>
<th style="width: 446px;"><strong>Description</strong></th>
<th style="width: 107px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">group_id</td>
<td style="width: 446px;">The ID of the group to move the agent to.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 187px;">agents_ids</td>
<td style="width: 446px;">Agents IDs.</td>
<td style="width: 107px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2517" data-line-end="2518">
<a id="Context_Output_2517"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 240px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 436px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 240px;">SentinelOne.Agent.AgentsMoved</td>
<td style="width: 64px;">Number</td>
<td style="width: 436px;">The number of agents that were moved to another group.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_890e6bba-fb17-4027-9db9-0a5468a7b642" class="code-line" data-line-start="2530" data-line-end="2531">
<a id="17_sentinelonedeletegroup_2530"></a>17. Delete a group</h3>
<hr>
<p>Deletes a group by the group ID.</p>
<h5 class="code-line" data-line-start="2535" data-line-end="2536">
<a id="Base_Command_2535"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2506" data-line-end="2507"><code>sentinelone-delete-group</code></h5>
<h5 class="code-line" data-line-start="2538" data-line-end="2539">
<a id="Input_2538"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 230.667px;"><strong>Argument Name</strong></th>
<th style="width: 380.333px;"><strong>Description</strong></th>
<th style="width: 130px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230.667px;">group_id</td>
<td style="width: 380.333px;">The ID of the group to delete.</td>
<td style="width: 130px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2545" data-line-end="2546">
<a id="Context_Output_2545"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2547" data-line-end="2548">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2549" data-line-end="2550">
<a id="Command_Example_2549"></a>Command Example</h5>
<pre>!sentinelone-delete-group group_id=661564034148420567</pre>
<h5 class="code-line" data-line-start="2552" data-line-end="2553">
<a id="Human_Readable_Output_2552"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2553" data-line-end="2554">
<a id="The_group_was_deleted_successfully_2553"></a>The group was deleted successfully</h3>
<p> </p>
<h3 id="h_b6361197-f4b1-4477-95b4-1cc5654d0f74" class="code-line" data-line-start="2555" data-line-end="2556">
<a id="18_sentineloneagentprocesses_2555"></a>18. Retrieve agent processes</h3>
<hr>
<p class="has-line-data" data-line-start="2557" data-line-end="2558">Retrieves running processes for a specific agent.</p>
<h5 class="code-line" data-line-start="2560" data-line-end="2561">
<a id="Base_Command_2560"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2560" data-line-end="2561"><code>sentinelone-agent-processes</code></h5>
<h5 class="code-line" data-line-start="2563" data-line-end="2564">
<a id="Input_2563"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">agents_ids</td>
<td style="width: 499px;">The ID of the agent from which to retrieve the processes.</td>
<td style="width: 88px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2570" data-line-end="2571">
<a id="Context_Output_2570"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 369px;"><strong>Path</strong></th>
<th style="width: 93px;"><strong>Type</strong></th>
<th style="width: 278px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 369px;">SentinelOne.Agent.memoryUsage</td>
<td style="width: 93px;">Number</td>
<td style="width: 278px;">Memory usage (MB).</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Agent.startTime</td>
<td style="width: 93px;">Date</td>
<td style="width: 278px;">The process start time.</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Agent.pid</td>
<td style="width: 93px;">Number</td>
<td style="width: 278px;">The process ID.</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Agent.processName</td>
<td style="width: 93px;">String</td>
<td style="width: 278px;">The name of the process.</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Agent.cpuUsage</td>
<td style="width: 93px;">Number</td>
<td style="width: 278px;">CPU usage (%).</td>
</tr>
<tr>
<td style="width: 369px;">SentinelOne.Agent.executablePath</td>
<td style="width: 93px;">String</td>
<td style="width: 278px;">Executable path.</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_62b6458d-750a-4457-9ea3-4cd6cfd566c1" class="code-line" data-line-start="2588" data-line-end="2589">
<a id="19_sentineloneconnectagent_2588"></a>19. Connect an agent</h3>
<hr>
<p>Connects agents to a network.</p>
<h5 class="code-line" data-line-start="2593" data-line-end="2594">
<a id="Base_Command_2593"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2560" data-line-end="2561"><code>sentinelone-connect-agent</code></h5>
<h5 class="code-line" data-line-start="2596" data-line-end="2597">
<a id="Input_2596"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 95px;"><strong>Argument Name</strong></th>
<th style="width: 574px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 95px;">agent_id</td>
<td style="width: 574px;">A CSV list of agent IDs to connect to the network. Run the list-agents command to get a list of agent IDs.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2603" data-line-end="2604">
<a id="Context_Output_2603"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 340.667px;"><strong>Path</strong></th>
<th style="width: 83.3333px;"><strong>Type</strong></th>
<th style="width: 317px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 340.667px;">SentinelOne.Agent.AgentsAffected</td>
<td style="width: 83.3333px;">Number</td>
<td style="width: 317px;">The number of affected agents.</td>
</tr>
<tr>
<td style="width: 340.667px;">SentinelOne.Agent.ID</td>
<td style="width: 83.3333px;">String</td>
<td style="width: 317px;">The IDs of the affected agents.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2611" data-line-end="2612">
<a id="Command_Example_2611"></a>Command Example</h5>
<pre>!sentinelone-connect-agent agent_id=657738871640371668</pre>
<h5 class="code-line" data-line-start="2614" data-line-end="2615">
<a id="Context_Example_2614"></a>Context Example</h5>
<pre>{
    "SentinelOne.Agent": {
        "ID": "657738871640371668", 
        "NetworkStatus": "connecting"
    }
}
</pre>
<h5 class="code-line" data-line-start="2624" data-line-end="2625">
<a id="Human_Readable_Output_2624"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="2625" data-line-end="2626">1 agent(s) successfully connected to the network.</p>
<h3 id="h_491ad0f2-97f3-4124-8884-91eb5c84cabc" class="code-line" data-line-start="2627" data-line-end="2628">
<a id="20_sentinelonedisconnectagent_2627"></a>20. Disconnect an agent</h3>
<hr>
<p class="has-line-data" data-line-start="2629" data-line-end="2630">Disconnects an agents from a network.</p>
<h5>Base Command</h5>
<p><code>sentinelone-disconnect-agent</code></p>
<h5 class="code-line" data-line-start="2635" data-line-end="2636">
<a id="Input_2635"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 92px;"><strong>Argument Name</strong></th>
<th style="width: 577px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 92px;">agent_id</td>
<td style="width: 577px;">A CSV list of agent IDs to disconnect from the network. Run the list-agents command to get a list of agent IDs.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2642" data-line-end="2643">
<a id="Context_Output_2642"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 345px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 323px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 345px;">SentinelOne.Agent.NetworkStatus</td>
<td style="width: 72px;">String</td>
<td style="width: 323px;">Agent network status.</td>
</tr>
<tr>
<td style="width: 345px;">SentinelOne.Agent.ID</td>
<td style="width: 72px;">String</td>
<td style="width: 323px;">The IDs of the affected agents.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2650" data-line-end="2651">
<a id="Command_Example_2650"></a>Command Example</h5>
<pre>!sentinelone-disconnect-agent agent_id=657738871640371668</pre>
<h5 class="code-line" data-line-start="2653" data-line-end="2654">
<a id="Context_Example_2653"></a>Context Example</h5>
<pre>{
    "SentinelOne.Agent": {
        "ID": "657738871640371668", 
        "NetworkStatus": "connecting"
    }
}
</pre>
<h5 class="code-line" data-line-start="2663" data-line-end="2664">
<a id="Human_Readable_Output_2663"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="2664" data-line-end="2665">1 agent(s) successfully disconnected from the network.</p>
<h3 id="h_790d12ec-b824-437d-9791-6fd705f475dd" class="code-line" data-line-start="2666" data-line-end="2667">
<a id="21_sentinelonebroadcastmessage_2666"></a>21. Broadcast a message to agents</h3>
<hr>
<p class="has-line-data" data-line-start="2668" data-line-end="2669">Broadcasts a message to all agents.</p>
<h5>Base Command</h5>
<h5 class="code-line" data-line-start="2632" data-line-end="2633"><code>sentinelone-broadcast-message</code></h5>
<h5 class="code-line" data-line-start="2674" data-line-end="2675">
<a id="Input_2674"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 498px;"><strong>Description</strong></th>
<th style="width: 89px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">message</td>
<td style="width: 498px;">The Message to broadcast to agents.</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">active_agent</td>
<td style="width: 498px;">Whether to only include active agents. Default is “false”.</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">group_id</td>
<td style="width: 498px;">List of Group IDs by which to filter the results.</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">agent_id</td>
<td style="width: 498px;">A list of Agent IDs by which to filter the results.</td>
<td style="width: 89px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">domain</td>
<td style="width: 498px;">Included network domains.</td>
<td style="width: 89px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2685" data-line-end="2686">
<a id="Context_Output_2685"></a>Context Output</h5>
<p class="has-line-data" data-line-start="2687" data-line-end="2688">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="2689" data-line-end="2690">
<a id="Command_Example_2689"></a>Command Example</h5>
<pre>!sentinelone-broadcast-message message="Hello World"</pre>
<h5 class="code-line" data-line-start="2692" data-line-end="2693">
<a id="Human_Readable_Output_2692"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="2693" data-line-end="2694">The message was successfully delivered to the agent(s)</p>
<h3 id="h_e9fd7e73-2fbe-48e0-8a28-8988b597498a" class="code-line" data-line-start="2695" data-line-end="2696">
<a id="22_sentinelonegetevents_2695"></a>22. Get Deep Visibility events</h3>
<hr>
<p class="has-line-data" data-line-start="2697" data-line-end="2698">Gets all Deep Visibility events that match the query.</p>
<h5 class="code-line" data-line-start="2700" data-line-end="2701">
<a id="Base_Command_2700"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2632" data-line-end="2633"><code>sentinelone-get-events</code></h5>
<h5 class="code-line" data-line-start="2703" data-line-end="2704">
<a id="Input_2703"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 94.3333px;"><strong>Argument Name</strong></th>
<th style="width: 574.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 94.3333px;">limit</td>
<td style="width: 574.667px;">Maximum number of items to return (1-100). Default is “50”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 94.3333px;">query_id</td>
<td style="width: 574.667px;">Query ID obtained when creating a query in the sentinelone-create-query command. Example: “q1xx2xx3”.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2711" data-line-end="2712">
<a id="Context_Output_2711"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 226px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 454px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">SentinelOne.Event.ProcessUID</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">Process unique identifier.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.SHA256</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.AgentOS</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">OS type. Can be “windows”, “linux”, “macos”, or “windows_legac”.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.ProcessID</td>
<td style="width: 60px;">Number</td>
<td style="width: 454px;">The process ID.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.User</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">User assigned to the event.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.Time</td>
<td style="width: 60px;">Date</td>
<td style="width: 454px;">Process start time.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.Endpoint</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">The agent name.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.SiteName</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">Site name.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.EventType</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">Event type. Can be “events”, “file”, “ip”, “url”, “dns”, “process”, “registry”, “scheduled_task”, or “logins”.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.ProcessName</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">The name of the process.</td>
</tr>
<tr>
<td style="width: 226px;">SentinelOne.Event.MD5</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 226px;">Event.ID</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">Event process ID.</td>
</tr>
<tr>
<td style="width: 226px;">Event.Name</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">Event name.</td>
</tr>
<tr>
<td style="width: 226px;">Event.Type</td>
<td style="width: 60px;">String</td>
<td style="width: 454px;">Event type.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2731" data-line-end="2732">
<a id="Command_Example_2731"></a>Command Example</h5>
<pre>!sentinelone-get-events limit="10" query_id="q5b327f7c84162549eb1d568c968ff655"</pre>
<h5 class="code-line" data-line-start="2734" data-line-end="2735">
<a id="Context_Example_2734"></a>Context Example</h5>
<pre>{
    "Event": [
        {
            "Type": "process", 
            "ID": "5556", 
            "Name": "svchost.exe"
        }, 
        {
            "Type": "process", 
            "ID": "5432", 
            "Name": "VSSVC.exe"
        }, 
        {
            "Type": "ip", 
            "ID": "1636", 
            "Name": "amazon-ssm-agent.exe"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }, 
        {
            "Type": "file", 
            "ID": "3996", 
            "Name": "Google Chrome"
        }
    ], 
    "SentinelOne.Event": [
        {
            "ProcessID": "5556", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "process", 
            "ProcessUID": "10EEF25AF81502CD", 
            "ProcessName": "svchost.exe", 
            "User": null, 
            "Time": "2019-08-04T04:48:36.440Z", 
            "SHA256": "438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7", 
            "AgentOS": "windows", 
            "MD5": "36f670d89040709013f6a460176767ec"
        }, 
        {
            "ProcessID": "5432", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "process", 
            "ProcessUID": "DAB10F03FC995CCA", 
            "ProcessName": "VSSVC.exe", 
            "User": null, 
            "Time": "2019-08-04T04:48:26.439Z", 
            "SHA256": "29c18ccdb5077ee158ee591e2226f2c95d27a0f26f259c16c621ecc20b499bed", 
            "AgentOS": "windows", 
            "MD5": "adf381b23416fd54d5dbb582dbb7992d"
        }, 
        {
            "ProcessID": "1636", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "ip", 
            "ProcessUID": "1525CEC635947A9A", 
            "ProcessName": "amazon-ssm-agent.exe", 
            "User": null, 
            "Time": "2019-06-27T08:01:32.077Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }, 
        {
            "ProcessID": "3996", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "EventType": "file", 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "User": null, 
            "Time": "2019-06-30T13:50:54.280Z", 
            "SHA256": null, 
            "AgentOS": "windows", 
            "MD5": null
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="2924" data-line-end="2925">
<a id="Human_Readable_Output_2924"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="2925" data-line-end="2926">
<a id="SentinelOne_Events_2925"></a>SentinelOne Events</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>EventType</th>
<th>SiteName</th>
<th>Time</th>
<th>AgentOS</th>
<th>ProcessID</th>
<th>ProcessUID</th>
<th>ProcessName</th>
<th>MD5</th>
<th>SHA256</th>
</tr>
</thead>
<tbody>
<tr>
<td>process</td>
<td>demisto</td>
<td>2019-08-04T04:48:36.440Z</td>
<td>windows</td>
<td>5556</td>
<td>10EEF25AF81502CD</td>
<td>svchost.exe</td>
<td>36f670d89040709013f6a460176767ec</td>
<td>438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7</td>
</tr>
<tr>
<td>process</td>
<td>demisto</td>
<td>2019-08-04T04:48:26.439Z</td>
<td>windows</td>
<td>5432</td>
<td>DAB10F03FC995CCA</td>
<td>VSSVC.exe</td>
<td>adf381b23416fd54d5dbb582dbb7992d</td>
<td>29c18ccdb5077ee158ee591e2226f2c95d27a0f26f259c16c621ecc20b499bed</td>
</tr>
<tr>
<td>ip</td>
<td>demisto</td>
<td>2019-06-27T08:01:32.077Z</td>
<td>windows</td>
<td>1636</td>
<td>1525CEC635947A9A</td>
<td>amazon-ssm-agent.exe</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td>windows</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7c988327-ccd8-4f2c-a296-097259bf4473" class="code-line" data-line-start="2940" data-line-end="2941">
<a id="23_sentinelonecreatequery_2940"></a>23. Create a Deep Visibility query</h3>
<hr>
<p class="has-line-data" data-line-start="2942" data-line-end="2943">Runs a Deep Visibility Query and returns the query ID. You can use the query ID for all other commands, such as the sentinelone-get-events command.</p>
<h5 class="code-line" data-line-start="2945" data-line-end="2946">
<a id="Base_Command_2945"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2632" data-line-end="2633"><code>sentinelone-create-query</code></h5>
<h5 class="code-line" data-line-start="2948" data-line-end="2949">
<a id="Input_2948"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">query</td>
<td style="width: 518px;">The query string for which to return events.</td>
<td style="width: 80px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">from_date</td>
<td style="width: 518px;">Query start date, for example, “2019-08-03T04:49:26.257525Z”.</td>
<td style="width: 80px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">to_date</td>
<td style="width: 518px;">Query end date, for example, “2019-08-03T04:49:26.257525Z”.</td>
<td style="width: 80px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2957" data-line-end="2958">
<a id="Context_Output_2957"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 358px;"><strong>Path</strong></th>
<th style="width: 79px;"><strong>Type</strong></th>
<th style="width: 304px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 358px;">SentinelOne.Query.FromDate</td>
<td style="width: 79px;">Date</td>
<td style="width: 304px;">Query start date.</td>
</tr>
<tr>
<td style="width: 358px;">SentinelOne.Query.Query</td>
<td style="width: 79px;">String</td>
<td style="width: 304px;">The search query string.</td>
</tr>
<tr>
<td style="width: 358px;">SentinelOne.Query.QueryID</td>
<td style="width: 79px;">String</td>
<td style="width: 304px;">The query ID.</td>
</tr>
<tr>
<td style="width: 358px;">SentinelOne.Query.ToDate</td>
<td style="width: 79px;">Date</td>
<td style="width: 304px;">Query end date.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2967" data-line-end="2968">
<a id="Command_Example_2967"></a>Command Example</h5>
<pre>!sentinelone-create-query query="AgentName Is Not Empty" from_date="2019-08-02T04:49:26.257525Z" to_date="2019-08-04T04:49:26.257525Z"</pre>
<h3 id="h_837965e2-5e05-4b58-b192-b25e0707c6c0" class="code-line" data-line-start="2973" data-line-end="2974">
<a id="24_sentinelonegetprocesses_2973"></a>24. Get a list of Deep Visibility events by process</h3>
<hr>
<p class="has-line-data" data-line-start="2975" data-line-end="2976">Gets a list of Deep Visibility events from query by event type process.</p>
<h5 class="code-line" data-line-start="2978" data-line-end="2979">
<a id="Base_Command_2978"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2632" data-line-end="2633"><code>sentinelone-get-processes</code></h5>
<h5 class="code-line" data-line-start="2981" data-line-end="2982">
<a id="Input_2981"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 78.3333px;"><strong>Argument Name</strong></th>
<th style="width: 589.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 78.3333px;">query_id</td>
<td style="width: 589.667px;">The queryId that is returned when creating a query under Create Query. Example: “q1xx2xx3”. Get the query_id from the “get-query-id” command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 78.3333px;">limit</td>
<td style="width: 589.667px;">Maximum number of items to return (1-100). Default is “50”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="2989" data-line-end="2990">
<a id="Context_Output_2989"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>SentinelOne.Event.ParentProcessID</td>
<td>Number</td>
<td>Parent process ID.</td>
</tr>
<tr>
<td>SentinelOne.Event.ProcessUID</td>
<td>String</td>
<td>The process unique identifier.</td>
</tr>
<tr>
<td>SentinelOne.Event.SHA1</td>
<td>String</td>
<td>SHA1 hash of the process image.</td>
</tr>
<tr>
<td>SentinelOne.Event.SubsystemType</td>
<td>String</td>
<td>Process sub-system.</td>
</tr>
<tr>
<td>SentinelOne.Event.ParentProcessStartTime</td>
<td>Date</td>
<td>The parent process start time.</td>
</tr>
<tr>
<td>SentinelOne.Event.ProcessID</td>
<td>Number</td>
<td>The process ID.</td>
</tr>
<tr>
<td>SentinelOne.Event.ParentProcessUID</td>
<td>String</td>
<td>Parent process unique identifier.</td>
</tr>
<tr>
<td>SentinelOne.Event.User</td>
<td>String</td>
<td>User assigned to the event.</td>
</tr>
<tr>
<td>SentinelOne.Event.Time</td>
<td>Date</td>
<td>Start time of the process.</td>
</tr>
<tr>
<td>SentinelOne.Event.ParentProcessName</td>
<td>String</td>
<td>Parent process name.</td>
</tr>
<tr>
<td>SentinelOne.Event.SiteName</td>
<td>String</td>
<td>Site name.</td>
</tr>
<tr>
<td>SentinelOne.Event.EventType</td>
<td>String</td>
<td>The event type.</td>
</tr>
<tr>
<td>SentinelOne.Event.Endpoint</td>
<td>String</td>
<td>The agent name (endpoint).</td>
</tr>
<tr>
<td>SentinelOne.Event.IntegrityLevel</td>
<td>String</td>
<td>Process integrity level.</td>
</tr>
<tr>
<td>SentinelOne.Event.CMD</td>
<td>String</td>
<td>Process CMD.</td>
</tr>
<tr>
<td>SentinelOne.Event.ProcessName</td>
<td>String</td>
<td>Process name.</td>
</tr>
<tr>
<td>SentinelOne.Event.ProcessDisplayName</td>
<td>String</td>
<td>Process display name.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="3012" data-line-end="3013">
<a id="Command_Example_3012"></a>Command Example</h5>
<p><code>!sentinelone-get-processes query_id="q5b327f7c84162549eb1d568c968ff655"</code></p>
<h5 class="code-line" data-line-start="3015" data-line-end="3016">
<a id="Context_Example_3015"></a>Context Example</h5>
<pre>{
    "SentinelOne.Event": [
        {
            "ProcessID": "5556", 
            "Time": "2019-08-04T04:48:36.440Z", 
            "CMD": null, 
            "ParentProcessStartTime": "2019-06-27T08:01:30.957Z", 
            "SHA1": "0dac68816ae7c09efc24d11c27c3274dfd147dee", 
            "ParentProcessID": "560", 
            "ProcessDisplayName": "Host Process for Windows Services", 
            "EventType": "process", 
            "ParentProcessName": "Services and Controller app", 
            "SubsystemType": "SYS_WIN32", 
            "ProcessUID": "10EEF25AF81502CD", 
            "ProcessName": "svchost.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "CFEE347DA897CF4C", 
            "IntegrityLevel": "SYSTEM"
        }, 
        {
            "ProcessID": "5432", 
            "Time": "2019-08-04T04:48:26.439Z", 
            "CMD": null, 
            "ParentProcessStartTime": "2019-06-27T08:01:30.957Z", 
            "SHA1": "cd5e7c15e7688d40d51d32b8286c2e1804a97349", 
            "ParentProcessID": "560", 
            "ProcessDisplayName": "Microsoft\u00ae Volume Shadow Copy Service", 
            "EventType": "process", 
            "ParentProcessName": "Services and Controller app", 
            "SubsystemType": "SYS_WIN32", 
            "ProcessUID": "DAB10F03FC995CCA", 
            "ProcessName": "VSSVC.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "CFEE347DA897CF4C", 
            "IntegrityLevel": "SYSTEM"
        }, 
        {
            "ProcessID": "1636", 
            "Time": "2019-06-27T08:01:32.077Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "ip", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "1525CEC635947A9A", 
            "ProcessName": "amazon-ssm-agent.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "1525CEC635947A9A", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "dns", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3840", 
            "Time": "2019-08-04T04:17:52.041Z", 
            "CMD": null, 
            "ParentProcessStartTime": "2019-06-30T13:50:54.280Z", 
            "SHA1": "03ffc95e7d54a40b7fd42aba048248f64026ae24", 
            "ParentProcessID": "3996", 
            "ProcessDisplayName": "Google Chrome", 
            "EventType": "process", 
            "ParentProcessName": "Google Chrome", 
            "SubsystemType": "SYS_WIN32", 
            "ProcessUID": "73CBEE7BFDEA4128", 
            "ProcessName": "chrome.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": "LOW"
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "dns", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3996", 
            "Time": "2019-06-30T13:50:54.280Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "file", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "84FEED6A0CB9C211", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "84FEED6A0CB9C211", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3872", 
            "Time": "2019-06-30T13:50:55.249Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "dns", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "25C25C96C5DED63C", 
            "ProcessName": "Google Chrome", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "25C25C96C5DED63C", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "3308", 
            "Time": "2019-06-27T08:04:32.183Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "scheduled_task", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "C4CBCB781DAA7B5F", 
            "ProcessName": "Windows Problem Reporting", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "C4CBCB781DAA7B5F", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "2508", 
            "Time": "2019-08-04T04:12:38.608Z", 
            "CMD": null, 
            "ParentProcessStartTime": "2019-06-27T08:01:31.423Z", 
            "SHA1": "f5cf72933752e92e5c41d1f6683a7c0863450670", 
            "ParentProcessID": "872", 
            "ProcessDisplayName": "Windows Problem Reporting", 
            "EventType": "process", 
            "ParentProcessName": "Host Process for Windows Services", 
            "SubsystemType": "SYS_WIN32", 
            "ProcessUID": "B25C1F9FCC7A718B", 
            "ProcessName": "wermgr.exe", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "6DCFCCC56860944F", 
            "IntegrityLevel": "SYSTEM"
        }, 
        {
            "ProcessID": "3308", 
            "Time": "2019-06-27T08:04:32.183Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "scheduled_task", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "C4CBCB781DAA7B5F", 
            "ProcessName": "Windows Problem Reporting", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "C4CBCB781DAA7B5F", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "4624", 
            "Time": "2019-08-04T04:09:34.054Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "dns", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "55F0E146874E0114", 
            "ProcessName": "Google Installer", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "55F0E146874E0114", 
            "IntegrityLevel": null
        }, 
        {
            "ProcessID": "4624", 
            "Time": "2019-08-04T04:09:34.054Z", 
            "CMD": null, 
            "ParentProcessStartTime": null, 
            "SHA1": null, 
            "ParentProcessID": null, 
            "ProcessDisplayName": null, 
            "EventType": "ip", 
            "ParentProcessName": null, 
            "SubsystemType": null, 
            "ProcessUID": "55F0E146874E0114", 
            "ProcessName": "Google Installer", 
            "Endpoint": "EC2AMAZ-AJ0KANC", 
            "SiteName": "demisto", 
            "User": null, 
            "ParentProcessUID": "55F0E146874E0114", 
            "IntegrityLevel": null
        }
    ]
}
</pre>
<h5 class="code-line" data-line-start="3973" data-line-end="3974">
<a id="Human_Readable_Output_3973"></a>Human Readable Output</h5>
<h3 class="code-line" data-line-start="3974" data-line-end="3975">
<a id="SentinelOne_Processes_3974"></a>SentinelOne Processes</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>EventType</th>
<th>SiteName</th>
<th>Time</th>
<th>ParentProcessID</th>
<th>ParentProcessUID</th>
<th>ProcessName</th>
<th>ParentProcessName</th>
<th>ProcessDisplayName</th>
<th>ProcessID</th>
<th>ProcessUID</th>
<th>SHA1</th>
<th>SubsystemType</th>
<th>IntegrityLevel</th>
<th>ParentProcessStartTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>process</td>
<td>demisto</td>
<td>2019-08-04T04:48:36.440Z</td>
<td>560</td>
<td>CFEE347DA897CF4C</td>
<td>svchost.exe</td>
<td>Services and Controller app</td>
<td>Host Process for Windows Services</td>
<td>5556</td>
<td>10EEF25AF81502CD</td>
<td>0dac68816ae7c09efc24d11c27c3274dfd147dee</td>
<td>SYS_WIN32</td>
<td>SYSTEM</td>
<td>2019-06-27T08:01:30.957Z</td>
</tr>
<tr>
<td>process</td>
<td>demisto</td>
<td>2019-08-04T04:48:26.439Z</td>
<td>560</td>
<td>CFEE347DA897CF4C</td>
<td>VSSVC.exe</td>
<td>Services and Controller app</td>
<td>Microsoft® Volume Shadow Copy Service</td>
<td>5432</td>
<td>DAB10F03FC995CCA</td>
<td>cd5e7c15e7688d40d51d32b8286c2e1804a97349</td>
<td>SYS_WIN32</td>
<td>SYSTEM</td>
<td>2019-06-27T08:01:30.957Z</td>
</tr>
<tr>
<td>ip</td>
<td>demisto</td>
<td>2019-06-27T08:01:32.077Z</td>
<td> </td>
<td>1525CEC635947A9A</td>
<td>amazon-ssm-agent.exe</td>
<td> </td>
<td> </td>
<td>1636</td>
<td>1525CEC635947A9A</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>dns</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>process</td>
<td>demisto</td>
<td>2019-08-04T04:17:52.041Z</td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td>chrome.exe</td>
<td>Google Chrome</td>
<td>Google Chrome</td>
<td>3840</td>
<td>73CBEE7BFDEA4128</td>
<td>03ffc95e7d54a40b7fd42aba048248f64026ae24</td>
<td>SYS_WIN32</td>
<td>LOW</td>
<td>2019-06-30T13:50:54.280Z</td>
</tr>
<tr>
<td>dns</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>file</td>
<td>demisto</td>
<td>2019-06-30T13:50:54.280Z</td>
<td> </td>
<td>84FEED6A0CB9C211</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3996</td>
<td>84FEED6A0CB9C211</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>dns</td>
<td>demisto</td>
<td>2019-06-30T13:50:55.249Z</td>
<td> </td>
<td>25C25C96C5DED63C</td>
<td>Google Chrome</td>
<td> </td>
<td> </td>
<td>3872</td>
<td>25C25C96C5DED63C</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>scheduled_task</td>
<td>demisto</td>
<td>2019-06-27T08:04:32.183Z</td>
<td> </td>
<td>C4CBCB781DAA7B5F</td>
<td>Windows Problem Reporting</td>
<td> </td>
<td> </td>
<td>3308</td>
<td>C4CBCB781DAA7B5F</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>process</td>
<td>demisto</td>
<td>2019-08-04T04:12:38.608Z</td>
<td>872</td>
<td>6DCFCCC56860944F</td>
<td>wermgr.exe</td>
<td>Host Process for Windows Services</td>
<td>Windows Problem Reporting</td>
<td>2508</td>
<td>B25C1F9FCC7A718B</td>
<td>f5cf72933752e92e5c41d1f6683a7c0863450670</td>
<td>SYS_WIN32</td>
<td>SYSTEM</td>
<td>2019-06-27T08:01:31.423Z</td>
</tr>
<tr>
<td>scheduled_task</td>
<td>demisto</td>
<td>2019-06-27T08:04:32.183Z</td>
<td> </td>
<td>C4CBCB781DAA7B5F</td>
<td>Windows Problem Reporting</td>
<td> </td>
<td> </td>
<td>3308</td>
<td>C4CBCB781DAA7B5F</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>dns</td>
<td>demisto</td>
<td>2019-08-04T04:09:34.054Z</td>
<td> </td>
<td>55F0E146874E0114</td>
<td>Google Installer</td>
<td> </td>
<td> </td>
<td>4624</td>
<td>55F0E146874E0114</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
<tr>
<td>ip</td>
<td>demisto</td>
<td>2019-08-04T04:09:34.054Z</td>
<td> </td>
<td>55F0E146874E0114</td>
<td>Google Installer</td>
<td> </td>
<td> </td>
<td>4624</td>
<td>55F0E146874E0114</td>
<td> </td>
<td> </td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_3172f88b-fc56-48e7-873d-393e69b11851" class="code-line" data-line-start="4029" data-line-end="4030">
<a id="25_sentineloneshutdownagent_4029"></a>25. Shutdown agent</h3>
<hr>
<p class="has-line-data" data-line-start="4031" data-line-end="4032">Shutdowns an agent by agent ID.</p>
<h5 class="code-line" data-line-start="4034" data-line-end="4035">
<a id="Base_Command_4034"></a>Base Command</h5>
<h5 class="code-line" data-line-start="2632" data-line-end="2633"><code>sentinelone-shutdown-agent</code></h5>
<h5 class="code-line" data-line-start="4037" data-line-end="4038">
<a id="Input_4037"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 76.3333px;"><strong>Argument Name</strong></th>
<th style="width: 592.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 76.3333px;">query</td>
<td style="width: 592.667px;">A free-text search term, will match applicable attributes (sub-string match). Note: A device’s physical addresses will only be matched if they start with the search term (not if they contain the search term).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 76.3333px;">agent_id</td>
<td style="width: 592.667px;">A CSV list of agents IDs to shutdown.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 76.3333px;">group_id</td>
<td style="width: 592.667px;">The ID of the network group.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="4046" data-line-end="4047">
<a id="Context_Output_4046"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 234px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 437px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 234px;">SentinelOne.Agent.ID</td>
<td style="width: 69px;">String</td>
<td style="width: 437px;">The ID of the agent that was shutdown.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="4053" data-line-end="4054">
<a id="Command_Example_4053"></a>Command Example</h5>
<pre>!sentinelone-shutdown-agent agent_id=685993599964815937</pre>
<h5 class="code-line" data-line-start="4056" data-line-end="4057">
<a id="Human_Readable_Output_4056"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="4057" data-line-end="4058">Shutting down 1 agent(s).</p>
<h3 id="h_72b83efd-8abc-48b4-897e-216cfe7d178e" class="code-line" data-line-start="4059" data-line-end="4060">
<a id="26_sentineloneuninstallagent_4059"></a>26. Uninstall an agent</h3>
<hr>
<p class="has-line-data" data-line-start="4061" data-line-end="4062">Uninstalls agent by agent ID.</p>
<h5 class="code-line" data-line-start="4064" data-line-end="4065">
<a id="Base_Command_4064"></a>Base Command</h5>
<h5 class="code-line" data-line-start="4062" data-line-end="4063"><code>sentinelone-uninstall-agent</code></h5>
<h5 class="code-line" data-line-start="4067" data-line-end="4068">
<a id="Input_4067"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 74.3333px;"><strong>Argument Name</strong></th>
<th style="width: 594.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 74.3333px;">query</td>
<td style="width: 594.667px;">A free-text search term, will match applicable attributes (sub-string match). Note: A device’s physical addresses will only be matched if they start with the search term (not if they contain the search term).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 74.3333px;">agent_id</td>
<td style="width: 594.667px;">A CSV list of agents IDs to shutdown.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 74.3333px;">group_id</td>
<td style="width: 594.667px;">The ID of the network group.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5 class="code-line" data-line-start="4076" data-line-end="4077">
<a id="Context_Output_4076"></a>Context Output</h5>
<p class="has-line-data" data-line-start="4078" data-line-end="4079">There is no context output for this command.</p>
<h5 class="code-line" data-line-start="4080" data-line-end="4081">
<a id="Command_Example_4080"></a>Command Example</h5>
<pre>!sentinelone-uninstall-agent agent_id=685993599964815937</pre>
<h5 class="code-line" data-line-start="4083" data-line-end="4084">
<a id="Human_Readable_Output_4083"></a>Human Readable Output</h5>
<p class="has-line-data" data-line-start="4084" data-line-end="4085">Uninstall was sent to 1 agent(s).</p>