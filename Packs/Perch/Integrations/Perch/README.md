<!-- HTML_DOC -->
<p>Use the Perch integration to manage alerts, indicators, and communities.</p>
<p>This integration was integrated and tested with the latest version of Perch.</p>
<h2>
<a id="Configure_Perch_on_Demisto_5"></a>Configure Perch on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Perch.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span>https://api.perch.rocks/)</strong></li>
<li><strong>API Token</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>Previous days to fetch</strong></li>
<li><strong>Credentials</strong></li>
<li><strong>Incident Soc Statuses to Fetch</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>
<a id="Commands_19"></a>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_376b5b32-fb7d-4104-9f94-95c720c2cf8a" target="_self">Search for alerts: perch-search-alerts</a></li>
<li><a href="#h_0d4a3fae-dc89-47dd-94a3-929bf3c206cc" target="_self">Get information for a community: perch-get-community</a></li>
<li><a href="#h_c446ffc2-a5c3-4e06-a3b2-3f438b554ae1" target="_self">Get a list of all communities: perch-list-communities</a></li>
<li><a href="#h_977e5e1e-1356-4ab6-a081-fc612fa29a70" target="_self">Create an indicator: perch-create-indicator</a></li>
</ol>
<h3 id="h_376b5b32-fb7d-4104-9f94-95c720c2cf8a">
<a id="1_Search_for_alerts_25"></a>1. Search for alerts</h3>
<hr>
<p>Searches for alerts in Perch.</p>
<h5>
<a id="Base_Command_28"></a>Base Command</h5>
<p><code>perch-search-alerts</code></p>
<h5>
<a id="Input_31"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 186px;"><strong>Argument Name</strong></th>
<th style="width: 452px;"><strong>Description</strong></th>
<th style="width: 102px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 186px;">page</td>
<td style="width: 452px;">Page of results to return.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">page_size</td>
<td style="width: 452px;">Number of results to return per page.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">closed</td>
<td style="width: 452px;">Whether the alert is closed.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">closed_at</td>
<td style="width: 452px;">Time that the alert was closed.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">community_id</td>
<td style="width: 452px;">Community ID that generated the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">created_at</td>
<td style="width: 452px;">Time that the alert was created.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">dest_ip</td>
<td style="width: 452px;">Destination IP address.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">dest_port</td>
<td style="width: 452px;">Destination port.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">full_url</td>
<td style="width: 452px;">Full URL of the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">id</td>
<td style="width: 452px;">ID of the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">indicator_id</td>
<td style="width: 452px;">ID of the indicator.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">indicator_loaded</td>
<td style="width: 452px;">Whether the indicator is loaded.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">observable_id</td>
<td style="width: 452px;">Observable ID.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">protocol</td>
<td style="width: 452px;">Protocol effected by the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">sensor_id</td>
<td style="width: 452px;">ID of the sensor that generated the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">sensor_name</td>
<td style="width: 452px;">Name of the sensor that generated the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">soc_status</td>
<td style="width: 452px;">Status in the SOC.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">src_ip</td>
<td style="width: 452px;">Source IP address.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">src_port</td>
<td style="width: 452px;">Source port.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">status</td>
<td style="width: 452px;">Status of the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">status_updated_at</td>
<td style="width: 452px;">Time that the status was last updated.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">team_id</td>
<td style="width: 452px;">ID of the team that generated the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">title</td>
<td style="width: 452px;">Title of the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">ts</td>
<td style="width: 452px;">Timestamp of the alert.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 186px;">ordering</td>
<td style="width: 452px;">Order of the returned alerts.</td>
<td style="width: 102px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_62"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 279px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 390px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 279px;">Perch.Alert.DestPort</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">Destination port of the alert.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.SrcPort</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">Source port of the alert.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.DestIP</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">Destination IP of the alert.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.IndicatorID</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">Indicator ID of the alert.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.SrcIP</td>
<td style="width: 71px;">String</td>
<td style="width: 390px;">IP address of the source.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.SrcGeo.Country</td>
<td style="width: 71px;">String</td>
<td style="width: 390px;">Country of the threat.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.SrcGeo.Latitude</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">Latitude of the detected threat.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.SrcGeo.Longitude</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">Longitude of the detected threat.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.SensorID</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">ID of the sensor that reported the threat.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.Title</td>
<td style="width: 71px;">String</td>
<td style="width: 390px;">Title of the alert.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.Protocol</td>
<td style="width: 71px;">String</td>
<td style="width: 390px;">Protocol on which the alert was detected.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.ID</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">ID of the alert.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.ObservableID</td>
<td style="width: 71px;">Number</td>
<td style="width: 390px;">ID of the observable event.</td>
</tr>
<tr>
<td style="width: 279px;">Perch.Alert.TS</td>
<td style="width: 71px;">Date</td>
<td style="width: 390px;">Timestamp of the alert.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_82"></a>Command Example</h5>
<pre>!perch-search-alerts page_size=1</pre>
<h5>
<a id="Context_Example_85"></a>Context Example</h5>
<pre>{
    "Perch": {
        "Alert": [
            {
                "Protocol": "TCP", 
                "Title": "ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 82", 
                "SrcPort": 30834, 
                "TS": "2019-07-22T08:49:28.518216+0000", 
                "ID": 854408, 
                "ObservableID": 908757, 
                "DestIP": "172.31.46.243", 
                "IndicatorID": "EmergingThreats:Indicator-2522162", 
                "SrcIP": "77.247.181.163", 
                "SensorID": 9185, 
                "SrcGeo": {
                    "Latitude": 52.3824, 
                    "Country": "Netherlands", 
                    "Longitude": 4.8995
                }, 
                "DestPort": 22
            }
        ]
    }
}
</pre>
<h5>
<a id="Human_Readable_Output_113"></a>Human Readable Output</h5>
<h3>
<a id="ET_TOR_Known_Tor_RelayRouter_Not_Exit_Node_Traffic_group_82_114"></a>ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 82</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Destination IP</th>
<th>Destination Port</th>
<th>ID</th>
<th>Indicator ID</th>
<th>Observable ID</th>
<th>Protocol</th>
<th>Sensor ID</th>
<th>Source Geo</th>
<th>Source IP</th>
<th>Source Port</th>
<th>Timestamp</th>
<th>Title</th>
</tr>
</thead>
<tbody>
<tr>
<td>172.31.46.243</td>
<td>22</td>
<td>854408</td>
<td>EmergingThreats:Indicator-2522162</td>
<td>908757</td>
<td>TCP</td>
<td>9185</td>
<td>Latitude: 52.3824&lt;br&gt;Longitude: 4.8995&lt;br&gt;Country Name: Netherlands</td>
<td>77.247.181.163</td>
<td>30834</td>
<td>2019-07-22T08:49:28.518216+0000</td>
<td>ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 82</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_0d4a3fae-dc89-47dd-94a3-929bf3c206cc">
<a id="2_Get_information_for_a_community_120"></a>2. Get information for a community</h3>
<hr>
<p>Gets community information by ID.</p>
<h5>
<a id="Base_Command_123"></a>Base Command</h5>
<p><code>perch-get-community</code></p>
<h5>
<a id="Input_126"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 282px;"><strong>Argument Name</strong></th>
<th style="width: 306px;"><strong>Description</strong></th>
<th style="width: 152px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 282px;">id</td>
<td style="width: 306px;">ID of the community.</td>
<td style="width: 152px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_133"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 260px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 412px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">Perch.Community.Allsectors</td>
<td style="width: 68px;">Boolean</td>
<td style="width: 412px;">Indicates if the community covers all sectors.</td>
</tr>
<tr>
<td style="width: 260px;">Perch.Community.Credentialreq</td>
<td style="width: 68px;">Number</td>
<td style="width: 412px;">Credentials required to interact with the community.</td>
</tr>
<tr>
<td style="width: 260px;">Perch.Community.Desc</td>
<td style="width: 68px;">String</td>
<td style="width: 412px;">Description of the community.</td>
</tr>
<tr>
<td style="width: 260px;">Perch.Community.Id</td>
<td style="width: 68px;">Number</td>
<td style="width: 412px;">ID of the community.</td>
</tr>
<tr>
<td style="width: 260px;">Perch.Community.Name</td>
<td style="width: 68px;">String</td>
<td style="width: 412px;">Name of the community.</td>
</tr>
<tr>
<td style="width: 260px;">Perch.Community.Poweredby</td>
<td style="width: 68px;">String</td>
<td style="width: 412px;">Organization providing the feed.</td>
</tr>
<tr>
<td style="width: 260px;">Perch.Community.Selectablefeeds</td>
<td style="width: 68px;">Boolean</td>
<td style="width: 412px;">Whether the feeds are selectable.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_146"></a>Command Example</h5>
<pre>!perch-get-community id=1</pre>
<h5>
<a id="Context_Example_149"></a>Context Example</h5>
<pre>{
    "Perch": {
        "Community": {
            "Selectablefeeds": true, 
            "Allsectors": true, 
            "Name": "Hail-a-TAXII", 
            "Credentialreq": 2, 
            "Poweredby": "Soltra Edge", 
            "Id": 1, 
            "Desc": "A repository of Open Source Cyber Threat Intellegence feeds in STIX format"
        }
    }
}
</pre>
<h5>
<a id="Human_Readable_Output_166"></a>Human Readable Output</h5>
<h3>
<a id="Communities_Found_167"></a>Communities Found</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>Allsectors</th>
<th>Credentialreq</th>
<th>Desc</th>
<th>Id</th>
<th>Name</th>
<th>Poweredby</th>
<th>Selectablefeeds</th>
</tr>
</thead>
<tbody>
<tr>
<td>true</td>
<td>2</td>
<td>A repository of Open Source Cyber Threat Intelligence feeds in STIX format</td>
<td>1</td>
<td>Hail-a-TAXII</td>
<td>Soltra Edge</td>
<td>true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_c446ffc2-a5c3-4e06-a3b2-3f438b554ae1">
<a id="3_Get_a_list_of_all_communities_173"></a>3. Get a list of all communities</h3>
<hr>
<p>Returns a list of all communities.</p>
<h5>
<a id="Base_Command_176"></a>Base Command</h5>
<p><code>perch-list-communities</code></p>
<h5>
<a id="Input_179"></a>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>
<a id="Context_Output_183"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 261px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 412px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">Perch.Community.Allsectors</td>
<td style="width: 67px;">Boolean</td>
<td style="width: 412px;">Indicates if the community covers all sectors.</td>
</tr>
<tr>
<td style="width: 261px;">Perch.Community.Credentialreq</td>
<td style="width: 67px;">Number</td>
<td style="width: 412px;">Credentials required to interact with the community.</td>
</tr>
<tr>
<td style="width: 261px;">Perch.Community.Desc</td>
<td style="width: 67px;">String</td>
<td style="width: 412px;">Description of the community.</td>
</tr>
<tr>
<td style="width: 261px;">Perch.Community.Id</td>
<td style="width: 67px;">Number</td>
<td style="width: 412px;">ID of the community.</td>
</tr>
<tr>
<td style="width: 261px;">Perch.Community.Name</td>
<td style="width: 67px;">String</td>
<td style="width: 412px;">Name of the community.</td>
</tr>
<tr>
<td style="width: 261px;">Perch.Community.Poweredby</td>
<td style="width: 67px;">String</td>
<td style="width: 412px;">Organization providing the feed.</td>
</tr>
<tr>
<td style="width: 261px;">Perch.Community.Selectablefeeds</td>
<td style="width: 67px;">Boolean</td>
<td style="width: 412px;">Whether the feeds are selectable.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_196"></a>Command Example</h5>
<pre>!perch-list-communities</pre>
<h5>
<a id="Context_Example_199"></a>Context Example</h5>
<pre>{
    "Perch": {
        "Community": [
            {
                "Selectablefeeds": true, 
                "Allsectors": true, 
                "Name": "Hail-a-TAXII", 
                "Credentialreq": 2, 
                "Poweredby": "Soltra Edge", 
                "Id": 1, 
                "Desc": "A repository of Open Source Cyber Threat Intellegence feeds in STIX format"
            }, 
            {
                "Selectablefeeds": false, 
                "Allsectors": true, 
                "Name": "DHS AIS", 
                "Credentialreq": 2, 
                "Poweredby": "Flare", 
                "Id": 5, 
                "Desc": "Department of Homeland Security - Automated Indicator Sharing"
            }, 
            {
                "Selectablefeeds": true, 
                "Allsectors": true, 
                "Name": "Emerging Threats", 
                "Credentialreq": 0, 
                "Poweredby": "Emerging Threats", 
                "Id": 8, 
                "Desc": "Open source intelligence data provided by Emerging Threats/ProofPoint"
            }
        ]
    }
}
</pre>
<h5>
<a id="Human_Readable_Output_236"></a>Human Readable Output</h5>
<h3>
<a id="Communities_Found_237"></a>Communities Found</h3>
<table class="table table-striped table-bordered" style="width: 707px;" border="2">
<thead>
<tr>
<th style="width: 78px;">Allsectors</th>
<th style="width: 107px;">Credentialreq</th>
<th style="width: 194px;">Desc</th>
<th style="width: 18px;">Id</th>
<th style="width: 67px;">Name</th>
<th style="width: 88px;">Poweredby</th>
<th style="width: 133px;">Selectablefeeds</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 78px;">true</td>
<td style="width: 107px;">2</td>
<td style="width: 194px;">A repository of Open Source Cyber Threat Intellegence feeds in STIX format</td>
<td style="width: 18px;">1</td>
<td style="width: 67px;">Hail-a-TAXII</td>
<td style="width: 88px;">Soltra Edge</td>
<td style="width: 133px;">true</td>
</tr>
<tr>
<td style="width: 78px;">true</td>
<td style="width: 107px;">2</td>
<td style="width: 194px;">Department of Homeland Security - Automated Indicator Sharing</td>
<td style="width: 18px;">5</td>
<td style="width: 67px;">DHS AIS</td>
<td style="width: 88px;">Flare</td>
<td style="width: 133px;">false</td>
</tr>
<tr>
<td style="width: 78px;">true</td>
<td style="width: 107px;">0</td>
<td style="width: 194px;">Open source intelligence data provided by Emerging Threats/ProofPoint</td>
<td style="width: 18px;">8</td>
<td style="width: 67px;">Emerging Threats</td>
<td style="width: 88px;">Emerging Threats</td>
<td style="width: 133px;">true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_977e5e1e-1356-4ab6-a081-fc612fa29a70">
<a id="4_Create_an_indicator_245"></a>4. Create an indicator</h3>
<hr>
<p>Creates an indicator in Perch.</p>
<h5>
<a id="Base_Command_248"></a>Base Command</h5>
<p><code>perch-create-indicator</code></p>
<h5>
<a id="Input_251"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 465px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">communities</td>
<td style="width: 465px;">Communities to report the indicator to.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">confidence</td>
<td style="width: 465px;">Confidence of the findings.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">type</td>
<td style="width: 465px;">Type of indicator.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">value</td>
<td style="width: 465px;">The value of the indicator.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">title</td>
<td style="width: 465px;">The title of the indicator.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">description</td>
<td style="width: 465px;">Description of the indicator.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">tlp</td>
<td style="width: 465px;">TLP of the Indicator.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">operator</td>
<td style="width: 465px;">Operator of the indicator.</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">first_sighting</td>
<td style="width: 465px;">When the indicator was first sighted.</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 179px;">email_summary</td>
<td style="width: 465px;">Sends an email with the summary of the indicator.</td>
<td style="width: 96px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_267"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 232px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 433px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 232px;">Perch.Indicator.Confidence</td>
<td style="width: 75px;">Unknown</td>
<td style="width: 433px;">Confidence of the indicator.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.UpdatedAt</td>
<td style="width: 75px;">Date</td>
<td style="width: 433px;">Date and time that the indicator was last updated.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.TLP</td>
<td style="width: 75px;">String</td>
<td style="width: 433px;">TLP of the Indicator.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.Title</td>
<td style="width: 75px;">String</td>
<td style="width: 433px;">Title of the indicator.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.ID</td>
<td style="width: 75px;">Number</td>
<td style="width: 433px;">ID of the indicator.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.CreatedAt</td>
<td style="width: 75px;">Date</td>
<td style="width: 433px;">Date that the indicator was created.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.Team</td>
<td style="width: 75px;">Number</td>
<td style="width: 433px;">ID of the team.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.PerchID</td>
<td style="width: 75px;">String</td>
<td style="width: 433px;">The Perch ID for the incident.</td>
</tr>
<tr>
<td style="width: 232px;">Perch.Indicator.CreatedBy</td>
<td style="width: 75px;">Number</td>
<td style="width: 433px;">ID of the user that created the incident.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_282"></a>Command Example</h5>
<pre>!perch-create-indicator communities=8 confidence=LOW description="Sample Alert Generated via Demisto" title="Sample Alert" tlp=WHITE type=Domain value="sample.com"</pre>
<h5>
<a id="Context_Example_285"></a>Context Example</h5>
<pre>{
    "Perch": {
        "Indicator": [
            {
                "Description": "Sample Alert Generated via Demisto", 
                "Title": "Sample Alert", 
                "UpdatedAt": "2019-07-23T20:06:26.046774Z", 
                "PerchID": "41716ec9-4001-4d20-8aba-04137fa47c83", 
                "CreatedBy": 11728, 
                "Team": 5394, 
                "ID": 1236830, 
                "CreatedAt": "2019-07-23T20:06:26.046757Z"
            }
        ]
    }
}
</pre>
<h5>
<a id="Human_Readable_Output_305"></a>Human Readable Output</h5>
<h3>
<a id="Sample_Alert_306"></a>Sample Alert</h3>
<table class="table table-striped table-bordered" style="width: 767px;" border="2">
<thead>
<tr>
<th style="width: 161px;">Created At</th>
<th style="width: 62px;">Created By</th>
<th style="width: 90px;">Description</th>
<th style="width: 63px;">ID</th>
<th style="width: 101px;">Perch ID</th>
<th style="width: 44px;">Team</th>
<th style="width: 53px;">Title</th>
<th style="width: 168px;">Updated At</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">2019-07-23T20:06:26.046757Z</td>
<td style="width: 62px;">11728</td>
<td style="width: 90px;">Sample Alert Generated via Demisto</td>
<td style="width: 63px;">1236830</td>
<td style="width: 101px;">41716ec9-4001-4d20-8aba-04137fa47c83</td>
<td style="width: 44px;">5394</td>
<td style="width: 53px;">Sample Alert</td>
<td style="width: 168px;">2019-07-23T20:06:26.046774Z</td>
</tr>
</tbody>
</table>
