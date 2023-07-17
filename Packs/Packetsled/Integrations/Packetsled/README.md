<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use this integration to access the PacketSled playbook and command query.</p>
<p>Employ incidents and artifacts from an investigation, or a full packet capture, based on the perspective of a user or a host.</p>
<p>Use either the playbook or the individual commands to get the level of detail necessary for your investigation.</p>
<p>This integration was integrated and tested with PacketSled v5.3.2 and earlier.</p>
<hr>
<h2>Use Cases</h2>
<ul>
<li>Extract incidents, files, or PCAP.</li>
<li>Extract metadata for a specific host.</li>
<li>Enumerate sensors.</li>
</ul>
<hr>
<h2>Prerequisites</h2>
<p>Make sure you have the following PacketSled information.</p>
<ul>
<li>Username and password for credential access</li>
<li>Confirm firewall rules to enable access to PacketSled API</li>
</ul>
<hr>
<h2> Configure PacketSled on Cortex XSOAR</h2>
<ol>
<li>Navigate to<strong> Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services.</strong>
</li>
<li>Search for PacketSled.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name:</strong><em> </em>textual name for the integration instance</li>
<li>
<strong>Server URL</strong> (https://&lt;customer_id&gt;.packetsled.com)</li>
<li>If you want to Cortex XSOAR incidents to be created automatically from this integration instance, click <strong>Fetch Incidents.</strong>
</li>
<li>
<strong>Credentials</strong>: PacketSled username</li>
<li>
<strong>Password: </strong>PacketSled password</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate credentials and configuration.</li>
<li>Click <strong>Done </strong>to install integration. </li>
</ol>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_25013883861528275295126">Extract incidents: packetsled-get-incidents</a></li>
<li><a href="#h_500531863251528275308393">Enumerate sensors: packetsled-get-sensors</a></li>
<li><a href="#h_913128742411528275317809">Extract metadata for a specific host: packetsled-get-flows</a></li>
<li><a href="#h_417734506581528275359373">Extract files: packetsled-get-files</a></li>
<li><a href="#h_24455140731528275375320">Extract PCAP: packetsled-get-pcaps</a></li>
</ol>
<hr>
<h3 id="h_25013883861528275295126">Extract incidents: packetsled-get-incidents</h3>
<p>Extracts all incidents that occurred from last time they were extracted.</p>
<h5>Inputs</h5>
<table style="height: 558px; width: 724px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 101px;"><strong>Parameter</strong></td>
<td style="width: 473px;"><strong>Description</strong></td>
<td style="width: 108px;"><strong>Required</strong></td>
</tr>
<tr>
<td style="width: 101px;">start_time</td>
<td style="width: 473px;">
<p>Beginning of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to 1 hour ago)</p>
</td>
<td style="width: 108px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 101px;">stop_time</td>
<td style="width: 473px;">
<p>End of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to current time)</p>
</td>
<td style="width: 108px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 101px;">envid</td>
<td style="width: 473px;">
<p>Unique ID in PacketSled to identify a group of sensors that belong to a single customer (by default, all sensors are queried)</p>
</td>
<td style="width: 108px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 101px;">probe</td>
<td style="width: 473px;">
<p>Unique ID in an envid used to identify a single sensor (by default, all sensors are queried)</p>
</td>
<td style="width: 108px;">
<p>Optional</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output </h5>
<pre>{  
   "name":"Source: Packetsled SENSOR: , ENTITY: ",
   "rawJSON":{  
      
   }
}</pre>
<hr>
<h3 id="h_500531863251528275308393">Enumerate sensors: packetsled-get-sensors</h3>
<p>Enumerates all attached sensors.</p>
<p>-NO FURTHER INFORMATION-</p>
<hr>
<h3 id="h_913128742411528275317809">Extract metadata for a specific host: packetsled-get-flows</h3>
<p><span style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;"><span style="font-family: Verdana, Arial, Helvetica, sans-serif;">Finds flow metadata based on the specified parameters. The flows are posted as JSON files to the War Room.</span></span></p>
<h5>Command Example</h5>
<p><code>!packetsled-get-flows entity=192.168.0.110 limit=10000</code></p>
<h5>Inputs</h5>
<table style="height: 158px; width: 726px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 131px;"><strong>Parameter</strong></td>
<td style="width: 1000px;"><strong>Description</strong></td>
<td style="width: 160px;"><strong>Required</strong></td>
</tr>
<tr>
<td style="width: 131px;">start_time</td>
<td style="width: 1000px;">
<p>Beginning of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to 1 hour ago)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">stop_time</td>
<td style="width: 1000px;">
<p>End of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to current time)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">envid</td>
<td style="width: 1000px;">
<p>Unique ID in PacketSled to identify a group of sensors that belong to a single customer (by default, all sensors are queried)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">probe</td>
<td style="width: 1000px;">
<p>Unique ID in an envid used to identify a single sensor (by default, all sensors are queried)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">entity</td>
<td style="width: 1000px;">
<p>IP address</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">port</td>
<td style="width: 1000px;">Port</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">geo</td>
<td style="width: 1000px;">Geographical code</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">family</td>
<td style="width: 1000px;">Protocol family (enumeration value)</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">proto</td>
<td style="width: 1000px;">Protocol (enumeration value)</td>
<td style="width: 160px;">Optional</td>
</tr>
</tbody>
</table>
<hr>
<h3 id="h_417734506581528275359373">Extract files: packetsled-get-files</h3>
<p>Finds file artifacts based on the specified parameters. The files are posted to the War Room.</p>
<h5>Inputs</h5>
<table style="height: 158px; width: 726px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 131px;"><strong>Parameter</strong></td>
<td style="width: 1000px;"><strong>Description</strong></td>
<td style="width: 160px;"><strong>Required</strong></td>
</tr>
<tr>
<td style="width: 131px;">start_time</td>
<td style="width: 1000px;">
<p>Beginning of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to 1 hour ago)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">stop_time</td>
<td style="width: 1000px;">
<p>End of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to current time)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">envid</td>
<td style="width: 1000px;">
<p>Unique ID in PacketSled to identify a group of sensors that belong to a single customer (by default, all sensors are queried)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">probe</td>
<td style="width: 1000px;">
<p>Unique ID in an envid used to identify a single sensor (by default, all sensors are queried)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">entity</td>
<td style="width: 1000px;">
<p>IP address</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">port</td>
<td style="width: 1000px;">Port</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">geo</td>
<td style="width: 1000px;">Geographical code</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">family</td>
<td style="width: 1000px;">Protocol family (enumeration value)</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">proto</td>
<td style="width: 1000px;">Protocol (enumeration value)</td>
<td style="width: 160px;">Optional</td>
</tr>
</tbody>
</table>
<hr>
<h3 id="h_24455140731528275375320">Extract PCAP: packetsled-get-pcaps</h3>
<p>Finds full packet capture files based on the specified parameters. The PCAP files are posted to the War Room.</p>
<h5>Command Example</h5>
<p><code>!packetsled-get-pcaps entity=192.168.0.110</code></p>
<h5>Inputs</h5>
<table style="height: 158px; width: 726px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 131px;"><strong>Parameter</strong></td>
<td style="width: 1000px;"><strong>Description</strong></td>
<td style="width: 160px;"><strong>Required</strong></td>
</tr>
<tr>
<td style="width: 131px;">start_time</td>
<td style="width: 1000px;">
<p>Beginning of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to 1 hour ago)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">stop_time</td>
<td style="width: 1000px;">
<p>End of the time range to query, can be either epoch seconds or ISO formatted datetime (defaults to current time)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">envid</td>
<td style="width: 1000px;">
<p>Unique ID in PacketSled to identify a group of sensors that belong to a single customer (by default, all sensors are queried)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">probe</td>
<td style="width: 1000px;">
<p>Unique ID in an envid used to identify a single sensor (by default, all sensors are queried)</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">entity</td>
<td style="width: 1000px;">
<p>IP address</p>
</td>
<td style="width: 160px;">
<p>Optional</p>
</td>
</tr>
<tr>
<td style="width: 131px;">port</td>
<td style="width: 1000px;">Port</td>
<td style="width: 160px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">proto</td>
<td style="width: 1000px;">A protocol (enumeration value)</td>
<td style="width: 160px;">Optional</td>
</tr>
</tbody>
</table>


### packetsled-sensors

***
List the sensors attached to the packetsled platform.

#### Base Command

`packetsled-sensors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Packetsled.Sensors | unknown | The list of sensors | 
| Packetsled.Sensors.label | unknown | The label of the sensor | 
| Packetsled.Sensors.envid | unknown | The environment id of the sensor | 
| Packetsled.Sensors.probe | unknown | The probe number of the sensor | 
### packetsled-get-events

***
Get all of the events for a given uid

#### Base Command

`packetsled-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uid | The uid to retrieve logs for. Use the _id attribute from a flow for this parameter value. | Required | 
| envid | The environment id of the probe to search. | Optional | 
| probe | The probe number of the probe to search. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Packetsled.Events | unknown | Retrieve all logs for a single flow | 
| Packetsled.Events._id | unknown | The unique id of the Event | 
| Packetsled.Events.src_ip | unknown | The originator of the Events | 
| Packetsled.Events.dest_ip | unknown | The respondant of the Events | 
