<!DOCTYPE html>
<div class="article-body"><p>Use the Palo Alto Networks Cortex integration to query your Palo Alto Networks Cortex environment.</p>
<p>There are several steps required to configure this integration. You will navigate between Demisto and <a href="https://apps.paloaltonetworks.com/marketplace/demisto" target="_blank" rel="noopener">Cortex Hub</a> to retrieve tokens required later in the process. Be sure to follow each procedure in order.</p>
<ol>
<li><a href="#h_ed302a66-2e1a-4748-abf9-3f771021c5f0" target="_self">Activate Demisto on Palo Alto Networks Cortex Hub</a></li>
<li><a href="#h_309d275b-0d49-4a8b-b62d-3aa3bff0bbd3" target="_self">Configure the Palo Alto Networks Cortex Integration on Demisto</a></li>
</ol>
<!-- <h2 id="h_7f333c44-f080-417c-b951-eed89f3c69dc">How to Get Your Demisto Verification Token</h2>
<p>
  To activate Demisto on Cortex Hub, you need to copy your Demisto verification
  token.
</p>
<ol>
  <li>
    Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>
    &gt; <strong>Servers &amp; Services</strong>.
  </li>
  <li>Search for Palo Alto Networks Cortex.</li>
  <li>
    Click <strong>Add instance</strong>.
  </li>
  <li>
    Click the question mark icon and copy the verification token. You will need
    to enter this as part of
    <a href="#h_ed302a66-2e1a-4748-abf9-3f771021c5f0" target="_self">activating Demisto on Cortex Hub</a>.
  </li>
</ol> -->
<h2 id="h_ed302a66-2e1a-4748-abf9-3f771021c5f0">Activate Demisto on Palo Alto Networks Cortex Hub</h2>
<ol>
<li>Navigate to <a href="https://apps.paloaltonetworks.com/marketplace/demisto" target="_blank" rel="noopener">Palo Alto Networks Cortex Hub</a>.</li>
<li>In the <strong>Apps from Palo Alto Networks</strong> section, locate Demisto and click <strong>Activate</strong>.</li>
<li>In the upper-right corner, click the gear icon.</li>
<li>Locate Demisto app, and click <strong>Add Instance</strong>.
<ul>
<li><strong>Instance Name</strong> (Required): A meaningful name for the instance.</li>
<li><strong>Description</strong> (Optional): A meaningful description for the instance.</li>
<li><strong>Region</strong> (Required): The region in which the instance is located.</li>
<li><strong>Cortex Data Lake</strong> (Required): Your Cortex Data Lake instance.</li>
<li><strong>Directory Sync</strong> (Required): Your Directory Sync instance.</li>
</ul>
</li>
<li>In the Your Cortex Apps section, click the Demisto icon.</li>
<li>When prompted, enter the Demisto verification token: <code>25$nhXyu4</code>.</li>
<li>Click <strong>Send</strong>, and when prompted, click <strong>Authorize</strong>.</li>
<li>In the Request for Approval window, click <strong>Allow</strong>.</li>
<li>When prompted, copy the Authentication Token, Authentication ID, and Authentication Key. You will need to enter this as part of <a href="#h_309d275b-0d49-4a8b-b62d-3aa3bff0bbd3" target="_self">configuring the Palo Alto Networks Cortex integration on Demisto</a>.</li>
</ol>
<h2 id="h_309d275b-0d49-4a8b-b62d-3aa3bff0bbd3">Configure the Palo Alto Networks Cortex Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Palo Alto Networks Cortex.</li>
<li>Click <strong>Add instance</strong>&nbsp;to create and configure a new integration instance.<br>
<ul>
<li><strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong> <font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">Authentication Token</font> </font> </strong> <font style="vertical-align: inherit;"> <font style="vertical-align: inherit;"> : received from the <a href="#h_ed302a66-2e1a-4748-abf9-3f771021c5f0" target="_self">Activate Demisto on Palo Alto Networks Cortex Hub</a> procedure. </font> </font></li>
<li><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;"> <strong>Authentication ID</strong>:&nbsp;received from the <a href="#h_ed302a66-2e1a-4748-abf9-3f771021c5f0" target="_self">Activate Demisto on Palo Alto Networks Cortex Hub</a> procedure. </font> </font></li>
<li><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;"> <strong>Authentication Key</strong>: received from the <a href="#h_ed302a66-2e1a-4748-abf9-3f771021c5f0" target="_self">Activate Demisto on Palo Alto Networks Cortex Hub</a> procedure. </font> </font></li>
</ul>
</li>
<li>Click&nbsp;<strong>Test</strong> to validate the integration and Demisto App Token.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_99645692961526205816030">Query logs: cortex-query-logs</a></li>
<li><a href="#h_148841960231526208015686">Get logs for critical threats: cortex-get-critical-threat-logs</a></li>
<li><a href="#h_105854380451526208025315">Get social applications: cortex-get-social-applications</a></li>
<li><a href="#h_64085101191533571089794">Query the Cortex logging service: cortex-search-by-file-hash</a></li>
<li><a href="#h_547af28f-01d1-4315-ba00-bea07c0dc286" target="_self">Query traffic logs:&nbsp;cortex-query-traffic-logs</a></li>
<li><a href="#h_cf65d1a7-d7ca-4a51-8e0d-1e6dbc499a41" target="_self">Query threat logs:&nbsp;cortex-query-threat-logs</a></li>
<li><a href="#h_453996b5-7677-4812-ae96-1947d005bd1c" target="_self">Query Traps logs:&nbsp;cortex-query-traps-logs</a></li>
<li><a href="#h_efdac8d4-7749-42ca-9da9-51a676dbd51f" target="_self">Query analytics logs:&nbsp;cortex-query-analytics-logs</a></li>
</ol>
<h3 id="h_99645692961526205816030">1. Query logs</h3>
<hr>
<p>Use this command to query logs in your Palo Alto Networks Cortex environment.<code></code></p>
<h5>Base Command</h5>
<p><code>cortex-query-logs</code></p>
<h5>Input</h5>
<table style="height: 167px; width: 782px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 139px;"><strong>Argument Name</strong></td>
<td style="width: 321px;"><strong>Description</strong></td>
<td style="width: 312px;"><strong>Example</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">startTime</td>
<td style="width: 321px;">Query start time</td>
<td style="width: 312px;">startTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 139px;">endTime</td>
<td style="width: 321px;">Query end time</td>
<td style="width: 312px;">endTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 139px;">query</td>
<td style="width: 321px;">Free text SQL query</td>
<td style="width: 312px;">
<p>For example, query="select * from panw.traffic limit 5".</p>
<p>There are multiple tables in Loggings, such as: threat, traffic. Refer to Cortex Logging service schema reference for the full list.</p>
</td>
</tr>
<tr>
<td style="width: 139px;">timeRange</td>
<td style="width: 321px;">Query time range, used with the rangeValue parameter</td>
<td style="width: 312px;">This example runs the query for the previous week:&nbsp;timeRange="weeks" rangeValue="1".</td>
</tr>
<tr>
<td style="width: 139px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">rangeValue</font> </font></td>
<td style="width: 321px;">Query time value, used with the timeRange parameter</td>
<td style="width: 312px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;"> This example runs the query for the previous week:&nbsp;timeRange="weeks" rangeValue="1". </font> </font></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 223px; width: 785px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 346px;"><strong>Path</strong></td>
<td style="width: 434px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 346px;">Cortex.Logging.id</td>
<td style="width: 434px;">Log ID</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.score</td>
<td style="width: 434px;">Log score</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.action</td>
<td style="width: 434px;">Log action</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.app</td>
<td style="width: 434px;">Log application</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.proto</td>
<td style="width: 434px;">Protocol used</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.dst</td>
<td style="width: 434px;">Destination IP</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.rule</td>
<td style="width: 434px;">Rule used for log</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.src</td>
<td style="width: 434px;">Source of action</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.category-of-app</td>
<td style="width: 434px;">Application's category</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.srcloc</td>
<td style="width: 434px;">Source location</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.dstloc</td>
<td style="width: 434px;">Destination location</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.characteristic-of-app</td>
<td style="width: 434px;">Application's characteristics</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.device_name</td>
<td style="width: 434px;">Device name</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.nat</td>
<td style="width: 434px;">Was NAT used?</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.natdport</td>
<td style="width: 434px;">NAT port</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.natdst</td>
<td style="width: 434px;">NAT destination</td>
</tr>
<tr>
<td style="width: 346px;">Cortex.Logging.natsrc</td>
<td style="width: 434px;">NAT source</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-query-logs startTime="2018-04-26 00:00:00" endTime="2018-04-28 00:00:00" query="select * from panw.traffic limit 5"</pre>
<h5>Context Example</h5>
<pre><span id="s-1" class="sBrace structure-1">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;<span id="s-2" class="sObjectK">"Logging"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBracket structure-2">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-5" class="sBrace structure-3">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-6" class="sObjectK">"action"</span><span id="s-7" class="sColon">:</span><span id="s-8" class="sObjectV">"allow"</span><span id="s-9" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-10" class="sObjectK">"action_source"</span><span id="s-11" class="sColon">:</span><span id="s-12" class="sObjectV">"from-policy"</span><span id="s-13" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-14" class="sObjectK">"actionflags"</span><span id="s-15" class="sColon">:</span><span id="s-16" class="sObjectV">-9223372036854776000</span><span id="s-17" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-18" class="sObjectK">"app"</span><span id="s-19" class="sColon">:</span><span id="s-20" class="sObjectV">"ssh"</span><span id="s-21" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-22" class="sObjectK">"assoc_id"</span><span id="s-23" class="sColon">:</span><span id="s-24" class="sObjectV">0</span><span id="s-25" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-26" class="sObjectK">"bytes"</span><span id="s-27" class="sColon">:</span><span id="s-28" class="sObjectV">4245</span><span id="s-29" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-30" class="sObjectK">"bytes_received"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sObjectV">2925</span><span id="s-33" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-34" class="sObjectK">"bytes_sent"</span><span id="s-35" class="sColon">:</span><span id="s-36" class="sObjectV">1320</span><span id="s-37" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-38" class="sObjectK">"category"</span><span id="s-39" class="sColon">:</span><span id="s-40" class="sObjectV">"0"</span><span id="s-41" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-42" class="sObjectK">"category-of-app"</span><span id="s-43" class="sColon">:</span><span id="s-44" class="sObjectV">"networking"</span><span id="s-45" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-46" class="sObjectK">"characteristic-of-app"</span><span id="s-47" class="sColon">:</span><span id="s-48" class="sBracket structure-4">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-49" class="sArrayV">"able-to-transfer-file"</span><span id="s-50" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-51" class="sArrayV">"has-known-vulnerability"</span><span id="s-52" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-53" class="sArrayV">"tunnel-other-application"</span><span id="s-54" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-55" class="sArrayV">"prone-to-misuse"</span><span id="s-56" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-57" class="sArrayV">"is-saas"</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-58" class="sBracket structure-4">]</span><span id="s-59" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-60" class="sObjectK">"chunks"</span><span id="s-61" class="sColon">:</span><span id="s-62" class="sObjectV">0</span><span id="s-63" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-64" class="sObjectK">"chunks_received"</span><span id="s-65" class="sColon">:</span><span id="s-66" class="sObjectV">0</span><span id="s-67" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-68" class="sObjectK">"chunks_sent"</span><span id="s-69" class="sColon">:</span><span id="s-70" class="sObjectV">0</span><span id="s-71" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-72" class="sObjectK">"cloud_hostname"</span><span id="s-73" class="sColon">:</span><span id="s-74" class="sObjectV">"PA-VM"</span><span id="s-75" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-76" class="sObjectK">"config_ver"</span><span id="s-77" class="sColon">:</span><span id="s-78" class="sObjectV">2049</span><span id="s-79" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-80" class="sObjectK">"customer-id"</span><span id="s-81" class="sColon">:</span><span id="s-82" class="sObjectV">"140744002"</span><span id="s-83" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-84" class="sObjectK">"device_name"</span><span id="s-85" class="sColon">:</span><span id="s-86" class="sObjectV">"PA-VM"</span><span id="s-87" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-88" class="sObjectK">"dg_hier_level_1"</span><span id="s-89" class="sColon">:</span><span id="s-90" class="sObjectV">13</span><span id="s-91" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-92" class="sObjectK">"dg_hier_level_2"</span><span id="s-93" class="sColon">:</span><span id="s-94" class="sObjectV">0</span><span id="s-95" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-96" class="sObjectK">"dg_hier_level_3"</span><span id="s-97" class="sColon">:</span><span id="s-98" class="sObjectV">0</span><span id="s-99" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-100" class="sObjectK">"dg_hier_level_4"</span><span id="s-101" class="sColon">:</span><span id="s-102" class="sObjectV">0</span><span id="s-103" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-104" class="sObjectK">"dport"</span><span id="s-105" class="sColon">:</span><span id="s-106" class="sObjectV">22</span><span id="s-107" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-108" class="sObjectK">"dst"</span><span id="s-109" class="sColon">:</span><span id="s-110" class="sObjectV">"172.31.23.156"</span><span id="s-111" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-112" class="sObjectK">"dstloc"</span><span id="s-113" class="sColon">:</span><span id="s-114" class="sObjectV">"172.16.0.0-172.31.255.255"</span><span id="s-115" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-116" class="sObjectK">"elapsed"</span><span id="s-117" class="sColon">:</span><span id="s-118" class="sObjectV">2</span><span id="s-119" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-120" class="sObjectK">"flags"</span><span id="s-121" class="sColon">:</span><span id="s-122" class="sObjectV">4194381</span><span id="s-123" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-124" class="sObjectK">"from"</span><span id="s-125" class="sColon">:</span><span id="s-126" class="sObjectV">"Untrust"</span><span id="s-127" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-128" class="sObjectK">"fwd"</span><span id="s-129" class="sColon">:</span><span id="s-130" class="sObjectV">1</span><span id="s-131" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-132" class="sObjectK">"id"</span><span id="s-133" class="sColon">:</span><span id="s-134" class="sObjectV">"140744002_lcaas:1:65862:1"</span><span id="s-135" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-136" class="sObjectK">"inbound_if"</span><span id="s-137" class="sColon">:</span><span id="s-138" class="sObjectV">"ethernet1/1"</span><span id="s-139" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-140" class="sObjectK">"is-saas-of-app"</span><span id="s-141" class="sColon">:</span><span id="s-142" class="sObjectV">0</span><span id="s-143" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-144" class="sObjectK">"logset"</span><span id="s-145" class="sColon">:</span><span id="s-146" class="sObjectV">"LCaaS"</span><span id="s-147" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-148" class="sObjectK">"nat"</span><span id="s-149" class="sColon">:</span><span id="s-150" class="sObjectV">1</span><span id="s-151" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-152" class="sObjectK">"natdport"</span><span id="s-153" class="sColon">:</span><span id="s-154" class="sObjectV">22</span><span id="s-155" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-156" class="sObjectK">"natdst"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"172.31.39.63"</span><span id="s-159" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-160" class="sObjectK">"natsport"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">55949</span><span id="s-163" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-164" class="sObjectK">"natsrc"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">"172.31.38.209"</span><span id="s-167" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-168" class="sObjectK">"non-standard-dport"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">0</span><span id="s-171" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-172" class="sObjectK">"outbound_if"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sObjectV">"ethernet1/2"</span><span id="s-175" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-176" class="sObjectK">"packets"</span><span id="s-177" class="sColon">:</span><span id="s-178" class="sObjectV">24</span><span id="s-179" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-180" class="sObjectK">"parent_session_id"</span><span id="s-181" class="sColon">:</span><span id="s-182" class="sObjectV">0</span><span id="s-183" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-184" class="sObjectK">"parent_start_time"</span><span id="s-185" class="sColon">:</span><span id="s-186" class="sObjectV">0</span><span id="s-187" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-188" class="sObjectK">"pkts_received"</span><span id="s-189" class="sColon">:</span><span id="s-190" class="sObjectV">12</span><span id="s-191" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-192" class="sObjectK">"pkts_sent"</span><span id="s-193" class="sColon">:</span><span id="s-194" class="sObjectV">12</span><span id="s-195" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-196" class="sObjectK">"proto"</span><span id="s-197" class="sColon">:</span><span id="s-198" class="sObjectV">"tcp"</span><span id="s-199" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-200" class="sObjectK">"receive_time"</span><span id="s-201" class="sColon">:</span><span id="s-202" class="sObjectV">1524528178</span><span id="s-203" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-204" class="sObjectK">"recsize"</span><span id="s-205" class="sColon">:</span><span id="s-206" class="sObjectV">1480</span><span id="s-207" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-208" class="sObjectK">"repeatcnt"</span><span id="s-209" class="sColon">:</span><span id="s-210" class="sObjectV">1</span><span id="s-211" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-212" class="sObjectK">"risk-of-app"</span><span id="s-213" class="sColon">:</span><span id="s-214" class="sObjectV">"4"</span><span id="s-215" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-216" class="sObjectK">"rule"</span><span id="s-217" class="sColon">:</span><span id="s-218" class="sObjectV">"MonitorAll"</span><span id="s-219" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-220" class="sObjectK">"sanctioned-state-of-app"</span><span id="s-221" class="sColon">:</span><span id="s-222" class="sObjectV">0</span><span id="s-223" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-224" class="sObjectK">"score"</span><span id="s-225" class="sColon">:</span><span id="s-226" class="sObjectV">2</span><span id="s-227" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-228" class="sObjectK">"seqno"</span><span id="s-229" class="sColon">:</span><span id="s-230" class="sObjectV">383249</span><span id="s-231" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-232" class="sObjectK">"serial"</span><span id="s-233" class="sColon">:</span><span id="s-234" class="sObjectV">""</span><span id="s-235" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-236" class="sObjectK">"session_end_reason"</span><span id="s-237" class="sColon">:</span><span id="s-238" class="sObjectV">"tcp-fin"</span><span id="s-239" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-240" class="sObjectK">"sessionid"</span><span id="s-241" class="sColon">:</span><span id="s-242" class="sObjectV">160523</span><span id="s-243" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-244" class="sObjectK">"sport"</span><span id="s-245" class="sColon">:</span><span id="s-246" class="sObjectV">48512</span><span id="s-247" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-248" class="sObjectK">"src"</span><span id="s-249" class="sColon">:</span><span id="s-250" class="sObjectV">"52.221.242.53"</span><span id="s-251" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-252" class="sObjectK">"srcloc"</span><span id="s-253" class="sColon">:</span><span id="s-254" class="sObjectV">"SG"</span><span id="s-255" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-256" class="sObjectK">"start"</span><span id="s-257" class="sColon">:</span><span id="s-258" class="sObjectV">1524528156</span><span id="s-259" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-260" class="sObjectK">"subcategory-of-app"</span><span id="s-261" class="sColon">:</span><span id="s-262" class="sObjectV">"encrypted-tunnel"</span><span id="s-263" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-264" class="sObjectK">"subtype"</span><span id="s-265" class="sColon">:</span><span id="s-266" class="sObjectV">"end"</span><span id="s-267" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-268" class="sObjectK">"technology-of-app"</span><span id="s-269" class="sColon">:</span><span id="s-270" class="sObjectV">"client-server"</span><span id="s-271" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-272" class="sObjectK">"time_generated"</span><span id="s-273" class="sColon">:</span><span id="s-274" class="sObjectV">1524528172</span><span id="s-275" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-276" class="sObjectK">"time_received"</span><span id="s-277" class="sColon">:</span><span id="s-278" class="sObjectV">1524528172</span><span id="s-279" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-280" class="sObjectK">"to"</span><span id="s-281" class="sColon">:</span><span id="s-282" class="sObjectV">"Trust"</span><span id="s-283" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-284" class="sObjectK">"tunnel"</span><span id="s-285" class="sColon">:</span><span id="s-286" class="sObjectV">0</span><span id="s-287" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-288" class="sObjectK">"tunneled-app"</span><span id="s-289" class="sColon">:</span><span id="s-290" class="sObjectV">"untunneled"</span><span id="s-291" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-292" class="sObjectK">"tunnelid_imsi"</span><span id="s-293" class="sColon">:</span><span id="s-294" class="sObjectV">0</span><span id="s-295" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-296" class="sObjectK">"type"</span><span id="s-297" class="sColon">:</span><span id="s-298" class="sObjectV">"traffic"</span><span id="s-299" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-300" class="sObjectK">"users"</span><span id="s-301" class="sColon">:</span><span id="s-302" class="sObjectV">"52.221.242.53"</span><span id="s-303" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-304" class="sObjectK">"vsys"</span><span id="s-305" class="sColon">:</span><span id="s-306" class="sObjectV">"vsys1"</span><span id="s-307" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-308" class="sObjectK">"vsys_id"</span><span id="s-309" class="sColon">:</span><span id="s-310" class="sObjectV">1</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-311" class="sBrace structure-3">}</span><span id="s-312" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-313" class="sBrace structure-3">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-314" class="sObjectK">"action"</span><span id="s-315" class="sColon">:</span><span id="s-316" class="sObjectV">"allow"</span><span id="s-317" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-318" class="sObjectK">"action_source"</span><span id="s-319" class="sColon">:</span><span id="s-320" class="sObjectV">"from-policy"</span><span id="s-321" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-322" class="sObjectK">"actionflags"</span><span id="s-323" class="sColon">:</span><span id="s-324" class="sObjectV">-9223372036854776000</span><span id="s-325" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-326" class="sObjectK">"app"</span><span id="s-327" class="sColon">:</span><span id="s-328" class="sObjectV">"dns"</span><span id="s-329" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-330" class="sObjectK">"assoc_id"</span><span id="s-331" class="sColon">:</span><span id="s-332" class="sObjectV">0</span><span id="s-333" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-334" class="sObjectK">"bytes"</span><span id="s-335" class="sColon">:</span><span id="s-336" class="sObjectV">227</span><span id="s-337" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-338" class="sObjectK">"bytes_received"</span><span id="s-339" class="sColon">:</span><span id="s-340" class="sObjectV">154</span><span id="s-341" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-342" class="sObjectK">"bytes_sent"</span><span id="s-343" class="sColon">:</span><span id="s-344" class="sObjectV">73</span><span id="s-345" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-346" class="sObjectK">"category"</span><span id="s-347" class="sColon">:</span><span id="s-348" class="sObjectV">"0"</span><span id="s-349" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-350" class="sObjectK">"category-of-app"</span><span id="s-351" class="sColon">:</span><span id="s-352" class="sObjectV">"networking"</span><span id="s-353" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-354" class="sObjectK">"characteristic-of-app"</span><span id="s-355" class="sColon">:</span><span id="s-356" class="sBracket structure-4">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-357" class="sArrayV">"able-to-transfer-file"</span><span id="s-358" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-359" class="sArrayV">"tunnel-other-application"</span><span id="s-360" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-361" class="sArrayV">"is-saas"</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-362" class="sBracket structure-4">]</span><span id="s-363" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-364" class="sObjectK">"chunks"</span><span id="s-365" class="sColon">:</span><span id="s-366" class="sObjectV">0</span><span id="s-367" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-368" class="sObjectK">"chunks_received"</span><span id="s-369" class="sColon">:</span><span id="s-370" class="sObjectV">0</span><span id="s-371" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-372" class="sObjectK">"chunks_sent"</span><span id="s-373" class="sColon">:</span><span id="s-374" class="sObjectV">0</span><span id="s-375" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-376" class="sObjectK">"cloud_hostname"</span><span id="s-377" class="sColon">:</span><span id="s-378" class="sObjectV">"PA-VM"</span><span id="s-379" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-380" class="sObjectK">"config_ver"</span><span id="s-381" class="sColon">:</span><span id="s-382" class="sObjectV">2049</span><span id="s-383" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-384" class="sObjectK">"customer-id"</span><span id="s-385" class="sColon">:</span><span id="s-386" class="sObjectV">"140744002"</span><span id="s-387" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-388" class="sObjectK">"device_name"</span><span id="s-389" class="sColon">:</span><span id="s-390" class="sObjectV">"PA-VM"</span><span id="s-391" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-392" class="sObjectK">"dg_hier_level_1"</span><span id="s-393" class="sColon">:</span><span id="s-394" class="sObjectV">13</span><span id="s-395" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-396" class="sObjectK">"dg_hier_level_2"</span><span id="s-397" class="sColon">:</span><span id="s-398" class="sObjectV">0</span><span id="s-399" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-400" class="sObjectK">"dg_hier_level_3"</span><span id="s-401" class="sColon">:</span><span id="s-402" class="sObjectV">0</span><span id="s-403" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-404" class="sObjectK">"dg_hier_level_4"</span><span id="s-405" class="sColon">:</span><span id="s-406" class="sObjectV">0</span><span id="s-407" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-408" class="sObjectK">"dport"</span><span id="s-409" class="sColon">:</span><span id="s-410" class="sObjectV">53</span><span id="s-411" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-412" class="sObjectK">"dst"</span><span id="s-413" class="sColon">:</span><span id="s-414" class="sObjectV">"8.8.8.8"</span><span id="s-415" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-416" class="sObjectK">"dstloc"</span><span id="s-417" class="sColon">:</span><span id="s-418" class="sObjectV">"US"</span><span id="s-419" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-420" class="sObjectK">"elapsed"</span><span id="s-421" class="sColon">:</span><span id="s-422" class="sObjectV">0</span><span id="s-423" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-424" class="sObjectK">"flags"</span><span id="s-425" class="sColon">:</span><span id="s-426" class="sObjectV">4194404</span><span id="s-427" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-428" class="sObjectK">"from"</span><span id="s-429" class="sColon">:</span><span id="s-430" class="sObjectV">"Trust"</span><span id="s-431" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-432" class="sObjectK">"fwd"</span><span id="s-433" class="sColon">:</span><span id="s-434" class="sObjectV">1</span><span id="s-435" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-436" class="sObjectK">"id"</span><span id="s-437" class="sColon">:</span><span id="s-438" class="sObjectV">"140744002_lcaas:1:65862:2"</span><span id="s-439" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-440" class="sObjectK">"inbound_if"</span><span id="s-441" class="sColon">:</span><span id="s-442" class="sObjectV">"ethernet1/2"</span><span id="s-443" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-444" class="sObjectK">"is-saas-of-app"</span><span id="s-445" class="sColon">:</span><span id="s-446" class="sObjectV">0</span><span id="s-447" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-448" class="sObjectK">"logset"</span><span id="s-449" class="sColon">:</span><span id="s-450" class="sObjectV">"LCaaS"</span><span id="s-451" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-452" class="sObjectK">"nat"</span><span id="s-453" class="sColon">:</span><span id="s-454" class="sObjectV">1</span><span id="s-455" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-456" class="sObjectK">"natdport"</span><span id="s-457" class="sColon">:</span><span id="s-458" class="sObjectV">53</span><span id="s-459" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-460" class="sObjectK">"natdst"</span><span id="s-461" class="sColon">:</span><span id="s-462" class="sObjectV">"8.8.8.8"</span><span id="s-463" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-464" class="sObjectK">"natsport"</span><span id="s-465" class="sColon">:</span><span id="s-466" class="sObjectV">40841</span><span id="s-467" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-468" class="sObjectK">"natsrc"</span><span id="s-469" class="sColon">:</span><span id="s-470" class="sObjectV">"172.31.23.156"</span><span id="s-471" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-472" class="sObjectK">"non-standard-dport"</span><span id="s-473" class="sColon">:</span><span id="s-474" class="sObjectV">0</span><span id="s-475" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-476" class="sObjectK">"outbound_if"</span><span id="s-477" class="sColon">:</span><span id="s-478" class="sObjectV">"ethernet1/1"</span><span id="s-479" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-480" class="sObjectK">"packets"</span><span id="s-481" class="sColon">:</span><span id="s-482" class="sObjectV">2</span><span id="s-483" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-484" class="sObjectK">"parent_session_id"</span><span id="s-485" class="sColon">:</span><span id="s-486" class="sObjectV">0</span><span id="s-487" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-488" class="sObjectK">"parent_start_time"</span><span id="s-489" class="sColon">:</span><span id="s-490" class="sObjectV">0</span><span id="s-491" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-492" class="sObjectK">"pkts_received"</span><span id="s-493" class="sColon">:</span><span id="s-494" class="sObjectV">1</span><span id="s-495" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-496" class="sObjectK">"pkts_sent"</span><span id="s-497" class="sColon">:</span><span id="s-498" class="sObjectV">1</span><span id="s-499" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-500" class="sObjectK">"proto"</span><span id="s-501" class="sColon">:</span><span id="s-502" class="sObjectV">"udp"</span><span id="s-503" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-504" class="sObjectK">"receive_time"</span><span id="s-505" class="sColon">:</span><span id="s-506" class="sObjectV">1524528178</span><span id="s-507" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-508" class="sObjectK">"recsize"</span><span id="s-509" class="sColon">:</span><span id="s-510" class="sObjectV">1470</span><span id="s-511" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-512" class="sObjectK">"repeatcnt"</span><span id="s-513" class="sColon">:</span><span id="s-514" class="sObjectV">1</span><span id="s-515" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-516" class="sObjectK">"risk-of-app"</span><span id="s-517" class="sColon">:</span><span id="s-518" class="sObjectV">"4"</span><span id="s-519" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-520" class="sObjectK">"rule"</span><span id="s-521" class="sColon">:</span><span id="s-522" class="sObjectV">"MonitorAll"</span><span id="s-523" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-524" class="sObjectK">"sanctioned-state-of-app"</span><span id="s-525" class="sColon">:</span><span id="s-526" class="sObjectV">0</span><span id="s-527" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-528" class="sObjectK">"score"</span><span id="s-529" class="sColon">:</span><span id="s-530" class="sObjectV">2</span><span id="s-531" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-532" class="sObjectK">"seqno"</span><span id="s-533" class="sColon">:</span><span id="s-534" class="sObjectV">383250</span><span id="s-535" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-536" class="sObjectK">"serial"</span><span id="s-537" class="sColon">:</span><span id="s-538" class="sObjectV">""</span><span id="s-539" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-540" class="sObjectK">"session_end_reason"</span><span id="s-541" class="sColon">:</span><span id="s-542" class="sObjectV">"aged-out"</span><span id="s-543" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-544" class="sObjectK">"sessionid"</span><span id="s-545" class="sColon">:</span><span id="s-546" class="sObjectV">160507</span><span id="s-547" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-548" class="sObjectK">"sport"</span><span id="s-549" class="sColon">:</span><span id="s-550" class="sObjectV">56973</span><span id="s-551" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-552" class="sObjectK">"src"</span><span id="s-553" class="sColon">:</span><span id="s-554" class="sObjectV">"172.31.39.63"</span><span id="s-555" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-556" class="sObjectK">"srcloc"</span><span id="s-557" class="sColon">:</span><span id="s-558" class="sObjectV">"172.16.0.0-172.31.255.255"</span><span id="s-559" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-560" class="sObjectK">"start"</span><span id="s-561" class="sColon">:</span><span id="s-562" class="sObjectV">1524528145</span><span id="s-563" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-564" class="sObjectK">"subcategory-of-app"</span><span id="s-565" class="sColon">:</span><span id="s-566" class="sObjectV">"infrastructure"</span><span id="s-567" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-568" class="sObjectK">"subtype"</span><span id="s-569" class="sColon">:</span><span id="s-570" class="sObjectV">"end"</span><span id="s-571" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-572" class="sObjectK">"technology-of-app"</span><span id="s-573" class="sColon">:</span><span id="s-574" class="sObjectV">"network-protocol"</span><span id="s-575" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-576" class="sObjectK">"time_generated"</span><span id="s-577" class="sColon">:</span><span id="s-578" class="sObjectV">1524528174</span><span id="s-579" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-580" class="sObjectK">"time_received"</span><span id="s-581" class="sColon">:</span><span id="s-582" class="sObjectV">1524528174</span><span id="s-583" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-584" class="sObjectK">"to"</span><span id="s-585" class="sColon">:</span><span id="s-586" class="sObjectV">"Untrust"</span><span id="s-587" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-588" class="sObjectK">"tunnel"</span><span id="s-589" class="sColon">:</span><span id="s-590" class="sObjectV">0</span><span id="s-591" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-592" class="sObjectK">"tunneled-app"</span><span id="s-593" class="sColon">:</span><span id="s-594" class="sObjectV">"untunneled"</span><span id="s-595" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-596" class="sObjectK">"tunnelid_imsi"</span><span id="s-597" class="sColon">:</span><span id="s-598" class="sObjectV">0</span><span id="s-599" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-600" class="sObjectK">"type"</span><span id="s-601" class="sColon">:</span><span id="s-602" class="sObjectV">"traffic"</span><span id="s-603" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-604" class="sObjectK">"users"</span><span id="s-605" class="sColon">:</span><span id="s-606" class="sObjectV">"172.31.39.63"</span><span id="s-607" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-608" class="sObjectK">"vsys"</span><span id="s-609" class="sColon">:</span><span id="s-610" class="sObjectV">"vsys1"</span><span id="s-611" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-612" class="sObjectK">"vsys_id"</span><span id="s-613" class="sColon">:</span><span id="s-614" class="sObjectV">1</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-615" class="sBrace structure-3">}</span><br>&nbsp;&nbsp;&nbsp;<span id="s-616" class="sBracket structure-2">]</span><br><span id="s-617" class="sBrace structure-1">}</span></pre>
<h3 id="h_148841960231526208015686">2. Return logs for critical threats</h3>
<hr>
<p>Use this command to return logs for critical threats.</p>
<h5>Base Command</h5>
<p><code>cortex-get-critical-threat-logs</code></p>
<h5>Input</h5>
<table style="height: 167px; width: 782px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 139px;"><strong>Argument Name</strong></td>
<td style="width: 321px;"><strong>Description</strong></td>
<td style="width: 312px;"><strong>Example</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">startTime</td>
<td style="width: 321px;">Query start time</td>
<td style="width: 312px;">startTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 139px;">endTime</td>
<td style="width: 321px;">Query end time</td>
<td style="width: 312px;">endTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 139px;">logsAmount</td>
<td style="width: 321px;">Number of logs.</td>
<td style="width: 312px;">
<p>Default is 10.</p>
</td>
</tr>
<tr>
<td style="width: 139px;">timeRange</td>
<td style="width: 321px;">Query time range, used with the rangeValue parameter</td>
<td style="width: 312px;">This example runs the query for the previous week:&nbsp;timeRange="weeks" rangeValue="1".</td>
</tr>
<tr>
<td style="width: 139px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">strictValue</font> </font></td>
<td style="width: 321px;">Query time value, used with the timeRange parameter</td>
<td style="width: 312px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;"> This example runs the query for the previous week:&nbsp;timeRange="weeks" rangeValue="1". </font> </font></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 223px;" border="2" width="787" cellpadding="6">
<thead>
<tr>
<td style="width: 390px;"><strong>Path</strong></td>
<td style="width: 390px;"><strong> <font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">Description</font> </font> </strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 390px;">Cortex.Logging.id</td>
<td style="width: 390px;">Log ID</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.score</td>
<td style="width: 390px;">Log score</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.action</td>
<td style="width: 390px;">Log action</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.app</td>
<td style="width: 390px;">Log application</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.proto</td>
<td style="width: 390px;">Protocol used</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.dst</td>
<td style="width: 390px;">Destination IP</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.rule</td>
<td style="width: 390px;">Rule used for log</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.src</td>
<td style="width: 390px;">Source of action</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.category-of-app</td>
<td style="width: 390px;">Application's category</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.srcloc</td>
<td style="width: 390px;">Source location</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.dstloc</td>
<td style="width: 390px;">Destination location</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.characteristic-of-app</td>
<td style="width: 390px;">Application's characteristics</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.device_name</td>
<td style="width: 390px;">Device name</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.nat</td>
<td style="width: 390px;">Was NAT used?</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.natdport</td>
<td style="width: 390px;">NAT port</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.natdst</td>
<td style="width: 390px;">NAT destination</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.natsrc</td>
<td style="width: 390px;">NAT source</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.risk-of-app</td>
<td style="width: 390px;">Application's risk</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.type</td>
<td style="width: 390px;">Threat type</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.pcap_id</td>
<td style="width: 390px;">Pcap ID</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.reportid</td>
<td style="width: 390px;">Report ID</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.category-of-threatid</td>
<td style="width: 390px;">Category of threat ID</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.subtype</td>
<td style="width: 390px;">Threat sub-type</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.time_received</td>
<td style="width: 390px;">Time the threat was received</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.pcap</td>
<td style="width: 390px;">PCAP</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.name-of-threatid</td>
<td style="width: 390px;">Name of threat ID</td>
</tr>
<tr>
<td style="width: 390px;">Cortex.Logging.severity</td>
<td style="width: 390px;">Threat severity</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-get-critical-threat-logs timeRange="weeks" rangeValue=2 logsAmount=5</pre>
<p>&nbsp;</p>
<h5>Context Example</h5>
<pre><span id="s-1" class="sBrace structure-1">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;<span id="s-2" class="sObjectK">"Logging"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBracket structure-2">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-5" class="sBrace structure-3">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-6" class="sObjectK">"action"</span><span id="s-7" class="sColon">:</span><span id="s-8" class="sObjectV">"4"</span><span id="s-9" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-10" class="sObjectK">"actionflags"</span><span id="s-11" class="sColon">:</span><span id="s-12" class="sObjectV">-6917529027641082000</span><span id="s-13" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-14" class="sObjectK">"app"</span><span id="s-15" class="sColon">:</span><span id="s-16" class="sObjectV">"web-browsing"</span><span id="s-17" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-18" class="sObjectK">"category"</span><span id="s-19" class="sColon">:</span><span id="s-20" class="sObjectV">"0"</span><span id="s-21" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-22" class="sObjectK">"category-of-app"</span><span id="s-23" class="sColon">:</span><span id="s-24" class="sObjectV">"general-internet"</span><span id="s-25" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-26" class="sObjectK">"category-of-threatid"</span><span id="s-27" class="sColon">:</span><span id="s-28" class="sObjectV">34</span><span id="s-29" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-30" class="sObjectK">"characteristic-of-app"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sBracket structure-4">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-33" class="sArrayV">"able-to-transfer-file"</span><span id="s-34" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-35" class="sArrayV">"has-known-vulnerability"</span><span id="s-36" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-37" class="sArrayV">"tunnel-other-application"</span><span id="s-38" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-39" class="sArrayV">"prone-to-misuse"</span><span id="s-40" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-41" class="sArrayV">"is-saas"</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-42" class="sBracket structure-4">]</span><span id="s-43" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-44" class="sObjectK">"cloud_hostname"</span><span id="s-45" class="sColon">:</span><span id="s-46" class="sObjectV">"PA-VM"</span><span id="s-47" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-48" class="sObjectK">"config_ver"</span><span id="s-49" class="sColon">:</span><span id="s-50" class="sObjectV">2049</span><span id="s-51" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-52" class="sObjectK">"contentver"</span><span id="s-53" class="sColon">:</span><span id="s-54" class="sObjectV">524358163</span><span id="s-55" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-56" class="sObjectK">"customer-id"</span><span id="s-57" class="sColon">:</span><span id="s-58" class="sObjectV">"140744002"</span><span id="s-59" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-60" class="sObjectK">"device_name"</span><span id="s-61" class="sColon">:</span><span id="s-62" class="sObjectV">"PA-VM"</span><span id="s-63" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-64" class="sObjectK">"dg_hier_level_1"</span><span id="s-65" class="sColon">:</span><span id="s-66" class="sObjectV">13</span><span id="s-67" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-68" class="sObjectK">"dg_hier_level_2"</span><span id="s-69" class="sColon">:</span><span id="s-70" class="sObjectV">0</span><span id="s-71" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-72" class="sObjectK">"dg_hier_level_3"</span><span id="s-73" class="sColon">:</span><span id="s-74" class="sObjectV">0</span><span id="s-75" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-76" class="sObjectK">"dg_hier_level_4"</span><span id="s-77" class="sColon">:</span><span id="s-78" class="sObjectV">0</span><span id="s-79" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-80" class="sObjectK">"direction"</span><span id="s-81" class="sColon">:</span><span id="s-82" class="sObjectV">0</span><span id="s-83" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-84" class="sObjectK">"dport"</span><span id="s-85" class="sColon">:</span><span id="s-86" class="sObjectV">80</span><span id="s-87" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-88" class="sObjectK">"dst"</span><span id="s-89" class="sColon">:</span><span id="s-90" class="sObjectV">"172.31.23.156"</span><span id="s-91" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-92" class="sObjectK">"dstloc"</span><span id="s-93" class="sColon">:</span><span id="s-94" class="sObjectV">"172.16.0.0-172.31.255.255"</span><span id="s-95" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-96" class="sObjectK">"flags"</span><span id="s-97" class="sColon">:</span><span id="s-98" class="sObjectV">4202496</span><span id="s-99" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-100" class="sObjectK">"from"</span><span id="s-101" class="sColon">:</span><span id="s-102" class="sObjectV">"Untrust"</span><span id="s-103" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-104" class="sObjectK">"fwd"</span><span id="s-105" class="sColon">:</span><span id="s-106" class="sObjectV">1</span><span id="s-107" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-108" class="sObjectK">"http_method"</span><span id="s-109" class="sColon">:</span><span id="s-110" class="sObjectV">"unknown"</span><span id="s-111" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-112" class="sObjectK">"id"</span><span id="s-113" class="sColon">:</span><span id="s-114" class="sObjectV">"140744002_lcaas:0:90490:4"</span><span id="s-115" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-116" class="sObjectK">"inbound_if"</span><span id="s-117" class="sColon">:</span><span id="s-118" class="sObjectV">"ethernet1/1"</span><span id="s-119" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-120" class="sObjectK">"is-saas-of-app"</span><span id="s-121" class="sColon">:</span><span id="s-122" class="sObjectV">0</span><span id="s-123" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-124" class="sObjectK">"log_feat_bit1"</span><span id="s-125" class="sColon">:</span><span id="s-126" class="sObjectV">1</span><span id="s-127" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-128" class="sObjectK">"logset"</span><span id="s-129" class="sColon">:</span><span id="s-130" class="sObjectV">"LCaaS"</span><span id="s-131" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-132" class="sObjectK">"misc"</span><span id="s-133" class="sColon">:</span><span id="s-134" class="sObjectV">"52.8.8.48/"</span><span id="s-135" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-136" class="sObjectK">"name-of-threatid"</span><span id="s-137" class="sColon">:</span><span id="s-138" class="sObjectV">"Apache&nbsp;Struts&nbsp;Jakarta&nbsp;Multipart&nbsp;Parser&nbsp;Remote&nbsp;Code&nbsp;Execution&nbsp;Vulnerability"</span><span id="s-139" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-140" class="sObjectK">"nat"</span><span id="s-141" class="sColon">:</span><span id="s-142" class="sObjectV">1</span><span id="s-143" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-144" class="sObjectK">"natdport"</span><span id="s-145" class="sColon">:</span><span id="s-146" class="sObjectV">80</span><span id="s-147" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-148" class="sObjectK">"natdst"</span><span id="s-149" class="sColon">:</span><span id="s-150" class="sObjectV">"172.31.39.63"</span><span id="s-151" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-152" class="sObjectK">"natsport"</span><span id="s-153" class="sColon">:</span><span id="s-154" class="sObjectV">60896</span><span id="s-155" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-156" class="sObjectK">"natsrc"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"172.31.38.209"</span><span id="s-159" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-160" class="sObjectK">"non-standard-dport"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">0</span><span id="s-163" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-164" class="sObjectK">"outbound_if"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">"ethernet1/2"</span><span id="s-167" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-168" class="sObjectK">"parent_session_id"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">0</span><span id="s-171" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-172" class="sObjectK">"parent_start_time"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sObjectV">0</span><span id="s-175" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-176" class="sObjectK">"pcap"</span><span id="s-177" class="sColon">:</span><span id="s-178" class="sObjectV">null</span><span id="s-179" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-180" class="sObjectK">"pcap_id"</span><span id="s-181" class="sColon">:</span><span id="s-182" class="sObjectV">0</span><span id="s-183" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-184" class="sObjectK">"proto"</span><span id="s-185" class="sColon">:</span><span id="s-186" class="sObjectV">"tcp"</span><span id="s-187" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-188" class="sObjectK">"receive_time"</span><span id="s-189" class="sColon">:</span><span id="s-190" class="sObjectV">1524753146</span><span id="s-191" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-192" class="sObjectK">"recsize"</span><span id="s-193" class="sColon">:</span><span id="s-194" class="sObjectV">1573</span><span id="s-195" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-196" class="sObjectK">"repeatcnt"</span><span id="s-197" class="sColon">:</span><span id="s-198" class="sObjectV">3</span><span id="s-199" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-200" class="sObjectK">"reportid"</span><span id="s-201" class="sColon">:</span><span id="s-202" class="sObjectV">0</span><span id="s-203" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-204" class="sObjectK">"risk-of-app"</span><span id="s-205" class="sColon">:</span><span id="s-206" class="sObjectV">"4"</span><span id="s-207" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-208" class="sObjectK">"rule"</span><span id="s-209" class="sColon">:</span><span id="s-210" class="sObjectV">"MonitorAll"</span><span id="s-211" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-212" class="sObjectK">"sanctioned-state-of-app"</span><span id="s-213" class="sColon">:</span><span id="s-214" class="sObjectV">0</span><span id="s-215" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-216" class="sObjectK">"score"</span><span id="s-217" class="sColon">:</span><span id="s-218" class="sObjectV">2</span><span id="s-219" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-220" class="sObjectK">"seqno"</span><span id="s-221" class="sColon">:</span><span id="s-222" class="sObjectV">434509</span><span id="s-223" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-224" class="sObjectK">"serial"</span><span id="s-225" class="sColon">:</span><span id="s-226" class="sObjectV">""</span><span id="s-227" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-228" class="sObjectK">"sessionid"</span><span id="s-229" class="sColon">:</span><span id="s-230" class="sObjectV">187358</span><span id="s-231" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-232" class="sObjectK">"severity"</span><span id="s-233" class="sColon">:</span><span id="s-234" class="sObjectV">"critical"</span><span id="s-235" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-236" class="sObjectK">"sig_flags"</span><span id="s-237" class="sColon">:</span><span id="s-238" class="sObjectV">0</span><span id="s-239" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-240" class="sObjectK">"sport"</span><span id="s-241" class="sColon">:</span><span id="s-242" class="sObjectV">53470</span><span id="s-243" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-244" class="sObjectK">"src"</span><span id="s-245" class="sColon">:</span><span id="s-246" class="sObjectV">"166.111.32.179"</span><span id="s-247" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-248" class="sObjectK">"srcloc"</span><span id="s-249" class="sColon">:</span><span id="s-250" class="sObjectV">"CN"</span><span id="s-251" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-252" class="sObjectK">"subcategory-of-app"</span><span id="s-253" class="sColon">:</span><span id="s-254" class="sObjectV">"internet-utility"</span><span id="s-255" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-256" class="sObjectK">"subtype"</span><span id="s-257" class="sColon">:</span><span id="s-258" class="sObjectV">"spyware-dns"</span><span id="s-259" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-260" class="sObjectK">"technology-of-app"</span><span id="s-261" class="sColon">:</span><span id="s-262" class="sObjectV">"browser-based"</span><span id="s-263" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-264" class="sObjectK">"threatid"</span><span id="s-265" class="sColon">:</span><span id="s-266" class="sObjectV">34221</span><span id="s-267" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-268" class="sObjectK">"time_generated"</span><span id="s-269" class="sColon">:</span><span id="s-270" class="sObjectV">1524753149</span><span id="s-271" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-272" class="sObjectK">"time_received"</span><span id="s-273" class="sColon">:</span><span id="s-274" class="sObjectV">1524753149</span><span id="s-275" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-276" class="sObjectK">"to"</span><span id="s-277" class="sColon">:</span><span id="s-278" class="sObjectV">"Trust"</span><span id="s-279" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-280" class="sObjectK">"tunnel"</span><span id="s-281" class="sColon">:</span><span id="s-282" class="sObjectV">0</span><span id="s-283" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-284" class="sObjectK">"tunneled-app"</span><span id="s-285" class="sColon">:</span><span id="s-286" class="sObjectV">"tunneled-app"</span><span id="s-287" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-288" class="sObjectK">"tunnelid_imsi"</span><span id="s-289" class="sColon">:</span><span id="s-290" class="sObjectV">0</span><span id="s-291" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-292" class="sObjectK">"type"</span><span id="s-293" class="sColon">:</span><span id="s-294" class="sObjectV">"threat"</span><span id="s-295" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-296" class="sObjectK">"url_idx"</span><span id="s-297" class="sColon">:</span><span id="s-298" class="sObjectV">1</span><span id="s-299" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-300" class="sObjectK">"users"</span><span id="s-301" class="sColon">:</span><span id="s-302" class="sObjectV">"166.111.32.179"</span><span id="s-303" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-304" class="sObjectK">"vsys"</span><span id="s-305" class="sColon">:</span><span id="s-306" class="sObjectV">"vsys1"</span><span id="s-307" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-308" class="sObjectK">"vsys_id"</span><span id="s-309" class="sColon">:</span><span id="s-310" class="sObjectV">1</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-311" class="sBrace structure-3">}</span><br>&nbsp;&nbsp;&nbsp;<span id="s-312" class="sBracket structure-2">]</span><br><span id="s-313" class="sBrace structure-1">}</span></pre>
<h3 id="h_105854380451526208025315">3. Get social applications</h3>
<p>Use this command to return social applications.</p>
<h5>Base Command</h5>
<p><code>cortex-get-social-applications</code></p>
<h5>Input</h5>
<table style="height: 167px; width: 782px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 139px;"><strong>Argument Name</strong></td>
<td style="width: 321px;"><strong>Description</strong></td>
<td style="width: 312px;"><strong>Example</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">startTime</td>
<td style="width: 321px;">Query start time</td>
<td style="width: 312px;">startTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 139px;">endTime</td>
<td style="width: 321px;">Query end time</td>
<td style="width: 312px;">endTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 139px;">logsAmount</td>
<td style="width: 321px;">Number of logs.</td>
<td style="width: 312px;">
<p>Default is 10.</p>
</td>
</tr>
<tr>
<td style="width: 139px;">timeRange</td>
<td style="width: 321px;">Query time range, used with the rangeValue parameter</td>
<td style="width: 312px;">This example runs the query for the previous week:&nbsp;timeRange="weeks" rangeValue="1".</td>
</tr>
<tr>
<td style="width: 139px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">strictValue</font> </font></td>
<td style="width: 321px;">Query time value, used with the timeRange parameter</td>
<td style="width: 312px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;"> This example runs the query for the previous week:&nbsp;timeRange="weeks" rangeValue="1". </font> </font></td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="height: 223px; width: 785px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 422px;"><strong>Path</strong></td>
<td style="width: 358px;"><strong> <font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">Description</font> </font> </strong></td>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 422px;">Cortex.Logging.id</td>
<td style="width: 358px;">Log ID</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.score</td>
<td style="width: 358px;">Log score</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.action</td>
<td style="width: 358px;">Log action</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.app</td>
<td style="width: 358px;">Log application</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.proto</td>
<td style="width: 358px;">Protocol used</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.dst</td>
<td style="width: 358px;">Destination IP</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.rule</td>
<td style="width: 358px;">Rule used for log</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.src</td>
<td style="width: 358px;">Source of action</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.category-of-app</td>
<td style="width: 358px;">Application's category</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.srcloc</td>
<td style="width: 358px;">Source location</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.dstloc</td>
<td style="width: 358px;">Destination location</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.characteristic-of-app</td>
<td style="width: 358px;">Application's characteristics</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.device_name</td>
<td style="width: 358px;">Device name</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.nat</td>
<td style="width: 358px;">Was NAT used?</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.natdport</td>
<td style="width: 358px;">NAT port</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.natdst</td>
<td style="width: 358px;">NAT destination</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.natsrc</td>
<td style="width: 358px;">NAT source</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.risk-of-app</td>
<td style="width: 358px;">Application's risk</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.aggregations.size</td>
<td style="width: 358px;">Aggregations size</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.natsport</td>
<td style="width: 358px;"><font style="vertical-align: inherit;"> <font style="vertical-align: inherit;">NAT port</font> </font></td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.start</td>
<td style="width: 358px;">Traffic start</td>
</tr>
<tr>
<td style="width: 422px;">Cortex.Logging.subcategory-of-apptime_received</td>
<td style="width: 358px;">Sub-category of application time</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-get-social-applications startTime="2018-04-26 00:00:00" endTime="2018-04-28 00:00:00" logsAmount=5</pre>
<p>Command Example</p>
<pre><span id="s-1" class="sBrace structure-1">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;<span id="s-2" class="sObjectK">"Logging"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBracket structure-2">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-5" class="sBrace structure-3">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-6" class="sObjectK">"action"</span><span id="s-7" class="sColon">:</span><span id="s-8" class="sObjectV">"allow"</span><span id="s-9" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-10" class="sObjectK">"action_source"</span><span id="s-11" class="sColon">:</span><span id="s-12" class="sObjectV">"from-policy"</span><span id="s-13" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-14" class="sObjectK">"actionflags"</span><span id="s-15" class="sColon">:</span><span id="s-16" class="sObjectV">-9223372036854776000</span><span id="s-17" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-18" class="sObjectK">"app"</span><span id="s-19" class="sColon">:</span><span id="s-20" class="sObjectV">"facebook-base"</span><span id="s-21" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-22" class="sObjectK">"assoc_id"</span><span id="s-23" class="sColon">:</span><span id="s-24" class="sObjectV">0</span><span id="s-25" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-26" class="sObjectK">"bytes"</span><span id="s-27" class="sColon">:</span><span id="s-28" class="sObjectV">5536</span><span id="s-29" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-30" class="sObjectK">"bytes_received"</span><span id="s-31" class="sColon">:</span><span id="s-32" class="sObjectV">3806</span><span id="s-33" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-34" class="sObjectK">"bytes_sent"</span><span id="s-35" class="sColon">:</span><span id="s-36" class="sObjectV">1730</span><span id="s-37" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-38" class="sObjectK">"category"</span><span id="s-39" class="sColon">:</span><span id="s-40" class="sObjectV">"10014"</span><span id="s-41" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-42" class="sObjectK">"category-of-app"</span><span id="s-43" class="sColon">:</span><span id="s-44" class="sObjectV">"collaboration"</span><span id="s-45" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-46" class="sObjectK">"characteristic-of-app"</span><span id="s-47" class="sColon">:</span><span id="s-48" class="sBracket structure-4">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-49" class="sArrayV">"able-to-transfer-file"</span><span id="s-50" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-51" class="sArrayV">"has-known-vulnerability"</span><span id="s-52" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-53" class="sArrayV">"tunnel-other-application"</span><span id="s-54" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-55" class="sArrayV">"prone-to-misuse"</span><span id="s-56" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-57" class="sArrayV">"is-saas"</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-58" class="sBracket structure-4">]</span><span id="s-59" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-60" class="sObjectK">"chunks"</span><span id="s-61" class="sColon">:</span><span id="s-62" class="sObjectV">0</span><span id="s-63" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-64" class="sObjectK">"chunks_received"</span><span id="s-65" class="sColon">:</span><span id="s-66" class="sObjectV">0</span><span id="s-67" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-68" class="sObjectK">"chunks_sent"</span><span id="s-69" class="sColon">:</span><span id="s-70" class="sObjectV">0</span><span id="s-71" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-72" class="sObjectK">"cloud_hostname"</span><span id="s-73" class="sColon">:</span><span id="s-74" class="sObjectV">"VM-Series"</span><span id="s-75" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-76" class="sObjectK">"config_ver"</span><span id="s-77" class="sColon">:</span><span id="s-78" class="sObjectV">2049</span><span id="s-79" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-80" class="sObjectK">"container-of-app"</span><span id="s-81" class="sColon">:</span><span id="s-82" class="sObjectV">"facebook"</span><span id="s-83" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-84" class="sObjectK">"customer-id"</span><span id="s-85" class="sColon">:</span><span id="s-86" class="sObjectV">"140744002"</span><span id="s-87" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-88" class="sObjectK">"device_name"</span><span id="s-89" class="sColon">:</span><span id="s-90" class="sObjectV">"VM-Series"</span><span id="s-91" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-92" class="sObjectK">"dg_hier_level_1"</span><span id="s-93" class="sColon">:</span><span id="s-94" class="sObjectV">13</span><span id="s-95" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-96" class="sObjectK">"dg_hier_level_2"</span><span id="s-97" class="sColon">:</span><span id="s-98" class="sObjectV">0</span><span id="s-99" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-100" class="sObjectK">"dg_hier_level_3"</span><span id="s-101" class="sColon">:</span><span id="s-102" class="sObjectV">0</span><span id="s-103" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-104" class="sObjectK">"dg_hier_level_4"</span><span id="s-105" class="sColon">:</span><span id="s-106" class="sObjectV">0</span><span id="s-107" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-108" class="sObjectK">"dport"</span><span id="s-109" class="sColon">:</span><span id="s-110" class="sObjectV">443</span><span id="s-111" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-112" class="sObjectK">"dst"</span><span id="s-113" class="sColon">:</span><span id="s-114" class="sObjectV">"157.240.1.18"</span><span id="s-115" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-116" class="sObjectK">"dstloc"</span><span id="s-117" class="sColon">:</span><span id="s-118" class="sObjectV">"US"</span><span id="s-119" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-120" class="sObjectK">"elapsed"</span><span id="s-121" class="sColon">:</span><span id="s-122" class="sObjectV">289</span><span id="s-123" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-124" class="sObjectK">"flags"</span><span id="s-125" class="sColon">:</span><span id="s-126" class="sObjectV">77</span><span id="s-127" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-128" class="sObjectK">"from"</span><span id="s-129" class="sColon">:</span><span id="s-130" class="sObjectV">"SCTC"</span><span id="s-131" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-132" class="sObjectK">"fwd"</span><span id="s-133" class="sColon">:</span><span id="s-134" class="sObjectV">1</span><span id="s-135" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-136" class="sObjectK">"id"</span><span id="s-137" class="sColon">:</span><span id="s-138" class="sObjectV">"140744002_lcaas:1:92075:333"</span><span id="s-139" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-140" class="sObjectK">"inbound_if"</span><span id="s-141" class="sColon">:</span><span id="s-142" class="sObjectV">"ethernet1/1"</span><span id="s-143" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-144" class="sObjectK">"is-saas-of-app"</span><span id="s-145" class="sColon">:</span><span id="s-146" class="sObjectV">0</span><span id="s-147" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-148" class="sObjectK">"logset"</span><span id="s-149" class="sColon">:</span><span id="s-150" class="sObjectV">"LCaaS"</span><span id="s-151" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-152" class="sObjectK">"natdport"</span><span id="s-153" class="sColon">:</span><span id="s-154" class="sObjectV">0</span><span id="s-155" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-156" class="sObjectK">"natdst"</span><span id="s-157" class="sColon">:</span><span id="s-158" class="sObjectV">"0.0.0.0"</span><span id="s-159" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-160" class="sObjectK">"natsport"</span><span id="s-161" class="sColon">:</span><span id="s-162" class="sObjectV">0</span><span id="s-163" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-164" class="sObjectK">"natsrc"</span><span id="s-165" class="sColon">:</span><span id="s-166" class="sObjectV">"0.0.0.0"</span><span id="s-167" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-168" class="sObjectK">"non-standard-dport"</span><span id="s-169" class="sColon">:</span><span id="s-170" class="sObjectV">0</span><span id="s-171" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-172" class="sObjectK">"outbound_if"</span><span id="s-173" class="sColon">:</span><span id="s-174" class="sObjectV">"ethernet1/1"</span><span id="s-175" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-176" class="sObjectK">"packets"</span><span id="s-177" class="sColon">:</span><span id="s-178" class="sObjectV">25</span><span id="s-179" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-180" class="sObjectK">"parent_session_id"</span><span id="s-181" class="sColon">:</span><span id="s-182" class="sObjectV">0</span><span id="s-183" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-184" class="sObjectK">"parent_start_time"</span><span id="s-185" class="sColon">:</span><span id="s-186" class="sObjectV">0</span><span id="s-187" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-188" class="sObjectK">"pkts_received"</span><span id="s-189" class="sColon">:</span><span id="s-190" class="sObjectV">17</span><span id="s-191" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-192" class="sObjectK">"pkts_sent"</span><span id="s-193" class="sColon">:</span><span id="s-194" class="sObjectV">8</span><span id="s-195" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-196" class="sObjectK">"proto"</span><span id="s-197" class="sColon">:</span><span id="s-198" class="sObjectV">"tcp"</span><span id="s-199" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-200" class="sObjectK">"receive_time"</span><span id="s-201" class="sColon">:</span><span id="s-202" class="sObjectV">1524761638</span><span id="s-203" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-204" class="sObjectK">"recsize"</span><span id="s-205" class="sColon">:</span><span id="s-206" class="sObjectV">1527</span><span id="s-207" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-208" class="sObjectK">"repeatcnt"</span><span id="s-209" class="sColon">:</span><span id="s-210" class="sObjectV">1</span><span id="s-211" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-212" class="sObjectK">"risk-of-app"</span><span id="s-213" class="sColon">:</span><span id="s-214" class="sObjectV">"4"</span><span id="s-215" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-216" class="sObjectK">"rule"</span><span id="s-217" class="sColon">:</span><span id="s-218" class="sObjectV">"MonitorAll-SCTC"</span><span id="s-219" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-220" class="sObjectK">"sanctioned-state-of-app"</span><span id="s-221" class="sColon">:</span><span id="s-222" class="sObjectV">0</span><span id="s-223" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-224" class="sObjectK">"score"</span><span id="s-225" class="sColon">:</span><span id="s-226" class="sObjectV">9.9996195</span><span id="s-227" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-228" class="sObjectK">"seqno"</span><span id="s-229" class="sColon">:</span><span id="s-230" class="sObjectV">123856604</span><span id="s-231" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-232" class="sObjectK">"serial"</span><span id="s-233" class="sColon">:</span><span id="s-234" class="sObjectV">""</span><span id="s-235" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-236" class="sObjectK">"session_end_reason"</span><span id="s-237" class="sColon">:</span><span id="s-238" class="sObjectV">"aged-out"</span><span id="s-239" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-240" class="sObjectK">"sessionid"</span><span id="s-241" class="sColon">:</span><span id="s-242" class="sObjectV">30298</span><span id="s-243" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-244" class="sObjectK">"sport"</span><span id="s-245" class="sColon">:</span><span id="s-246" class="sObjectV">47385</span><span id="s-247" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-248" class="sObjectK">"src"</span><span id="s-249" class="sColon">:</span><span id="s-250" class="sObjectV">"192.168.200.5"</span><span id="s-251" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-252" class="sObjectK">"srcloc"</span><span id="s-253" class="sColon">:</span><span id="s-254" class="sObjectV">"192.168.0.0-192.168.255.255"</span><span id="s-255" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-256" class="sObjectK">"start"</span><span id="s-257" class="sColon">:</span><span id="s-258" class="sObjectV">1524761209</span><span id="s-259" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-260" class="sObjectK">"subcategory-of-app"</span><span id="s-261" class="sColon">:</span><span id="s-262" class="sObjectV">"social-networking"</span><span id="s-263" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-264" class="sObjectK">"subtype"</span><span id="s-265" class="sColon">:</span><span id="s-266" class="sObjectV">"end"</span><span id="s-267" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-268" class="sObjectK">"technology-of-app"</span><span id="s-269" class="sColon">:</span><span id="s-270" class="sObjectV">"browser-based"</span><span id="s-271" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-272" class="sObjectK">"time_generated"</span><span id="s-273" class="sColon">:</span><span id="s-274" class="sObjectV">1524761621</span><span id="s-275" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-276" class="sObjectK">"time_received"</span><span id="s-277" class="sColon">:</span><span id="s-278" class="sObjectV">1524761621</span><span id="s-279" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-280" class="sObjectK">"to"</span><span id="s-281" class="sColon">:</span><span id="s-282" class="sObjectV">"SCTC"</span><span id="s-283" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-284" class="sObjectK">"tunnel"</span><span id="s-285" class="sColon">:</span><span id="s-286" class="sObjectV">0</span><span id="s-287" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-288" class="sObjectK">"tunneled-app"</span><span id="s-289" class="sColon">:</span><span id="s-290" class="sObjectV">"tunneled-app"</span><span id="s-291" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-292" class="sObjectK">"tunnelid_imsi"</span><span id="s-293" class="sColon">:</span><span id="s-294" class="sObjectV">0</span><span id="s-295" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-296" class="sObjectK">"type"</span><span id="s-297" class="sColon">:</span><span id="s-298" class="sObjectV">"traffic"</span><span id="s-299" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-300" class="sObjectK">"users"</span><span id="s-301" class="sColon">:</span><span id="s-302" class="sObjectV">"192.168.200.5"</span><span id="s-303" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-304" class="sObjectK">"vsys"</span><span id="s-305" class="sColon">:</span><span id="s-306" class="sObjectV">"vsys1"</span><span id="s-307" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-308" class="sObjectK">"vsys_id"</span><span id="s-309" class="sColon">:</span><span id="s-310" class="sObjectV">1</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-311" class="sBrace structure-3">}</span><span id="s-312" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-313" class="sBrace structure-3">{&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-314" class="sObjectK">"action"</span><span id="s-315" class="sColon">:</span><span id="s-316" class="sObjectV">"allow"</span><span id="s-317" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-318" class="sObjectK">"action_source"</span><span id="s-319" class="sColon">:</span><span id="s-320" class="sObjectV">"from-policy"</span><span id="s-321" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-322" class="sObjectK">"actionflags"</span><span id="s-323" class="sColon">:</span><span id="s-324" class="sObjectV">-9223372036854776000</span><span id="s-325" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-326" class="sObjectK">"app"</span><span id="s-327" class="sColon">:</span><span id="s-328" class="sObjectV">"linkedin-base"</span><span id="s-329" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-330" class="sObjectK">"assoc_id"</span><span id="s-331" class="sColon">:</span><span id="s-332" class="sObjectV">0</span><span id="s-333" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-334" class="sObjectK">"bytes"</span><span id="s-335" class="sColon">:</span><span id="s-336" class="sObjectV">9641</span><span id="s-337" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-338" class="sObjectK">"bytes_received"</span><span id="s-339" class="sColon">:</span><span id="s-340" class="sObjectV">6935</span><span id="s-341" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-342" class="sObjectK">"bytes_sent"</span><span id="s-343" class="sColon">:</span><span id="s-344" class="sObjectV">2706</span><span id="s-345" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-346" class="sObjectK">"category"</span><span id="s-347" class="sColon">:</span><span id="s-348" class="sObjectV">"10065"</span><span id="s-349" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-350" class="sObjectK">"category-of-app"</span><span id="s-351" class="sColon">:</span><span id="s-352" class="sObjectV">"collaboration"</span><span id="s-353" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-354" class="sObjectK">"characteristic-of-app"</span><span id="s-355" class="sColon">:</span><span id="s-356" class="sBracket structure-4">[&nbsp;&nbsp;</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-357" class="sArrayV">"has-known-vulnerability"</span><span id="s-358" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-359" class="sArrayV">"tunnel-other-application"</span><span id="s-360" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-361" class="sArrayV">"is-saas"</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-362" class="sBracket structure-4">]</span><span id="s-363" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-364" class="sObjectK">"chunks"</span><span id="s-365" class="sColon">:</span><span id="s-366" class="sObjectV">0</span><span id="s-367" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-368" class="sObjectK">"chunks_received"</span><span id="s-369" class="sColon">:</span><span id="s-370" class="sObjectV">0</span><span id="s-371" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-372" class="sObjectK">"chunks_sent"</span><span id="s-373" class="sColon">:</span><span id="s-374" class="sObjectV">0</span><span id="s-375" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-376" class="sObjectK">"cloud_hostname"</span><span id="s-377" class="sColon">:</span><span id="s-378" class="sObjectV">"VM-Series"</span><span id="s-379" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-380" class="sObjectK">"config_ver"</span><span id="s-381" class="sColon">:</span><span id="s-382" class="sObjectV">2049</span><span id="s-383" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-384" class="sObjectK">"container-of-app"</span><span id="s-385" class="sColon">:</span><span id="s-386" class="sObjectV">"linkedin"</span><span id="s-387" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-388" class="sObjectK">"customer-id"</span><span id="s-389" class="sColon">:</span><span id="s-390" class="sObjectV">"140744002"</span><span id="s-391" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-392" class="sObjectK">"device_name"</span><span id="s-393" class="sColon">:</span><span id="s-394" class="sObjectV">"VM-Series"</span><span id="s-395" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-396" class="sObjectK">"dg_hier_level_1"</span><span id="s-397" class="sColon">:</span><span id="s-398" class="sObjectV">13</span><span id="s-399" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-400" class="sObjectK">"dg_hier_level_2"</span><span id="s-401" class="sColon">:</span><span id="s-402" class="sObjectV">0</span><span id="s-403" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-404" class="sObjectK">"dg_hier_level_3"</span><span id="s-405" class="sColon">:</span><span id="s-406" class="sObjectV">0</span><span id="s-407" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-408" class="sObjectK">"dg_hier_level_4"</span><span id="s-409" class="sColon">:</span><span id="s-410" class="sObjectV">0</span><span id="s-411" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-412" class="sObjectK">"dport"</span><span id="s-413" class="sColon">:</span><span id="s-414" class="sObjectV">443</span><span id="s-415" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-416" class="sObjectK">"dst"</span><span id="s-417" class="sColon">:</span><span id="s-418" class="sObjectV">"152.195.133.1"</span><span id="s-419" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-420" class="sObjectK">"dstloc"</span><span id="s-421" class="sColon">:</span><span id="s-422" class="sObjectV">"US"</span><span id="s-423" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-424" class="sObjectK">"elapsed"</span><span id="s-425" class="sColon">:</span><span id="s-426" class="sObjectV">204</span><span id="s-427" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-428" class="sObjectK">"flags"</span><span id="s-429" class="sColon">:</span><span id="s-430" class="sObjectV">77</span><span id="s-431" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-432" class="sObjectK">"from"</span><span id="s-433" class="sColon">:</span><span id="s-434" class="sObjectV">"SCTC"</span><span id="s-435" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-436" class="sObjectK">"fwd"</span><span id="s-437" class="sColon">:</span><span id="s-438" class="sObjectV">1</span><span id="s-439" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-440" class="sObjectK">"id"</span><span id="s-441" class="sColon">:</span><span id="s-442" class="sObjectV">"140744002_lcaas:1:92075:640"</span><span id="s-443" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-444" class="sObjectK">"inbound_if"</span><span id="s-445" class="sColon">:</span><span id="s-446" class="sObjectV">"ethernet1/1"</span><span id="s-447" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-448" class="sObjectK">"is-saas-of-app"</span><span id="s-449" class="sColon">:</span><span id="s-450" class="sObjectV">0</span><span id="s-451" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-452" class="sObjectK">"logset"</span><span id="s-453" class="sColon">:</span><span id="s-454" class="sObjectV">"LCaaS"</span><span id="s-455" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-456" class="sObjectK">"natdport"</span><span id="s-457" class="sColon">:</span><span id="s-458" class="sObjectV">0</span><span id="s-459" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-460" class="sObjectK">"natdst"</span><span id="s-461" class="sColon">:</span><span id="s-462" class="sObjectV">"0.0.0.0"</span><span id="s-463" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-464" class="sObjectK">"natsport"</span><span id="s-465" class="sColon">:</span><span id="s-466" class="sObjectV">0</span><span id="s-467" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-468" class="sObjectK">"natsrc"</span><span id="s-469" class="sColon">:</span><span id="s-470" class="sObjectV">"0.0.0.0"</span><span id="s-471" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-472" class="sObjectK">"non-standard-dport"</span><span id="s-473" class="sColon">:</span><span id="s-474" class="sObjectV">0</span><span id="s-475" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-476" class="sObjectK">"outbound_if"</span><span id="s-477" class="sColon">:</span><span id="s-478" class="sObjectV">"ethernet1/1"</span><span id="s-479" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-480" class="sObjectK">"packets"</span><span id="s-481" class="sColon">:</span><span id="s-482" class="sObjectV">35</span><span id="s-483" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-484" class="sObjectK">"parent_session_id"</span><span id="s-485" class="sColon">:</span><span id="s-486" class="sObjectV">0</span><span id="s-487" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-488" class="sObjectK">"parent_start_time"</span><span id="s-489" class="sColon">:</span><span id="s-490" class="sObjectV">0</span><span id="s-491" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-492" class="sObjectK">"pkts_received"</span><span id="s-493" class="sColon">:</span><span id="s-494" class="sObjectV">17</span><span id="s-495" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-496" class="sObjectK">"pkts_sent"</span><span id="s-497" class="sColon">:</span><span id="s-498" class="sObjectV">18</span><span id="s-499" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-500" class="sObjectK">"proto"</span><span id="s-501" class="sColon">:</span><span id="s-502" class="sObjectV">"tcp"</span><span id="s-503" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-504" class="sObjectK">"receive_time"</span><span id="s-505" class="sColon">:</span><span id="s-506" class="sObjectV">1524761638</span><span id="s-507" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-508" class="sObjectK">"recsize"</span><span id="s-509" class="sColon">:</span><span id="s-510" class="sObjectV">1517</span><span id="s-511" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-512" class="sObjectK">"repeatcnt"</span><span id="s-513" class="sColon">:</span><span id="s-514" class="sObjectV">1</span><span id="s-515" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-516" class="sObjectK">"risk-of-app"</span><span id="s-517" class="sColon">:</span><span id="s-518" class="sObjectV">"3"</span><span id="s-519" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-520" class="sObjectK">"rule"</span><span id="s-521" class="sColon">:</span><span id="s-522" class="sObjectV">"MonitorAll-SCTC"</span><span id="s-523" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-524" class="sObjectK">"sanctioned-state-of-app"</span><span id="s-525" class="sColon">:</span><span id="s-526" class="sObjectV">0</span><span id="s-527" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-528" class="sObjectK">"score"</span><span id="s-529" class="sColon">:</span><span id="s-530" class="sObjectV">9.9996195</span><span id="s-531" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-532" class="sObjectK">"seqno"</span><span id="s-533" class="sColon">:</span><span id="s-534" class="sObjectV">123856911</span><span id="s-535" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-536" class="sObjectK">"serial"</span><span id="s-537" class="sColon">:</span><span id="s-538" class="sObjectV">""</span><span id="s-539" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-540" class="sObjectK">"session_end_reason"</span><span id="s-541" class="sColon">:</span><span id="s-542" class="sObjectV">"tcp-rst-from-server"</span><span id="s-543" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-544" class="sObjectK">"sessionid"</span><span id="s-545" class="sColon">:</span><span id="s-546" class="sObjectV">45992</span><span id="s-547" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-548" class="sObjectK">"sport"</span><span id="s-549" class="sColon">:</span><span id="s-550" class="sObjectV">53712</span><span id="s-551" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-552" class="sObjectK">"src"</span><span id="s-553" class="sColon">:</span><span id="s-554" class="sObjectV">"10.11.48.7"</span><span id="s-555" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-556" class="sObjectK">"srcloc"</span><span id="s-557" class="sColon">:</span><span id="s-558" class="sObjectV">"10.0.0.0-10.255.255.255"</span><span id="s-559" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-560" class="sObjectK">"start"</span><span id="s-561" class="sColon">:</span><span id="s-562" class="sObjectV">1524761403</span><span id="s-563" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-564" class="sObjectK">"subcategory-of-app"</span><span id="s-565" class="sColon">:</span><span id="s-566" class="sObjectV">"social-networking"</span><span id="s-567" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-568" class="sObjectK">"subtype"</span><span id="s-569" class="sColon">:</span><span id="s-570" class="sObjectV">"end"</span><span id="s-571" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-572" class="sObjectK">"technology-of-app"</span><span id="s-573" class="sColon">:</span><span id="s-574" class="sObjectV">"browser-based"</span><span id="s-575" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-576" class="sObjectK">"time_generated"</span><span id="s-577" class="sColon">:</span><span id="s-578" class="sObjectV">1524761624</span><span id="s-579" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-580" class="sObjectK">"time_received"</span><span id="s-581" class="sColon">:</span><span id="s-582" class="sObjectV">1524761624</span><span id="s-583" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-584" class="sObjectK">"to"</span><span id="s-585" class="sColon">:</span><span id="s-586" class="sObjectV">"SCTC"</span><span id="s-587" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-588" class="sObjectK">"tunnel"</span><span id="s-589" class="sColon">:</span><span id="s-590" class="sObjectV">0</span><span id="s-591" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-592" class="sObjectK">"tunneled-app"</span><span id="s-593" class="sColon">:</span><span id="s-594" class="sObjectV">"tunneled-app"</span><span id="s-595" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-596" class="sObjectK">"tunnelid_imsi"</span><span id="s-597" class="sColon">:</span><span id="s-598" class="sObjectV">0</span><span id="s-599" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-600" class="sObjectK">"type"</span><span id="s-601" class="sColon">:</span><span id="s-602" class="sObjectV">"traffic"</span><span id="s-603" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-604" class="sObjectK">"users"</span><span id="s-605" class="sColon">:</span><span id="s-606" class="sObjectV">"10.11.48.7"</span><span id="s-607" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-608" class="sObjectK">"vsys"</span><span id="s-609" class="sColon">:</span><span id="s-610" class="sObjectV">"vsys1"</span><span id="s-611" class="sComma">,</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-612" class="sObjectK">"vsys_id"</span><span id="s-613" class="sColon">:</span><span id="s-614" class="sObjectV">1</span><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span id="s-615" class="sBrace structure-3">}</span><br>&nbsp;&nbsp;&nbsp;<span id="s-616" class="sBracket structure-2">]</span><br><span id="s-617" class="sBrace structure-1">}</span></pre>
<h3 id="h_64085101191533571089794">4. Query the Cortex logging service</h3>
<hr>
<p>Executes a query on the Cortex logging service.</p>
<h5>Base Command</h5>
<p><code>cortex-search-by-file-hash</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 467px;"><strong>Argument Name</strong></th>
<th style="width: 235px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 467px;">startTime</td>
<td style="width: 235px;">Query start time. For example, startTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 467px;">endTime</td>
<td style="width: 235px;">Query end time. For example, endTime="2018-04-26 00:00:00"</td>
</tr>
<tr>
<td style="width: 467px;">logsAmount</td>
<td style="width: 235px;">Amount of logs. Default is 10</td>
</tr>
<tr>
<td style="width: 467px;">timeRange</td>
<td style="width: 235px;">Time range for the query, used with rangeValue. For example, timeRange="weeks" rangeValue="1" would run the query on the last week.</td>
</tr>
<tr>
<td style="width: 467px;">rangeValue</td>
<td style="width: 235px;">Time value for the query, used with timeRange. For example, timeRange="weeks" rangeValue="1" would run the query on the last week.</td>
</tr>
<tr>
<td style="width: 467px;">SHA256</td>
<td style="width: 235px;">File hash for the query. For example, SHA256="503ca1a4fc0d48b18c0336f544ba0f0abf305ae3a3f49b3c2b86" will return all logs related to this file.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 386px;"><strong>Path</strong></th>
<th style="width: 81px;"><strong>Type</strong></th>
<th style="width: 241px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 386px;">Cortex.Logging.id</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Log ID</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.score</td>
<td style="width: 81px;">number</td>
<td style="width: 241px;">Log score</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.action</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Log action</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.app</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Log app</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.proto</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">The protocol used</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.dst</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Destination IP</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.rule</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Rule used</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.src</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">The source of the action</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.category-of-app</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Application's category</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.srcloc</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Source location</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.dstloc</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Destination location</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.characteristic-of-app</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Application's characteristics</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.device_name</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Device name</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.nat</td>
<td style="width: 81px;">number</td>
<td style="width: 241px;">Whether NAT was used</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.natdport</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">NAT port</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.natdst</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">NAT destination</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.natsrc</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">NAT source</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.risk-of-app</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Risk of application</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.type</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Threat type</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.pcad_id</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Pcap ID</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.reportid</td>
<td style="width: 81px;">number</td>
<td style="width: 241px;">Report ID</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.category-of-threatid</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Category of threat ID</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.subtype</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Threat sub-type</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.time_received</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Time received</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.pcap</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Pcap</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.name-of-threatid</td>
<td style="width: 81px;">string</td>
<td style="width: 241px;">Name of threat ID</td>
</tr>
<tr>
<td style="width: 386px;">Cortex.Logging.severity</td>
<td style="width: 81px;">unknown</td>
<td style="width: 241px;">Threat Severity</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-search-by-file-hash SHA256=503ca1a4fc0d48b18c0336f544ba0f0abf305ae3a3f49b3c2b86b8645d6572dc</pre>
<h4>Context Example</h4>
<pre>{
  "Cortex": {
    "Logging": [
      {
        "SHA256": "503ca1a4fc0d48b18c0336f544ba0f0abf305ae3a3f49b3c2b86b8645d6572dc",
        "action": "allow",
        "actionflags": -6917529027641082000,
        "app": "google-app-engine",
        "category": "malicious",
        "category-of-app": "general-internet",
        "category-of-threatid": "unknown",
        "characteristic-of-app": [
          "has-known-vulnerability",
          "tunnel-other-application",
          "prone-to-misuse",
          "is-saas"
        ],
        "cloud": "wildfire.paloaltonetworks.com",
        "cloud_hostname": "PA-VM",
        "config_ver": 2049,
        "contentver": 0,
        "customer-id": "140744002",
        "device_name": "PA-VM",
        "dg_hier_level_1": 13,
        "dg_hier_level_2": 0,
        "dg_hier_level_3": 0,
        "dg_hier_level_4": 0,
        "direction": "server-to-client",
        "dport": 80,
        "dst": "216.58.195.78",
        "dstloc": "US",
        "filename": "echomalware",
        "filetype": "pe",
        "flags": 4202496,
        "from": "Trust",
        "fwd": 1,
        "http_method": "unknown",
        "id": "140744002_lcaas:1:381684:0",
        "inbound_if": "ethernet1/2",
        "is-saas-of-app": 0,
        "log_feat_bit1": 1,
        "logset": "LCaaS",
        "name-of-threatid": "Windows Executable (EXE)",
        "nat": 1,
        "natdport": 80,
        "natdst": "216.58.195.78",
        "natsport": 38085,
        "natsrc": "172.31.23.156",
        "non-standard-dport": 0,
        "outbound_if": "ethernet1/1",
        "parent_session_id": 0,
        "parent_start_time": 0,
        "pcap": null,
        "pcap_id": 0,
        "proto": "tcp",
        "receive_time": 1527033937,
        "recsize": 1704,
        "repeatcnt": 1,
        "reportid": 9794151710,
        "risk-of-app": "3",
        "rule": "MonitorAll",
        "sanctioned-state-of-app": 0,
        "score": 2.139842,
        "seqno": 829961,
        "serial": "",
        "sessionid": 99875,
        "severity": "high",
        "sig_flags": 0,
        "sport": 35072,
        "src": "172.31.39.63",
        "srcloc": "172.16.0.0-172.31.255.255",
        "srcuser": "test@email.com",
        "subcategory-of-app": "internet-utility",
        "subject": null,
        "subtype": "wildfire",
        "technology-of-app": "browser-based",
        "threatid": 52020,
        "time_generated": 1527033928,
        "time_received": 1527033928,
        "to": "Untrust",
        "tunnel": 0,
        "tunneled-app": "tunneled-app",
        "tunnelid_imsi": 0,
        "type": "threat",
        "url_idx": 1,
        "users": "test@email.com",
        "vsys": "vsys1",
        "vsys_id": 1
      }
    ]
  }
}
</pre>
<h5>Human Readable Output</h5>
<p><img src="https://github.com/demisto/content/raw/f1905b0493aa2a06c0ad0306a77e6fb0e0e5214f/Packs/DeprecatedContent/Integrations/PaloAltoNetworksCortex/doc_files/mceclip0.png" width="751" height="416"></p>
<h3 id="h_547af28f-01d1-4315-ba00-bea07c0dc286">5. Query traffic logs</h3>
<hr>
<p>Searches the Cortex panw.traffic table, which is the traffic logs table for PAN-OS and Panorama.</p>
<h5>Base Command</h5>
<p><code>cortex-query-traffic-logs</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">ip</td>
<td style="width: 501px;">An IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">rule</td>
<td style="width: 501px;">A rule name or an array of rule names to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">from_zone</td>
<td style="width: 501px;">A source zone name or an array of source zone names to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">to_zone</td>
<td style="width: 501px;">A destination zone name or an array of zone names to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">port</td>
<td style="width: 501px;">A destination port number or an array of destination port numbers to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">action</td>
<td style="width: 501px;">An action name or an array of action names to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">query</td>
<td style="width: 501px;">A free-text query for which to search. This forms the WHERE part of the query, for example, !cortex-query-traffic-logs query="src LIKE '192.168.1.*' AND dst='8.8.8.8'"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">fields</td>
<td style="width: 501px;">The fields that are selected in the query. Selection can be "all" (same as *) or a list of specific fields in the table. List of fields can be found after viewing all the outputed fields with all.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">startTime</td>
<td style="width: 501px;">The query start time. For example, startTime="2018-04-26 00:00:00"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">endTime</td>
<td style="width: 501px;">The query end time. For example, endTime="2018-04-26 00:00:00".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">timeRange</td>
<td style="width: 501px;">The time range for the query, used with the rangeValue argument. The following example runs the query on the previous week, timeRange="weeks" timeValue="1".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">rangeValue</td>
<td style="width: 501px;">The time value for the query, used with the timeRange argument. The following example runs the query on the previous week, timeRange="weeks" timeValue="1".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">limit</td>
<td style="width: 501px;">The number of logs to return. Default is 5.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 300px;"><strong>Path</strong></th>
<th style="width: 42px;"><strong>Type</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Action</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Identifies the action that the firewall took for the network traffic.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.RiskOfApp</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Indicates the risk of the application, from a network security perspective. The risk range is 1-5, where 5 is the riskiest.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Natsport</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Post-NAT source port.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.SessionID</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Identifies the firewall's internal identifier for a specific network session.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Packets</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Number of total packets (transmit and receive) seen for the session.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.CharacteristicOfApp</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Identifies the behaviorial characteristic of the application associated with the network traffic.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.App</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Application associated with the network traffic.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Vsys</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Virtual system associated with the network traffic.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Nat</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.ReceiveTime</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Time the log was received at the management plane.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.SubcategoryOfApp</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Identifies the application's subcategory. The subcategory is related to the application's category,</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Users</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Srcuser or dstuser or srcip (one of).</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Proto</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">IP protocol associated with the session.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.TunneledApp</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Whether the application is tunneled.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Natdport</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Post-NAT destination port.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Dst</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Original destination IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Natdst</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Rule</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Name of the security policy rule that the network traffic matched.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Dport</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Network traffic's destination port. If this value is 0, then the app is using its standard port.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Elapsed</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Total time taken for the network session to complete.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.DeviceName</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">The hostname of the firewall that logged the network traffic.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Subtype</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Traffic log subtype. Values are: start, end, drop, deny.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.TimeReceived</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Time the log was received at the management plane.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.SessionEndReason</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">The reason a session terminated. If the termination had multiple causes. This field displays only the highest priority reason.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Natsrc</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Src</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Original source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Start</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Time when the session was established.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.TimeGenerated</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Time the log was generated on the data plane.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.CategoryOfApp</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Identifies the high-level family of the application.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Srcloc</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Dstloc</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Serial</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Serial number of the firewall that generated the log.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Bytes</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Number of total bytes (transmit and receive).</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.VsysID</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">A unique identifier for a virtual system on a Palo Alto Networks firewall.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.To</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Networking zone to which the traffic was sent.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Category</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">URL category associated with the session (if applicable).</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Sport</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Source port utilized by the session.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.Tunnel</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Type of tunnel.</td>
</tr>
<tr>
<td style="width: 300px;">Cortex.Logging.Traffic.IsPhishing</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">Detected enterprise credential submission by an end user.</td>
</tr>
<tr>
<td style="width: 300px;">IP.Address</td>
<td style="width: 42px;">String</td>
<td style="width: 366px;">IP address.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-query-traffic-logs rule=To_Internet,To_VPN limit=2</pre>
<h5>Context Example</h5>
<pre>{
    "Cortex.Logging.Traffic": [
        {
            "Action": "allow",
            "App": "dns",
            "Bytes": 309,
            "Category": "any",
            "CategoryOfApp": "networking",
            "CharacteristicOfApp": [
                "able-to-transfer-file",
                "tunnel-other-application",
                "is-saas"
            ],
            "DeviceName": "DEVICE NAME",
            "Dport": 53,
            "Dst": "8.8.8.8",
            "Dstloc": "US",
            "Elapsed": 1,
            "Natdst": "0.0.0.0",
            "Natsrc": "0.0.0.0",
            "Packets": 2,
            "Proto": "udp",
            "ReceiveTime": 1571995273,
            "RiskOfApp": "3",
            "Rule": "To_Internet",
            "Serial": "007051000058440",
            "SessionEndReason": "aged-out",
            "SessionID": 107112,
            "Sport": 34105,
            "Src": "8.8.8.8",
            "Srcloc": "10.0.0.0-10.255.255.255",
            "Start": 1571995220,
            "SubcategoryOfApp": "infrastructure",
            "Subtype": "end",
            "TimeGenerated": 1571995250,
            "TimeReceived": 1571995250,
            "To": "internet",
            "Tunnel": "N/A",
            "TunneledApp": "untunneled",
            "Users": "8.8.8.8",
            "Vsys": "vsys1",
            "VsysID": 1,
            "id": "42635546_lcaas:4:2012540:1",
            "score": 1.9452807
        },
        {
            "Action": "allow",
            "App": "dns",
            "Bytes": 309,
            "Category": "any",
            "CategoryOfApp": "networking",
            "CharacteristicOfApp": [
                "able-to-transfer-file",
                "tunnel-other-application",
                "is-saas"
            ],
            "DeviceName": "DEVICE NAME",
            "Dport": 53,
            "Dst": "8.8.8.8",
            "Dstloc": "US",
            "Natdst": "0.0.0.0",
            "Natsrc": "0.0.0.0",
            "Packets": 2,
            "Proto": "udp",
            "ReceiveTime": 1571995273,
            "RiskOfApp": "3",
            "Rule": "To_Internet",
            "Serial": "007051000058440",
            "SessionEndReason": "aged-out",
            "SessionID": 225363,
            "Sport": 50230,
            "Src": "8.8.8.8",
            "Srcloc": "10.0.0.0-10.255.255.255",
            "Start": 1571995222,
            "SubcategoryOfApp": "infrastructure",
            "Subtype": "end",
            "TimeGenerated": 1571995251,
            "TimeReceived": 1571995251,
            "To": "internet",
            "Tunnel": "N/A",
            "TunneledApp": "untunneled",
            "Users": "8.8.8.8",
            "Vsys": "vsys1",
            "VsysID": 1,
            "id": "42635546_lcaas:4:2012540:8",
            "score": 1.9452807
        }
    ],
    "IP": [
        {
            "Address": "8.8.8.8"
        },
        {
            "Address": "0.0.0.0"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Logs traffic table</h3>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 122px;"><strong>Source Address</strong></th>
<th style="width: 162px;"><strong>Destination Address</strong></th>
<th style="width: 90px;"><strong>Application</strong></th>
<th style="width: 50px;"><strong>Action</strong></th>
<th style="width: 83px;"><strong>Rule</strong></th>
<th style="width: 162px;"><strong>Time Generated</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 122px;">8.8.8.8</td>
<td style="width: 162px;">8.8.8.8</td>
<td style="width: 90px;">dns</td>
<td style="width: 50px;">allow</td>
<td style="width: 83px;">To_Internet</td>
<td style="width: 162px;">2019-10-25T09:20:50</td>
</tr>
<tr>
<td style="width: 122px;">8.8.8.8</td>
<td style="width: 162px;">8.8.8.8</td>
<td style="width: 90px;">dns</td>
<td style="width: 50px;">allow</td>
<td style="width: 83px;">To_Internet</td>
<td style="width: 162px;">2019-10-25T09:20:51</td>
</tr>
</tbody>
</table>
<h3>Additional Information</h3>
<p>If the user is using the command with field="all" then the human readable output will contain the following fields: Source Address, Destination Address, Application, Action, Rule &amp; Time Generated. If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: field1, field2 &amp; field3.</p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_cf65d1a7-d7ca-4a51-8e0d-1e6dbc499a41">6. Query threat logs</h3>
<hr>
<p>Searches the Cortex panw.threat table, which is the threat logs table for PAN-OS/Panorama.</p>
<h5>Base Command</h5>
<p><code>cortex-query-threat-logs</code></p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 498px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">ip</td>
<td style="width: 498px;">An IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">rule</td>
<td style="width: 498px;">Rule name or array of rule names to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">from_zone</td>
<td style="width: 498px;">Source zone or array of zones to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">to_zone</td>
<td style="width: 498px;">Destination zone or array of zones to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">port</td>
<td style="width: 498px;">Port or array of ports to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">action</td>
<td style="width: 498px;">Action or array of actions lo search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">query</td>
<td style="width: 498px;">Free input query to search. This is the WHERE part of the query. so an example will be !cortex-query-traffic-logs query="src LIKE '192.168.1.*' AND dst = '192.168.1.12'"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">fields</td>
<td style="width: 498px;">The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">hash</td>
<td style="width: 498px;">SHA256 hash or array of SHA256 hashes to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">url</td>
<td style="width: 498px;">URL or array of URLs to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">startTime</td>
<td style="width: 498px;">The query start time. For example, startTime="2018-04-26 00:00:00"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">endTime</td>
<td style="width: 498px;">The query end time. For example, endTime="2018-04-26 00:00:00"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">timeRange</td>
<td style="width: 498px;">The time range for the query, used with the rangeValue argument. For example, timeRange="weeks" timeValue="1" would run the query on the previous week.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">rangeValue</td>
<td style="width: 498px;">The time value for the query, used with the timeRange argument. For example, timeRange="weeks" rangeValue="1" would run the query on the previous week.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">limit</td>
<td style="width: 498px;">The number of logs to return. Default is 5.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<p>t</p>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 310px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 346px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.SessionID</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Identifies the firewall's internal identifier for a specific network session.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Action</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Identifies the action that the firewall took for the network traffic.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.App</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Application associated with the network traffic.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Nat</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.SubcategoryOfApp</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category_of_app.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.PcapID</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Packet capture (pcap) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap_id of 0 (no associated pcap) , or an ID referencing the extended pcap file.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Natdst</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Flags</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Dport</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Network traffic's destination port. If this value is 0, then the app is using its standard port.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.ThreatID</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Natsrc</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.CategoryOfApp</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Identifies the managing application, or parent, of the application associated with this network traffic, if any.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Srcloc</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Dstloc</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.To</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Networking zone to which the traffic was sent.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.RiskOfApp</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Indicates how risky the application is from a network security perspective. Values range from 1-5, where 5 is the riskiest.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Natsport</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Post-NAT source port.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.URLDenied</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Session was denied due to a URL filtering rule.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.CharacteristicOfApp</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Identifies the behaviorial characteristic of the application associated with the network traffic.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.HTTPMethod</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Only in URL filtering logs. Describes the HTTP Method used in the web request</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.From</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The networking zone from which the traffic originated.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Vsys</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Virtual system associated with the network traffic.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.ReceiveTime</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Time the log was received at the management plane.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Users</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Srcuser or dstuser or srcip (one of).</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Proto</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">IP protocol associated with the session.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Natdport</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Post-NAT destination port.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Dst</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Original destination IP address. The IP address is an IPv4/ IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Rule</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Name of the security policy rule that the network traffic matched.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.CategoryOfThreatID</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Threat category of the detected threat.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.DeviceName</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The hostname of the firewall that logged the network traffic.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Subtype</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Subtype of the threat log.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.TimeReceived</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Time the log was received at the management plane.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Direction</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Indicates the direction of the attack, client-to-server or server-to-client:</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Misc</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The meaning of this field differs according to the log's subtype: Subtype is URL, this field contains the requested URI. Subtype is File, this field contains the file name or file type. Subtype is Virus, this field contains the file name. Subtype is WildFire, this field contains the file name.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Severity</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Severity associated with the event.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Src</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Original source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.TimeGenerated</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Time the log was generated on the data plane.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Serial</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Serial number of the firewall that generated the log.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.VsysID</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">A unique identifier for a virtual system on a Palo Alto Networks firewall.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.URLDomain</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The name of the internet domain that was visited in this session.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Category</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">For the URL subtype, this identifies the URL Category. For the WildFire subtype, this identifies the verdict on the file. It is one of ‘malicious’, ‘phishing’, ‘grayware’, or ‘benign’;</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.Sport</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">Source port utilized by the session.</td>
</tr>
<tr>
<td style="width: 310px;">Cortex.Logging.Threat.IsPhishing</td>
<td style="width: 52px;">Boolean</td>
<td style="width: 346px;">Detected enterprise credential submission by an end user.</td>
</tr>
<tr>
<td style="width: 310px;">IP.Address</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">IP address.</td>
</tr>
<tr>
<td style="width: 310px;">Domain.Name</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The domain name, for example: "google.com".</td>
</tr>
<tr>
<td style="width: 310px;">File.SHA256</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 310px;">File.Name</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The full file name (including file extension).</td>
</tr>
<tr>
<td style="width: 310px;">File.Type</td>
<td style="width: 52px;">String</td>
<td style="width: 346px;">The file type, as determined by libmagic (same as displayed in file entries).</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-query-threat-logs fields=src,dst ip=8.8.8.8 limit=1</pre>
<h5>Context Example</h5>
<pre>{
    "Cortex.Logging.Threat": [
        {
            "Dst": "7.7.7.7",
            "Src": "8.8.8.8",
            "id": "42635546_lcaas:4:2023012:4",
            "score": 4.7690573
        }
    ],
    "IP": [
        {
            "Address": "8.8.8.8"
        },
        {
            "Address": "7.7.7.7"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Logs threat table</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>src</strong></th>
<th><strong>dst</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>8.8.8.8</td>
<td>7.7.7.7</td>
</tr>
</tbody>
</table>
<h3>Additional Information</h3>
<p>If the user is using the command with field="all" then the human readable output will contain the following fields: Source Address, Destination Address, Application, Action, Rule &amp; Time Generated. If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: field1, field2 &amp; field3.</p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_453996b5-7677-4812-ae96-1947d005bd1c">7. Query Traps logs</h3>
<hr>
<p>Searches the Cortex tms.threat table, which is the threat logs table for the Traps endpoint protection and response.</p>
<h5>Base Command</h5>
<p><code>cortex-query-traps-logs</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">ip</td>
<td style="width: 501px;">IP or array of IPs to search for example 1.1.1.1,2.2.2.2.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">host</td>
<td style="width: 501px;">Host or array of hosts to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">user</td>
<td style="width: 501px;">User or an array or users to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">category</td>
<td style="width: 501px;">Category or array of categories to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">hash</td>
<td style="width: 501px;">Hash or array of hashes to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">query</td>
<td style="width: 501px;">Free-text input query to search. This is the WHERE part of the query so an example will be src = '1.1.1.1' OR rule = 'test rule'.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">fields</td>
<td style="width: 501px;">The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">startTime</td>
<td style="width: 501px;">The query start time. For example, startTime="2018-04-26 00:00:00".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">endTime</td>
<td style="width: 501px;">The query end time. For example, endTime="2018-04-26 00:00:00".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">timeRange</td>
<td style="width: 501px;">The time range for the query, used with the rangeValue argument. For example, timeRange="weeks" timeValue="1" would run the query on the previous week.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">rangeValue</td>
<td style="width: 501px;">The time value for the query, used with the timeRange argument. For example, timeRange="weeks" rangeValue="1" would run the query on the previous week.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">limit</td>
<td style="width: 501px;">The number of logs to return. Default is 5.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 782px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 503px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 186px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.Severity</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Severity level associated with the event.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.AgentID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Unique identifier for the Traps agent.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.OsType</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Operating system of the endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.IsVdi</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Indicates whether the endpoint is a virtual desktop infrastructure (VDI).</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.OSVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Full version number of the operating system running on the endpoint. For example, 6.1.7601.19135.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.Is64</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Indicates whether the endpoint is running a 64-bit version of Windows.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.AgentIP</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.DeviceName</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Hostname of the endpoint on which the event was logged.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.DeviceDomain</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Domain to which the endpoint belongs.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.Username</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The username on which the event was logged.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.AgentTime</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Universal Time Coordinated (UTC) equivalent of the time at which an agent logged an event. ISO-8601 string representation.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.AgentVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Version of the Traps agent.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EndPointHeader.ProtectionStatus</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The Traps agent status.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.RecordType</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Record type associated with the event.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.TrapsID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Tenant external ID.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.EventType</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Subtype of the event.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.UUID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Unique identifier for the event in Cortex.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.ServerHost</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Hostname of the Traps management service.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.GeneratedTime</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Universal Time Coordinated (UTC) equivalent of the time at which an event was logged.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.ServerComponentVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Software version of the Traps management service.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.RegionID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Region ID.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.CustomerID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Customer ID.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.ServerTime</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Universal Time Coordinated (UTC) equivalent of the time at which the server generated the log. If the log was generated on an endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.OriginalAgentTime</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Original time on the endpoint device.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.Facility</td>
<td style="width: 53px;">Sting</td>
<td style="width: 186px;">The Traps system component that initiated the event For example:, TrapsAgent, TrapsServiceCore, TrapsServiceManagement, TrapsServiceBackend.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.PreventionKey</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Unique identifier for security events.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Processes.PID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Process identifier.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Processes.ParentID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Parent process identifier.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Processes.ExeFileIdx</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Index of target files for specific security events such as: Scanning, Malicious DLL, Malicious Macro events.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Processes.UserIdx</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Index of users.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Processes.CommandLine</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Command line executed with the process.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Processes.Terminated</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Termination action taken on the file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Files.RawFullPath</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Full path for the executed file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Files.FileName</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">File name.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Files.SHA256</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Files.FileSize</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">File size.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Users.Username</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Username of the active user on the endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Users.Domain</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Domain to which the user account belongs.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.PostDetected</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Was post detected.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Terminate</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Termination action taken on the file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Verdict</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Traps verdict for the file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.Blocked</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Block action taken on the file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.TargetProcessIdx</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The prevention target process index in the processes array.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.ModuleCategory</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Security module name.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.PreventionMode</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The prevention mode used.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.TrapsSeverity</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Traps Severity level associated with the event defined for the Traps management service.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.User.Username</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source username initiating the process.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.PID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process ID (PID).</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.ParentID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Parent ID for the source process.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.CommandLine</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process command line.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.InstanceID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Traps instance ID.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.Terminated</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process termination action taken on the file.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.RawFullPath</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process raw full path.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.FileName</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process file name.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.SHA256</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process SHA256 hash.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.FileSize</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process file size.</td>
</tr>
<tr>
<td style="width: 503px;">Cortex.Logging.Traps.MessageData.SourceProcess.InnerObjectSHA256</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Source process inner object SHA256 hash</td>
</tr>
<tr>
<td style="width: 503px;">Endpoint.Hostname</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The hostname that is mapped to this endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Endpoint.IPAddress</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Endpoint.Domain</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The domain of the endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Endpoint.OSVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">OS version.</td>
</tr>
<tr>
<td style="width: 503px;">Endpoint.OS</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Endpoint OS.</td>
</tr>
<tr>
<td style="width: 503px;">Endpoint.ID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The unique ID within the tool retrieving the endpoint.</td>
</tr>
<tr>
<td style="width: 503px;">Host.Hostname</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 503px;">Host.IPAddress</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The IP address of the host.</td>
</tr>
<tr>
<td style="width: 503px;">Host.Domain</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The domain of the host.</td>
</tr>
<tr>
<td style="width: 503px;">Host.OSVersion</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The OS version of the host.</td>
</tr>
<tr>
<td style="width: 503px;">Host.OS</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Host OS.</td>
</tr>
<tr>
<td style="width: 503px;">Host.ID</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The unique ID within the tool retrieving the host.</td>
</tr>
<tr>
<td style="width: 503px;">Process.PID</td>
<td style="width: 53px;">Number</td>
<td style="width: 186px;">The PID of the process.</td>
</tr>
<tr>
<td style="width: 503px;">Process.Parent</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">Parent process objects.</td>
</tr>
<tr>
<td style="width: 503px;">Process.CommandLine</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The full command line (including arguments).</td>
</tr>
<tr>
<td style="width: 503px;">Process.SHA256</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The SHA256 hash of the process.</td>
</tr>
<tr>
<td style="width: 503px;">Process.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The name of the process.</td>
</tr>
<tr>
<td style="width: 503px;">Process.Path</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The file system path to the binary file.</td>
</tr>
<tr>
<td style="width: 503px;">File.Name</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The full file name (including file extension).</td>
</tr>
<tr>
<td style="width: 503px;">File.Type</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The file type, as determined by libmagic (same as displayed in file entries).</td>
</tr>
<tr>
<td style="width: 503px;">File.Path</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The path where the file is located.</td>
</tr>
<tr>
<td style="width: 503px;">File.Size</td>
<td style="width: 53px;">Number</td>
<td style="width: 186px;">The size of the file in bytes.</td>
</tr>
<tr>
<td style="width: 503px;">File.SHA256</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 503px;">File.DigitalSignature.Publisher</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The publisher of the digital signature for the file.</td>
</tr>
<tr>
<td style="width: 503px;">File.Company</td>
<td style="width: 53px;">String</td>
<td style="width: 186px;">The name of the company that released a binary.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-query-traps-logs startTime=2011-10-25T00:00:31 endTime=2019-10-27T00:00:31 fields=endPointHeader.userName limit=4 user=administrator,tim,josh</pre>
<h5>Context Example</h5>
<pre>{
    "Cortex.Logging.Traps": [
        {
            "EndPointHeader": {
                "Username": "administrator"
            },
            "id": "9c8228bd-c26b-452c-855f-bbd83070809f",
            "score": 1.452933
        },
        {
            "EndPointHeader": {
                "Username": "administrator"
            },
            "id": "8d54c329-5ef7-4563-9018-a1b69cb90bbd",
            "score": 1.452933
        },
        {
            "EndPointHeader": {
                "Username": "administrator"
            },
            "id": "cbdf7fc6-5fa3-4090-aa3d-4f0aaf3b45d9",
            "score": 1.452933
        },
        {
            "EndPointHeader": {
                "Username": "administrator"
            },
            "id": "df2ef772-ce37-41a5-a4de-bacee0135d58",
            "score": 1.452933
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Logs traps table</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>endPointHeader.userName</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>administrator</td>
</tr>
<tr>
<td>administrator</td>
</tr>
<tr>
<td>administrator</td>
</tr>
<tr>
<td>administrator</td>
</tr>
</tbody>
</table>
<h3>Additional Information</h3>
<p>If the user is using the command with field="all" then the human readable output will contain the following fields: Severity, Event Type, User, Agent Address, Agent Name &amp; Agent Time. If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: field1, field2 &amp; field3.</p>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3 id="h_efdac8d4-7749-42ca-9da9-51a676dbd51f">8. Query analytics logs</h3>
<hr>
<p>Searches the Cortex tms.analytics table, which is the endpoint logs table for Traps Analytics.</p>
<h5>Base Command</h5>
<p><code>cortex-query-analytics-logs</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">ip</td>
<td style="width: 497px;">Agent IP or array of agent IP to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">host</td>
<td style="width: 497px;">Agent host name or array of agent host names to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">user</td>
<td style="width: 497px;">Username or array of usernames to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">category</td>
<td style="width: 497px;">Event category or array of event categories to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">hash</td>
<td style="width: 497px;">Hash or array of hashes to search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">query</td>
<td style="width: 497px;">Free-text input query to search. This forms the WHERE part of the query. For example, endPointHeader.agentIp = '1.1.1.1'.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">fields</td>
<td style="width: 497px;">The fields that are selected in the query. Selection can be "all" (same as *) or a list of specific fields in the table. You can find the list of fields after viewing all the outputed fields with "all".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">startTime</td>
<td style="width: 497px;">The query start time. For example, startTime="2018-04-26 00:00:00".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">endTime</td>
<td style="width: 497px;">The query end time. For example, endTime="2018-04-26 00:00:00".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">timeRange</td>
<td style="width: 497px;">The time range for the query, used with the rangeValue argument. For example, timeRange="weeks" timeValue="1" would run the query on the previous week.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">rangeValue</td>
<td style="width: 497px;">The time value for the query, used with the timeRange argument. For example, timeRange="weeks" rangeValue="1" would run the query on the previous week.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">limit</td>
<td style="width: 497px;">The number of logs to return. Default is 5.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width: 774px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 500px;"><strong>Path</strong></th>
<th style="width: 48px;"><strong>Type</strong></th>
<th style="width: 186px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.AgentID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Unique identifier for the Traps agent.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.OsType</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Operating system of the endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.IsVdi</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Indicates whether the endpoint is a virtual desktop infrastructure (VDI).</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.OSVersion</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Full version number of the operating system running on the endpoint. For example, 6.1.7601.19135.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.Is64</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Indicates whether the endpoint is running a 64-bit version of Windows.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.AgentIP</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.DeviceName</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Hostname of the endpoint on which the event was logged.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.DeviceDomain</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Domain to which the endpoint belongs.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.Username</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The username on which the event was logged.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.UserDomain</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Username of the active user on the endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.AgentTime</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Universal Time Coordinated (UTC) equivalent of the time at which an agent logged an event. ISO-8601 string representation.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.AgentVersion</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Version of the Traps agent.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.ProtectionStatus</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Status of the Traps protection.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EndPointHeader.DataCollectionStatus</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Status of the agent logging.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.TrapsID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Tenant external ID.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.EventType</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Subtype of event.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.UUID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Event unique ID.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.GeneratedTime</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Universal Time Coordinated (UTC) equivalent of the time at which an event was logged. For agent events, this represents the time on the endpoint. For policy, configuration, and system events, this represents the time on the Traps management service. ISO-8601 string representation (for example, 2017-01-24T09:08:59Z).</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.RegionID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">ID of the Traps management service region.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.OriginalAgentTime</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Original timestamp for endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.Facility</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The Traps system component that initiated the event, for example TrapsAgent, TrapsServiceCore, TrapsServiceManagement, TrapsServiceBackend.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.type</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Type of file.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.SHA256</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.FileName</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">File name, without the path or the file type extension.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.FilePath</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Full path, aligned with OS format.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.FileSize</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Size of the file in bytes.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.Reported</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Whether the file was reported.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.Blocked</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Whether the file was blocked.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.LocalAnalysisResult.Trusted</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Trusted signer result.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.LocalAnalysisResult.Publishers</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">File publisher.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.LocalAnalysisResult.TrustedID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Trusted ID.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.ExecutionCount</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">File execution count.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.MessageData.LastSeen</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The date the file was last seen.</td>
</tr>
<tr>
<td style="width: 500px;">Cortex.Logging.Analytics.Severity</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The threat severity.</td>
</tr>
<tr>
<td style="width: 500px;">Endpoint.Hostname</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The hostname that is mapped to this endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Endpoint.IPAddress</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Endpoint.Domain</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The domain of the endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Endpoint.OSVersion</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">OS version.</td>
</tr>
<tr>
<td style="width: 500px;">Endpoint.OS</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Endpoint OS.</td>
</tr>
<tr>
<td style="width: 500px;">Endpoint.ID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The unique ID within the tool retrieving the endpoint.</td>
</tr>
<tr>
<td style="width: 500px;">Host.Hostname</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 500px;">Host.IPAddress</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The IP address of the host.</td>
</tr>
<tr>
<td style="width: 500px;">Host.Domain</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The domain of the host.</td>
</tr>
<tr>
<td style="width: 500px;">Host.OSVersion</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The OS version of the host.</td>
</tr>
<tr>
<td style="width: 500px;">Host.OS</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">Host OS.</td>
</tr>
<tr>
<td style="width: 500px;">Host.ID</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The unique ID within the tool retrieving the host.</td>
</tr>
<tr>
<td style="width: 500px;">File.Name</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The full file name (including file extension).</td>
</tr>
<tr>
<td style="width: 500px;">File.Type</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The file type, as determined by libmagic (same as displayed in file entries).</td>
</tr>
<tr>
<td style="width: 500px;">File.Path</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The path where the file is located.</td>
</tr>
<tr>
<td style="width: 500px;">File.Size</td>
<td style="width: 48px;">Number</td>
<td style="width: 186px;">The size of the file in bytes.</td>
</tr>
<tr>
<td style="width: 500px;">File.SHA256</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 500px;">File.DigitalSignature.Publisher</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The publisher of the digital signature for the file.</td>
</tr>
<tr>
<td style="width: 500px;">File.Company</td>
<td style="width: 48px;">String</td>
<td style="width: 186px;">The name of the company that released a binary.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5>Command Example</h5>
<pre>!cortex-query-analytics-logs fields=all host=DC1ENV9APC51 user=Administrator</pre>
<h5>Context Example</h5>
<pre>{
    "Cortex.Logging.Analytics": [
        {
            "AgentID": "30e55fb7590b0a907906b5620960931f",
            "EndPointHeader": {
                "AgentIP": "8.8.8.8",
                "AgentTime": "2019-10-26T14:20:08.124Z",
                "AgentVersion": "6.0.0.4961",
                "DeviceDomain": "DEVICE DOMAIN",
                "DeviceName": "DEVICE NAME",
                "Is64": "The endpoint is running x64 architecture",
                "IsVdi": "",
                "OSVersion": "10.0.17134",
                "OsType": "Windows",
                "ProtectionStatus": 0,
                "UserDomain": "USER DOMAIN",
                "Username": "Administrator"
            },
            "EventType": "AgentTimelineEvent",
            "Facility": "TrapsAgent",
            "GeneratedTime": "2019-10-26T14:20:08.124Z",
            "MessageData": {
                "@type": "type.googleapis.com/cloud_api.HashEventObject",
                "Blocked": 0,
                "ExecutionCount": 49616,
                "FileName": "backgroundTaskHost.exe",
                "FilePath": "C:\\Windows\\System32\\",
                "FileSize": 19352,
                "LastSeen": "2019-10-26T14:20:00.532694200Z",
                "LocalAnalysisResult": {
                    "Publishers": [
                        "Microsoft Windows"
                    ],
                    "Trusted": "None",
                    "TrustedID": ""
                },
                "Reported": 0,
                "SHA256": "48b9eb1e31b0c2418742ce07675d58c974dd9f03007988c90c1e38f217f5c65b",
                "Type": "pe"
            },
            "OriginalAgentTime": "2019-10-26T14:20:00.532694200Z",
            "RegionID": "Americas (N. Virginia)",
            "TrapsID": "8692543548339348938",
            "UUID": "8dc1aaa6-7d38-4c7d-89b3-d37fe1e9008d",
            "id": "8dc1aaa6-7d38-4c7d-89b3-d37fe1e9008d",
            "score": 5.3399997
        },
        {
            "AgentID": "30e55fb7590b0a907906b5620960931f",
            "EndPointHeader": {
                "AgentIP": "8.8.8.8",
                "AgentTime": "2019-10-26T14:19:51.853Z",
                "AgentVersion": "6.0.0.4961",
                "DeviceDomain": "DEVICE DOMAIN",
                "DeviceName": "DEVICE NAME",
                "Is64": "The endpoint is running x64 architecture",
                "IsVdi": "",
                "OSVersion": "10.0.17134",
                "OsType": "Windows",
                "ProtectionStatus": 0,
                "UserDomain": "USER DOMAIN",
                "Username": "Administrator"
            },
            "EventType": "AgentTimelineEvent",
            "Facility": "TrapsAgent",
            "GeneratedTime": "2019-10-26T14:19:51.853Z",
            "MessageData": {
                "@type": "type.googleapis.com/cloud_api.HashEventObject",
                "Blocked": 0,
                "ExecutionCount": 9612,
                "FileName": "SearchProtocolHost.exe",
                "FilePath": "C:\\Windows\\System32\\",
                "FileSize": 406528,
                "LastSeen": "2019-10-26T14:19:44.261083400Z",
                "LocalAnalysisResult": {
                    "Publishers": [
                        "Microsoft Windows"
                    ],
                    "Trusted": "None",
                    "TrustedID": ""
                },
                "Reported": 0,
                "SHA256": "aee8842a078b3cf5566b3c95e4b521c2639e878fa4749a58d69700452c051261",
                "Type": "pe"
            },
            "OriginalAgentTime": "2019-10-26T14:19:44.261083400Z",
            "RegionID": "Americas (N. Virginia)",
            "TrapsID": "8692543548339348938",
            "UUID": "ebb20522-07db-4f1f-9a04-439e661d079e",
            "id": "ebb20522-07db-4f1f-9a04-439e661d079e",
            "score": 5.3399997
        },
        {
            "AgentID": "30e55fb7590b0a907906b5620960931f",
            "EndPointHeader": {
                "AgentIP": "8.8.8.8",
                "AgentTime": "2019-10-26T14:19:51.884Z",
                "AgentVersion": "6.0.0.4961",
                "DeviceDomain": "DEVICE DOMAIN",
                "DeviceName": "DEVICE NAME",
                "Is64": "The endpoint is running x64 architecture",
                "IsVdi": "",
                "OSVersion": "10.0.17134",
                "OsType": "Windows",
                "ProtectionStatus": 0,
                "UserDomain": "USER DOMAIN",
                "Username": "Administrator"
            },
            "EventType": "AgentTimelineEvent",
            "Facility": "TrapsAgent",
            "GeneratedTime": "2019-10-26T14:19:51.884Z",
            "MessageData": {
                "@type": "type.googleapis.com/cloud_api.HashEventObject",
                "Blocked": 0,
                "ExecutionCount": 9613,
                "FileName": "SearchFilterHost.exe",
                "FilePath": "C:\\Windows\\System32\\",
                "FileSize": 227328,
                "LastSeen": "2019-10-26T14:19:44.292322500Z",
                "LocalAnalysisResult": {
                    "Publishers": [
                        "Microsoft Windows"
                    ],
                    "Trusted": "None",
                    "TrustedID": ""
                },
                "Reported": 0,
                "SHA256": "6c033c5c65e3d788c66aa9079ce69e882a74dd14bd3d7539ad76ec7f13a34b8a",
                "Type": "pe"
            },
            "OriginalAgentTime": "2019-10-26T14:19:44.292322500Z",
            "RegionID": "Americas (N. Virginia)",
            "TrapsID": "8692543548339348938",
            "UUID": "3cd17b17-a0de-492d-81d9-ac6584757305",
            "id": "3cd17b17-a0de-492d-81d9-ac6584757305",
            "score": 5.3399997
        },
        {
            "AgentID": "30e55fb7590b0a907906b5620960931f",
            "EndPointHeader": {
                "AgentIP": "8.8.8.8",
                "AgentTime": "2019-10-26T14:20:08.124Z",
                "AgentVersion": "6.0.0.4961",
                "DeviceDomain": "DEVICE DOMAIN",
                "DeviceName": "DEVICE NAME",
                "Is64": "The endpoint is running x64 architecture",
                "IsVdi": "",
                "OSVersion": "10.0.17134",
                "OsType": "Windows",
                "ProtectionStatus": 0,
                "UserDomain": "USER DOMAIN",
                "Username": "Administrator"
            },
            "EventType": "AgentTimelineEvent",
            "Facility": "TrapsAgent",
            "GeneratedTime": "2019-10-26T14:20:08.124Z",
            "MessageData": {
                "@type": "type.googleapis.com/cloud_api.HashEventObject",
                "Blocked": 0,
                "ExecutionCount": 83238,
                "FileName": "conhost.exe",
                "FilePath": "C:\\Windows\\System32\\",
                "FileSize": 625664,
                "LastSeen": "2019-10-26T14:20:00.532694200Z",
                "LocalAnalysisResult": {
                    "Publishers": [
                        "Microsoft Windows"
                    ],
                    "Trusted": "None",
                    "TrustedID": ""
                },
                "Reported": 0,
                "SHA256": "04b6a35bc504401989b9e674c57c9e84d0cbdbbd9d8ce0ce83d7ceca0b7175ed",
                "Type": "pe"
            },
            "OriginalAgentTime": "2019-10-26T14:20:00.532694200Z",
            "RegionID": "Americas (N. Virginia)",
            "TrapsID": "8692543548339348938",
            "UUID": "fb53ea16-c9c7-4e3c-b6bf-179f9e89a4bb",
            "id": "fb53ea16-c9c7-4e3c-b6bf-179f9e89a4bb",
            "score": 5.3399997
        },
        {
            "AgentID": "30e55fb7590b0a907906b5620960931f",
            "EndPointHeader": {
                "AgentIP": "8.8.8.8",
                "AgentTime": "2019-10-26T14:20:08.202Z",
                "AgentVersion": "6.0.0.4961",
                "DeviceDomain": "DEVICE DOMAIN",
                "DeviceName": "DEVICE NAME",
                "Is64": "The endpoint is running x64 architecture",
                "IsVdi": "",
                "OSVersion": "10.0.17134",
                "OsType": "Windows",
                "ProtectionStatus": 0,
                "UserDomain": "USER DOMAIN",
                "Username": "Administrator"
            },
            "EventType": "AgentTimelineEvent",
            "Facility": "TrapsAgent",
            "GeneratedTime": "2019-10-26T14:20:08.202Z",
            "MessageData": {
                "@type": "type.googleapis.com/cloud_api.HashEventObject",
                "Blocked": 0,
                "ExecutionCount": 73500,
                "FileName": "timeout.exe",
                "FilePath": "C:\\Windows\\System32\\",
                "FileSize": 30720,
                "LastSeen": "2019-10-26T14:20:00.610816500Z",
                "LocalAnalysisResult": {
                    "Publishers": [
                        "Microsoft Windows"
                    ],
                    "Trusted": "None",
                    "TrustedID": ""
                },
                "Reported": 0,
                "SHA256": "b7d686c4c92d1c0bbf1604b8c43684e227353293b3206a1220bab77562504b3c",
                "Type": "pe"
            },
            "OriginalAgentTime": "2019-10-26T14:20:00.610816500Z",
            "RegionID": "Americas (N. Virginia)",
            "TrapsID": "8692543548339348938",
            "UUID": "df8ff6a8-65b2-4932-b7da-c56ddc84f1c3",
            "id": "df8ff6a8-65b2-4932-b7da-c56ddc84f1c3",
            "score": 5.3399997
        }
    ],
    "Endpoint": [
        {
            "Domain": "DEVICE DOMAIN",
            "Hostname": "DEVICE NAME",
            "ID": "30e55fb7590b0a907906b5620960931f",
            "IP": "8.8.8.8",
            "OS": "Windows",
            "OSVersion": "10.0.17134"
        }
    ],
    "File": [
        {
            "DigitalSignature.Publisher": [
                "Microsoft Windows"
            ],
            "Name": "backgroundTaskHost.exe",
            "Path": "C:\\Windows\\System32\\",
            "SHA256": "48b9eb1e31b0c2418742ce07675d58c974dd9f03007988c90c1e38f217f5c65b",
            "Size": 19352,
            "Type": "pe"
        },
        {
            "DigitalSignature.Publisher": [
                "Microsoft Windows"
            ],
            "Name": "SearchProtocolHost.exe",
            "Path": "C:\\Windows\\System32\\",
            "SHA256": "aee8842a078b3cf5566b3c95e4b521c2639e878fa4749a58d69700452c051261",
            "Size": 406528,
            "Type": "pe"
        },
        {
            "DigitalSignature.Publisher": [
                "Microsoft Windows"
            ],
            "Name": "SearchFilterHost.exe",
            "Path": "C:\\Windows\\System32\\",
            "SHA256": "6c033c5c65e3d788c66aa9079ce69e882a74dd14bd3d7539ad76ec7f13a34b8a",
            "Size": 227328,
            "Type": "pe"
        },
        {
            "DigitalSignature.Publisher": [
                "Microsoft Windows"
            ],
            "Name": "conhost.exe",
            "Path": "C:\\Windows\\System32\\",
            "SHA256": "04b6a35bc504401989b9e674c57c9e84d0cbdbbd9d8ce0ce83d7ceca0b7175ed",
            "Size": 625664,
            "Type": "pe"
        },
        {
            "DigitalSignature.Publisher": [
                "Microsoft Windows"
            ],
            "Name": "timeout.exe",
            "Path": "C:\\Windows\\System32\\",
            "SHA256": "b7d686c4c92d1c0bbf1604b8c43684e227353293b3206a1220bab77562504b3c",
            "Size": 30720,
            "Type": "pe"
        }
    ],
    "Host": [
        {
            "Domain": "DEVICE DOMAIN",
            "Hostname": "DEVICE NAME",
            "ID": "30e55fb7590b0a907906b5620960931f",
            "IP": "8.8.8.8",
            "OS": "Windows",
            "OSVersion": "10.0.17134"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Logs analytics table</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Event Type</strong></th>
<th><strong>User</strong></th>
<th><strong>Agent Address</strong></th>
<th><strong>Agent Name</strong></th>
<th><strong>Agent Time</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>AgentTimelineEvent</td>
<td>Administrator</td>
<td>8.8.8.8</td>
<td>DEVICE NAME</td>
<td>2019-10-26T14:20:08.124Z</td>
</tr>
<tr>
<td>AgentTimelineEvent</td>
<td>Administrator</td>
<td>8.8.8.8</td>
<td>DEVICE NAME</td>
<td>2019-10-26T14:19:51.853Z</td>
</tr>
<tr>
<td>AgentTimelineEvent</td>
<td>Administrator</td>
<td>8.8.8.8</td>
<td>DEVICE NAME</td>
<td>2019-10-26T14:19:51.884Z</td>
</tr>
<tr>
<td>AgentTimelineEvent</td>
<td>Administrator</td>
<td>8.8.8.8</td>
<td>DEVICE NAME</td>
<td>2019-10-26T14:20:08.124Z</td>
</tr>
<tr>
<td>AgentTimelineEvent</td>
<td>Administrator</td>
<td>8.8.8.8</td>
<td>DEVICE NAME</td>
<td>2019-10-26T14:20:08.202Z</td>
</tr>
</tbody>
</table>
<p><!-- remove the following comments to manually add an image: --> <!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 --></p>
<h3>Additional Information</h3>
<p>If the user is using the command with field="all" then the human readable output will contain the following fields: Severity, Event Type, User, Agent Address, Agent Name &amp; Agent Time. If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: field1, field2 &amp; field3.</p></div>
