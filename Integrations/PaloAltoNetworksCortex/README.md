<h3>5. cortex-query-traffic-logs</h3>
<hr>
<p>Searches the Cortex panw.traffic table, which is the traffic logs table for PAN-OS and Panorama.</p>
<h5>Base Command</h5>
<p>
  <code>cortex-query-traffic-logs</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip</td>
      <td>An IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rule</td>
      <td>A rule name or an array of rule names to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>from_zone</td>
      <td>A source zone  name or an array of source zone names to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>to_zone</td>
      <td>A destination zone name or an array of zone names to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>port</td>
      <td>A destination port number or an array of destination port numbers to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>action</td>
      <td>An action name or an array of action names to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query</td>
      <td>A free-text query for which to search. This forms the WHERE part of the query, for example, !cortex-query-traffic-logs query="src LIKE '192.168.1.*' AND dst='8.8.8.8'"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>The fields that are selected in the query. Selection can be "all" (same as *) or a list of specific fields in the table. List of fields can be found after viewing all the outputed fields with all.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>startTime</td>
      <td>The query start time. For example, startTime="2018-04-26 00:00:00"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>endTime</td>
      <td>The query end time. For example, endTime="2018-04-26 00:00:00".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>timeRange</td>
      <td>The time range for the query, used with the rangeValue argument. The following example runs the query on the previous week, timeRange="weeks" timeValue="1".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rangeValue</td>
      <td>The time value for the query, used with the timeRange argument. The following example runs the query on the previous week, timeRange="weeks" timeValue="1".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The number of logs to return. Default is 5.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Cortex.Logging.Traffic.Action</td>
      <td>String</td>
      <td>Identifies the action that the firewall took for the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.RiskOfApp</td>
      <td>String</td>
      <td>Indicates the risk of the application, from a network security perspective. The risk range is 1-5, where 5 is the riskiest.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Natsport</td>
      <td>String</td>
      <td>Post-NAT source port.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.SessionID</td>
      <td>String</td>
      <td>Identifies the firewall's internal identifier for a specific network session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Packets</td>
      <td>String</td>
      <td>Number of total packets (transmit and receive) seen for the session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.CharacteristicOfApp</td>
      <td>String</td>
      <td>Identifies the behaviorial characteristic of the application associated with the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.App</td>
      <td>String</td>
      <td>Application associated with the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Vsys</td>
      <td>String</td>
      <td>Virtual system associated with the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Nat</td>
      <td>String</td>
      <td>Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.ReceiveTime</td>
      <td>String</td>
      <td>Time the log was received at the management plane.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.SubcategoryOfApp</td>
      <td>String</td>
      <td>Identifies the application's subcategory. The subcategory is related to the application's category,</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Users</td>
      <td>String</td>
      <td>Srcuser or dstuser or srcip (one of).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Proto</td>
      <td>String</td>
      <td>IP protocol associated with the session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.TunneledApp</td>
      <td>String</td>
      <td>Whether the application is tunneled.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Natdport</td>
      <td>String</td>
      <td>Post-NAT destination port.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Dst</td>
      <td>String</td>
      <td>Original destination IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Natdst</td>
      <td>String</td>
      <td>If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Rule</td>
      <td>String</td>
      <td>Name of the security policy rule that the network traffic matched.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Dport</td>
      <td>String</td>
      <td>Network traffic's destination port. If this value is 0, then the app is using its standard port.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Elapsed</td>
      <td>String</td>
      <td>Total time taken for the network session to complete.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.DeviceName</td>
      <td>String</td>
      <td>The hostname of the firewall that logged the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Subtype</td>
      <td>String</td>
      <td>Traffic log subtype. Values are: start, end, drop, deny.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.TimeReceived</td>
      <td>String</td>
      <td>Time the log was received at the management plane.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.SessionEndReason</td>
      <td>String</td>
      <td>The reason a session terminated. If the termination had multiple causes. This field displays only the highest priority reason.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Natsrc</td>
      <td>String</td>
      <td>If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Src</td>
      <td>String</td>
      <td>Original source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Start</td>
      <td>String</td>
      <td>Time when the session was established.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.TimeGenerated</td>
      <td>String</td>
      <td>Time the log was generated on the data plane.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.CategoryOfApp</td>
      <td>String</td>
      <td>Identifies the high-level family of the application.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Srcloc</td>
      <td>String</td>
      <td>Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Dstloc</td>
      <td>String</td>
      <td>Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Serial</td>
      <td>String</td>
      <td>Serial number of the firewall that generated the log.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Bytes</td>
      <td>String</td>
      <td>Number of total bytes (transmit and receive).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.VsysID</td>
      <td>String</td>
      <td>A unique identifier for a virtual system on a Palo Alto Networks firewall.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.To</td>
      <td>String</td>
      <td>Networking zone to which the traffic was sent.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Category</td>
      <td>String</td>
      <td>URL category associated with the session (if applicable).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Sport</td>
      <td>String</td>
      <td>Source port utilized by the session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.Tunnel</td>
      <td>String</td>
      <td>Type of tunnel.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traffic.IsPhishing</td>
      <td>String</td>
      <td>Detected enterprise credential submission by an end user.</td>
    </tr>
    <tr>
      <td>IP.Address</td>
      <td>String</td>
      <td>IP address.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cortex-query-traffic-logs rule=To_Internet,To_VPN limit=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
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
<p>
<h3>Logs traffic table</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Source Address</strong></th>
      <th><strong>Destination Address</strong></th>
      <th><strong>Application</strong></th>
      <th><strong>Action</strong></th>
      <th><strong>Rule</strong></th>
      <th><strong>Time Generated</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 8.8.8.8 </td>
      <td> 8.8.8.8 </td>
      <td> dns </td>
      <td> allow </td>
      <td> To_Internet </td>
      <td> 2019-10-25T09:20:50 </td>
    </tr>
    <tr>
      <td> 8.8.8.8 </td>
      <td> 8.8.8.8 </td>
      <td> dns </td>
      <td> allow </td>
      <td> To_Internet </td>
      <td> 2019-10-25T09:20:51 </td>
    </tr>
  </tbody>
</table>
<h3>Additional Information</h3>
    <p>
        
        If the user is using the command with field="all" then the human readable output will contain the following fields: </br>
        Source Address, Destination Address, Application, Action, Rule & Time Generated. </br> </br>
        If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: </br>
        field1, field2 & field3. </br>
        
    </p>


<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>6. cortex-query-threat-logs</h3>
<hr>
<p>Searches the Cortex panw.threat table, which is the threat logs table for PAN-OS/Panorama.</p>
<h5>Base Command</h5>
<p>
  <code>cortex-query-threat-logs</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip</td>
      <td>An IP address or an array of IP addresses for which to search, for example 1.1.1.1,2.2.2.2.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rule</td>
      <td>Rule name or array of rule names to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>from_zone</td>
      <td>Source zone or array of zones to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>to_zone</td>
      <td>Destination zone or array of zones to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>port</td>
      <td>Port or array of ports to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>action</td>
      <td>Action or array of actions lo search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query</td>
      <td>Free input query to search. This is the WHERE part of the query. so an example will be !cortex-query-traffic-logs query="src LIKE '192.168.1.*' AND dst = '192.168.1.12'"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>hash</td>
      <td>SHA256 hash or array of SHA256 hashes to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>url</td>
      <td>URL or array of URLs to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>startTime</td>
      <td>The query start time. For example, startTime="2018-04-26 00:00:00"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>endTime</td>
      <td>The query end time. For example, endTime="2018-04-26 00:00:00"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>timeRange</td>
      <td>The time range for the query, used with the rangeValue argument. For example, timeRange="weeks" timeValue="1" would run the query on the previous week.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rangeValue</td>
      <td>The time value for the query, used with the timeRange argument. For example, timeRange="weeks" rangeValue="1" would run the query on the previous week.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The number of logs to return. Default is 5.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Cortex.Logging.Threat.SessionID</td>
      <td>String</td>
      <td>Identifies the firewall's internal identifier for a specific network session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Action</td>
      <td>String</td>
      <td>Identifies the action that the firewall took for the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.App</td>
      <td>String</td>
      <td>Application associated with the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Nat</td>
      <td>String</td>
      <td>Indicates whether the firewall is performing network address translation (NAT) for the logged traffic. If it is, this value is 1.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.SubcategoryOfApp</td>
      <td>String</td>
      <td>Identifies the application's subcategory. The subcategoryis related to the application's category, which is identified in category_of_app.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.PcapID</td>
      <td>String</td>
      <td>Packet capture (pcap) ID. This is used to correlate threat pcap files with extended pcaps taken as a part of the session flow. All threat logs will contain either a pcap_id of 0 (no associated pcap) , or an ID referencing the extended pcap file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Natdst</td>
      <td>String</td>
      <td>If destination NAT performed, the post-NAT destination IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Flags</td>
      <td>String</td>
      <td>Bit field which provides details on the session, such as whether the session use IPv6, whether the session was denied due to a URL filtering rule, and/or whether the log corresponds to a transaction within an HTTP proxy session.</td>t
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Dport</td>
      <td>String</td>
      <td>Network traffic's destination port. If this value is 0, then the app is using its standard port.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.ThreatID</td>
      <td>String</td>
      <td>Numerical identifier for the threat type. All threats encountered by Palo Alto Networks firewalls are assigned a unique identifier</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Natsrc</td>
      <td>String</td>
      <td>If source NAT was performed, the post-NAT source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.CategoryOfApp</td>
      <td>String</td>
      <td>Identifies the managing application, or parent, of the application associated with this network traffic, if any.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Srcloc</td>
      <td>String</td>
      <td>Source country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Dstloc</td>
      <td>String</td>
      <td>Destination country or internal region for private addresses. The internal region is a user-defined name for a specific network in the user's enterprise.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.To</td>
      <td>String</td>
      <td>Networking zone to which the traffic was sent.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.RiskOfApp</td>
      <td>String</td>
      <td>Indicates how risky the application is from a network security perspective. Values range from 1-5, where 5 is the riskiest.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Natsport</td>
      <td>String</td>
      <td>Post-NAT source port.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.URLDenied</td>
      <td>String</td>
      <td>Session was denied due to a URL filtering rule.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.CharacteristicOfApp</td>
      <td>String</td>
      <td>Identifies the behaviorial characteristic of the application associated with the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.HTTPMethod</td>
      <td>String</td>
      <td>Only in URL filtering logs. Describes the HTTP Method used in the web request</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.From</td>
      <td>String</td>
      <td>The networking zone from which the traffic originated.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Vsys</td>
      <td>String</td>
      <td>Virtual system associated with the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.ReceiveTime</td>
      <td>String</td>
      <td>Time the log was received at the management plane.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Users</td>
      <td>String</td>
      <td>Srcuser or dstuser or srcip (one of).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Proto</td>
      <td>String</td>
      <td>IP protocol associated with the session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Natdport</td>
      <td>String</td>
      <td>Post-NAT destination port.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Dst</td>
      <td>String</td>
      <td>Original destination IP address. The IP address is an IPv4/ IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Rule</td>
      <td>String</td>
      <td>Name of the security policy rule that the network traffic matched.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.CategoryOfThreatID</td>
      <td>String</td>
      <td>Threat category of the detected threat.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.DeviceName</td>
      <td>String</td>
      <td>The hostname of the firewall that logged the network traffic.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Subtype</td>
      <td>String</td>
      <td>Subtype of the threat log.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.TimeReceived</td>
      <td>String</td>
      <td>Time the log was received at the management plane.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Direction</td>
      <td>String</td>
      <td>Indicates the direction of the attack, client-to-server or server-to-client:</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Misc</td>
      <td>String</td>
      <td>The meaning of this field differs according to the log's subtype: Subtype is URL, this field contains the requested URI. Subtype is File, this field contains the file name or file type. Subtype is Virus, this field contains the file name. Subtype is WildFire, this field contains the file name.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Severity</td>
      <td>String</td>
      <td>Severity associated with the event.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Src</td>
      <td>String</td>
      <td>Original source IP address. The IP address is an IPv4/IPv6 address in hex format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.TimeGenerated</td>
      <td>String</td>
      <td>Time the log was generated on the data plane.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Serial</td>
      <td>String</td>
      <td>Serial number of the firewall that generated the log.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.VsysID</td>
      <td>String</td>
      <td>A unique identifier for a virtual system on a Palo Alto Networks firewall.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.URLDomain</td>
      <td>String</td>
      <td>The name of the internet domain that was visited in this session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Category</td>
      <td>String</td>
      <td>For the URL subtype, this identifies the URL Category. For the WildFire subtype, this identifies the verdict on the file. It is one of ‘malicious’, ‘phishing’, ‘grayware’, or ‘benign’;</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.Sport</td>
      <td>String</td>
      <td>Source port utilized by the session.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Threat.IsPhishing</td>
      <td>Boolean</td>
      <td>Detected enterprise credential submission by an end user.</td>
    </tr>
    <tr>
      <td>IP.Address</td>
      <td>String</td>
      <td>IP address.</td>
    </tr>
    <tr>
      <td>Domain.Name</td>
      <td>String</td>
      <td>The domain name, for example: "google.com".</td>
    </tr>
    <tr>
      <td>File.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
      <td>File.Name</td>
      <td>String</td>
      <td>The full file name (including file extension).</td>
    </tr>
    <tr>
      <td>File.Type</td>
      <td>String</td>
      <td>The file type, as determined by libmagic (same as displayed in file entries).</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cortex-query-threat-logs fields=src,dst ip=8.8.8.8 limit=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
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
<p>
<h3>Logs threat table</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>src</strong></th>
      <th><strong>dst</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 8.8.8.8 </td>
      <td> 7.7.7.7 </td>
    </tr>
  </tbody>
</table>
<h3>Additional Information</h3>
    <p>
        If the user is using the command with field="all" then the human readable output will contain the following fields: </br>
        Source Address, Destination Address, Application, Action, Rule & Time Generated. </br> </br>
        If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: </br>
        field1, field2 & field3. </br>
    </p>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>7. cortex-query-traps-logs</h3>
<hr>
<p>Searches the Cortex tms.threat table, which is the threat logs table for the Traps endpoint protection and response.</p>
<h5>Base Command</h5>
<p>
  <code>cortex-query-traps-logs</code>
</p>

<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip</td>
      <td>IP or array of IPs to search for example 1.1.1.1,2.2.2.2.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>host</td>
      <td>Host or array of hosts to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>user</td>
      <td>User or an array or users to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>category</td>
      <td>Category or array of categories to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>hash</td>
      <td>Hash or array of hashes to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query</td>
      <td>Free-text input query to search. This is the WHERE part of the query so an example will be src = '1.1.1.1' OR rule = 'test rule'.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>The fields that are selected in the query. Selection can be "all" (same as *) or listing of specific fields in the table. List of fields can be found after viewing all the outputed fields with all.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>startTime</td>
      <td>The query start time. For example, startTime="2018-04-26 00:00:00".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>endTime</td>
      <td>The query end time. For example, endTime="2018-04-26 00:00:00".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>timeRange</td>
      <td>The time range for the query, used with the rangeValue argument. For example, timeRange="weeks" timeValue="1" would run the query on the previous week.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rangeValue</td>
      <td>The time value for the query, used with the timeRange argument. For example, timeRange="weeks" rangeValue="1" would run the query on the previous week.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The number of logs to return. Default is 5.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Cortex.Logging.Traps.Severity</td>
      <td>String</td>
      <td>Severity level associated with the event.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.AgentID</td>
      <td>String</td>
      <td>Unique identifier for the Traps agent.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.OsType</td>
      <td>String</td>
      <td>Operating system of the endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.IsVdi</td>
      <td>String</td>
      <td>Indicates whether the endpoint is a virtual desktop infrastructure (VDI).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.OSVersion</td>
      <td>String</td>
      <td>Full version number of the operating system running on the endpoint. For example, 6.1.7601.19135.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.Is64</td>
      <td>String</td>
      <td>Indicates whether the endpoint is running a 64-bit version of Windows.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.AgentIP</td>
      <td>String</td>
      <td>IP address of the endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.DeviceName</td>
      <td>String</td>
      <td>Hostname of the endpoint on which the event was logged.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.DeviceDomain</td>
      <td>String</td>
      <td>Domain to which the endpoint belongs.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.Username</td>
      <td>String</td>
      <td>The username on which the event was logged.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.AgentTime</td>
      <td>String</td>
      <td>Universal Time Coordinated (UTC) equivalent of the time at which an agent logged an event. ISO-8601 string representation.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.AgentVersion</td>
      <td>String</td>
      <td>Version of the Traps agent.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EndPointHeader.ProtectionStatus</td>
      <td>String</td>
      <td>The Traps agent status.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.RecordType</td>
      <td>String</td>
      <td>Record type associated with the event.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.TrapsID</td>
      <td>String</td>
      <td>Tenant external ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.EventType</td>
      <td>String</td>
      <td>Subtype of the event.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.UUID</td>
      <td>String</td>
      <td>Unique identifier for the event in Cortex.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.ServerHost</td>
      <td>String</td>
      <td>Hostname of the Traps management service.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.GeneratedTime</td>
      <td>String</td>
      <td>Universal Time Coordinated (UTC) equivalent of the time at which an event was logged.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.ServerComponentVersion</td>
      <td>String</td>
      <td>Software version of the Traps management service.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.RegionID</td>
      <td>String</td>
      <td>Region ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.CustomerID</td>
      <td>String</td>
      <td>Customer ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.ServerTime</td>
      <td>String</td>
      <td>Universal Time Coordinated (UTC) equivalent of the time at which the server generated the log. If the log was generated on an endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.OriginalAgentTime</td>
      <td>String</td>
      <td>Original time on the endpoint device.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.Facility</td>
      <td>Sting</td>
      <td>The Traps system component that initiated the event For example:, TrapsAgent, TrapsServiceCore, TrapsServiceManagement, TrapsServiceBackend.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.PreventionKey</td>
      <td>String</td>
      <td>Unique identifier for security events.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Processes.PID</td>
      <td>String</td>
      <td>Process identifier.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Processes.ParentID</td>
      <td>String</td>
      <td>Parent process identifier.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Processes.ExeFileIdx</td>
      <td>String</td>
      <td>Index of target files for specific security events such as: Scanning, Malicious DLL, Malicious Macro events.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Processes.UserIdx</td>
      <td>String</td>
      <td>Index of users.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Processes.CommandLine</td>
      <td>String</td>
      <td>Command line executed with the process.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Processes.Terminated</td>
      <td>String</td>
      <td>Termination action taken on the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Files.RawFullPath</td>
      <td>String</td>
      <td>Full path for the executed file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Files.FileName</td>
      <td>String</td>
      <td>File name.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Files.SHA256</td>
      <td>String</td>
      <td>SHA256 hash of the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Files.FileSize</td>
      <td>String</td>
      <td>File size.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Users.Username</td>
      <td>String</td>
      <td>Username of the active user on the endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Users.Domain</td>
      <td>String</td>
      <td>Domain to which the user account belongs.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.PostDetected</td>
      <td>String</td>
      <td>Was post detected.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Terminate</td>
      <td>String</td>
      <td>Termination action taken on the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Verdict</td>
      <td>String</td>
      <td>Traps verdict for the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.Blocked</td>
      <td>String</td>
      <td>Block action taken on the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.TargetProcessIdx</td>
      <td>String</td>
      <td>The prevention target process index in the processes array.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.ModuleCategory</td>
      <td>String</td>
      <td>Security module name.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.PreventionMode</td>
      <td>String</td>
      <td>The prevention mode used.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.TrapsSeverity</td>
      <td>String</td>
      <td>Traps Severity level associated with the event defined for the Traps management service.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.User.Username</td>
      <td>String</td>
      <td>Source username initiating the process.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.PID</td>
      <td>String</td>
      <td>Source process ID (PID).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.ParentID</td>
      <td>String</td>
      <td>Parent ID for the source process.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.CommandLine</td>
      <td>String</td>
      <td>Source process command line.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.InstanceID</td>
      <td>String</td>
      <td>Traps instance ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.Terminated</td>
      <td>String</td>
      <td>Source process termination action taken on the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.RawFullPath</td>
      <td>String</td>
      <td>Source process raw full path.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.FileName</td>
      <td>String</td>
      <td>Source process file name.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.SHA256</td>
      <td>String</td>
      <td>Source process SHA256 hash.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.FileSize</td>
      <td>String</td>
      <td>Source process file size.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Traps.MessageData.SourceProcess.InnerObjectSHA256</td>
      <td>String</td>
      <td>Source process inner object SHA256 hash</td>
    </tr>
    <tr>
      <td>Endpoint.Hostname</td>
      <td>String</td>
      <td>The hostname that is mapped to this endpoint.</td>
    </tr>
    <tr>
      <td>Endpoint.IPAddress</td>
      <td>String</td>
      <td>The IP address of the endpoint.</td>
    </tr>
    <tr>
      <td>Endpoint.Domain</td>
      <td>String</td>
      <td>The domain of the endpoint.</td>
    </tr>
    <tr>
      <td>Endpoint.OSVersion</td>
      <td>String</td>
      <td>OS version.</td>
    </tr>
    <tr>
      <td>Endpoint.OS</td>
      <td>String</td>
      <td>Endpoint OS.</td>
    </tr>
    <tr>
      <td>Endpoint.ID</td>
      <td>String</td>
      <td>The unique ID within the tool retrieving the endpoint.</td>
    </tr>
    <tr>
      <td>Host.Hostname</td>
      <td>String</td>
      <td>The name of the host.</td>
    </tr>
    <tr>
      <td>Host.IPAddress</td>
      <td>String</td>
      <td>The IP address of the host.</td>
    </tr>
    <tr>
      <td>Host.Domain</td>
      <td>String</td>
      <td>The domain of the host.</td>
    </tr>
    <tr>
      <td>Host.OSVersion</td>
      <td>String</td>
      <td>The OS version of the host.</td>
    </tr>
    <tr>
      <td>Host.OS</td>
      <td>String</td>
      <td>Host OS.</td>
    </tr>
    <tr>
      <td>Host.ID</td>
      <td>String</td>
      <td>The unique ID within the tool retrieving the host.</td>
    </tr>
    <tr>
      <td>Process.PID</td>
      <td>Number</td>
      <td>The PID of the process.</td>
    </tr>
    <tr>
      <td>Process.Parent</td>
      <td>String</td>
      <td>Parent process objects.</td>
    </tr>
    <tr>
      <td>Process.CommandLine</td>
      <td>String</td>
      <td>The full command line (including arguments).</td>
    </tr>
    <tr>
      <td>Process.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the process.</td>
    </tr>
    <tr>
      <td>Process.Name</td>
      <td>String</td>
      <td>The name of the process.</td>
    </tr>
    <tr>
      <td>Process.Path</td>
      <td>String</td>
      <td>The file system path to the binary file.</td>
    </tr>
    <tr>
      <td>File.Name</td>
      <td>String</td>
      <td>The full file name (including file extension).</td>
    </tr>
    <tr>
      <td>File.Type</td>
      <td>String</td>
      <td>The file type, as determined by libmagic (same as displayed in file entries).</td>
    </tr>
    <tr>
      <td>File.Path</td>
      <td>String</td>
      <td>The path where the file is located.</td>
    </tr>
    <tr>
      <td>File.Size</td>
      <td>Number</td>
      <td>The size of the file in bytes.</td>
    </tr>
    <tr>
      <td>File.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
      <td>File.DigitalSignature.Publisher</td>
      <td>String</td>
      <td>The publisher of the digital signature for the file.</td>
    </tr>
    <tr>
      <td>File.Company</td>
      <td>String</td>
      <td>The name of the company that released a binary.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cortex-query-traps-logs startTime=2011-10-25T00:00:31 endTime=2019-10-27T00:00:31 fields=endPointHeader.userName limit=4 user=administrator,tim,josh</code>
</p>
<h5>Context Example</h5>
<pre>
{
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
<p>
<h3>Logs traps table</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>endPointHeader.userName</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> administrator </td>
    </tr>
    <tr>
      <td> administrator </td>
    </tr>
    <tr>
      <td> administrator </td>
    </tr>
    <tr>
      <td> administrator </td>
    </tr>
  </tbody>
</table>
<h3>Additional Information</h3>
    <p>
        If the user is using the command with field="all" then the human readable output will contain the following fields: </br>
        Severity, Event Type, User, Agent Address, Agent Name & Agent Time. </br> </br>
        If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: </br>
        field1, field2 & field3. </br>
    </p>


<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->

<h3>8. cortex-query-analytics-logs</h3>
<hr>
<p>Searches the Cortex tms.analytics table, which is the endpoint logs table for Traps Analytics.</p>
<h5>Base Command</h5>
<p>
  <code>cortex-query-analytics-logs</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip</td>
      <td>Agent IP or array of agent IP  to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>host</td>
      <td>Agent host name or array of agent host names to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>user</td>
      <td>Username or array of usernames to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>category</td>
      <td>Event category or array of event categories to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>hash</td>
      <td>Hash or array of hashes to search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query</td>
      <td>Free-text input query to search. This forms the WHERE part of the query. For example, endPointHeader.agentIp = '1.1.1.1'.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>The fields that are selected in the query. Selection can be "all" (same as *) or a list of specific fields in the table. You can find the list of fields after viewing all the outputed fields with "all".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>startTime</td>
      <td>The query start time. For example, startTime="2018-04-26 00:00:00".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>endTime</td>
      <td>The query end time. For example, endTime="2018-04-26 00:00:00".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>timeRange</td>
      <td>The time range for the query, used with the rangeValue argument. For example, timeRange="weeks" timeValue="1" would run the query on the previous week.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rangeValue</td>
      <td>The time value for the query, used with the timeRange argument. For example, timeRange="weeks" rangeValue="1" would run the query on the previous week.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The number of logs to return. Default is 5.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Cortex.Logging.Analytics.AgentID</td>
      <td>String</td>
      <td>Unique identifier for the Traps agent.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.OsType</td>
      <td>String</td>
      <td>Operating system of the endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.IsVdi</td>
      <td>String</td>
      <td>Indicates whether the endpoint is a virtual desktop infrastructure (VDI).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.OSVersion</td>
      <td>String</td>
      <td>Full version number of the operating system running on the endpoint. For example, 6.1.7601.19135.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.Is64</td>
      <td>String</td>
      <td>Indicates whether the endpoint is running a 64-bit version of Windows.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.AgentIP</td>
      <td>String</td>
      <td>IP address of the endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.DeviceName</td>
      <td>String</td>
      <td>Hostname of the endpoint on which the event was logged.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.DeviceDomain</td>
      <td>String</td>
      <td>Domain to which the endpoint belongs.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.Username</td>
      <td>String</td>
      <td>The username on which the event was logged.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.UserDomain</td>
      <td>String</td>
      <td>Username of the active user on the endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.AgentTime</td>
      <td>String</td>
      <td>Universal Time Coordinated (UTC) equivalent of the time at which an agent logged an event. ISO-8601 string representation.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.AgentVersion</td>
      <td>String</td>
      <td>Version of the Traps agent.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.ProtectionStatus</td>
      <td>String</td>
      <td>Status of the Traps protection.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EndPointHeader.DataCollectionStatus</td>
      <td>String</td>
      <td>Status of the agent logging.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.TrapsID</td>
      <td>String</td>
      <td>Tenant external ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.EventType</td>
      <td>String</td>
      <td>Subtype of event.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.UUID</td>
      <td>String</td>
      <td>Event unique ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.GeneratedTime</td>
      <td>String</td>
      <td>Universal Time Coordinated (UTC) equivalent of the time at which an event was logged. For agent events, this represents the time on the endpoint. For policy, configuration, and system events, this represents the time on the Traps management service. ISO-8601 string representation (for example, 2017-01-24T09:08:59Z).</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.RegionID</td>
      <td>String</td>
      <td>ID of the Traps management service region.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.OriginalAgentTime</td>
      <td>String</td>
      <td>Original timestamp for endpoint.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.Facility</td>
      <td>String</td>
      <td>The Traps system component that initiated the event, for example TrapsAgent, TrapsServiceCore, TrapsServiceManagement, TrapsServiceBackend.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.type</td>
      <td>String</td>
      <td>Type of file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.FileName</td>
      <td>String</td>
      <td>File name, without the path or the file type extension.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.FilePath</td>
      <td>String</td>
      <td>Full path, aligned with OS format.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.FileSize</td>
      <td>String</td>
      <td>Size of the file in bytes.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.Reported</td>
      <td>String</td>
      <td>Whether the file was reported.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.Blocked</td>
      <td>String</td>
      <td>Whether the file was blocked.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.LocalAnalysisResult.Trusted</td>
      <td>String</td>
      <td>Trusted signer result.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.LocalAnalysisResult.Publishers</td>
      <td>String</td>
      <td>File publisher.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.LocalAnalysisResult.TrustedID</td>
      <td>String</td>
      <td>Trusted ID.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.ExecutionCount</td>
      <td>String</td>
      <td>File execution count.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.MessageData.LastSeen</td>
      <td>String</td>
      <td>The date the file was last seen.</td>
    </tr>
    <tr>
      <td>Cortex.Logging.Analytics.Severity</td>
      <td>String</td>
      <td>The threat severity.</td>
    </tr>
    <tr>
      <td>Endpoint.Hostname</td>
      <td>String</td>
      <td>The hostname that is mapped to this endpoint.</td>
    </tr>
    <tr>
      <td>Endpoint.IPAddress</td>
      <td>String</td>
      <td>The IP address of the endpoint.</td>
    </tr>
    <tr>
      <td>Endpoint.Domain</td>
      <td>String</td>
      <td>The domain of the endpoint.</td>
    </tr>
    <tr>
      <td>Endpoint.OSVersion</td>
      <td>String</td>
      <td>OS version.</td>
    </tr>
    <tr>
      <td>Endpoint.OS</td>
      <td>String</td>
      <td>Endpoint OS.</td>
    </tr>
    <tr>
      <td>Endpoint.ID</td>
      <td>String</td>
      <td>The unique ID within the tool retrieving the endpoint.</td>
    </tr>
    <tr>
      <td>Host.Hostname</td>
      <td>String</td>
      <td>The name of the host.</td>
    </tr>
    <tr>
      <td>Host.IPAddress</td>
      <td>String</td>
      <td>The IP address of the host.</td>
    </tr>
    <tr>
      <td>Host.Domain</td>
      <td>String</td>
      <td>The domain of the host.</td>
    </tr>
    <tr>
      <td>Host.OSVersion</td>
      <td>String</td>
      <td>The OS version of the host.</td>
    </tr>
    <tr>
      <td>Host.OS</td>
      <td>String</td>
      <td>Host OS.</td>
    </tr>
    <tr>
      <td>Host.ID</td>
      <td>String</td>
      <td>The unique ID within the tool retrieving the host.</td>
    </tr>
    <tr>
      <td>File.Name</td>
      <td>String</td>
      <td>The full file name (including file extension).</td>
    </tr>
    <tr>
      <td>File.Type</td>
      <td>String</td>
      <td>The file type, as determined by libmagic (same as displayed in file entries).</td>
    </tr>
    <tr>
      <td>File.Path</td>
      <td>String</td>
      <td>The path where the file is located.</td>
    </tr>
    <tr>
      <td>File.Size</td>
      <td>Number</td>
      <td>The size of the file in bytes.</td>
    </tr>
    <tr>
      <td>File.SHA256</td>
      <td>String</td>
      <td>The SHA256 hash of the file.</td>
    </tr>
    <tr>
      <td>File.DigitalSignature.Publisher</td>
      <td>String</td>
      <td>The publisher of the digital signature for the file.</td>
    </tr>
    <tr>
      <td>File.Company</td>
      <td>String</td>
      <td>The name of the company that released a binary.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!cortex-query-analytics-logs fields=all host=DC1ENV9APC51 user=Administrator</code>
</p>
<h5>Context Example</h5>
<pre>
{
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
<p>
<h3>Logs analytics table</h3>
<table style="width:750px" border="2" cellpadding="6">
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
      <td> AgentTimelineEvent </td>
      <td> Administrator </td>
      <td> 8.8.8.8 </td>
      <td> DEVICE NAME </td>
      <td> 2019-10-26T14:20:08.124Z </td>
    </tr>
    <tr>
      <td> AgentTimelineEvent </td>
      <td> Administrator </td>
      <td> 8.8.8.8 </td>
      <td> DEVICE NAME </td>
      <td> 2019-10-26T14:19:51.853Z </td>
    </tr>
    <tr>
      <td> AgentTimelineEvent </td>
      <td> Administrator </td>
      <td> 8.8.8.8 </td>
      <td> DEVICE NAME </td>
      <td> 2019-10-26T14:19:51.884Z </td>
    </tr>
    <tr>
      <td> AgentTimelineEvent </td>
      <td> Administrator </td>
      <td> 8.8.8.8 </td>
      <td> DEVICE NAME </td>
      <td> 2019-10-26T14:20:08.124Z </td>
    </tr>
    <tr>
      <td> AgentTimelineEvent </td>
      <td> Administrator </td>
      <td> 8.8.8.8 </td>
      <td> DEVICE NAME </td>
      <td> 2019-10-26T14:20:08.202Z </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
<h3>Additional Information</h3>
    <p>
        If the user is using the command with field="all" then the human readable output will contain the following fields: </br>
        Severity, Event Type, User, Agent Address, Agent Name & Agent Time. </br> </br>
        If the user is using the command with fields="field1,field2,field3" then the human readable output will contain the following fields: </br>
        field1, field2 & field3. </br>
    </p>