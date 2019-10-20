<p>
The ARIA Cybesecurity Solutions Software-Defined Security (SDS)  platform integrates with Demisto to add robustness when responding to incidents. The combination of ARIA hardware, in the form of a Secure Intelligent Adapter (SIA), and software, specifically Packet Intelligence and SDS orchestrator (SDSo), provides the elements required to react instantly when an incident is detected. When integrated with the ARIA solution, you can create playbooks that instruct one or more SIAs to add, modify, or delete rules automatically. These rule changes, which take effect immediately, can block conversations, redirect packets to a recorder or VLAN, or perform a variety of other actions.

This integration was integrated and tested with version xx of ARIA Packet Intelligence
</p>
<h2>ARIA Packet Intelligence Playbook</h2>
<p>playbook-Aria-Packet-Intelligence-Test</p>
<h2>Use Cases</h2>
<p>1.Block Conversation 2. Alert and Record Conversation</p>
<h2>Detailed Description</h2>
<p>Populate this section with the .md file contents for detailed description.</p>
<h2>Configure ARIA Packet Intelligence on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for ARIA Packet Intelligence.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>SDSo Base URL (e.g. http://&lt;IP address or FQDN of SDSo Node&gt;:7443);</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>aria-block-conversation: aria-block-conversation</li>
  <li>aria-unblock-conversation: aria-unblock-conversation</li>
  <li>aria-record-conversation: aria-record-conversation</li>
  <li>aria-stop-recording-conversation: aria-stop-recording-conversation</li>
  <li>aria-alert-conversation: aria-alert-conversation</li>
  <li>aria-mute-alert-conversation: aria-mute-alert-conversation</li>
  <li>aria-block-dest-port: aria-block-dest-port</li>
  <li>aria-unblock-dest-port: aria-unblock-dest-port</li>
  <li>aria-record-dest-port: aria-record-dest-port</li>
  <li>aria-stop-recording-dest-port: aria-stop-recording-dest-port</li>
  <li>aria-alert-dest-port: aria-alert-dest-port</li>
  <li>aria-mute-alert-dest-port: aria-mute-alert-dest-port</li>
  <li>aria-block-src-port: aria-block-src-port</li>
  <li>aria-unblock-src-port: aria-unblock-src-port</li>
  <li>aria-record-src-port: aria-record-src-port</li>
  <li>aria-stop-recording-src-port: aria-stop-recording-src-port</li>
  <li>aria-alert-src-port: aria-alert-src-port</li>
  <li>aria-mute-alert-src-port: aria-mute-alert-src-port</li>
  <li>aria-block-dest-subnet: aria-block-dest-subnet</li>
  <li>aria-unblock-dest-subnet: aria-unblock-dest-subnet</li>
  <li>aria-record-dest-subnet: aria-record-dest-subnet</li>
  <li>aria-stop-recording-dest-subnet: aria-stop-recording-dest-subnet</li>
  <li>aria-alert-dest-subnet: aria-alert-dest-subnet</li>
  <li>aria-mute-alert-dest-subnet: aria-mute-alert-dest-subnet</li>
  <li>aria-block-src-subnet: aria-block-src-subnet</li>
  <li>aria-unblock-src-subnet: aria-unblock-src-subnet</li>
  <li>aria-record-src-subnet: aria-record-src-subnet</li>
  <li>aria-stop-recording-src-subnet: aria-stop-recording-src-subnet</li>
  <li>aria-alert-src-subnet: aria-alert-src-subnet</li>
  <li>aria-mute-alert-src-subnet: aria-mute-alert-src-subnet</li>
</ol>
<h3>1. aria-block-conversation</h3>
<hr>
<p>Creates a rule that drops all packets matching the specified 5-tuple values.</p>
<h5>Base Command</h5>
<p>
  <code>aria-block-conversation</code>
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
      <td>src_ip</td>
      <td>The source IP address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>src_port</td>
      <td>The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>target_ip</td>
      <td>The destination IP address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>target_port</td>
      <td>The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocol</td>
      <td>The protocol (e.g., TCP) used for the packets.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.BlockConversation.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.BlockConversation.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.BlockConversation.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convBlock" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.BlockConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "aa5395d0-be3b-b76d-b2c3-58f4fccb115b"
            }
        ],
        "Rule": {
            "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : DROP, END",
            "Name": "convBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420423
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-block-conversation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: convBlock<br>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : DROP, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420423</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'aa5395d0-be3b-b76d-b2c3-58f4fccb115b', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>2. aria-unblock-conversation</h3>
<hr>
<p>Deletes a named rule from the 5-tuple logic block. This allows the previously blocked conversation to resume.</p>
<h5>Base Command</h5>
<p>
  <code>aria-unblock-conversation</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.UnblockConversation.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.UnblockConversation.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.UnblockConversation.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-unblock-conversation rule_name="convBlock" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.UnblockConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "92bf73e5-c899-f2fa-76bb-a959cf053b61"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "convBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420426
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-unblock-conversation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: convBlock<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420426<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '92bf73e5-c899-f2fa-76bb-a959cf053b61', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>3. aria-record-conversation</h3>
<hr>
<p>Creates a rule that redirects a conversation matching 5-tuple values to the Packet Recorder. Packets are tagged with the VID specified in the instance.</p>
<h5>Base Command</h5>
<p>
  <code>aria-record-conversation</code>
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
      <td>src_ip</td>
      <td>The source IP address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>src_port</td>
      <td>The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>target_ip</td>
      <td>The destination IP address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>target_port</td>
      <td>The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocol</td>
      <td>The protocol (e.g., TCP) used for the packets.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>vlan_id</td>
      <td>The VLAN ID your network switch uses to forward packets to the Packet Recorder.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>sia_interface</td>
      <td>The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.RecordConversation.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.RecordConversation.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.RecordConversation.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.RecordConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "7fc5d306-9d8e-65b5-8465-2e1fb8fb347e"
            }
        ],
        "Rule": {
            "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
            "Name": "convRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420435
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-record-conversation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: convRecord<br>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420435</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '7fc5d306-9d8e-65b5-8465-2e1fb8fb347e', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>4. aria-stop-recording-conversation</h3>
<hr>
<p>Removes the named rule from the 5-tuple block. This stops redirecting traffic to the Packet Recorder.</p>
<h5>Base Command</h5>
<p>
  <code>aria-stop-recording-conversation</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.StopRecordingConversation.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingConversation.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingConversation.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-stop-recording-conversation rule_name="convRecord" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.StopRecordingConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "806b7df1-142a-7b1d-73ba-e3409b3ae1b7"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "convRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420445
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-stop-recording-conversation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: convRecord<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420445<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '806b7df1-142a-7b1d-73ba-e3409b3ae1b7', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>5. aria-alert-conversation</h3>
<hr>
<p>Adds a rule that generates an alert when a conversation matching the specified 5-tuple values is detected.</p>
<h5>Base Command</h5>
<p>
  <code>aria-alert-conversation</code>
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
      <td>src_ip</td>
      <td>The source IP address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>src_port</td>
      <td>The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>target_ip</td>
      <td>The destination IP address.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>target_port</td>
      <td>The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocol</td>
      <td>The protocol (e.g., TCP) used for the packets.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.AlertConversation.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.AlertConversation.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.AlertConversation.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convAlert" transport_type="email" tti_index="2" aio_index="4" trigger_type="re-trigger-count" trigger_value="1000" label_sia_group="Engineering"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.AlertConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "4bb24d36-09d1-200c-dbe0-a22704846484"
            }
        ],
        "Rule": {
            "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END",
            "Name": "convAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420453
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-alert-conversation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: convAlert<br>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420453</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '4bb24d36-09d1-200c-dbe0-a22704846484', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>6. aria-mute-alert-conversation</h3>
<hr>
<p>Removes a named rule from the 5-tuple logic block, disabling the alerts.</p>
<h5>Base Command</h5>
<p>
  <code>aria-mute-alert-conversation</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.MuteAlertConversation.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertConversation.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertConversation.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-mute-alert-conversation rule_name="convAlert" label_sia_group="Engineering"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.MuteAlertConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "a00c637c-4811-45e0-ae55-fab9cab8c10a"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "convAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420460
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-mute-alert-conversation</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: convAlert<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420460<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'a00c637c-4811-45e0-ae55-fab9cab8c10a', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>7. aria-block-dest-port</h3>
<hr>
<p>Creates a rule that blocks packets destined for one or more specific ports.</p>
<h5>Base Command</h5>
<p>
  <code>aria-block-dest-port</code>
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
      <td>port_range</td>
      <td>The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.BlockDestPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.BlockDestPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.BlockDestPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-dest-port port_range="389, 400-404" rule_name="destPortBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.BlockDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "b7bfd2a3-51d1-e9ba-b5bf-d8b4d5f21b8f"
            }
        ],
        "Rule": {
            "Definition": "389, 400 - 404: DROP, END",
            "Name": "destPortBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420469
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-block-dest-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destPortBlock<br>Definition: 389, 400 - 404: DROP, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420469</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'b7bfd2a3-51d1-e9ba-b5bf-d8b4d5f21b8f', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>8. aria-unblock-dest-port</h3>
<hr>
<p>Removes a named rule from the destination port logic block. This allows the previously blocked traffic to resume.</p>
<h5>Base Command</h5>
<p>
  <code>aria-unblock-dest-port</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.UnblockDestPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.UnblockDestPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.UnblockDestPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-unblock-dest-port rule_name="destPortBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.UnblockDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "8c1e5ab0-1e77-1b27-68d7-cab420fdf8c3"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "destPortBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420477
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-unblock-dest-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destPortBlock<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420477<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8c1e5ab0-1e77-1b27-68d7-cab420fdf8c3', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>9. aria-record-dest-port</h3>
<hr>
<p>Adds a rule that redirects traffic destined for one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.</p>
<h5>Base Command</h5>
<p>
  <code>aria-record-dest-port</code>
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
      <td>port_range</td>
      <td>The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>vlan_id</td>
      <td>The VLAN ID your network switch uses to forward packets to the Packet Recorder.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>sia_interface</td>
      <td>The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.RecordDestPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.RecordDestPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.RecordDestPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-dest-port port_range="390, 420, 421" rule_name="destPortRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.RecordDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "4361c6ed-042c-502f-a329-06d4e2c4b4a1"
            }
        ],
        "Rule": {
            "Definition": "390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
            "Name": "destPortRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420486
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-record-dest-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destPortRecord<br>Definition: 390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420486</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '4361c6ed-042c-502f-a329-06d4e2c4b4a1', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>10. aria-stop-recording-dest-port</h3>
<hr>
<p>Removes a named rule from the destination port logic block. This stops redirecting traffic to the Packet Recorder.</p>
<h5>Base Command</h5>
<p>
  <code>aria-stop-recording-dest-port</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.StopRecordingDestPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingDestPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingDestPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-stop-recording-dest-port rule_name="destPortRecord" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.StopRecordingDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "9cb30bff-fb0f-eb7b-2790-6942e7585548"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "destPortRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420494
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-stop-recording-dest-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destPortRecord<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420494<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '9cb30bff-fb0f-eb7b-2790-6942e7585548', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>11. aria-alert-dest-port</h3>
<hr>
<p>Creates a rule that generates an alert when traffic destined for one or more ports is detected.</p>
<h5>Base Command</h5>
<p>
  <code>aria-alert-dest-port</code>
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
      <td>port_range</td>
      <td>The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.AlertDestPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.AlertDestPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.AlertDestPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-dest-port port_range="389-400" rule_name="destPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.AlertDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "f1858475-74b5-cdd9-e427-763ddb897211"
            }
        ],
        "Rule": {
            "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
            "Name": "destPortAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420503
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-alert-dest-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destPortAlert<br>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420503</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f1858475-74b5-cdd9-e427-763ddb897211', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>12. aria-mute-alert-dest-port</h3>
<hr>
<p>Removes a named rule from the destination port logic block, disabling the alerts.</p>
<h5>Base Command</h5>
<p>
  <code>aria-mute-alert-dest-port</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.MuteAlertDestPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertDestPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertDestPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-mute-alert-dest-port rule_name="destPortAlert" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.MuteAlertDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "f034b7f4-258a-49ab-0226-7bc651c34e10"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "destPortAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420511
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-mute-alert-dest-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destPortAlert<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420511<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f034b7f4-258a-49ab-0226-7bc651c34e10', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>13. aria-block-src-port</h3>
<hr>
<p>Adds a rule that blocks packets originating from one or more specific ports.</p>
<h5>Base Command</h5>
<p>
  <code>aria-block-src-port</code>
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
      <td>port_range</td>
      <td>The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.BlockSrcPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.BlockSrcPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.BlockSrcPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-src-port port_range="389, 400-404" rule_name="srcPortBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.BlockSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "93ad5260-f138-ed0c-6ac0-e1a6f721747e"
            }
        ],
        "Rule": {
            "Definition": "389, 400 - 404: DROP, END",
            "Name": "srcPortBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420518
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-block-src-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcPortBlock<br>Definition: 389, 400 - 404: DROP, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420518</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '93ad5260-f138-ed0c-6ac0-e1a6f721747e', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>14. aria-unblock-src-port</h3>
<hr>
<p>Removes a named rule from the source port logic block. This allows the previously blocked traffic to resume.</p>
<h5>Base Command</h5>
<p>
  <code>aria-unblock-src-port</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.UnblockSrcPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.UnblockSrcPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.UnblockSrcPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-unblock-src-port rule_name="srcPortBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.UnblockSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "344f83ed-ff1f-1e54-3d82-e59530b02ae6"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "srcPortBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420526
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-unblock-src-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcPortBlock<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420526<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '344f83ed-ff1f-1e54-3d82-e59530b02ae6', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>15. aria-record-src-port</h3>
<hr>
<p>Adds a rule that redirects traffic originating from one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.</p>
<h5>Base Command</h5>
<p>
  <code>aria-record-src-port</code>
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
      <td>port_range</td>
      <td>The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>vlan_id</td>
      <td>The VLAN ID your network switch uses to forward packets to the Packet Recorder.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>sia_interface</td>
      <td>The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.RecordSrcPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.RecordSrcPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.RecordSrcPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-src-port port_range="390, 420" rule_name="srcPortRecord" sia_interface="B" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.RecordSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "b133454a-d7b9-50dd-fb9b-3cc769c49396"
            }
        ],
        "Rule": {
            "Definition": "390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END",
            "Name": "srcPortRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420533
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-record-src-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcPortRecord<br>Definition: 390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420533</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'b133454a-d7b9-50dd-fb9b-3cc769c49396', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>16. aria-stop-recording-src-port</h3>
<hr>
<p>Removes a named rule from the source port logic block. This stops redirecting traffic to the Packet Recorder.</p>
<h5>Base Command</h5>
<p>
  <code>aria-stop-recording-src-port</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.StopRecordingSrcPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingSrcPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingSrcPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-stop-recording-src-port rule_name="srcPortRecord" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.StopRecordingSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "42ef11aa-5655-0b42-15e1-e94bdd966058"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "srcPortRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420541
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-stop-recording-src-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcPortRecord<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420541<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '42ef11aa-5655-0b42-15e1-e94bdd966058', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>17. aria-alert-src-port</h3>
<hr>
<p>Creates a rule that generates an alert when traffic originating from one or more ports is detected.</p>
<h5>Base Command</h5>
<p>
  <code>aria-alert-src-port</code>
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
      <td>port_range</td>
      <td>The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.AlertSrcPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.AlertSrcPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.AlertSrcPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-src-port port_range="389-400" rule_name="srcPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.AlertSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "c07dc77e-d661-9a09-2266-ad5d341e8e63"
            }
        ],
        "Rule": {
            "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
            "Name": "srcPortAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420549
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-alert-src-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcPortAlert<br>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420549</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c07dc77e-d661-9a09-2266-ad5d341e8e63', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>18. aria-mute-alert-src-port</h3>
<hr>
<p>Removes a named rule from the source port logic block, disabling the alerts.</p>
<h5>Base Command</h5>
<p>
  <code>aria-mute-alert-src-port</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.MuteAlertSrcPort.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertSrcPort.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertSrcPort.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-mute-alert-src-port rule_name="srcPortAlert" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.MuteAlertSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "9a31502b-40db-98e9-ea12-b0b512045b4d"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "srcPortAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420558
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-mute-alert-src-port</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcPortAlert<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420558<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '9a31502b-40db-98e9-ea12-b0b512045b4d', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>19. aria-block-dest-subnet</h3>
<hr>
<p>Adds a rule that blocks packets destined for a specific IP address or range of IP addresses.</p>
<h5>Base Command</h5>
<p>
  <code>aria-block-dest-subnet</code>
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
      <td>target_ip</td>
      <td>The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.BlockDestSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.BlockDestSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.BlockDestSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.BlockDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "4609e8c0-55a4-ec06-3548-71cc5b5a67be"
            }
        ],
        "Rule": {
            "Definition": "192.168.1.2/24: DROP, END",
            "Name": "destSubnetBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420567
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-block-dest-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destSubnetBlock<br>Definition: 192.168.1.2/24: DROP, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420567</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '4609e8c0-55a4-ec06-3548-71cc5b5a67be', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>20. aria-unblock-dest-subnet</h3>
<hr>
<p>Removes a named rule from the destination subnet logic block. This allows the previously blocked traffic to resume.</p>
<h5>Base Command</h5>
<p>
  <code>aria-unblock-dest-subnet</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.UnblockDestSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.UnblockDestSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.UnblockDestSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-unblock-dest-subnet rule_name="destSubnetBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.UnblockDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "deba7913-d38b-08bd-263c-7e00dd5765a7"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "destSubnetBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420574
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-unblock-dest-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destSubnetBlock<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420574<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'deba7913-d38b-08bd-263c-7e00dd5765a7', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>21. aria-record-dest-subnet</h3>
<hr>
<p>Creates a rule that redirects traffic destined for a specific IP address or range of IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.</p>
<h5>Base Command</h5>
<p>
  <code>aria-record-dest-subnet</code>
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
      <td>target_ip</td>
      <td>The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>vlan_id</td>
      <td>The VLAN ID your network switch uses to forward packets to the Packet Recorder.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>sia_interface</td>
      <td>The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.RecordDestSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.RecordDestSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.RecordDestSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-dest-subnet target_ip="192.168.10.23/32" rule_name="destSubnetRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.RecordDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "d832ae22-cb14-18e4-2e3f-8c08333feb0f"
            }
        ],
        "Rule": {
            "Definition": "192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
            "Name": "destSubnetRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420583
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-record-dest-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destSubnetRecord<br>Definition: 192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420583</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'd832ae22-cb14-18e4-2e3f-8c08333feb0f', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>22. aria-stop-recording-dest-subnet</h3>
<hr>
<p>Removes a named rule from the destination subnet logic block. This stops redirecting traffic to the Packet Recorder.</p>
<h5>Base Command</h5>
<p>
  <code>aria-stop-recording-dest-subnet</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.StopRecordingDestSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingDestSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingDestSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-stop-recording-dest-subnet rule_name="destSubnetRecord" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.StopRecordingDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "1e6d1679-8652-13f8-f3e7-41a0e10c1335"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "destSubnetRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420591
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-stop-recording-dest-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destSubnetRecord<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420591<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1e6d1679-8652-13f8-f3e7-41a0e10c1335', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>23. aria-alert-dest-subnet</h3>
<hr>
<p>Creates a rule that generates an alert when traffic destined for a specific IP address or range of IP addresses is detected.</p>
<h5>Base Command</h5>
<p>
  <code>aria-alert-dest-subnet</code>
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
      <td>target_ip</td>
      <td>The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.AlertDestSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.AlertDestSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.AlertDestSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.AlertDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "d53a30dd-f6b8-b2c1-9f5c-4cd2e455bcc9"
            }
        ],
        "Rule": {
            "Definition": "192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
            "Name": "destSubnetAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420599
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-alert-dest-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destSubnetAlert<br>Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420599</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'd53a30dd-f6b8-b2c1-9f5c-4cd2e455bcc9', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>24. aria-mute-alert-dest-subnet</h3>
<hr>
<p>Removes a named rule from the destination subnet logic block, disabling the alerts.</p>
<h5>Base Command</h5>
<p>
  <code>aria-mute-alert-dest-subnet</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.MuteAlertDestSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertDestSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertDestSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-mute-alert-dest-subnet rule_name="destSubnetAlert" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.MuteAlertDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "8b23a582-25b6-a2d9-7d76-39b3e1ce1584"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "destSubnetAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420608
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-mute-alert-dest-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: destSubnetAlert<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420608<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8b23a582-25b6-a2d9-7d76-39b3e1ce1584', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>25. aria-block-src-subnet</h3>
<hr>
<p>Adds a rule that blocks packets originating from a specific IP address or range of IP addresses.</p>
<h5>Base Command</h5>
<p>
  <code>aria-block-src-subnet</code>
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
      <td>src_ip</td>
      <td>The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.BlockSrcSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.BlockSrcSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.BlockSrcSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.BlockSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "a8916b20-5d9a-0337-23ce-1c399922df05"
            }
        ],
        "Rule": {
            "Definition": "192.168.1.2/24: DROP, END",
            "Name": "srcSubnetBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420616
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-block-src-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcSubnetBlock<br>Definition: 192.168.1.2/24: DROP, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420616</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'a8916b20-5d9a-0337-23ce-1c399922df05', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>26. aria-unblock-src-subnet</h3>
<hr>
<p>Removes a named rule from the source subnet logic block. This allows the previously blocked traffic to resume.</p>
<h5>Base Command</h5>
<p>
  <code>aria-unblock-src-subnet</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.UnblockSrcSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.UnblockSrcSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.UnblockSrcSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-unblock-src-subnet rule_name="srcSubnetBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.UnblockSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "c7405878-aa74-9301-7422-b91ae84be8eb"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "srcSubnetBlock"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420624
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-unblock-src-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcSubnetBlock<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420624<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c7405878-aa74-9301-7422-b91ae84be8eb', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>27. aria-record-src-subnet</h3>
<hr>
<p>Creates a rule that redirects traffic originating from one or more specific IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.</p>
<h5>Base Command</h5>
<p>
  <code>aria-record-src-subnet</code>
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
      <td>src_ip</td>
      <td>The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>vlan_id</td>
      <td>The VLAN ID your network switch uses to forward packets to the Packet Recorder.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>sia_interface</td>
      <td>The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.RecordSrcSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.RecordSrcSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.RecordSrcSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.RecordSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "7bc02e02-c6d5-2b80-5423-1a6fc245c3f9"
            }
        ],
        "Rule": {
            "Definition": "192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
            "Name": "srcSubnetRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420632
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-record-src-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcSubnetRecord<br>Definition: 192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420632</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '7bc02e02-c6d5-2b80-5423-1a6fc245c3f9', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>28. aria-stop-recording-src-subnet</h3>
<hr>
<p>Removes a named rule from the source subnet logic block. This stops redirecting traffic to the Packet Recorder.</p>
<h5>Base Command</h5>
<p>
  <code>aria-stop-recording-src-subnet</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.StopRecordingSrcSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingSrcSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.StopRecordingSrcSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-stop-recording-src-subnet rule_name="srcSubnetRecord" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.StopRecordingSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "52dc6968-2269-ae46-7dfc-accbda8973e5"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "srcSubnetRecord"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420640
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-stop-recording-src-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcSubnetRecord<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420640<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '52dc6968-2269-ae46-7dfc-accbda8973e5', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>29. aria-alert-src-subnet</h3>
<hr>
<p>Adds a rule that generates an alert when traffic originating from a specific IP address or range of IP addresses is detected.</p>
<h5>Base Command</h5>
<p>
  <code>aria-alert-src-subnet</code>
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
      <td>src_ip</td>
      <td>The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>rule_name</td>
      <td>The name of the rule to create.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>transport_type</td>
      <td>The type of notification to generate. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>tti_index</td>
      <td>The index of the entry in the transport type table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>aio_index</td>
      <td>The index of the entry in the alert information object table.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_type</td>
      <td>The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>trigger_value</td>
      <td>The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo.</td>
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
      <td>Aria.AlertSrcSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.AlertSrcSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.AlertSrcSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.AlertSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "8a0d8a84-3248-aadb-db11-dbe96562d1ef"
            }
        ],
        "Rule": {
            "Definition": "192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
            "Name": "srcSubnetAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420648
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-alert-src-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcSubnetAlert<br>Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END</td>
      <td>code: 201<br>command_state: Success<br>timestamp: 1571420648</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8a0d8a84-3248-aadb-db11-dbe96562d1ef', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3>30. aria-mute-alert-src-subnet</h3>
<hr>
<p>Removes a named rule from the source subnet logic block, disabling the alerts.</p>
<h5>Base Command</h5>
<p>
  <code>aria-mute-alert-src-subnet</code>
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
      <td>rule_name</td>
      <td>The name of the rule to delete.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>label_sia_group</td>
      <td>The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_name</td>
      <td>The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>label_sia_region</td>
      <td>The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo.</td>
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
      <td>Aria.MuteAlertSrcSubnet.Rule</td>
      <td>string</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertSrcSubnet.Status</td>
      <td>string</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>Aria.MuteAlertSrcSubnet.Endpoints</td>
      <td>string</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-mute-alert-src-subnet rule_name="srcSubnetAlert" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Aria.MuteAlertSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
                "IPAddress": "10.1.1.0",
                "Model": "sia-lx2160",
                "OS": "GNU/Linux",
                "Processor": "sia-lx2160",
                "Processors": 1,
                "completion": true,
                "trid": "07e9f255-efb0-d60e-8118-ba947c4be47f"
            }
        ],
        "Rule": {
            "Definition": "",
            "Name": "srcSubnetAlert"
        },
        "Status": {
            "code": 201,
            "command_state": "Success",
            "timestamp": 1571420656
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>aria-mute-alert-src-subnet</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Rule</strong></th>
      <th><strong>Status</strong></th>
      <th><strong>Endpoints</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Name: srcSubnetAlert<br>Definition: </td>
      <td>code: 201<br>timestamp: 1571420656<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '07e9f255-efb0-d60e-8118-ba947c4be47f', 'completion': True}</td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>
<h2>Additional Information</h2>
<p>For more information, please see the ARIA_SOAR_Integration_Guide_Demisto.</p>
