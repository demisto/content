<p>
The ARIA Cybesecurity Solutions Software-Defined Security (SDS)  platform integrates with Demisto to add robustness when responding to incidents. The combination of ARIA hardware, in the form of a Secure Intelligent Adapter (SIA), and software, specifically Packet Intelligence and SDS orchestrator (SDSo), provides the elements required to react instantly when an incident is detected. When integrated with the ARIA solution, you can create playbooks that instruct one or more SIAs to add, modify, or delete rules automatically. These rule changes, which take effect immediately, can block conversations, redirect packets to a recorder or VLAN, or perform a variety of other actions. 

This integration was integrated and tested with version xx of ARIA Packet Intelligece
</p>
<h2>ARIA Packet Intelligece Playbook</h2>
<p>playbook_aria_packet_intelligence_test</p>
<h2>Use Cases</h2>
<p>1.Block Conversation 2. Alert and Record Conversation</p>
<h2>Detailed Description</h2>
<p>Users should install SDSo onto a server according to the instructions in Software-Defined Security Installation Guide. During the installation process you can determine the IP address or FQDN of your SDSo instance which is used in the SDSo Base URL. You should also install an SIA according to the Secure Intelligent Adapter Installation Guide. For more information on connecting an SDSo and SIA see the Software-Defined Security Orchestrator User Guide. In addition, you must deploy the PI security service to your SIA, see the Packet Intelligence User Guide for more information.</p>
<h2>Configure ARIA Packet Intelligece on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for ARIA Packet Intelligece.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>SDSo Base URL</strong></li>
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
      <td>aria.block_conversation.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.block_conversation.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.block_conversation.Endpoints</td>
      <td>Unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-conversation src_ip="192.168.0.100" src_port="389" target_ip="192.168.0.101" target_port="390" protocol="tcp" rule_name="convBlock" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.block_conversation": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "786e3798-205b-7365-7da6-2928e9b62784"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : DROP, END",
                "Name": "convBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570722987
            }
        }
    ]
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
      <td>Name: convBlock<br>Definition: 192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : DROP, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570722987</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '786e3798-205b-7365-7da6-2928e9b62784', 'completion': True}</td>
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
      <td>aria.unblock_conversation.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.unblock_conversation.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.unblock_conversation.Endpoints</td>
      <td>unknown</td>
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
    "aria.unblock_conversation": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "5f54a55c-e89b-8fd2-c3af-20922d50cef9"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "convBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570722990
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570722990<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '5f54a55c-e89b-8fd2-c3af-20922d50cef9', 'completion': True}</td>
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
      <td>aria.record_conversation.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.record_conversation.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.record_conversation.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-conversation src_ip="192.168.0.100" src_port="389" target_ip="192.168.0.101" target_port="390" protocol="tcp" rule_name="convRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.record_conversation": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "f162fe08-07bd-ad1a-03d1-994e064d95fc"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "convRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570722998
            }
        }
    ]
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
      <td>Name: convRecord<br>Definition: 192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570722998</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f162fe08-07bd-ad1a-03d1-994e064d95fc', 'completion': True}</td>
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
      <td>aria.stop_recording_conversation.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_conversation.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_conversation.Endpoints</td>
      <td>unknown</td>
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
    "aria.stop_recording_conversation": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "3d054434-7078-1e53-8ca1-d66d494f83ab"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "convRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723007
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723007<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '3d054434-7078-1e53-8ca1-d66d494f83ab', 'completion': True}</td>
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
      <td>aria.alert_conversation.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.alert_conversation.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.alert_conversation.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-conversation src_ip="192.168.0.100" src_port="389" target_ip="192.168.0.101" target_port="390" protocol="tcp" rule_name="convAlert" transport_type="email" tti_index="2" aio_index="4" trigger_type="re-trigger-count" trigger_value="1000" label_sia_group="Engineering"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.alert_conversation": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "42ee40a4-9315-2678-0db7-8a5a06286180"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END",
                "Name": "convAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723015
            }
        }
    ]
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
      <td>Name: convAlert<br>Definition: 192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723015</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '42ee40a4-9315-2678-0db7-8a5a06286180', 'completion': True}</td>
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
      <td>aria.mute_alert_conversation.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_conversation.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_conversation.Endpoints</td>
      <td>unknown</td>
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
    "aria.mute_alert_conversation": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "28e78bfe-2b5e-b5a7-6360-e6a3e4fde148"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "convAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723024
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723024<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '28e78bfe-2b5e-b5a7-6360-e6a3e4fde148', 'completion': True}</td>
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
      <td>aria.block_dest_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.block_dest_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.block_dest_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.block_dest_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "9c0d0f2b-13d4-65df-e645-3e9a5b10a291"
                }
            ],
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END",
                "Name": "destPortBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723032
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723032</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '9c0d0f2b-13d4-65df-e645-3e9a5b10a291', 'completion': True}</td>
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
      <td>aria.unblock_dest_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.unblock_dest_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.unblock_dest_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.unblock_dest_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "c3df6fce-f727-abe5-a596-aad4086a384d"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "destPortBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723040
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723040<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c3df6fce-f727-abe5-a596-aad4086a384d', 'completion': True}</td>
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
      <td>aria.record_dest_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.record_dest_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.record_dest_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.record_dest_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "8546ba08-ea88-7329-9340-96b42fe6449e"
                }
            ],
            "Rule": {
                "Definition": "390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "destPortRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723048
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723048</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8546ba08-ea88-7329-9340-96b42fe6449e', 'completion': True}</td>
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
      <td>aria.stop_recording_dest_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_dest_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_dest_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.stop_recording_dest_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "740917e5-2152-9229-b592-4392adc37cd9"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "destPortRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723056
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723056<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '740917e5-2152-9229-b592-4392adc37cd9', 'completion': True}</td>
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
      <td>aria.alert_dest_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.alert_dest_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.alert_dest_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.alert_dest_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "8fffe721-8c5e-09f8-07ef-467d5c856b18"
                }
            ],
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "destPortAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723064
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723064</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8fffe721-8c5e-09f8-07ef-467d5c856b18', 'completion': True}</td>
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
      <td>aria.mute_alert_dest_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_dest_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_dest_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.mute_alert_dest_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "34af0fc9-00b2-c30c-ba0d-980131082358"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "destPortAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723072
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723072<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '34af0fc9-00b2-c30c-ba0d-980131082358', 'completion': True}</td>
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
      <td>aria.block_src_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.block_src_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.block_src_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.block_src_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "5f39160c-d4b2-145f-c9cd-a0f892717335"
                }
            ],
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END",
                "Name": "srcPortBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723079
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723079</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '5f39160c-d4b2-145f-c9cd-a0f892717335', 'completion': True}</td>
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
      <td>aria.unblock_src_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.unblock_src_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.unblock_src_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.unblock_src_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "9cc13f49-a8b6-59d8-26be-81a0e8956b5d"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "srcPortBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723086
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723086<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '9cc13f49-a8b6-59d8-26be-81a0e8956b5d', 'completion': True}</td>
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
      <td>aria.record_src_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.record_src_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.record_src_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.record_src_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "2a4edffd-9656-e58c-4e22-9a53b3be9099"
                }
            ],
            "Rule": {
                "Definition": "390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "srcPortRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723095
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723095</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '2a4edffd-9656-e58c-4e22-9a53b3be9099', 'completion': True}</td>
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
      <td>aria.stop_recording_src_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_src_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_src_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.stop_recording_src_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "46f11318-f2da-6d2c-46ca-5eaa3125f05e"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "srcPortRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723104
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723104<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '46f11318-f2da-6d2c-46ca-5eaa3125f05e', 'completion': True}</td>
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
      <td>aria.alert_src_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.alert_src_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.alert_src_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.alert_src_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "be8f9fba-ffe7-e262-1d3d-1d83b8c53861"
                }
            ],
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "srcPortAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723111
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723111</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'be8f9fba-ffe7-e262-1d3d-1d83b8c53861', 'completion': True}</td>
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
      <td>aria.mute_alert_src_port.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_src_port.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_src_port.Endpoints</td>
      <td>unknown</td>
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
    "aria.mute_alert_src_port": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "6911a14b-ab45-9cd2-67ba-57dda34acc07"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "srcPortAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723120
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723120<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '6911a14b-ab45-9cd2-67ba-57dda34acc07', 'completion': True}</td>
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
      <td>aria.block_dest_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.block_dest_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.block_dest_subnet.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-dest-subnet target_ip="192.168.1.0/24" rule_name="destSubnetBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.block_dest_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "f056eaec-1d3a-a14d-d65e-790737d06adf"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.0/24: DROP, END",
                "Name": "destSubnetBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723127
            }
        }
    ]
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
      <td>Name: destSubnetBlock<br>Definition: 192.168.1.0/24: DROP, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723127</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f056eaec-1d3a-a14d-d65e-790737d06adf', 'completion': True}</td>
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
      <td>aria.unblock_dest_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.unblock_dest_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.unblock_dest_subnet.Endpoints</td>
      <td>unknown</td>
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
    "aria.unblock_dest_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "1fe8457f-13f9-1989-0c48-5ceed85eb3a9"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "destSubnetBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723136
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723136<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1fe8457f-13f9-1989-0c48-5ceed85eb3a9', 'completion': True}</td>
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
      <td>aria.record_dest_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.record_dest_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.record_dest_subnet.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-dest-subnet target_ip="192.168.0.100/32" rule_name="destSubnetRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.record_dest_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "ee466760-e3d9-9674-3816-04dfacb2b43b"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.100/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "destSubnetRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723143
            }
        }
    ]
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
      <td>Name: destSubnetRecord<br>Definition: 192.168.0.100/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723143</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'ee466760-e3d9-9674-3816-04dfacb2b43b', 'completion': True}</td>
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
      <td>aria.stop_recording_dest_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_dest_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_dest_subnet.Endpoints</td>
      <td>unknown</td>
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
    "aria.stop_recording_dest_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "e7ca730f-301c-9c18-1ee7-eabcd71a375f"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "destSubnetRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723151
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723151<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'e7ca730f-301c-9c18-1ee7-eabcd71a375f', 'completion': True}</td>
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
      <td>aria.alert_dest_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.alert_dest_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.alert_dest_subnet.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-dest-subnet target_ip="192.168.1.0/24" rule_name="destSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.alert_dest_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "c7a44826-0e87-1349-a118-2d45c66c8878"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "destSubnetAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723158
            }
        }
    ]
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
      <td>Name: destSubnetAlert<br>Definition: 192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723158</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c7a44826-0e87-1349-a118-2d45c66c8878', 'completion': True}</td>
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
      <td>aria.mute_alert_dest_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_dest_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_dest_subnet.Endpoints</td>
      <td>unknown</td>
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
    "aria.mute_alert_dest_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "c04f3f24-c4e2-04a6-17e5-d78f02a042ac"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "destSubnetAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723166
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723166<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c04f3f24-c4e2-04a6-17e5-d78f02a042ac', 'completion': True}</td>
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
      <td>aria.block_src_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.block_src_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.block_src_subnet.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-block-src-subnet src_ip="192.168.1.0/24" rule_name="srcSubnetBlock" label_sia_region="US"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.block_src_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "6ad93bd1-6963-f738-9748-54086f9267b2"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.0/24: DROP, END",
                "Name": "srcSubnetBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723175
            }
        }
    ]
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
      <td>Name: srcSubnetBlock<br>Definition: 192.168.1.0/24: DROP, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723175</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '6ad93bd1-6963-f738-9748-54086f9267b2', 'completion': True}</td>
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
      <td>aria.unblock_src_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.unblock_src_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.unblock_src_subnet.Endpoints</td>
      <td>unknown</td>
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
    "aria.unblock_src_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "a02d41b7-5e31-1ec3-9dfa-8ba31ad8d645"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "srcSubnetBlock"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723183
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723183<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'a02d41b7-5e31-1ec3-9dfa-8ba31ad8d645', 'completion': True}</td>
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
      <td>aria.record_src_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.record_src_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.record_src_subnet.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-record-src-subnet src_ip="192.168.1.0/24" rule_name="srcSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.record_src_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "829b55ab-644e-db17-b8a4-0a1ec825516a"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.0/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "srcSubnetRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723192
            }
        }
    ]
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
      <td>Name: srcSubnetRecord<br>Definition: 192.168.1.0/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723192</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '829b55ab-644e-db17-b8a4-0a1ec825516a', 'completion': True}</td>
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
      <td>aria.stop_recording_src_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_src_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.stop_recording_src_subnet.Endpoints</td>
      <td>unknown</td>
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
    "aria.stop_recording_src_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "eefe605b-4c3a-98af-01db-a7eb9d9f28df"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "srcSubnetRecord"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723200
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723200<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'eefe605b-4c3a-98af-01db-a7eb9d9f28df', 'completion': True}</td>
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
      <td>aria.alert_src_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.alert_src_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.alert_src_subnet.Endpoints</td>
      <td>unknown</td>
      <td>Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!aria-alert-src-subnet src_ip="192.168.1.0/24" rule_name="srcSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "aria.alert_src_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "3a336ed6-9586-b7f0-2c60-9bb358dfb91a"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "srcSubnetAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723208
            }
        }
    ]
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
      <td>Name: srcSubnetAlert<br>Definition: 192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END</td>
      <td>code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570723208</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '3a336ed6-9586-b7f0-2c60-9bb358dfb91a', 'completion': True}</td>
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
      <td>aria.mute_alert_src_subnet.Rule</td>
      <td>Unknown</td>
      <td>Specifies the name of the rule and the settings that define the rule.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_src_subnet.Status</td>
      <td>Unknown</td>
      <td>Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error.</td>
    </tr>
    <tr>
      <td>aria.mute_alert_src_subnet.Endpoints</td>
      <td>unknown</td>
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
    "aria.mute_alert_src_subnet": [
        {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>",
                    "IPAddress": "10.6.0.146",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "Processors": 1,
                    "completion": true,
                    "trid": "bf3aa17a-5f74-492d-526c-ad664835612b"
                }
            ],
            "Rule": {
                "Definition": "",
                "Name": "srcSubnetAlert"
            },
            "Status": {
                "code": 201,
                "command_state": "Success",
                "error_info": "",
                "timestamp": 1570723215
            }
        }
    ]
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
      <td>code: 201<br>error_info: <br>timestamp: 1570723215<br>command_state: Success</td>
      <td>{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_6c4a3c7e-7428-44f5-8d90-63f58c0539ff>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'bf3aa17a-5f74-492d-526c-ad664835612b', 'completion': True}</td>
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
