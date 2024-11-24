The ARIA Cybesecurity Solutions Software-Defined Security (SDS) platform integrates with Cortex XSOAR to add robustness when responding to incidents. The combination of ARIA hardware, in the form of a Secure Intelligent Adapter (SIA), and software, specifically Packet Intelligence and SDS orchestrator (SDSo), provides the elements required to react instantly when an incident is detected. When integrated with the ARIA solution, you can create playbooks that instruct one or more SIAs to add, modify, or delete rules automatically. These rule changes, which take effect immediately, can block conversations, redirect packets to a recorder or VLAN, or perform a variety of other actions.
This integration was integrated and tested with version 1.0.9 of ARIA Packet Intelligence
## Configure ARIA Packet Intelligence in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| sdso | SDSo Base URL \(e.g. http://&lt;IP address or FQDN of SDSo Node&gt;:7443\) | True |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

Note that all commands support a remediation configuration string (RCS). It is a set of parameters that defines how and 
where the rule will be deployed. This string consists of two sets containing comma-separated lists, with the dollar sign ($)
separating the sets. For details of the RCS, please refer to the Appendix at the end of this document and the ARIA SOAR Integration Guide for Cortex XSOAR.
### aria-block-conversation
***
Creates a rule that drops all packets that match the specified 5-tuple values.


#### Base Command

`aria-block-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required | 
| src_port | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| target_ip | The destination IP address. | Required | 
| target_port | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| protocol | The protocol used for the packets (e.g., TCP). | Optional | 
| rule_name | The name of the rule to create. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.BlockConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convBlock" rcs="PIdevice@all"```

#### Context Example
```json
{
    "Aria": {
        "BlockConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "230e10c2-0dea-c12f-8929-092130038061"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "04972eb4-45b2-a877-12f2-4fcc7638f6c1"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : DROP, END",
                "Name": "convBlock",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688609
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convBlock<br/>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 \<\> TCP : DROP, END<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1601688609 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '230e10c2-0dea-c12f-8929-092130038061', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '04972eb4-45b2-a877-12f2-4fcc7638f6c1', 'instance_number': '0', 'completion': True} |


### aria-unblock-conversation
***
Deletes a named rule from the 5-tuple logic block. This allows the previously blocked conversation to resume.


#### Base Command

`aria-unblock-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.UnblockConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-conversation rule_name="convBlock" rcs="PIdevice@all"```

#### Context Example
```json
{
    "Aria": {
        "UnblockConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "09a47807-a7c1-2870-2f32-6cdcf0c908a4"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "de1db8f5-4c79-c425-1f6d-ff6bec3b7214"
                }
            ],
            "Rule": {
                "Definition": "Remove convBlock",
                "Name": "convBlock",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688613
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convBlock<br/>Definition: Remove convBlock<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1601688613 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '09a47807-a7c1-2870-2f32-6cdcf0c908a4', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'de1db8f5-4c79-c425-1f6d-ff6bec3b7214', 'completion': True} |


### aria-record-conversation
***
Creates a rule that redirects a conversation that matches 5-tuple values to the Packet Recorder. Packets are tagged with the VID specified in the instance.


#### Base Command

`aria-record-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required | 
| src_port | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| target_ip | The destination IP address. | Required | 
| target_port | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| protocol | The protocol used for the packets (e.g., TCP) . | Optional | 
| vlan_id | The VLAN ID that your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. Can be A or B. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate. Can be email or syslog. | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is re-trigger-ms or re-triggersec, this is the total amount of time (in msecs or secs), respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.RecordConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="PIdevice@all"```

#### Context Example
```json
{
    "Aria": {
        "RecordConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "0fbc758b-ab0d-95f4-9955-56c96089fa98"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "ab63e403-4f3a-1f3c-6005-c01d249eb185"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "convRecord",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688621
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convRecord<br/>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 \<\> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1601688621 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '0fbc758b-ab0d-95f4-9955-56c96089fa98', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'ab63e403-4f3a-1f3c-6005-c01d249eb185', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-conversation
***
Removes the named rule from the 5-tuple block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.StopRecordingConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-conversation rule_name="convRecord" rcs="PIdevice@all"```

#### Context Example
```json
{
    "Aria": {
        "StopRecordingConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "2d4d8363-176b-2dc7-b9a2-2815d78c186b"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "423e0e00-6eff-b471-385e-040ea4c89455"
                }
            ],
            "Rule": {
                "Definition": "Remove convRecord",
                "Name": "convRecord",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688630
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convRecord<br/>Definition: Remove convRecord<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1601688630 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '2d4d8363-176b-2dc7-b9a2-2815d78c186b', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '423e0e00-6eff-b471-385e-040ea4c89455', 'completion': True} |


### aria-alert-conversation
***
Adds a rule that generates an alert when a conversation that matches the specified 5-tuple values is detected.


#### Base Command

`aria-alert-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required | 
| src_port | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| target_ip | The destination IP address. | Required | 
| target_port | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| protocol | The protocol used for the packets (e.g., TCP) . | Optional | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.AlertConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convAlert" transport_type="email" tti_index="2" aio_index="4" trigger_type="re-trigger-count" trigger_value="1000"```

#### Context Example
```json
{
    "Aria": {
        "AlertConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "92573cdb-9e81-b408-1417-6668cddae433"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "48808901-91b2-5284-d1a3-39cb5fcb1add"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END",
                "Name": "convAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688638
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convAlert<br/>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 \<\> TCP : ALERT email 2 4 re-trigger-count 1000, END<br/>RCS: null | command_state: Success<br/>timestamp: 1601688638 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '92573cdb-9e81-b408-1417-6668cddae433', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '48808901-91b2-5284-d1a3-39cb5fcb1add', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-conversation
***
Removes a named rule from the 5-tuple logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertConversation.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-conversation rule_name="convAlert"```

#### Context Example
```json
{
    "Aria": {
        "MuteAlertConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "6fd436e6-1b5c-9e6d-7e93-a76c4da30be5"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "5d379b52-7100-3238-7d63-e2e77613ead3"
                }
            ],
            "Rule": {
                "Definition": "Remove convAlert",
                "Name": "convAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688644
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convAlert<br/>Definition: Remove convAlert<br/>RCS: null | command_state: Success<br/>timestamp: 1601688644 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '6fd436e6-1b5c-9e6d-7e93-a76c4da30be5', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '5d379b52-7100-3238-7d63-e2e77613ead3', 'completion': True} |


### aria-block-dest-port
***
Creates a rule that blocks packets destined for one or more specified ports.


#### Base Command

`aria-block-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s) to block. This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockDestPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.BlockDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-dest-port port_range="389, 400-404" rule_name="destPortBlock"```

#### Context Example
```json
{
    "Aria": {
        "BlockDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "acfb02ca-5c8c-82d6-dedf-4ba0dfc23244"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "7d46ce85-88ab-0802-2d84-8019fcbd4635"
                }
            ],
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END",
                "Name": "destPortBlock",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688652
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortBlock<br/>Definition: 389, 400 - 404: DROP, END<br/>RCS: null | command_state: Success<br/>timestamp: 1601688652 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'acfb02ca-5c8c-82d6-dedf-4ba0dfc23244', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '7d46ce85-88ab-0802-2d84-8019fcbd4635', 'instance_number': '0', 'completion': True} |


### aria-unblock-dest-port
***
Removes a named rule from the destination port logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockDestPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-dest-port rule_name="destPortBlock"```

#### Context Example
```json
{
    "Aria": {
        "UnblockDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "75355cd0-d6c9-27ae-cd9d-440a124d45bf"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "57d55eb9-e48b-3925-aaa0-cc1134182aab"
                }
            ],
            "Rule": {
                "Definition": "Remove destPortBlock",
                "Name": "destPortBlock",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688659
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortBlock<br/>Definition: Remove destPortBlock<br/>RCS: null | command_state: Success<br/>timestamp: 1601688659 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '75355cd0-d6c9-27ae-cd9d-440a124d45bf', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '57d55eb9-e48b-3925-aaa0-cc1134182aab', 'completion': True} |


### aria-record-dest-port
***
Adds a rule that redirects traffic that is destined for one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.


#### Base Command

`aria-record-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| vlan_id | The VLAN ID that your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. Can be A or B. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate. Can be email or syslog. | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.RecordDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-dest-port port_range="390, 420, 421" rule_name="destPortRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1"rcs="PIdevice@sia12"```

#### Context Example
```json
{
    "Aria": {
        "RecordDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "c09ea941-6c65-ccde-7048-6150ba936d2b"
                }
            ],
            "Rule": {
                "Definition": "390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "destPortRecord",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688666
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortRecord<br/>Definition: 390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1601688666 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'c09ea941-6c65-ccde-7048-6150ba936d2b', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-dest-port
***
Removes a named rule from the destination port logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.StopRecordingDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingDestPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-dest-port rule_name="destPortRecord" rcs="PIdevice@sia12"```

#### Context Example
```json
{
    "Aria": {
        "StopRecordingDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "0fcc428c-5aa9-de08-c41c-4ed82d63ae5d"
                }
            ],
            "Rule": {
                "Definition": "Remove destPortRecord",
                "Name": "destPortRecord",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688671
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortRecord<br/>Definition: Remove destPortRecord<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1601688671 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '0fcc428c-5aa9-de08-c41c-4ed82d63ae5d', 'completion': True} |


### aria-alert-dest-port
***
Creates a rule that generates an alert when traffic destined for one or more ports is detected.


#### Base Command

`aria-alert-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertDestPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.AlertDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertDestPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-dest-port port_range="389-400" rule_name="destPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" rcs="PIdevice@sia12"```

#### Context Example
```json
{
    "Aria": {
        "AlertDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "62dcb6da-b233-b0af-46df-e940087fe267"
                }
            ],
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "destPortAlert",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688680
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortAlert<br/>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1601688680 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '62dcb6da-b233-b0af-46df-e940087fe267', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-dest-port
***
Removes a named rule from the destination port logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.MuteAlertDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertDestPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-dest-port rule_name="destPortAlert" rcs="PIdevice@sia12"```

#### Context Example
```json
{
    "Aria": {
        "MuteAlertDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "b79b2d3c-af73-e7d5-eaaf-d8e080c03cfd"
                }
            ],
            "Rule": {
                "Definition": "Remove destPortAlert",
                "Name": "destPortAlert",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688687
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortAlert<br/>Definition: Remove destPortAlert<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1601688687 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'b79b2d3c-af73-e7d5-eaaf-d8e080c03cfd', 'completion': True} |


### aria-block-src-port
***
Adds a rule that blocks packets originating from one or more specific ports.


#### Base Command

`aria-block-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.BlockSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-src-port port_range="389, 400-404" rule_name="srcPortBlock" rcs="PIdevice@all.all.sia32"```

#### Context Example
```json
{
    "Aria": {
        "BlockSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "b4b8e8e2-39f8-7af7-beca-f256f7d4eb93"
                }
            ],
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END",
                "Name": "srcPortBlock",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688693
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortBlock<br/>Definition: 389, 400 - 404: DROP, END<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1601688693 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'b4b8e8e2-39f8-7af7-beca-f256f7d4eb93', 'instance_number': '0', 'completion': True} |


### aria-unblock-src-port
***
Removes a named rule from the source port logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-src-port rule_name="srcPortBlock" rcs="PIdevice@all.all.sia32"```

#### Context Example
```json
{
    "Aria": {
        "UnblockSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "7e389793-bc05-0b45-8a95-f0d7e9fa1da8"
                }
            ],
            "Rule": {
                "Definition": "Remove srcPortBlock",
                "Name": "srcPortBlock",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688699
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortBlock<br/>Definition: Remove srcPortBlock<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1601688699 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '7e389793-bc05-0b45-8a95-f0d7e9fa1da8', 'completion': True} |


### aria-record-src-port
***
Adds a rule that redirects traffic originating from one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.


#### Base Command

`aria-record-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. Can be A or B. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate. Can be email or syslog. | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.RecordSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-src-port port_range="390, 420" rule_name="srcPortRecord" sia_interface="B" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="PIdevice@all.all.sia32"```

#### Context Example
```json
{
    "Aria": {
        "RecordSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "2684d0ed-c355-fdb9-85ae-3d6464108ff2"
                }
            ],
            "Rule": {
                "Definition": "390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "srcPortRecord",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688706
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortRecord<br/>Definition: 390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1601688706 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '2684d0ed-c355-fdb9-85ae-3d6464108ff2', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-src-port
***
Removes a named rule from the source port logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.StopRecordingSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-src-port rule_name="srcPortRecord" rcs="PIdevice@all.all.sia32"```

#### Context Example
```json
{
    "Aria": {
        "StopRecordingSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "68464a28-1502-7421-9ac0-e4f9672a2a33"
                }
            ],
            "Rule": {
                "Definition": "Remove srcPortRecord",
                "Name": "srcPortRecord",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688712
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortRecord<br/>Definition: Remove srcPortRecord<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1601688712 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '68464a28-1502-7421-9ac0-e4f9672a2a33', 'completion': True} |


### aria-alert-src-port
***
Creates a rule that generates an alert when traffic originating from one or more ports is detected.


#### Base Command

`aria-alert-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate. Can be email or syslog | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.AlertSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-src-port port_range="389-400" rule_name="srcPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" rcs="PIdevice@sia12,sia32"```

#### Context Example
```json
{
    "Aria": {
        "AlertSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "dcd87781-f63f-cf2e-24ca-e6623467fbe4"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "6f085ea9-385d-78f9-2a43-50b80fd5e656"
                }
            ],
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "srcPortAlert",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688721
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortAlert<br/>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1601688721 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'dcd87781-f63f-cf2e-24ca-e6623467fbe4', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '6f085ea9-385d-78f9-2a43-50b80fd5e656', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-src-port
***
Removes a named rule from the source port logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-src-port rule_name="srcPortAlert" rcs="PIdevice@sia12,sia32"```

#### Context Example
```json
{
    "Aria": {
        "MuteAlertSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "57fab3e3-7d94-174a-ae7a-942b45ebba63"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "9ce59360-c23a-a3f2-2c23-79c200bb4b4f"
                }
            ],
            "Rule": {
                "Definition": "Remove srcPortAlert",
                "Name": "srcPortAlert",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688729
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortAlert<br/>Definition: Remove srcPortAlert<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1601688729 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '57fab3e3-7d94-174a-ae7a-942b45ebba63', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '9ce59360-c23a-a3f2-2c23-79c200bb4b4f', 'completion': True} |


### aria-block-dest-subnet
***
Adds a rule that blocks packets destined for a specific IP address or range of IP addresses.


#### Base Command

`aria-block-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP address and mask of the destination IP address(es), in the format &lt;IP_address&gt;/&lt;mask&gt;. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.BlockDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetBlock" rcs="PIdevice@sia12,sia32"```

#### Context Example
```json
{
    "Aria": {
        "BlockDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "0f7b6c11-bf19-bb23-eca4-8ea9ec47b35e"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "ffa29b82-9953-0dc3-102f-b16690f111bd"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: DROP, END",
                "Name": "destSubnetBlock",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688736
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetBlock<br/>Definition: 192.168.1.2/24: DROP, END<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1601688736 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '0f7b6c11-bf19-bb23-eca4-8ea9ec47b35e', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'ffa29b82-9953-0dc3-102f-b16690f111bd', 'instance_number': '0', 'completion': True} |


### aria-unblock-dest-subnet
***
Removes a named rule from the destination subnet logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-dest-subnet rule_name="destSubnetBlock" rcs="PIdevice@sia12,sia32"```

#### Context Example
```json
{
    "Aria": {
        "UnblockDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "67a27b63-4141-6eba-841f-7f7af8f236bb"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "993dbafd-f335-0a71-8501-8e5135686b6a"
                }
            ],
            "Rule": {
                "Definition": "Remove destSubnetBlock",
                "Name": "destSubnetBlock",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688743
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetBlock<br/>Definition: Remove destSubnetBlock<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1601688743 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '67a27b63-4141-6eba-841f-7f7af8f236bb', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '993dbafd-f335-0a71-8501-8e5135686b6a', 'completion': True} |


### aria-record-dest-subnet
***
Creates a rule that redirects traffic destined for a specific IP address or range of IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.


#### Base Command

`aria-record-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP address and mask of the destination IP address(es), in the format &lt;IP_address&gt;/&lt;mask&gt;. If the mask is omitted, a value of 32 is used. | Required | 
| vlan_id | The VLAN ID that your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. Can be A or B. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate.  | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.RecordDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-dest-subnet target_ip="192.168.10.23/32" rule_name="destSubnetRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="PIdevice@US.HR.all"```

#### Context Example
```json
{
    "Aria": {
        "RecordDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "747751b0-449a-17c2-24b5-be629b5f0869"
                }
            ],
            "Rule": {
                "Definition": "192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "destSubnetRecord",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688752
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetRecord<br/>Definition: 192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1601688752 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '747751b0-449a-17c2-24b5-be629b5f0869', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-dest-subnet
***
Removes a named rule from the destination subnet logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.StopRecordingDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-dest-subnet rule_name="destSubnetRecord" rcs="PIdevice@US.HR.all"```

#### Context Example
```json
{
    "Aria": {
        "StopRecordingDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "2deabe1b-c7a9-64c4-d43d-5ceba0c81b94"
                }
            ],
            "Rule": {
                "Definition": "Remove destSubnetRecord",
                "Name": "destSubnetRecord",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688759
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetRecord<br/>Definition: Remove destSubnetRecord<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1601688759 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '2deabe1b-c7a9-64c4-d43d-5ceba0c81b94', 'completion': True} |


### aria-alert-dest-subnet
***
Creates a rule that generates an alert when traffic destined for a specific IP address or range of IP addresses is detected.


#### Base Command

`aria-alert-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP address and mask of the destination IP address(es), in the format &lt;IP_address&gt;/&lt;mask&gt;. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate. Can be email or syslog. | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.AlertDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" rcs="PIdevice@US.HR.all"```

#### Context Example
```json
{
    "Aria": {
        "AlertDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "56323db6-be93-a52a-04a7-23c28526d382"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "destSubnetAlert",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688766
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetAlert<br/>Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1601688766 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '56323db6-be93-a52a-04a7-23c28526d382', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-dest-subnet
***
Removes a named rule from the destination subnet logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-dest-subnet rule_name="destSubnetAlert" rcs="PIdevice@US.HR.all"```

#### Context Example
```json
{
    "Aria": {
        "MuteAlertDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "2ded90f8-772c-cc3c-66ab-5c72bd197dec"
                }
            ],
            "Rule": {
                "Definition": "Remove destSubnetAlert",
                "Name": "destSubnetAlert",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688775
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetAlert<br/>Definition: Remove destSubnetAlert<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1601688775 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '2ded90f8-772c-cc3c-66ab-5c72bd197dec', 'completion': True} |


### aria-block-src-subnet
***
Adds a rule that blocks packets originating from a specific IP address or range of IP addresses.


#### Base Command

`aria-block-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP address and mask of the source IP address(es), in the format &lt;IP_address&gt;/&lt;mask&gt;. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.BlockSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetBlock" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```json
{
    "Aria": {
        "BlockSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "b341314d-6a94-9432-10f2-e82d426765b0"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: DROP, END",
                "Name": "srcSubnetBlock",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688782
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetBlock<br/>Definition: 192.168.1.2/24: DROP, END<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1601688782 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'b341314d-6a94-9432-10f2-e82d426765b0', 'instance_number': '0', 'completion': True} |


### aria-unblock-src-subnet
***
Removes a named rule from the source subnet logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-src-subnet rule_name="srcSubnetBlock" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```json
{
    "Aria": {
        "UnblockSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "8d2edba7-d4db-73a4-fcb3-c885db966ec1"
                }
            ],
            "Rule": {
                "Definition": "Remove srcSubnetBlock",
                "Name": "srcSubnetBlock",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688789
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetBlock<br/>Definition: Remove srcSubnetBlock<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1601688789 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '8d2edba7-d4db-73a4-fcb3-c885db966ec1', 'completion': True} |


### aria-record-src-subnet
***
Creates a rule that redirects traffic originating from one or more specific IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.


#### Base Command

`aria-record-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP address and mask of the source IP address(es), in the format &lt;IP_address&gt;/&lt;mask&gt;. If the mask is omitted, a value of 32 is used. | Required | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. Can be A or B. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate. Can be email or syslog. | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.RecordSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```json
{
    "Aria": {
        "RecordSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "52092233-a96c-39be-66ff-7ab52bb38dc1"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "srcSubnetRecord",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688798
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetRecord<br/>Definition: 192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1601688798 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '52092233-a96c-39be-66ff-7ab52bb38dc1', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-src-subnet
***
Removes a named rule from the source subnet logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.StopRecordingSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-src-subnet rule_name="srcSubnetRecord" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```json
{
    "Aria": {
        "StopRecordingSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "6ce98c59-d145-c0e8-dfd4-0a3b348e9d1b"
                }
            ],
            "Rule": {
                "Definition": "Remove srcSubnetRecord",
                "Name": "srcSubnetRecord",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688806
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetRecord<br/>Definition: Remove srcSubnetRecord<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1601688806 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '6ce98c59-d145-c0e8-dfd4-0a3b348e9d1b', 'completion': True} |


### aria-alert-src-subnet
***
Adds a rule that generates an alert when traffic originating from a specific IP address or range of IP addresses is detected.


#### Base Command

`aria-alert-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP address and mask of the source IP address(es), in the format &lt;IP_address&gt;/&lt;mask&gt;. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. After the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets that match the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. re-trigger-timed-ms: The alert is triggered, and then the application waits the amount of time (in msecs) defined in the trigger_value field. Once this time passes, the alert is triggered again. re-trigger-timed-sec: The alert is triggered, and then the application waits the amount of time (in seconds) defined in the trigger_value field. After this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.AlertSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200"```

#### Context Example
```json
{
    "Aria": {
        "AlertSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "ad0fe8eb-5c43-e121-2618-8c09e942068d"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "6b6916d1-ff47-ab71-fac6-473626bd9b0b"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "srcSubnetAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688814
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetAlert<br/>Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: null | command_state: Success<br/>timestamp: 1601688814 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'ad0fe8eb-5c43-e121-2618-8c09e942068d', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '6b6916d1-ff47-ab71-fac6-473626bd9b0b', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-src-subnet
***
Removes a named rule from the source subnet logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. Please refer to the integration documentation for more information. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-src-subnet rule_name="srcSubnetAlert"```

#### Context Example
```json
{
    "Aria": {
        "MuteAlertSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "a56e3ae8-f361-e648-e286-4e4f8e04d13b"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "9ed18816-79d1-316e-68d8-7021a3b4f2e7"
                }
            ],
            "Rule": {
                "Definition": "Remove srcSubnetAlert",
                "Name": "srcSubnetAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1601688822
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetAlert<br/>Definition: Remove srcSubnetAlert<br/>RCS: null | command_state: Success<br/>timestamp: 1601688822 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_590c49ce-1286-481b-ae07-f4192130e7af>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'a56e3ae8-f361-e648-e286-4e4f8e04d13b', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_07023d45-d4a0-4204-949d-86ce009fd172>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '9ed18816-79d1-316e-68d8-7021a3b4f2e7', 'completion': True} |

## Appendix
The remediation configuration string is a set of parameters that defines how and where the remediation rule
will be deployed. This string consists of two sets containing comma-separated lists, with the dollar sign ($)
separating the sets. These two sets are:

* Security Domain List: Identifies the list of security domains, which consist of one or more regions,
nodes, or clusters. Only devices bound to the security domains listed here are evaluated when finding
a match.
* Remediation Device List: Identifies the list of remediation devices, or SIAs running PI, that will
execute the action. These devices must be part of a security domain specified in the security domain
list.

See the following section for details about the syntax used for each of these sets.

#### Security Domain List
The security domain list follows the format securityDomain@&lt;domain1&gt;, &lt;domain2&gt;, ...
&lt;domainN&gt;. If more than one domain is provided, remediation devices in all listed domains are
evaluated. For example, if SIA1 and SIA2 are part of &lt;domain1&gt;, and SIA 3 and SIA4 are part of
&lt;domain2&gt;, all SIAs (1-4) will be evaluated when attempting to find a match. If omitted, the action
is executed on the SIA(s) defined in the remediation device list.
> |Note|
> |---|
> |The list must contain at least one security domain if securityDomain@ is provided. If the list is empty, the string will fail. You can omit the entire string, but not just the list.|

#### Remediation Device List

This remediation device list is required and follows the format:
* PIdevice@&lt;sia1&gt;, &lt;sia2&gt;, ... &lt;siaN&gt;

The SIAs can be identified based on the SIA name or SIA label. <br/>
The SIA name is simply the name given to the SIA, such as SIA1. <br/>
The SIA label follows a specific schema and uses the format:
* &lt;region\>.&lt;group\>.&lt;name\>

For example, the label for SIA1 in the engineering group, which is part of the MA region would be
MA.engineering.SIA1. 

It’s also possible to specify one or more security domains using the format:
* ^&lt;domain1&gt;,&lt;domain2&gt;,...,&lt;domainN&gt;

If the security domain list (securityDomain) is provided, these domains must intersect with one or
more in the security domain list; otherwise, the remediation action will not be executed. For
example, if the security domain list includes ARIA-North, and ARIA-South is specified as the
PIdevice, only those SIAs that are members of both ARIA-North and ARIA-South will be included.
If no SIAs exist in either domain, the action will not be executed.
To provide granularity based on labels, the SIA field accepts wildcards, inclusions, exclusions, and
the keyword all.

An asterisk (\*) denotes a wildcard, indicating any string for that particular label will return a
match. For example, MA.engineering.\* returns all SIAs in the engineering group of the MA
region.

The inclusion option allows you to provide a list of strings for a specific label, such as group. This
comma-separated list is enclosed in parentheses ( ) and removes the need to spell out each name
individually. For example, MA.(engineering,sales).\* replaces MA.engineering.\*,
MA.sales.\*.

To exclude one or more areas, add the exclamation point (!) to a list enclosed in parentheses ( ).
This returns every SIA except any specified in the exclusion list. 
For example MA.!(engineering).\* returns everything in the MA region except those SIAs that are part of the
engineering group.

Finally, you can use the keyword all to return all matches for that particular label, which is
equivalent to using the wildcard. For example, MA.all.all is equivalent to "MA.\*.\*".

#### RCS Examples:
> |RCS string|Explanation|
> |---|---|
> | PIdevice@all | This is the default RCS if not provided in the command. It will send rules to all the SIAs attached to the SDSo. |
> | PIdevice@MA.ENG.\* | This RCS will select SIAs which have a region label "MA" and a group label "ENG". |
> | PIdevice@MA.HR.!(sia1, sia2) | This RCS will select all SIAs with a region label "MA" and a group label "HR", while excluding SIAs with name labels of "sia1" and "sia2". |
> | securityDomain@ARIA-NORTH@<br/>PIdevice@MA.HR.sia1,sia2,^ARIA-SOUTH| This RCS will select the SIA with a region label of "MA", group label of "HR", and name label of "sia1". It will also select the SIA named "sia2" as well as any SIAs that are members of both domains (i.e., ARIA-NORTH and ARIA-SOUTH). |

## Additional Information
For more information, please see the ARIA_SOAR_Integration_Guide_XSOAR.