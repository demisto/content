The ARIA Cybesecurity Solutions Software-Defined Security (SDS)  platform integrates with Demisto to add robustness when responding to incidents. The combination of ARIA hardware, in the form of a Secure Intelligent Adapter (SIA), and software, specifically Packet Intelligence and SDS orchestrator (SDSo), provides the elements required to react instantly when an incident is detected. When integrated with the ARIA solution, you can create playbooks that instruct one or more SIAs to add, modify, or delete rules automatically. These rule changes, which take effect immediately, can block conversations, redirect packets to a recorder or VLAN, or perform a variety of other actions.
This integration was integrated and tested with version 2.0.0 of ARIA Packet Intelligence
## Configure ARIA Packet Intelligence on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ARIA Packet Intelligence.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| sdso | SDSo Base URL \(e.g. http://&lt;IP address or FQDN of SDSo Node&gt;:7443\) | True |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

Note that all commands support a remediation configuration string (RCS). It is a set of parameters that defines how and 
where the rule will be deployed. This string consists of two sets containing comma-separated lists, with the dollar sign ($)
separating the sets. For details of the RCS, please refer to the Appendix at the end of this document and the ARIA SOAR Integration Guide for Demisto.
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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.BlockConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convBlock" rcs="PIdevice@all"```

#### Context Example
```
{
    "Aria": {
        "BlockConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "53ca2810-485d-a0e7-2f0e-c72c7cdd0f91"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "eb59a176-7f6f-3950-e6ba-541a4a1f636f"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : DROP, END",
                "Name": "convBlock",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354371
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convBlock<br/>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : DROP, END<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1600354371 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '53ca2810-485d-a0e7-2f0e-c72c7cdd0f91', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'eb59a176-7f6f-3950-e6ba-541a4a1f636f', 'instance_number': '0', 'completion': True} |


### aria-unblock-conversation
***
Deletes a named rule from the 5-tuple logic block. This allows the previously blocked conversation to resume.


#### Base Command

`aria-unblock-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.UnblockConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-conversation rule_name="convBlock" rcs="PIdevice@all"```

#### Context Example
```
{
    "Aria": {
        "UnblockConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "fc590df2-d4cd-4311-4631-4d5af25071c7"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "45cd785f-5d2f-6029-f8f3-7eb425ccd17c"
                }
            ],
            "Rule": {
                "Definition": "Remove convBlock",
                "Name": "convBlock",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354376
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convBlock<br/>Definition: Remove convBlock<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1600354376 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'fc590df2-d4cd-4311-4631-4d5af25071c7', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '45cd785f-5d2f-6029-f8f3-7eb425ccd17c', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.RecordConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="PIdevice@all"```

#### Context Example
```
{
    "Aria": {
        "RecordConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "ae0c4f77-d40e-11d9-55a9-4cb19d356949"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "d4fcd0ac-54bc-aae8-56fe-e621b6999779"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "convRecord",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354383
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convRecord<br/>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1600354383 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'ae0c4f77-d40e-11d9-55a9-4cb19d356949', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'd4fcd0ac-54bc-aae8-56fe-e621b6999779', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-conversation
***
Removes the named rule from the 5-tuple block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.StopRecordingConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-conversation rule_name="convRecord" rcs="PIdevice@all"```

#### Context Example
```
{
    "Aria": {
        "StopRecordingConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "d9efbf48-bf7b-fe86-01c3-82624952a0eb"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "5de3ac0d-7556-a910-94d4-14cedae6acef"
                }
            ],
            "Rule": {
                "Definition": "Remove convRecord",
                "Name": "convRecord",
                "RCS": "PIdevice@all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354391
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convRecord<br/>Definition: Remove convRecord<br/>RCS: PIdevice@all | command_state: Success<br/>timestamp: 1600354391 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'd9efbf48-bf7b-fe86-01c3-82624952a0eb', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '5de3ac0d-7556-a910-94d4-14cedae6acef', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.AlertConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convAlert" transport_type="email" tti_index="2" aio_index="4" trigger_type="re-trigger-count" trigger_value="1000"```

#### Context Example
```
{
    "Aria": {
        "AlertConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "786f12d4-87ad-79ae-c860-3753a2740bd1"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "10f3a323-8b9d-ab8d-4ae5-e173ec6ce317"
                }
            ],
            "Rule": {
                "Definition": "192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END",
                "Name": "convAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354398
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convAlert<br/>Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END<br/>RCS: null | command_state: Success<br/>timestamp: 1600354398 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '786f12d4-87ad-79ae-c860-3753a2740bd1', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '10f3a323-8b9d-ab8d-4ae5-e173ec6ce317', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-conversation
***
Removes a named rule from the 5-tuple logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-conversation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertConversation.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertConversation.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-conversation rule_name="convAlert"```

#### Context Example
```
{
    "Aria": {
        "MuteAlertConversation": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "12d5dd82-abfe-c3c8-6432-a3070d7fa6be"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "b1c70231-b63d-9702-d528-bc155d615bc6"
                }
            ],
            "Rule": {
                "Definition": "Remove convAlert",
                "Name": "convAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354408
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-conversation
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: convAlert<br/>Definition: Remove convAlert<br/>RCS: null | command_state: Success<br/>timestamp: 1600354408 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '12d5dd82-abfe-c3c8-6432-a3070d7fa6be', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'b1c70231-b63d-9702-d528-bc155d615bc6', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockDestPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.BlockDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-dest-port port_range="389, 400-404" rule_name="destPortBlock"```

#### Context Example
```
{
    "Aria": {
        "BlockDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "8aa255b7-1556-1b0f-8eb0-3c3ac77a3423"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "3cb7b9a7-936c-8131-93e6-fac4ad8e3dd8"
                }
            ],
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END",
                "Name": "destPortBlock",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354415
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortBlock<br/>Definition: 389, 400 - 404: DROP, END<br/>RCS: null | command_state: Success<br/>timestamp: 1600354415 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '8aa255b7-1556-1b0f-8eb0-3c3ac77a3423', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '3cb7b9a7-936c-8131-93e6-fac4ad8e3dd8', 'instance_number': '0', 'completion': True} |


### aria-unblock-dest-port
***
Removes a named rule from the destination port logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockDestPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-dest-port rule_name="destPortBlock"```

#### Context Example
```
{
    "Aria": {
        "UnblockDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "aaaed5e9-d336-6054-6522-d86fa81cdac8"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "4f93e860-2c3f-12d4-a82d-595cd70f1259"
                }
            ],
            "Rule": {
                "Definition": "Remove destPortBlock",
                "Name": "destPortBlock",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354423
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortBlock<br/>Definition: Remove destPortBlock<br/>RCS: null | command_state: Success<br/>timestamp: 1600354423 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'aaaed5e9-d336-6054-6522-d86fa81cdac8', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '4f93e860-2c3f-12d4-a82d-595cd70f1259', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.RecordDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-dest-port port_range="390, 420, 421" rule_name="destPortRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1"rcs="PIdevice@sia12"```

#### Context Example
```
{
    "Aria": {
        "RecordDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "0b9faffd-2db1-c28c-9f6a-a18c6b51fd59"
                }
            ],
            "Rule": {
                "Definition": "390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "destPortRecord",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354430
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortRecord<br/>Definition: 390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1600354430 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '0b9faffd-2db1-c28c-9f6a-a18c6b51fd59', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-dest-port
***
Removes a named rule from the destination port logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.StopRecordingDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingDestPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-dest-port rule_name="destPortRecord" rcs="PIdevice@sia12"```

#### Context Example
```
{
    "Aria": {
        "StopRecordingDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "f44b76d8-38cb-d130-d235-5225136a016e"
                }
            ],
            "Rule": {
                "Definition": "Remove destPortRecord",
                "Name": "destPortRecord",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354438
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortRecord<br/>Definition: Remove destPortRecord<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1600354438 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'f44b76d8-38cb-d130-d235-5225136a016e', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertDestPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.AlertDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertDestPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-dest-port port_range="389-400" rule_name="destPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" rcs="PIdevice@sia12"```

#### Context Example
```
{
    "Aria": {
        "AlertDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "bb70583f-e33b-1cba-20ef-3009bf70b82d"
                }
            ],
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "destPortAlert",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354446
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortAlert<br/>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1600354446 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'bb70583f-e33b-1cba-20ef-3009bf70b82d', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-dest-port
***
Removes a named rule from the destination port logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-dest-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.MuteAlertDestPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertDestPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-dest-port rule_name="destPortAlert" rcs="PIdevice@sia12"```

#### Context Example
```
{
    "Aria": {
        "MuteAlertDestPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "e0cdc674-5d4c-fce9-70d5-1c2b8a0741d4"
                }
            ],
            "Rule": {
                "Definition": "Remove destPortAlert",
                "Name": "destPortAlert",
                "RCS": "PIdevice@sia12"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354453
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-dest-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destPortAlert<br/>Definition: Remove destPortAlert<br/>RCS: PIdevice@sia12 | command_state: Success<br/>timestamp: 1600354453 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'e0cdc674-5d4c-fce9-70d5-1c2b8a0741d4', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.BlockSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-src-port port_range="389, 400-404" rule_name="srcPortBlock" rcs="PIdevice@all.all.sia32"```

#### Context Example
```
{
    "Aria": {
        "BlockSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "9c667338-4608-d75a-38ec-6d4498bfec91"
                }
            ],
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END",
                "Name": "srcPortBlock",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354460
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortBlock<br/>Definition: 389, 400 - 404: DROP, END<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1600354460 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '9c667338-4608-d75a-38ec-6d4498bfec91', 'instance_number': '0', 'completion': True} |


### aria-unblock-src-port
***
Removes a named rule from the source port logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-src-port rule_name="srcPortBlock" rcs="PIdevice@all.all.sia32"```

#### Context Example
```
{
    "Aria": {
        "UnblockSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "ed3d1d25-aa4c-0960-49e7-8cccfa30adef"
                }
            ],
            "Rule": {
                "Definition": "Remove srcPortBlock",
                "Name": "srcPortBlock",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354464
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortBlock<br/>Definition: Remove srcPortBlock<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1600354464 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'ed3d1d25-aa4c-0960-49e7-8cccfa30adef', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.RecordSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-src-port port_range="390, 420" rule_name="srcPortRecord" sia_interface="B" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="PIdevice@all.all.sia32"```

#### Context Example
```
{
    "Aria": {
        "RecordSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "acefbd23-a92c-7381-8c36-065ea491378f"
                }
            ],
            "Rule": {
                "Definition": "390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "srcPortRecord",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354472
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortRecord<br/>Definition: 390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1600354472 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'acefbd23-a92c-7381-8c36-065ea491378f', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-src-port
***
Removes a named rule from the source port logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.StopRecordingSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-src-port rule_name="srcPortRecord" rcs="PIdevice@all.all.sia32"```

#### Context Example
```
{
    "Aria": {
        "StopRecordingSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "86911012-70b6-f822-967d-7de9b5846c90"
                }
            ],
            "Rule": {
                "Definition": "Remove srcPortRecord",
                "Name": "srcPortRecord",
                "RCS": "PIdevice@all.all.sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354479
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortRecord<br/>Definition: Remove srcPortRecord<br/>RCS: PIdevice@all.all.sia32 | command_state: Success<br/>timestamp: 1600354479 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '86911012-70b6-f822-967d-7de9b5846c90', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.AlertSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-src-port port_range="389-400" rule_name="srcPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" rcs="PIdevice@sia12,sia32"```

#### Context Example
```
{
    "Aria": {
        "AlertSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "53231d39-1a0d-82fb-0523-c37b30e86aaa"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "2c4a43c0-b95d-e9cc-5c0b-5310f58494f5"
                }
            ],
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "srcPortAlert",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354486
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortAlert<br/>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1600354486 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '53231d39-1a0d-82fb-0523-c37b30e86aaa', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '2c4a43c0-b95d-e9cc-5c0b-5310f58494f5', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-src-port
***
Removes a named rule from the source port logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-src-port`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertSrcPort.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertSrcPort.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertSrcPort.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-src-port rule_name="srcPortAlert" rcs="PIdevice@sia12,sia32"```

#### Context Example
```
{
    "Aria": {
        "MuteAlertSrcPort": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "15c7a338-dabf-708e-2899-88081907f21a"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "d959a37c-b130-86ca-cb8a-9b897aa2f832"
                }
            ],
            "Rule": {
                "Definition": "Remove srcPortAlert",
                "Name": "srcPortAlert",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354494
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-src-port
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcPortAlert<br/>Definition: Remove srcPortAlert<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1600354494 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '15c7a338-dabf-708e-2899-88081907f21a', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'd959a37c-b130-86ca-cb8a-9b897aa2f832', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.BlockDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetBlock" rcs="PIdevice@sia12,sia32"```

#### Context Example
```
{
    "Aria": {
        "BlockDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "10bdd6ab-c242-6b48-1597-c8ce142ee30a"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "e371c5eb-3cf2-f08b-fc79-1d2995f54f42"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: DROP, END",
                "Name": "destSubnetBlock",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354501
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetBlock<br/>Definition: 192.168.1.2/24: DROP, END<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1600354501 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '10bdd6ab-c242-6b48-1597-c8ce142ee30a', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'e371c5eb-3cf2-f08b-fc79-1d2995f54f42', 'instance_number': '0', 'completion': True} |


### aria-unblock-dest-subnet
***
Removes a named rule from the destination subnet logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-dest-subnet rule_name="destSubnetBlock" rcs="PIdevice@sia12,sia32"```

#### Context Example
```
{
    "Aria": {
        "UnblockDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "513ea8c2-3e5c-1e84-c954-e02204dcb6ff"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "16f30df8-2a7f-e0fd-09b5-f68d710e2f4f"
                }
            ],
            "Rule": {
                "Definition": "Remove destSubnetBlock",
                "Name": "destSubnetBlock",
                "RCS": "PIdevice@sia12,sia32"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354508
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetBlock<br/>Definition: Remove destSubnetBlock<br/>RCS: PIdevice@sia12,sia32 | command_state: Success<br/>timestamp: 1600354508 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '513ea8c2-3e5c-1e84-c954-e02204dcb6ff', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '16f30df8-2a7f-e0fd-09b5-f68d710e2f4f', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.RecordDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-dest-subnet target_ip="192.168.10.23/32" rule_name="destSubnetRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="PIdevice@US.HR.all"```

#### Context Example
```
{
    "Aria": {
        "RecordDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "f8aa3376-cd1d-9253-fad3-ea341beea954"
                }
            ],
            "Rule": {
                "Definition": "192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "destSubnetRecord",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354517
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetRecord<br/>Definition: 192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1600354517 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'f8aa3376-cd1d-9253-fad3-ea341beea954', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-dest-subnet
***
Removes a named rule from the destination subnet logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.StopRecordingDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-dest-subnet rule_name="destSubnetRecord" rcs="PIdevice@US.HR.all"```

#### Context Example
```
{
    "Aria": {
        "StopRecordingDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "9da35b23-8f4f-8b67-daaf-68567141cd80"
                }
            ],
            "Rule": {
                "Definition": "Remove destSubnetRecord",
                "Name": "destSubnetRecord",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354524
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetRecord<br/>Definition: Remove destSubnetRecord<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1600354524 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '9da35b23-8f4f-8b67-daaf-68567141cd80', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.AlertDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" rcs="PIdevice@US.HR.all"```

#### Context Example
```
{
    "Aria": {
        "AlertDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "a43d55b2-a20d-d090-f0e5-03be8227860b"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "destSubnetAlert",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354532
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetAlert<br/>Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1600354532 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'a43d55b2-a20d-d090-f0e5-03be8227860b', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-dest-subnet
***
Removes a named rule from the destination subnet logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-dest-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertDestSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertDestSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertDestSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-dest-subnet rule_name="destSubnetAlert" rcs="PIdevice@US.HR.all"```

#### Context Example
```
{
    "Aria": {
        "MuteAlertDestSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "58e741dc-1ad4-a1ac-33a6-05d630f3d3af"
                }
            ],
            "Rule": {
                "Definition": "Remove destSubnetAlert",
                "Name": "destSubnetAlert",
                "RCS": "PIdevice@US.HR.all"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354539
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-dest-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: destSubnetAlert<br/>Definition: Remove destSubnetAlert<br/>RCS: PIdevice@US.HR.all | command_state: Success<br/>timestamp: 1600354539 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '58e741dc-1ad4-a1ac-33a6-05d630f3d3af', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.BlockSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.BlockSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-block-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetBlock" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```
{
    "Aria": {
        "BlockSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "a31c0086-8dea-ffd4-ab2f-920d6e5ade66"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: DROP, END",
                "Name": "srcSubnetBlock",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354547
            }
        }
    }
}
```

#### Human Readable Output

>### aria-block-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetBlock<br/>Definition: 192.168.1.2/24: DROP, END<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1600354547 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'a31c0086-8dea-ffd4-ab2f-920d6e5ade66', 'instance_number': '0', 'completion': True} |


### aria-unblock-src-subnet
***
Removes a named rule from the source subnet logic block. This allows the previously blocked traffic to resume.


#### Base Command

`aria-unblock-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.UnblockSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.UnblockSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-unblock-src-subnet rule_name="srcSubnetBlock" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```
{
    "Aria": {
        "UnblockSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "b0838dff-048b-7be8-2fe8-f727feda0867"
                }
            ],
            "Rule": {
                "Definition": "Remove srcSubnetBlock",
                "Name": "srcSubnetBlock",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354554
            }
        }
    }
}
```

#### Human Readable Output

>### aria-unblock-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetBlock<br/>Definition: Remove srcSubnetBlock<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1600354554 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'b0838dff-048b-7be8-2fe8-f727feda0867', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. | 
| Aria.RecordSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.RecordSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-record-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```
{
    "Aria": {
        "RecordSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "9344ee5c-d794-d3f6-3457-16a2bbd3d28c"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END",
                "Name": "srcSubnetRecord",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354562
            }
        }
    }
}
```

#### Human Readable Output

>### aria-record-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetRecord<br/>Definition: 192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1600354562 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '9344ee5c-d794-d3f6-3457-16a2bbd3d28c', 'instance_number': '0', 'completion': True} |


### aria-stop-recording-src-subnet
***
Removes a named rule from the source subnet logic block. This stops redirecting traffic to the Packet Recorder.


#### Base Command

`aria-stop-recording-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.StopRecordingSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.StopRecordingSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-stop-recording-src-subnet rule_name="srcSubnetRecord" rcs="securityDomain@aria$PIdevice@all.all.!(sia12)"```

#### Context Example
```
{
    "Aria": {
        "StopRecordingSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "3717bd79-984d-0542-8500-d9679eefddc8"
                }
            ],
            "Rule": {
                "Definition": "Remove srcSubnetRecord",
                "Name": "srcSubnetRecord",
                "RCS": "securityDomain@aria$PIdevice@all.all.!(sia12)"
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354569
            }
        }
    }
}
```

#### Human Readable Output

>### aria-stop-recording-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetRecord<br/>Definition: Remove srcSubnetRecord<br/>RCS: securityDomain@aria$PIdevice@all.all.!(sia12) | command_state: Success<br/>timestamp: 1600354569 | {'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '3717bd79-984d-0542-8500-d9679eefddc8', 'completion': True} |


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
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.AlertSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.AlertSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-alert-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200"```

#### Context Example
```
{
    "Aria": {
        "AlertSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "03fd0a01-4429-5017-ccd0-1b2d73e3d083"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "instance_number": "0",
                    "trid": "3aeade68-1a0f-8089-db4c-f7483b7dd5fd"
                }
            ],
            "Rule": {
                "Definition": "192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END",
                "Name": "srcSubnetAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354576
            }
        }
    }
}
```

#### Human Readable Output

>### aria-alert-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetAlert<br/>Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END<br/>RCS: null | command_state: Success<br/>timestamp: 1600354576 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '03fd0a01-4429-5017-ccd0-1b2d73e3d083', 'instance_number': '0', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '3aeade68-1a0f-8089-db4c-f7483b7dd5fd', 'instance_number': '0', 'completion': True} |


### aria-mute-alert-src-subnet
***
Removes a named rule from the source subnet logic block, disabling the alerts.


#### Base Command

`aria-mute-alert-src-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| rcs | The remediation configuration string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertSrcSubnet.Rule | string | The name of the rule and the settings that define the rule. | 
| Aria.MuteAlertSrcSubnet.Status | string | The state of the command, and the timestamp indicating when the command completed. Possible states include "Success", "Failure", or "Endpoint matching RCS not found". | 
| Aria.MuteAlertSrcSubnet.Endpoints | string | Endpoint information, such as the IP address, about the SIAs that were modified based on the rule change. | 


#### Command Example
```!aria-mute-alert-src-subnet rule_name="srcSubnetAlert"```

#### Context Example
```
{
    "Aria": {
        "MuteAlertSrcSubnet": {
            "Endpoints": [
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>",
                    "IPAddress": "192.168.0.100",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "0d3ad806-b4e8-3a70-100d-98fb900ee762"
                },
                {
                    "FQN": "<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>",
                    "IPAddress": "192.168.0.101",
                    "Model": "sia-lx2160",
                    "OS": "GNU/Linux",
                    "Processor": "sia-lx2160",
                    "completion": true,
                    "trid": "b5231220-21b9-6c39-ca04-a62977c191c3"
                }
            ],
            "Rule": {
                "Definition": "Remove srcSubnetAlert",
                "Name": "srcSubnetAlert",
                "RCS": null
            },
            "Status": {
                "command_state": "Success",
                "timestamp": 1600354584
            }
        }
    }
}
```

#### Human Readable Output

>### aria-mute-alert-src-subnet
>|Rule|Status|Endpoints|
>|---|---|---|
>| Name: srcSubnetAlert<br/>Definition: Remove srcSubnetAlert<br/>RCS: null | command_state: Success<br/>timestamp: 1600354584 | {'FQN': '<sds_cluster_0>.<sds_node_sia12>.<sds_component_PacketIntelligence>.<sds_uuid_c0457a81-153c-4d4d-9d0a-8cedd226c6a3>', 'IPAddress': '192.168.0.100', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': '0d3ad806-b4e8-3a70-100d-98fb900ee762', 'completion': True},<br/>{'FQN': '<sds_cluster_0>.<sds_node_sia32>.<sds_component_PacketIntelligence>.<sds_uuid_ac94a671-bff6-48b8-be48-79855ba81fd0>', 'IPAddress': '192.168.0.101', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'trid': 'b5231220-21b9-6c39-ca04-a62977c191c3', 'completion': True} |

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
For more information, please see the ARIA_SOAR_Integration_Guide_Demisto.