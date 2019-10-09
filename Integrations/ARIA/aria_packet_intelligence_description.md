## Overview
---

The ARIA Cybesecurity Solutions Software-Defined Security (SDS)  platform integrates with Demisto to add robustness when responding to incidents. The combination of ARIA hardware, in the form of a Secure Intelligent Adapter (SIA), and software, specifically Packet Intelligence and SDS orchestrator (SDSo), provides the elements required to react instantly when an incident is detected. When integrated with the ARIA solution, you can create playbooks that instruct one or more SIAs to add, modify, or delete rules automatically. These rule changes, which take effect immediately, can block conversations, redirect packets to a recorder or VLAN, or perform a variety of other actions. 
This integration was integrated and tested with version xx of ARIA Packet Intelligece
## ARIA Packet Intelligece Playbook
---

## Use Cases
---

## Configure ARIA Packet Intelligece on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ARIA Packet Intelligece.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __SDSo Base URL__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. aria-block-conversation
2. aria-unblock-conversation
3. aria-record-conversation
4. aria-stop-recording-conversation
5. aria-alert-conversation
6. aria-mute-alert-conversation
7. aria-block-dest-port
8. aria-unblock-dest-port
9. aria-record-dest-port
10. aria-stop-recording-dest-port
11. aria-alert-dest-port
12. aria-mute-alert-dest-port
13. aria-block-src-port
14. aria-unblock-src-port
15. aria-record-src-port
16. aria-stop-recording-src-port
17. aria-alert-src-port
18. aria-mute-alert-src-port
19. aria-block-dest-subnet
20. aria-unblock-dest-subnet
21. aria-record-dest-subnet
22. aria-stop-recording-dest-subnet
23. aria-alert-dest-subnet
24. aria-mute-alert-dest-subnet
25. aria-block-src-subnet
26. aria-unblock-src-subnet
27. aria-record-src-subnet
28. aria-stop-recording-src-subnet
29. aria-alert-src-subnet
30. aria-mute-alert-src-subnet
### 1. aria-block-conversation
---
Creates a rule that drops all packets matching the specified 5-tuple values.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-block-conversation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required | 
| src_port | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| target_ip | The destination IP address. | Required | 
| target_port | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| protocol | The protocol (e.g., TCP) used for the packets. | Optional | 
| rule_name | The name of the rule to create. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.block_conversation.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.block_conversation.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.block_conversation.Endpoints | Unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-block-conversation src_ip="192.168.0.100" src_port="389" target_ip="192.168.0.101" target_port="390" protocol="tcp" rule_name="convBlock" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.block_conversation": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560665, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "ca05df9d-9c02-6bc2-0491-bb58c9b60a9e", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : DROP, END", 
                "Name": "convBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-block-conversation
|Rule|Status|Endpoints|
|---|---|---|
|Name: convBlock<br>Definition: 192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : DROP, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560665|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'ca05df9d-9c02-6bc2-0491-bb58c9b60a9e', 'completion': True}|


### 2. aria-unblock-conversation
---
Deletes a named rule from the 5-tuple logic block. This allows the previously blocked conversation to resume.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-unblock-conversation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.unblock_conversation.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.unblock_conversation.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.unblock_conversation.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-unblock-conversation rule_name="convBlock" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.unblock_conversation": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560667, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "74da4bf9-5ced-bcb7-2dde-e8260dad1bb2", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "convBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-unblock-conversation
|Rule|Status|Endpoints|
|---|---|---|
|Name: convBlock<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560667<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '74da4bf9-5ced-bcb7-2dde-e8260dad1bb2', 'completion': True}|


### 3. aria-record-conversation
---
Creates a rule that redirects a conversation matching 5-tuple values to the Packet Recorder. Packets are tagged with the VID specified in the instance.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-record-conversation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required | 
| src_port | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| target_ip | The destination IP address. | Required | 
| target_port | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| protocol | The protocol (e.g., TCP) used for the packets. | Optional | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate.  | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.record_conversation.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.record_conversation.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.record_conversation.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-record-conversation src_ip="192.168.0.100" src_port="389" target_ip="192.168.0.101" target_port="390" protocol="tcp" rule_name="convRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.record_conversation": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560674, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "956f4ace-d10f-5125-c04e-37d0991e1c71", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END", 
                "Name": "convRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-record-conversation
|Rule|Status|Endpoints|
|---|---|---|
|Name: convRecord<br>Definition: 192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560674|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '956f4ace-d10f-5125-c04e-37d0991e1c71', 'completion': True}|


### 4. aria-stop-recording-conversation
---
Removes the named rule from the 5-tuple block. This stops redirecting traffic to the Packet Recorder.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-stop-recording-conversation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.stop_recording_conversation.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.stop_recording_conversation.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.stop_recording_conversation.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-stop-recording-conversation rule_name="convRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.stop_recording_conversation": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560683, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "ad1eb986-afb2-32be-5fd5-dbd283a14f69", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "convRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-stop-recording-conversation
|Rule|Status|Endpoints|
|---|---|---|
|Name: convRecord<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560683<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'ad1eb986-afb2-32be-5fd5-dbd283a14f69', 'completion': True}|


### 5. aria-alert-conversation
---
Adds a rule that generates an alert when a conversation matching the specified 5-tuple values is detected.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-alert-conversation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required | 
| src_port | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| target_ip | The destination IP address. | Required | 
| target_port | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Optional | 
| protocol | The protocol (e.g., TCP) used for the packets. | Optional | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.alert_conversation.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.alert_conversation.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.alert_conversation.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-alert-conversation src_ip="192.168.0.100" src_port="389" target_ip="192.168.0.101" target_port="390" protocol="tcp" rule_name="convAlert" transport_type="email" tti_index="2" aio_index="4" trigger_type="re-trigger-count" trigger_value="1000" label_sia_group="Engineering"
```

##### Context Example
```
{
    "aria.alert_conversation": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560689, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "0fc8e0e2-0d56-139f-0242-ba227d39bac6", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END", 
                "Name": "convAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-alert-conversation
|Rule|Status|Endpoints|
|---|---|---|
|Name: convAlert<br>Definition: 192.168.0.101/32 @ 390 & 192.168.0.100/32 @ 389 <> TCP : ALERT email 2 4 re-trigger-count 1000, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560689|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '0fc8e0e2-0d56-139f-0242-ba227d39bac6', 'completion': True}|


### 6. aria-mute-alert-conversation
---
Removes a named rule from the 5-tuple logic block, disabling the alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-mute-alert-conversation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.mute_alert_conversation.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.mute_alert_conversation.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.mute_alert_conversation.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-mute-alert-conversation rule_name="convAlert" label_sia_group="Engineering"
```

##### Context Example
```
{
    "aria.mute_alert_conversation": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560697, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "a1f1387d-b318-23c4-2586-b36731ad8f12", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "convAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-mute-alert-conversation
|Rule|Status|Endpoints|
|---|---|---|
|Name: convAlert<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560697<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'a1f1387d-b318-23c4-2586-b36731ad8f12', 'completion': True}|


### 7. aria-block-dest-port
---
Creates a rule that blocks packets destined for one or more specific ports.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-block-dest-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.block_dest_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.block_dest_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.block_dest_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-block-dest-port port_range="389, 400-404" rule_name="destPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.block_dest_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560705, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "467a6d3a-b21c-530a-7aaf-545d11447e5e", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END", 
                "Name": "destPortBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-block-dest-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: destPortBlock<br>Definition: 389, 400 - 404: DROP, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560705|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '467a6d3a-b21c-530a-7aaf-545d11447e5e', 'completion': True}|


### 8. aria-unblock-dest-port
---
Removes a named rule from the destination port logic block. This allows the previously blocked traffic to resume.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-unblock-dest-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.unblock_dest_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.unblock_dest_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.unblock_dest_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-unblock-dest-port rule_name="destPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.unblock_dest_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560713, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "694feb0a-f900-5387-73dd-3bf939d29226", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "destPortBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-unblock-dest-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: destPortBlock<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560713<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '694feb0a-f900-5387-73dd-3bf939d29226', 'completion': True}|


### 9. aria-record-dest-port
---
Adds a rule that redirects traffic destined for one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-record-dest-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate.  | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.record_dest_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.record_dest_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.record_dest_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-record-dest-port port_range="390, 420, 421" rule_name="destPortRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.record_dest_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560720, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "8804ed98-8f85-f7c1-2556-fa3987ba8c72", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END", 
                "Name": "destPortRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-record-dest-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: destPortRecord<br>Definition: 390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560720|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8804ed98-8f85-f7c1-2556-fa3987ba8c72', 'completion': True}|


### 10. aria-stop-recording-dest-port
---
Removes a named rule from the destination port logic block. This stops redirecting traffic to the Packet Recorder.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-stop-recording-dest-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.stop_recording_dest_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.stop_recording_dest_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.stop_recording_dest_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-stop-recording-dest-port rule_name="destPortRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.stop_recording_dest_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560727, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "f37cec0b-5ffe-c85b-4e1d-5049ebe25d87", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "destPortRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-stop-recording-dest-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: destPortRecord<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560727<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f37cec0b-5ffe-c85b-4e1d-5049ebe25d87', 'completion': True}|


### 11. aria-alert-dest-port
---
Creates a rule that generates an alert when traffic destined for one or more ports is detected.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-alert-dest-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.alert_dest_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.alert_dest_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.alert_dest_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-alert-dest-port port_range="389-400" rule_name="destPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.alert_dest_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560735, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "1959aad5-0f44-5757-3ebf-a89c2d24ed8a", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END", 
                "Name": "destPortAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-alert-dest-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: destPortAlert<br>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560735|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1959aad5-0f44-5757-3ebf-a89c2d24ed8a', 'completion': True}|


### 12. aria-mute-alert-dest-port
---
Removes a named rule from the destination port logic block, disabling the alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-mute-alert-dest-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.mute_alert_dest_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.mute_alert_dest_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.mute_alert_dest_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-mute-alert-dest-port rule_name="destPortAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.mute_alert_dest_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560742, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "f8e9527a-e981-d667-5450-cf99fa59549a", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "destPortAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-mute-alert-dest-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: destPortAlert<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560742<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f8e9527a-e981-d667-5450-cf99fa59549a', 'completion': True}|


### 13. aria-block-src-port
---
Adds a rule that blocks packets originating from one or more specific ports.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-block-src-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.block_src_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.block_src_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.block_src_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-block-src-port port_range="389, 400-404" rule_name="srcPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.block_src_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560750, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "dd115634-9fbc-f0e0-4c88-8424d2b77541", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "389, 400 - 404: DROP, END", 
                "Name": "srcPortBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-block-src-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcPortBlock<br>Definition: 389, 400 - 404: DROP, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560750|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'dd115634-9fbc-f0e0-4c88-8424d2b77541', 'completion': True}|


### 14. aria-unblock-src-port
---
Removes a named rule from the source port logic block. This allows the previously blocked traffic to resume.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-unblock-src-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.unblock_src_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.unblock_src_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.unblock_src_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-unblock-src-port rule_name="srcPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.unblock_src_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560758, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "cfd81065-c47a-a382-46d7-d8184077b404", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "srcPortBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-unblock-src-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcPortBlock<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560758<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'cfd81065-c47a-a382-46d7-d8184077b404', 'completion': True}|


### 15. aria-record-src-port
---
Adds a rule that redirects traffic originating from one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-record-src-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate.  | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.record_src_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.record_src_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.record_src_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-record-src-port port_range="390, 420" rule_name="srcPortRecord" sia_interface="B" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.record_src_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560766, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "3fe42202-8b69-82f7-4af7-3f319a53d8fc", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END", 
                "Name": "srcPortRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-record-src-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcPortRecord<br>Definition: 390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560766|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '3fe42202-8b69-82f7-4af7-3f319a53d8fc', 'completion': True}|


### 16. aria-stop-recording-src-port
---
Removes a named rule from the source port logic block. This stops redirecting traffic to the Packet Recorder.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-stop-recording-src-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.stop_recording_src_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.stop_recording_src_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.stop_recording_src_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-stop-recording-src-port rule_name="srcPortRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.stop_recording_src_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560773, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "bc4fab83-6207-ad84-2433-7bce0ed72c30", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "srcPortRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-stop-recording-src-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcPortRecord<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560773<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'bc4fab83-6207-ad84-2433-7bce0ed72c30', 'completion': True}|


### 17. aria-alert-src-port
---
Creates a rule that generates an alert when traffic originating from one or more ports is detected.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-alert-src-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”). | Required | 
| rule_name | The name of the rule to create | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.alert_src_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.alert_src_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.alert_src_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-alert-src-port port_range="389-400" rule_name="srcPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.alert_src_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560781, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "efcb964f-2ac1-c3ac-9015-15c4a9d882b0", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END", 
                "Name": "srcPortAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-alert-src-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcPortAlert<br>Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560781|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'efcb964f-2ac1-c3ac-9015-15c4a9d882b0', 'completion': True}|


### 18. aria-mute-alert-src-port
---
Removes a named rule from the source port logic block, disabling the alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-mute-alert-src-port`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.mute_alert_src_port.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.mute_alert_src_port.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.mute_alert_src_port.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-mute-alert-src-port rule_name="srcPortAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.mute_alert_src_port": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560788, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "1e941216-d674-73d6-8ec4-2a9a99dff9c7", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "srcPortAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-mute-alert-src-port
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcPortAlert<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560788<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1e941216-d674-73d6-8ec4-2a9a99dff9c7', 'completion': True}|


### 19. aria-block-dest-subnet
---
Adds a rule that blocks packets destined for a specific IP address or range of IP addresses.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-block-dest-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.block_dest_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.block_dest_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.block_dest_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-block-dest-subnet target_ip="192.168.1.0/24" rule_name="destSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.block_dest_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560795, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "6043fd50-8f3c-6b5a-12dc-fcf0dc8f9fa8", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.1.0/24: DROP, END", 
                "Name": "destSubnetBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-block-dest-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: destSubnetBlock<br>Definition: 192.168.1.0/24: DROP, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560795|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '6043fd50-8f3c-6b5a-12dc-fcf0dc8f9fa8', 'completion': True}|


### 20. aria-unblock-dest-subnet
---
Removes a named rule from the destination subnet logic block. This allows the previously blocked traffic to resume.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-unblock-dest-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.unblock_dest_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.unblock_dest_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.unblock_dest_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-unblock-dest-subnet rule_name="destSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.unblock_dest_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560801, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "8ef72c98-fd4f-f05f-5d9a-8353cd0e2a27", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "destSubnetBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-unblock-dest-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: destSubnetBlock<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560801<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8ef72c98-fd4f-f05f-5d9a-8353cd0e2a27', 'completion': True}|


### 21. aria-record-dest-subnet
---
Creates a rule that redirects traffic destined for a specific IP address or range of IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-record-dest-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used. | Required | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate.  | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.record_dest_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.record_dest_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.record_dest_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-record-dest-subnet target_ip="192.168.0.100/32" rule_name="destSubnetRecord" vlan_id="1234"  transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.record_dest_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560809, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "d6c1c2d4-9327-686e-5dc8-6c9c7d05217e", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.0.100/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END", 
                "Name": "destSubnetRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-record-dest-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: destSubnetRecord<br>Definition: 192.168.0.100/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560809|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'd6c1c2d4-9327-686e-5dc8-6c9c7d05217e', 'completion': True}|


### 22. aria-stop-recording-dest-subnet
---
Removes a named rule from the destination subnet logic block. This stops redirecting traffic to the Packet Recorder.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-stop-recording-dest-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.stop_recording_dest_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.stop_recording_dest_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.stop_recording_dest_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-stop-recording-dest-subnet rule_name="destSubnetRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.stop_recording_dest_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560816, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "26d4f91b-c134-d8ca-49b4-20497decdb93", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "destSubnetRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-stop-recording-dest-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: destSubnetRecord<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560816<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '26d4f91b-c134-d8ca-49b4-20497decdb93', 'completion': True}|


### 23. aria-alert-dest-subnet
---
Creates a rule that generates an alert when traffic destined for a specific IP address or range of IP addresses is detected.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-alert-dest-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.alert_dest_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.alert_dest_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.alert_dest_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-alert-dest-subnet target_ip="192.168.1.0/24" rule_name="destSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.alert_dest_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560824, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "1207c764-e569-5541-ccbf-617e0739f7b4", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END", 
                "Name": "destSubnetAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-alert-dest-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: destSubnetAlert<br>Definition: 192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560824|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1207c764-e569-5541-ccbf-617e0739f7b4', 'completion': True}|


### 24. aria-mute-alert-dest-subnet
---
Removes a named rule from the destination subnet logic block, disabling the alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-mute-alert-dest-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.mute_alert_dest_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.mute_alert_dest_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.mute_alert_dest_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-mute-alert-dest-subnet rule_name="destSubnetAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.mute_alert_dest_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560832, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "b87189bd-06e4-f812-0cfb-5293688a2099", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "destSubnetAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-mute-alert-dest-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: destSubnetAlert<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560832<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'b87189bd-06e4-f812-0cfb-5293688a2099', 'completion': True}|


### 25. aria-block-src-subnet
---
Adds a rule that blocks packets originating from a specific IP address or range of IP addresses.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-block-src-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.block_src_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.block_src_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.block_src_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-block-src-subnet src_ip="192.168.1.0/24" rule_name="srcSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.block_src_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560840, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "82252100-79c3-a69f-21a7-b0d0201564b2", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.1.0/24: DROP, END", 
                "Name": "srcSubnetBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-block-src-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcSubnetBlock<br>Definition: 192.168.1.0/24: DROP, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560840|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '82252100-79c3-a69f-21a7-b0d0201564b2', 'completion': True}|


### 26. aria-unblock-src-subnet
---
Removes a named rule from the source subnet logic block. This allows the previously blocked traffic to resume.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-unblock-src-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.unblock_src_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.unblock_src_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.unblock_src_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-unblock-src-subnet rule_name="srcSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "aria.unblock_src_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560846, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "1e3094e9-ae94-99be-70b1-1b29be7bf30d", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "srcSubnetBlock"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-unblock-src-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcSubnetBlock<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560846<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1e3094e9-ae94-99be-70b1-1b29be7bf30d', 'completion': True}|


### 27. aria-record-src-subnet
---
Creates a rule that redirects traffic originating from one or more specific IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-record-src-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used. | Required | 
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required | 
| rule_name | The name of the rule to create. | Required | 
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional | 
| transport_type | The type of notification to generate.  | Optional | 
| tti_index | The index of the entry in the transport type table. | Optional | 
| aio_index | The index of the entry in the alert information object table. | Optional | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.record_src_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.record_src_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.record_src_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-record-src-subnet src_ip="192.168.1.0/24" rule_name="srcSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.record_src_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560853, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "74310aef-8bea-1476-adf5-05bf4c2a2f9f", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.1.0/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END", 
                "Name": "srcSubnetRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-record-src-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcSubnetRecord<br>Definition: 192.168.1.0/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560853|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '74310aef-8bea-1476-adf5-05bf4c2a2f9f', 'completion': True}|


### 28. aria-stop-recording-src-subnet
---
Removes a named rule from the source subnet logic block. This stops redirecting traffic to the Packet Recorder.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-stop-recording-src-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.stop_recording_src_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.stop_recording_src_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.stop_recording_src_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-stop-recording-src-subnet rule_name="srcSubnetRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.stop_recording_src_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560861, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "ab6172e3-edd5-b893-898c-e3495bd3643f", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "srcSubnetRecord"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-stop-recording-src-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcSubnetRecord<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560861<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'ab6172e3-edd5-b893-898c-e3495bd3643f', 'completion': True}|


### 29. aria-alert-src-subnet
---
Adds a rule that generates an alert when traffic originating from a specific IP address or range of IP addresses is detected.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-alert-src-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>. If the mask is omitted, a value of 32 is used. | Required | 
| rule_name | The name of the rule to create. | Required | 
| transport_type | The type of notification to generate.  | Required | 
| tti_index | The index of the entry in the transport type table. | Required | 
| aio_index | The index of the entry in the alert information object table. | Required | 
| trigger_type | The frequency of the alert. one-shot: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out.  re-trigger-count: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met.  re-trigger-timed-ms: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again.  re-trigger-timed-sec: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required | 
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is one-shot or retrigger-count, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191, If the trigger_type is re-trigger-ms or re-triggersec, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.alert_src_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.alert_src_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.alert_src_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-alert-src-subnet src_ip="192.168.1.0/24" rule_name="srcSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "aria.alert_src_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560868, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "db4febce-f532-0de2-808f-11438c4fe838", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END", 
                "Name": "srcSubnetAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-alert-src-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcSubnetAlert<br>Definition: 192.168.1.0/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END|code: 201<br>error_info: <br>command_state: Success<br>timestamp: 1570560868|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'db4febce-f532-0de2-808f-11438c4fe838', 'completion': True}|


### 30. aria-mute-alert-src-subnet
---
Removes a named rule from the source subnet logic block, disabling the alerts.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`aria-mute-alert-src-subnet`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required | 
| label_sia_group | The name of the group to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_name | The name of the SIA. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 
| label_sia_region | The name of the region to which the SIA belongs. NOTE: Only two labels are allowed. If you enter values for all three labels, the command will fail. Also, if no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| aria.mute_alert_src_subnet.Rule | Unknown | Specifies the name of the rule and the settings that define the rule. | 
| aria.mute_alert_src_subnet.Status | Unknown | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. | 
| aria.mute_alert_src_subnet.Endpoints | unknown | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. | 


##### Command Example
```!aria-mute-alert-src-subnet rule_name="srcSubnetAlert" label_sia_name="sia17"```

##### Context Example
```
{
    "aria.mute_alert_src_subnet": [
        {
            "Status": {
                "command_state": "Success", 
                "timestamp": 1570560875, 
                "code": 201, 
                "error_info": ""
            }, 
            "Endpoints": [
                {
                    "completion": true, 
                    "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>", 
                    "Processors": 1, 
                    "OS": "GNU/Linux", 
                    "trid": "bdd9989b-02f3-c113-7d72-573ea3fca80c", 
                    "Model": "sia-lx2160", 
                    "IPAddress": "10.6.0.146", 
                    "Processor": "sia-lx2160"
                }
            ], 
            "Rule": {
                "Definition": "", 
                "Name": "srcSubnetAlert"
            }
        }
    ]
}
```

##### Human Readable Output
### aria-mute-alert-src-subnet
|Rule|Status|Endpoints|
|---|---|---|
|Name: srcSubnetAlert<br>Definition: |code: 201<br>error_info: <br>timestamp: 1570560875<br>command_state: Success|{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_PacketIntelligence>.<sds_uuid_b91f99e5-37cd-4150-a780-b408eedb2c6d>', 'IPAddress': '10.6.0.146', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'bdd9989b-02f3-c113-7d72-573ea3fca80c', 'completion': True}|


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* f'Wrong transport_type {transport_type}! Valid values are email, SMS, syslog or webhook'
* 'Transport type info index(tti_index
* 'Alert info object index(aio_index
* f'Wrong trigger_type {trigger_type}! Valid values are one-shot, re-trigger-count, '
're-trigger-timed-ms, re-trigger-timed-sec'
* 'Trigger value(trigger_value
* 'Port must be in 0-65535!'
* 'Wrong port range format!'
* 'Port must be in 0-65535!'
* 'Subnet mask must be in range [1, 32].'
* 'Wrong IP format!'
* 'Wrong IP format!'
* 'Command only supports two SIA labels!'
* f'Please provide tti_index, aio_index, trigger_type and trigger_value to '
f'use {transport_type} to send an alert.'
* f'Please provide tti_index, aio_index, trigger_type and trigger_value '
f'to use {transport_type} to send an alert.'
* f'Please provide tti_index, aio_index, trigger_type and trigger_value '
f'to use {transport_type} to send an alert.'
* f'Please provide tti_index, aio_index, trigger_type and trigger_value '
f'to use {transport_type} to send an alert.'
* f'Please provide tti_index, aio_index, trigger_type and trigger_value '
f'to use {transport_type} to send an alert.'
* f'Command "{command}" is not implemented.'
