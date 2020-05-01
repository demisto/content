Use the ARIA Packet Intelligence integration to create playbooks that instruct one or more Secure Intelligent Adapters (SIA) to add, modify, or delete rules automatically. These rule changes can block conversations, redirect packets to a recorder or VLAN, or perform a variety of other actions. 


## Configure ARIA Packet Intelligence on Demisto

1.  Navigate to **Settings** > **Integrations**  > **Servers & Services**.
2.  Search for ARIA Packet Intelligence.
3.  Click **Add instance** to create and configure a new integration instance.
    
  | **Parameter** | **Description** | **Required** |
  | --------- | ----------- | ------- |
  | Name | A meaningful name for the integration instance. For example: ARIA Packet Intelligence Instance Alpha | Required |
  | SDSo Base URL | The base URL for the integration. For example: http://[IP address or FQDN of SDSo Node]:7443  | Required  |
    
4.  Click **Test** to validate the new instance.

## Commands

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Block a conversation

* * *

Creates a rule that drops all packets matching the specified 5-tuple values.

##### Base Command

`aria-block-conversation`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required |
| src_port | The source port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Optional |
| target_ip | The destination IP address. | Required |
| target_port | The destination port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Optional |
| protocol | The protocol (for example, TCP) used for the packets. | Optional |
| rule_name | The name of the rule to create. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.BlockConversation.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this  returns information about the error. |
| Aria.BlockConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example

```
!aria-block-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convBlock" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.BlockConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-block-conversation

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: convBlockDefinition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 &lt;&gt; TCP : DROP, END | code: 201 command_state: Success timestamp: 1571420423 | `{'FQN':'<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'aa5395d0-be3b-b76d-b2c3-58f4fccb115b', 'completion': True}` |

### Unblock a conversation

* * *

Deletes a named rule from the 5-tuple logic block. This allows the previously blocked conversation to resume.

##### Base Command

`aria-unblock-conversation`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.UnblockConversation.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.UnblockConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example

```
!aria-unblock-conversation rule_name="convBlock" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.UnblockConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-unblock-conversation

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: convBlock Definition: | code: 201 timestamp: 1571420426 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '92bf73e5-c899-f2fa-76bb-a959cf053b61', 'completion': True}` |

### Record a conversation

* * *

Creates a rule that redirects a conversation matching 5-tuple values to the Packet Recorder. Packets are tagged with the VID specified in the instance.

##### Base Command

`aria-record-conversation`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required |
| src_port | The source port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Optional |
| target_ip | The destination IP address. | Required |
| target_port | The destination port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Optional |
| protocol | The protocol (for example, TCP) used for the packets. | Optional |
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required |
| rule_name | The name of the rule to create. | Required |
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional |
| transport_type | The type of notification to generate. | Optional |
| tti_index | The index of the entry in the transport type table. | Optional |
| aio_index | The index of the entry in the alert information object table. | Optional |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.RecordConversation.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.RecordConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example

```
!aria-record-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.RecordConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-record-conversation

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: convRecord
Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 &lt;&gt; TCP : REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END | code: 201 command_state: Success timestamp: 1571420435 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '7fc5d306-9d8e-65b5-8465-2e1fb8fb347e', 'completion': True}` |

### Stop Recording a conversation

* * *

Removes the named rule from the 5-tuple block. This stops redirecting traffic to the Packet Recorder.

##### Base Command

`aria-stop-recording-conversation`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.StopRecordingConversation.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.StopRecordingConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-stop-recording-conversation rule_name="convRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.StopRecordingConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-stop-recording-conversation

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: convRecord Definition: | code: 201 timestamp: 1571420445 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '806b7df1-142a-7b1d-73ba-e3409b3ae1b7', 'completion': True}` |

### Add a conversation alert

* * *

Adds a rule that generates an alert when a conversation matching the specified 5-tuple values is detected.

##### Base Command

`aria-alert-conversation`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The source IP address. | Required |
| src_port | The source port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Optional |
| target_ip | The destination IP address. | Required |
| target_port | The destination port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Optional |
| protocol | The protocol (for example, TCP) used for the packets. | Optional |
| rule_name | The name of the rule to create. | Required |
| transport_type | The type of notification to generate. | Required |
| tti_index | The index of the entry in the transport type table. | Required |
| aio_index | The index of the entry in the alert information object table. | Required |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.AlertConversation.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.AlertConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-alert-conversation src_ip="192.168.10.23" src_port="389" target_ip="192.168.0.1" target_port="390" protocol="tcp" rule_name="convAlert" transport_type="email" tti_index="2" aio_index="4" trigger_type="re-trigger-count" trigger_value="1000" label_sia_group="Engineering"
```

##### Context Example

```
{
    "Aria.AlertConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
``` 

##### Human Readable Output

##### aria-alert-conversation

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: convAlert
Definition: 192.168.0.1/32 @ 390 & 192.168.10.23/32 @ 389 &lt;&gt; TCP : ALERT email 2 4 re-trigger-count 1000, END | code: 201 command_state: Success timestamp: 1571420453 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '4bb24d36-09d1-200c-dbe0-a22704846484', 'completion': True}` |

### Mute an alert

* * *

Removes a named rule from the 5-tuple logic block, disabling the alerts.

##### Base Command

`aria-mute-alert-conversation`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertConversation.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.MuteAlertConversation.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.MuteAlertConversation.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-mute-alert-conversation rule_name="convAlert" label_sia_group="Engineering"
```
##### Context Example
```
{
    "Aria.MuteAlertConversation": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-mute-alert-conversation

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: convAlert Definition: | code: 201 timestamp: 1571420460 command_state: Success | {'FQN':,'...', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'a00c637c-4811-45e0-ae55-fab9cab8c10a', 'completion': True}|

### Block a destination port

* * *

Creates a rule that blocks packets destined for specific ports.

##### Base Command

`aria-block-dest-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Required |
| rule_name | The name of the rule to create. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.BlockDestPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.BlockDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-block-dest-port port_range="389, 400-404" rule_name="destPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "Aria.BlockDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-block-dest-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destPortBlock Definition: 389, 400 - 404: DROP, END | code: 201 command_state: Success timestamp: 1571420469 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'b7bfd2a3-51d1-e9ba-b5bf-d8b4d5f21b8f', 'completion': True}` |

### Unblock a destination port

* * *

Removes a named rule from the destination port logic block. This allows the previously blocked traffic to resume.

##### Base Command

`aria-unblock-dest-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.UnblockDestPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.UnblockDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-unblock-dest-port rule_name="destPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "Aria.UnblockDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-unblock-dest-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destPortBlock
Definition: | code: 201timestamp: 1571420477 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8c1e5ab0-1e77-1b27-68d7-cab420fdf8c3', 'completion': True}` |

### Record a destination port

* * *

Adds a rule that redirects traffic destined for one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.

##### Base Command

`aria-record-dest-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Required |
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required |
| rule_name | The name of the rule to create. | Required |
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional |
| transport_type | The type of notification to generate. | Optional |
| tti_index | The index of the entry in the transport type table. | Optional |
| aio_index | The index of the entry in the alert information object table. | Optional |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.RecordDestPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.RecordDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-record-dest-port port_range="390, 420, 421" rule_name="destPortRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.RecordDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-record-dest-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destPortRecordDefinition: 390, 420, 421: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END | code: 201 command_state: Success timestamp: 1571420486 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '4361c6ed-042c-502f-a329-06d4e2c4b4a1', 'completion': True}` |

### Stop recording a destination port

* * *

Removes a named rule from the destination port logic block. This stops redirecting traffic to the Packet Recorder.

##### Base Command

`aria-stop-recording-dest-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.StopRecordingDestPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.StopRecordingDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-stop-recording-dest-port rule_name="destPortRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.StopRecordingDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-stop-recording-dest-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destPortRecord Definition: | code: 201 timestamp: 1571420494 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '9cb30bff-fb0f-eb7b-2790-6942e7585548', 'completion': True}` |

### Create a destination port traffic alert

* * *

Creates a rule that generates an alert when traffic destined for one or more ports is detected.

##### Base Command

`aria-alert-dest-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The destination port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Required |
| rule_name | The name of the rule to create. | Required |
| transport_type | The type of notification to generate. | Required |
| tti_index | The index of the entry in the transport type table. | Required |
| aio_index | The index of the entry in the alert information object table. | Required |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.AlertDestPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.AlertDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-alert-dest-port port_range="389-400" rule_name="destPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.AlertDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-alert-dest-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destPortAlert Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END | code: 201 command_state: Success timestamp: 1571420503 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f1858475-74b5-cdd9-e427-763ddb897211', 'completion': True}` |

### Disable a destination port traffic alert

* * *

Removes a named rule from the destination port logic block, disabling the alerts.

##### Base Command

`aria-mute-alert-dest-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertDestPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.MuteAlertDestPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.MuteAlertDestPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-mute-alert-dest-port rule_name="destPortAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.MuteAlertDestPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-mute-alert-dest-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destPortAlert Definition: | code: 201 timestamp: 1571420511command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'f034b7f4-258a-49ab-0226-7bc651c34e10', 'completion': True}` |

### Block a source port

* * *

Adds a rule that blocks packets originating from one or more specific ports.

##### Base Command

`aria-block-src-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Required |
| rule_name | The name of the rule to create. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.BlockSrcPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.BlockSrcPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-block-src-port port_range="389, 400-404" rule_name="srcPortBlock" label_sia_region="US"
```

##### Context Example
```
{
    "Aria.BlockSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-block-src-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcPortBlock Definition: 389, 400 - 404: DROP, END | code: 201 command_state: Success timestamp: 1571420518 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '93ad5260-f138-ed0c-6ac0-e1a6f721747e', 'completion': True}` |

### Unblock a source port

* * *

Removes a named rule from the source port logic block. This allows the previously blocked traffic to resume.

##### Base Command

`aria-unblock-src-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.UnblockSrcPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.UnblockSrcPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-unblock-src-port rule_name="srcPortBlock" label_sia_region="US"`
```
##### Context Example
```
{
    "Aria.UnblockSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-unblock-src-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcPortBlock Definition: | code: 201 timestamp: 1571420526 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '344f83ed-ff1f-1e54-3d82-e59530b02ae6', 'completion': True}` |

### Record a source port

* * *

Adds a rule that redirects traffic originating from one or more ports to the Packet Recorder. Packets are tagged with the VID specified in the instance.

##### Base Command

`aria-record-src-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Required |
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required |
| rule_name | The name of the rule to create. | Required |
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional |
| transport_type | The type of notification to generate. | Optional |
| tti_index | The index of the entry in the transport type table. | Optional |
| aio_index | The index of the entry in the alert information object table. | Optional |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.RecordSrcPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.RecordSrcPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-record-src-port port_range="390, 420" rule_name="srcPortRecord" sia_interface="B" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.RecordSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-record-src-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcPortRecordDefinition: 390, 420: REDIRECT-VLAN B 1234, ALERT email 2 4 one-shot 1, END | code: 201 command_state: Successtimestamp: 1571420533 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'b133454a-d7b9-50dd-fb9b-3cc769c49396', 'completion': True}` |

### Stop recording a source port

* * *

Removes a named rule from the source port logic block. This stops redirecting traffic to the Packet Recorder.

##### Base Command

`aria-stop-recording-src-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.StopRecordingSrcPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.StopRecordingSrcPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-stop-recording-src-port rule_name="srcPortRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.StopRecordingSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-stop-recording-src-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcPortRecord
Definition: | code: 201 timestamp: 1571420541 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '42ef11aa-5655-0b42-15e1-e94bdd966058', 'completion': True}` |

### Create a source port alert

* * *

Creates a rule that generates an alert when traffic originating from one or more ports is detected.

##### Base Command

`aria-alert-src-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port_range | The source port(s). This accepts a comma-separated list (for example, “1, 3”), a range (for example, “1-3”), or a combination (for example, “1, 3-5”). | Required |
| rule_name | The name of the rule to create | Required |
| transport_type | The type of notification to generate. | Required |
| tti_index | The index of the entry in the transport type table. | Required |
| aio_index | The index of the entry in the alert information object table. | Required |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.AlertSrcPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.AlertSrcPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-alert-src-port port_range="389-400" rule_name="srcPortAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.AlertSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-alert-src-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcPortAlert
Definition: 389 - 400: ALERT syslog 2 4 re-trigger-timed-sec 200, END | code: 201 command_state: Success timestamp: 1571420549 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c07dc77e-d661-9a09-2266-ad5d341e8e63', 'completion': True}` |

### Mute a source port alert

* * *

Removes a named rule from the source port logic block, disabling the alerts.

##### Base Command

`aria-mute-alert-src-port`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertSrcPort.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.MuteAlertSrcPort.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.MuteAlertSrcPort.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-mute-alert-src-port rule_name="srcPortAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.MuteAlertSrcPort": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-mute-alert-src-port

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcPortAlert Definition: | code: 201 timestamp: 1571420558 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '9a31502b-40db-98e9-ea12-b0b512045b4d', 'completion': True}` |

### Block a destination subnet

* * *

Adds a rule that blocks packets destined for a specific IP Address or range of IP Addresses.

##### Base Command

`aria-block-dest-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP Address and mask of the destination IP Address(es), in the format <ip_address>/\<mask>. If the mask is omitted, a value of 32 is used.\</mask></ip_address> | Required |
| rule_name | The name of the rule to create. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.BlockDestSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.BlockDestSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-block-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "Aria.BlockDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-block-dest-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destSubnetBlock
Definition: 192.168.1.2/24: DROP, END | code: 201 command_state: Success timestamp: 1571420567 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '4609e8c0-55a4-ec06-3548-71cc5b5a67be', 'completion': True}` |

### Unblock a destination subnet

* * *

Removes a named rule from the destination subnet logic block. This allows the previously blocked traffic to resume.

##### Base Command

`aria-unblock-dest-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.UnblockDestSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.UnblockDestSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example

```
!aria-unblock-dest-subnet rule_name="destSubnetBlock" label_sia_region="US"
```
##### Context Example
```
{
    "Aria.UnblockDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-unblock-dest-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destSubnetBlock Definition: | code: 201 timestamp: 1571420574command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'deba7913-d38b-08bd-263c-7e00dd5765a7', 'completion': True}` |

### Record a destination subnet

* * *

Creates a rule that redirects traffic destined for a specific IP address or range of IP addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.

##### Base Command

`aria-record-dest-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP Address and mask of the destination IP Address(es), in the format <ip_address>/\<mask>. If the mask is omitted, a value of 32 is used.\</mask></ip_address> | Required |
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required |
| rule_name | The name of the rule to create. | Required |
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional |
| transport_type | The type of notification to generate. | Optional |
| tti_index | The index of the entry in the transport type table. | Optional |
| aio_index | The index of the entry in the alert information object table. | Optional |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.RecordDestSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.RecordDestSubnet.Endpoints | string | Returns endpoints information, such as the IP Address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-record-dest-subnet target_ip="192.168.10.23/32" rule_name="destSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.RecordDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-record-dest-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destSubnetRecord Definition: 192.168.10.23/32: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END | code: 201 command_state: Success timestamp: 1571420583 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'd832ae22-cb14-18e4-2e3f-8c08333feb0f', 'completion': True}` |

### Stop recording a destination subnet

* * *

Removes a named rule from the destination subnet logic block. This stops redirecting traffic to the Packet Recorder.

##### Base Command

`aria-stop-recording-dest-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.StopRecordingDestSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.StopRecordingDestSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-stop-recording-dest-subnet rule_name="destSubnetRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.StopRecordingDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-stop-recording-dest-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destSubnetRecord Definition: | code: 201 timestamp: 1571420591 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '1e6d1679-8652-13f8-f3e7-41a0e10c1335', 'completion': True}` |

### Create a destination subnet alert

* * *

Creates a rule that generates an alert when traffic destined for a specific IP Address or range of IP Addresses is detected.

##### Base Command

`aria-alert-dest-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_ip | The IP Address and mask of the destination IP Address(es), in the format <ip_address>/\<mask>. If the mask is omitted, a value of 32 is used.\</mask></ip_address> | Required |
| rule_name | The name of the rule to create. | Required |
| transport_type | The type of notification to generate. | Required |
| tti_index | The index of the entry in the transport type table. | Required |
| aio_index | The index of the entry in the alert information object table. | Required |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.AlertDestSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.AlertDestSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-alert-dest-subnet target_ip="192.168.1.2/24" rule_name="destSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.AlertDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-alert-dest-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destSubnetAlert Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END | code: 201 command_state: Success timestamp: 1571420599 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'd53a30dd-f6b8-b2c1-9f5c-4cd2e455bcc9', 'completion': True}` |

### Mute a destination subnet alert 

* * *

Removes a named rule from the destination subnet logic block, disabling the alerts.

##### Base Command

`aria-mute-alert-dest-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertDestSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.MuteAlertDestSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.MuteAlertDestSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-mute-alert-dest-subnet rule_name="destSubnetAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.MuteAlertDestSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-mute-alert-dest-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: destSubnetAlert Definition: | code: 201 timestamp: 1571420608 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8b23a582-25b6-a2d9-7d76-39b3e1ce1584', 'completion': True}` |

### Block a source subnet

* * *

Adds a rule that blocks packets originating from a specific IP address or range of IP addresses.

##### Base Command

`aria-block-src-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP Address and mask of the source IP Address(es), in the format <ip_address>/\<mask>. If the mask is omitted, a value of 32 is used.\</mask></ip_address> | Required |
| rule_name | The name of the rule to create. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.BlockSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.BlockSrcSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.BlockSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-block-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "Aria.BlockSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-block-src-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcSubnetBlock
Definition: 192.168.1.2/24: DROP, END | code: 201 command_state: Success timestamp: 1571420616 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'a8916b20-5d9a-0337-23ce-1c399922df05', 'completion': True}` |

### Unblock a source subnet

* * *

Removes a named rule from the source subnet logic block. This allows the previously blocked traffic to resume.

##### Base Command

`aria-unblock-src-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.UnblockSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.UnblockSrcSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.UnblockSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-unblock-src-subnet rule_name="srcSubnetBlock" label_sia_region="US"
```

##### Context Example
```
{
    "Aria.UnblockSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-unblock-src-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcSubnetBlock
Definition: | code: 201 timestamp: 1571420624 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': 'c7405878-aa74-9301-7422-b91ae84be8eb', 'completion': True}` |

### Record a source subnet

* * *

Creates a rule that redirects traffic originating from one or more specific IP Addresses to the Packet Recorder. Packets are tagged with the VID specified in the instance.

##### Base Command

`aria-record-src-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP Address and mask of the source IP Address(es), in the format <ip_address>/\<mask>. If the mask is omitted, a value of 32 is used.\</mask></ip_address> | Required |
| vlan_id | The VLAN ID your network switch uses to forward packets to the Packet Recorder. | Required |
| rule_name | The name of the rule to create. | Required |
| sia_interface | The letter of the interface on the SIA used for forwarding packets. If omitted, interface A is used. | Optional |
| transport_type | The type of notification to generate. | Optional |
| tti_index | The index of the entry in the transport type table. | Optional |
| aio_index | The index of the entry in the alert information object table. | Optional |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Optional |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Optional |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.RecordSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.RecordSrcSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.RecordSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-record-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetRecord" vlan_id="1234" transport_type="email" tti_index="2" aio_index="4" trigger_type="one-shot" trigger_value="1" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.RecordSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-record-src-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcSubnetRecordDefinition: 192.168.1.2/24: REDIRECT-VLAN A 1234, ALERT email 2 4 one-shot 1, END | code: 201 command_state: Success timestamp: 1571420632 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '7bc02e02-c6d5-2b80-5423-1a6fc245c3f9', 'completion': True}` |

### Stop recording a source subnet

* * *

Removes a named rule from the source subnet logic block. This stops redirecting traffic to the Packet Recorder.

##### Base Command

`aria-stop-recording-src-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.StopRecordingSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.StopRecordingSrcSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.StopRecordingSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-stop-recording-src-subnet rule_name="srcSubnetRecord" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.StopRecordingSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-stop-recording-src-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcSubnetRecord Definition: | code: 201 timestamp: 1571420640 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '52dc6968-2269-ae46-7dfc-accbda8973e5', 'completion': True}` |

### Create a source subnet alert 

* * *

Adds a rule that generates an alert when traffic originating from a specific IP Address or range of IP addresses is detected.

##### Base Command

`aria-alert-src-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| src_ip | The IP Address and mask of the source IP Address(es), in the format <ip_address>/\<mask>. If the mask is omitted, a value of 32 is used.\</mask></ip_address> | Required |
| rule_name | The name of the rule to create. | Required |
| transport_type | The type of notification to generate. | Required |
| tti_index | The index of the entry in the transport type table. | Required |
| aio_index | The index of the entry in the alert information object table. | Required |
| trigger_type | The frequency of the alert. ***one-shot***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. Once the alert triggers, it is disabled until the flow expires or times out. ***re-trigger-count***: The alert is triggered when the number of packets matching the criteria reaches the threshold specified in the trigger_value field. The counter then resets to 0, and the alert is triggered again the next time the threshold is met. ***re-trigger-timed-ms***: The alert is triggered, and then the application waits the number of msecs defined in the trigger_value field. Once this time passes, the alert is triggered again. ***re-trigger-timed-sec***: The alert is triggered, and then the application waits the number of seconds defined in the trigger_value field. Once this time passes, the alert is triggered again. | Required |
| trigger_value | The threshold that must be met before the alert is triggered. The value entered here depends on the trigger_type. If the trigger_type is ***one-shot*** or ***retrigger-count***, this is the total number of packets that must be received before the alert is triggered. The valid range is 1-8191. If the trigger_type is ***re-trigger-ms*** or ***re-triggersec***, this is the total number of msecs or secs, respectively, that must elapse before the alert is triggered again. The valid range is 1-8191. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is added to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.AlertSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.AlertSrcSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.AlertSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-alert-src-subnet src_ip="192.168.1.2/24" rule_name="srcSubnetAlert" transport_type="syslog" tti_index="2" aio_index="4" trigger_type="re-trigger-timed-sec" trigger_value="200" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.AlertSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-alert-src-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcSubnetAlert
Definition: 192.168.1.2/24: ALERT syslog 2 4 re-trigger-timed-sec 200, END | code: 201 command_state: Success timestamp: 1571420648 | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '8a0d8a84-3248-aadb-db11-dbe96562d1ef', 'completion': True}` |

### Mute a source subnet alert

* * *

Removes a named rule from the source subnet logic block, disabling the alerts.

##### Base Command

`aria-mute-alert-src-subnet`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name | The name of the rule to delete. | Required |
| label_sia_group | The name of the group to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_name | The name of the SIA. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |
| label_sia_region | The name of the region to which the SIA belongs. Only two labels are allowed. If you enter values for all three labels, the command will fail. If no labels are provided (i.e., they are empty), the rule is deleted to every SIA attached to the SDSo. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Aria.MuteAlertSrcSubnet.Rule | string | Specifies the name of the rule and the settings that define the rule. |
| Aria.MuteAlertSrcSubnet.Status | string | Returns the response code, the state of the command, and the timestamp indicating when the command completed. If an error occurs or the response code is not 201, this also returns information about the error. |
| Aria.MuteAlertSrcSubnet.Endpoints | string | Returns endpoints information, such as the IP address, about the SIAs that were modified based on the rule change. |

##### Command Example
```
!aria-mute-alert-src-subnet rule_name="srcSubnetAlert" label_sia_name="sia17"
```

##### Context Example
```
{
    "Aria.MuteAlertSrcSubnet": {
        "Endpoints": [
            {
                "FQN": "<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>",
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
```

##### Human Readable Output

##### aria-mute-alert-src-subnet

| **Rule** | **Status** | **Endpoints** |
| --- | --- | --- |
| Name: srcSubnetAlert
Definition: | code: 201 timestamp: 1571420656 command_state: Success | `{'FQN': '<sds_cluster_0>.<sds_node_sia17>.<sds_component_packetintelligence>.<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>', 'IPAddress': '10.1.1.0', 'Model': 'sia-lx2160', 'OS': 'GNU/Linux', 'Processor': 'sia-lx2160', 'Processors': 1, 'trid': '07e9f255-efb0-d60e-8118-ba947c4be47f', 'completion': True}` |
