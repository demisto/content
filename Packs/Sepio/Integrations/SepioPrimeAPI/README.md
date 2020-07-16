Integrate with Sepio Prime
This integration was integrated and tested with version xx of Sepio
## Configure Sepio on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Sepio.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://sepio\-prime\) | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| fetch_time | Initial time to start fetching incidents. In days. | True |
| min_severity | Alert severity to retrieve. Values are: Warning, Error, Critical | False |
| category | Alert category to retrieve. Values are:USB, Network | True |
| max_alerts | Maximum number of alerts to fetch at a time | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### sepio-query-agents
***
Get Agents


#### Base Command

`sepio-query-agents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_identifier | Filter results based on Host Identifier. | Optional | 
| ip_address | Filter results based on IP Address. | Optional | 
| uuid | Filter results based on Agent’s UUID. | Optional | 
| has_unapproved_peripherals | Filter only agents that have unapproved peripherals that are attached. | Optional | 
| has_vulnerable_peripherals | Filter only agents that have vulnerable peripherals that are attached. | Optional | 
| has_known_attack_tools | Filter only agents that have identified attack tools that attached. | Optional | 
| limit | Maximum number of Agent entries to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sepio.Agent.HostIdentifier | string | Sepio Agent’s instance assigned textual name. usually derived from the HOST name of the workstation.  This is not a unique identifier of the Sepio Agent’s instance. | 
| Sepio.Agent.IpAddress | string | Sepio Agent IP Address. | 
| Sepio.Agent.UUID | string | Sepio Agent’s instance unique identifier. | 
| Sepio.Agent.OsVersion | string | Version of the Operation System of the host running Sepio Agent. | 
| Sepio.Agent.HardwareModel | string | The hardware model of the host running Sepio Agent. | 
| Sepio.Agent.NicInfo | string | A list of the network interfaces of the host running Sepio Agent. | 
| Sepio.Agent.LastUpdate | date | Last update time. Format  YYYY\-MM\-DDThh:mm:ss.sTZD | 
| Sepio.Agent.Status | string | Current status of Sepio Agent. | 
| Sepio.Agent.HasUnapprovedPeripherals | boolean | True if the Agent has at least one approved peripheral device that is attached. | 
| Sepio.Agent.HasVulnerablePeripherals | boolean | True if the Agent has at least one vulnerable peripheral that is attached. | 
| Sepio.Agent.HasKnownAttackTools | boolean | True if the Agent has at least one peripheral that is identified as a known attack tool. | 
| Sepio.Agent.LastConfiguration | date | Last configuration time. Format YYYY\-MM\-DDThh:mm:ss.sTZD | 
| Sepio.Agent.Version | string | Version of Sepio Agent. | 
| Sepio.Agent.License | string | Agent’s license status \(Pending/Expired/Invalid/Activated\). | 


#### Command Example
```!sepio-query-agents uuid=BFEBFBFF000806EAL1HF8C4003Z ip_address=192.168.100.120 host_identifier=DESKTOP-ANTONY has_known_attack_tools=False has_unapproved_peripherals=False has_vulnerable_peripherals=False limit=1000```

#### Context Example
```
{}
```

#### Human Readable Output

>null

### sepio-query-peripherals
***
Get Peripherals


#### Base Command

`sepio-query-peripherals`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_identifier | Filter results based on Host Identifier. | Optional | 
| host_uuid | Filter results based on the UUID of the Agent. | Optional | 
| vendor_name | Filter peripheral devices that contain a certain textual name (partial or full, "contains") in the vendor name. | Optional | 
| product_name | Filter peripheral devices that contain a certain textual name (partial or full, "contains") in the product name. | Optional | 
| serial_number | Filter peripheral devices that contain a certain text value (partial or full, "contains") in the serial number. | Optional | 
| is_unapproved_peripheral | Filter only unapproved peripheral devices that are attached. | Optional | 
| is_vulnerable_peripheral | Filter only vulnerable peripheral devices that are attached. | Optional | 
| is_known_attack_tool | Filter only peripheral devices that are identified as known attack tools. | Optional | 
| limit | Maximum number of peripheral device entries to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sepio.Peripheral.HostIdentifier | string | Sepio Agent’s instance assigned textual name. usually derived from the HOST name of the workstation.  This is not a unique identifier of the Sepio Agent’s instance. | 
| Sepio.Peripheral.HostUUID | string | Sepio Agent’s instance unique identifier. | 
| Sepio.Peripheral.DeviceID | string | Sepio device unique identifier. | 
| Sepio.Peripheral.DeviceType | string | Textual text indication of the device type. | 
| Sepio.Peripheral.VID | string | Peripheral device VendorID. | 
| Sepio.Peripheral.VendorName | string | Peripheral device vendor Name. | 
| Sepio.Peripheral.PID | string | Peripheral device ProductID. | 
| Sepio.Peripheral.ProductName | string | Peripheral device product Name. | 
| Sepio.Peripheral.SerialNumber | string | Peripheral device serial number \(when applicable\). | 
| Sepio.Peripheral.Status | string | Current status of the peripheral device. | 
| Sepio.Peripheral.IsUnapprovedPeripheral | boolean | True if the Agent has at least one unapproved peripheral device that is attached. | 
| Sepio.Peripheral.IsVulnerablePeripheral | boolean | True if the Agent has at least one vulnerable peripheral that is attached. | 
| Sepio.Peripheral.IsKnownAttackTool | boolean | True if the Agent has at least one peripheral that is identified as a known attack tool. | 


#### Command Example
```!sepio-query-peripherals host_uuid=BFEBFBFF000806EAL1HF8C4003Z vendor_name="Logitech, Inc." product_name="Keyboard K120" limit=20```

#### Context Example
```
{
    "Sepio": {
        "Peripheral": [
            {
                "DeviceID": "USB\\VID_046D&PID_C31C\\5&20DBD6CE&0&1",
                "DeviceType": "NO_DEV",
                "HostIdentifier": "DESKTOP-ANTONY",
                "HostUUID": "BFEBFBFF000806EAL1HF8C4003Z",
                "IsKnownAttackTool": false,
                "IsUnapprovedPeripheral": false,
                "IsVulnerablePeripheral": false,
                "PID": "C31C",
                "ProductName": "Keyboard K120",
                "SerialNumber": "",
                "Status": "OK",
                "VID": "046D",
                "VendorName": "Logitech, Inc."
            },
            {
                "DeviceID": "USB\\VID_046D&PID_C31C&MI_00\\6&284FE535&0&0000",
                "DeviceType": "Keyboard",
                "HostIdentifier": "DESKTOP-ANTONY",
                "HostUUID": "BFEBFBFF000806EAL1HF8C4003Z",
                "IsKnownAttackTool": false,
                "IsUnapprovedPeripheral": false,
                "IsVulnerablePeripheral": false,
                "PID": "C31C",
                "ProductName": "Keyboard K120",
                "SerialNumber": "",
                "Status": "OK",
                "VID": "046D",
                "VendorName": "Logitech, Inc."
            },
            {
                "DeviceID": "USB\\VID_046D&PID_C31C&MI_01\\6&284FE535&0&0001",
                "DeviceType": "HID",
                "HostIdentifier": "DESKTOP-ANTONY",
                "HostUUID": "BFEBFBFF000806EAL1HF8C4003Z",
                "IsKnownAttackTool": false,
                "IsUnapprovedPeripheral": false,
                "IsVulnerablePeripheral": false,
                "PID": "C31C",
                "ProductName": "Keyboard K120",
                "SerialNumber": "",
                "Status": "OK",
                "VID": "046D",
                "VendorName": "Logitech, Inc."
            },
            {
                "DeviceID": "USB\\VID_046D&PID_C31C\\5&20DBD6CE&0&3",
                "DeviceType": "NO_DEV",
                "HostIdentifier": "DESKTOP-ANTONY",
                "HostUUID": "BFEBFBFF000806EAL1HF8C4003Z",
                "IsKnownAttackTool": false,
                "IsUnapprovedPeripheral": false,
                "IsVulnerablePeripheral": false,
                "PID": "C31C",
                "ProductName": "Keyboard K120",
                "SerialNumber": "",
                "Status": "OK",
                "VID": "046D",
                "VendorName": "Logitech, Inc."
            },
            {
                "DeviceID": "USB\\VID_046D&PID_C31C&MI_00\\6&2DC83EB&0&0000",
                "DeviceType": "Keyboard",
                "HostIdentifier": "DESKTOP-ANTONY",
                "HostUUID": "BFEBFBFF000806EAL1HF8C4003Z",
                "IsKnownAttackTool": false,
                "IsUnapprovedPeripheral": false,
                "IsVulnerablePeripheral": false,
                "PID": "C31C",
                "ProductName": "Keyboard K120",
                "SerialNumber": "",
                "Status": "OK",
                "VID": "046D",
                "VendorName": "Logitech, Inc."
            },
            {
                "DeviceID": "USB\\VID_046D&PID_C31C&MI_01\\6&2DC83EB&0&0001",
                "DeviceType": "HID",
                "HostIdentifier": "DESKTOP-ANTONY",
                "HostUUID": "BFEBFBFF000806EAL1HF8C4003Z",
                "IsKnownAttackTool": false,
                "IsUnapprovedPeripheral": false,
                "IsVulnerablePeripheral": false,
                "PID": "C31C",
                "ProductName": "Keyboard K120",
                "SerialNumber": "",
                "Status": "OK",
                "VID": "046D",
                "VendorName": "Logitech, Inc."
            }
        ]
    }
}
```

#### Human Readable Output

>### Peripherals
>|HostUUID|DeviceID|Status|IsUnapprovedPeripheral|IsVulnerablePeripheral|IsKnownAttackTool|
>|---|---|---|---|---|---|
>| BFEBFBFF000806EAL1HF8C4003Z | USB\VID_046D&PID_C31C\5&20DBD6CE&0&1 | OK | false | false | false |
>| BFEBFBFF000806EAL1HF8C4003Z | USB\VID_046D&PID_C31C&MI_00\6&284FE535&0&0000 | OK | false | false | false |
>| BFEBFBFF000806EAL1HF8C4003Z | USB\VID_046D&PID_C31C&MI_01\6&284FE535&0&0001 | OK | false | false | false |
>| BFEBFBFF000806EAL1HF8C4003Z | USB\VID_046D&PID_C31C\5&20DBD6CE&0&3 | OK | false | false | false |
>| BFEBFBFF000806EAL1HF8C4003Z | USB\VID_046D&PID_C31C&MI_00\6&2DC83EB&0&0000 | OK | false | false | false |
>| BFEBFBFF000806EAL1HF8C4003Z | USB\VID_046D&PID_C31C&MI_01\6&2DC83EB&0&0001 | OK | false | false | false |


### sepio-query-switches
***
Get Switches


#### Base Command

`sepio-query-switches`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | Filter results based on IP Address. | Optional | 
| switch_name | Filter results based on switch name. | Optional | 
| model | Filter only switches that are of the specified model (partial or full, "begins with"). | Optional | 
| ios_version | Filter only switches that run a certain iosVersion (partial or full, "contains"). | Optional | 
| is_alarmed | Filter only switches that are alarmed. | Optional | 
| limit | Maximum number of switch entries to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sepio.Switch.SwitchID | string | Switch unique identifier. | 
| Sepio.Switch.IpAddress | string | IP Address of the switch. | 
| Sepio.Switch.Name | string | Assigned name of the switch. | 
| Sepio.Switch.Model | string | The specific switch model. | 
| Sepio.Switch.IosVersion | string | The IOS version the switch is running. | 
| Sepio.Switch.LastUpdate | string | Last update time. Format yyyy\-MM\-dd hh:ss:mm. | 
| Sepio.Switch.NumberOfPorts | number | The total number of switch ports. | 
| Sepio.Switch.Status | string | Current status of the switch port. | 
| Sepio.Switch.IsAlarmed | boolean | True if the switch port is alarmed. | 


#### Command Example
```!sepio-query-switches switch_name=sepio2960g ios_version=12.2(52)SE ip_address=192.168.100.25 model=WS-C2960G-24TC-L```

#### Context Example
```
{
    "Sepio": {
        "Switch": {
            "IosVersion": "12.2(52)SE",
            "IpAddress": "192.168.100.25",
            "IsAlarmed": false,
            "LastUpdate": "07/02/2020 18:26:37",
            "Model": "WS-C2960G-24TC-L",
            "Name": "sepio2960g",
            "NumberOfPorts": 24,
            "Status": "Unable to connect",
            "SwitchID": "DC:7B:94:96:17:80_FOC1428V67S"
        }
    }
}
```

#### Human Readable Output

>### Switches
>|SwitchID|Status|IsAlarmed|
>|---|---|---|
>| DC:7B:94:96:17:80_FOC1428V67S | Unable to connect | false |


### sepio-query-switch-ports
***
Get Switch Ports


#### Base Command

`sepio-query-switch-ports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| switch_ip_address | Filter results based on switch IP Address. | Optional | 
| switch_name | Filter results based on switch name. | Optional | 
| port_id | Filter results based on port id. | Optional | 
| port_name | Filter results based on port name. | Optional | 
| link_partner_data_contains | Filter only switch ports that contain the specified address (partial or full, "contains"). | Optional | 
| is_alarmed | Filter only switch ports that are alarmed. | Optional | 
| limit | Maximum number of switch port entries to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sepio.Port.SwitchID | string | Port Switch unique identifier. | 
| Sepio.Port.SwitchIpAddress | string | IP Address of the switch. | 
| Sepio.Port.SwitchName | string | Assigned name of the switch. | 
| Sepio.Port.PortID | string | Port unique identifier inside the switch. | 
| Sepio.Port.Name | string | Assigned name of the switch port. | 
| Sepio.Port.LastUpdate | string | Last update time. | 
| Sepio.Port.NumberOfMacAddresses | number | The number of MAC addresses detected on the switch port. | 
| Sepio.Port.LinkPartners | string | List of the MAC addresses detected on the switch port \(limited to maximum of 10\) | 
| Sepio.Port.Status | string | Current status of the switch port. | 
| Sepio.Switch.IsAlarmed | boolean | True if the switch port is alarmed. | 
| Sepio.Port.AlarmInfo | string | Details about the cause of alarm \(only if alarmed\). | 


#### Command Example
```!sepio-query-switch-ports switch_name=sepio2960g switch_ip_address=192.168.100.25 port_id=Gi0/8 link_partner_data_contains=000C2980EA75,000C29AE0D5E```

#### Context Example
```
{}
```

#### Human Readable Output

>null

### sepio-query-system-events
***
Get Events


#### Base Command

`sepio-query-system-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_datetime | Filter results based on event timestamp. | Optional | 
| end_datetime | Filter results based on event timestamp. | Optional | 
| min_severity | Filter only events of specific or higher severity than (&gt;=). | Optional | 
| category | Filter results based on event category. | Optional | 
| source | Filter results based on source entity of the event (partial or full, "contains"). | Optional | 
| peripheral_type | Filter only events (in the case of Peripheral events) that match a certain peripheral type. can contain multiple peripheral types separated with comma, i.e '1,2,3,4' or single type, i.e '1' | Optional | 
| limit | Maximum number of event entries to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Sepio.Event.CreationDatetime | string | Timestamp of the event. | 
| Sepio.Event.Severity | string | Severity level of the event. | 
| Sepio.Event.Category | string | Category of the event. | 
| Sepio.Event.Source | string | Source entity. | 
| Sepio.Event.Description | string | Event Description. | 
| Sepio.Event.PeripheralType | string | Type of peripheral device \(in the case of Peripheral Security events\). | 
| Sepio.Event.Details | string | Additional details that contain textual description of the event. | 


#### Command Example
```!sepio-query-system-events start_datetime=2020-03-01T09:01:05Z end_datetime=2020-05-10T09:28:05Z min_severity=Warning peripheral_type=1,2,3,4```

#### Context Example
```
{
    "Sepio": {
        "Event": [
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-04T11:14:28.227317",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 046D/C077  (Logitech, Inc. M105 Optical Mouse)",
                "EventID": 123,
                "PeripheralType": "2",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-04T11:14:28.227317",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 1A40/0101  (Terminus Technology Inc. Hub)",
                "EventID": 338,
                "PeripheralType": "4",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-04T11:14:28.227317",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 045E/07F8  (Microsoft Corp. Wired Keyboard 600 (model 1576) 00)",
                "EventID": 341,
                "PeripheralType": "1",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-05T10:10:28.008277",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 1A40/0101  (Terminus Technology Inc. Hub)",
                "EventID": 274,
                "PeripheralType": "4",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-05T10:10:28.008277",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 045E/07F8  (Microsoft Corp. Wired Keyboard 600 (model 1576) 00)",
                "EventID": 275,
                "PeripheralType": "1",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-05T10:10:29.062256",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 046D/C077  (Logitech, Inc. M105 Optical Mouse)",
                "EventID": 276,
                "PeripheralType": "2",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-05T10:12:10.285774",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 1A40/0101  (Terminus Technology Inc. Hub)",
                "EventID": 211,
                "PeripheralType": "4",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-05T10:12:11.341571",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 046D/C077  (Logitech, Inc. M105 Optical Mouse)",
                "EventID": 221,
                "PeripheralType": "2",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            },
            {
                "Category": "USB",
                "CreationDatetime": "2020-03-05T10:12:11.341571",
                "Description": "New USB peripheral detected",
                "Details": "[Agent] Vulnerable Device VID/PID are 045E/07F8  (Microsoft Corp. Wired Keyboard 600 (model 1576) 00)",
                "EventID": 220,
                "PeripheralType": "1",
                "Severity": "Warning",
                "Source": "DESKTOP-9LR722S (192.168.100.128)"
            }
        ]
    }
}
```

#### Human Readable Output

>### Events
>|EventID|CreationDatetime|Category|Source|Description|
>|---|---|---|---|---|
>| 123 | 2020-03-04T11:14:28.227317 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 338 | 2020-03-04T11:14:28.227317 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 341 | 2020-03-04T11:14:28.227317 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 274 | 2020-03-05T10:10:28.008277 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 275 | 2020-03-05T10:10:28.008277 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 276 | 2020-03-05T10:10:29.062256 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 211 | 2020-03-05T10:12:10.285774 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 221 | 2020-03-05T10:12:11.341571 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |
>| 220 | 2020-03-05T10:12:11.341571 | USB | DESKTOP-9LR722S (192.168.100.128) | New USB peripheral detected |


### sepio-set-agent-mode
***
Set Agent Mode


#### Base Command

`sepio-set-agent-mode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the Agent to set. | Optional | 
| host_identifier | Host identifier of the Agent to set. | Optional | 
| ip_address | IP Address of the Agent to set. | Optional | 
| mode | New mode to apply – "Free" or "Armed". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sepio-set-agent-mode mode=Free uuid=BFEBFBFF000806EAL1HF8C4003Z```

#### Context Example
```
{}
```

#### Human Readable Output

>Agent ['BFEBFBFF000806EAL1HF8C4003Z'] mode has been changed successfully to 'Free'

### sepio-set-peripherals-mode
***
Set Agent Peripherals Mode


#### Base Command

`sepio-set-peripherals-mode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the Agent to set. | Optional | 
| host_identifier | Host identifier of the Agent to set. | Optional | 
| ip_address | IP Address of the Agent to set. | Optional | 
| vid | VendorID of the peripheral to set. | Required | 
| pid | ProductID of the peripheral to set. | Required | 
| mode | New mode to apply – "Approve" or "Disapprove". | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!sepio-set-peripherals-mode mode=Approve uuid=BFEBFBFF000806EAL1HF8C4003Z vid=046D pid=C31C```

#### Context Example
```
{}
```

#### Human Readable Output

>Peripherals of ['BFEBFBFF000806EAL1HF8C4003Z'] with vid '046D' and pid 'C31C' mode changed successfully to 'Approve'
