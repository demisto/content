## Overview
---
Use the Cisco Adaptive Security Appliance Software integration to manage interfaces, rules, and network objects.
This integration was integrated and tested with version 9.12(3) of Cisco ASA

## Configure Cisco ASA on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cisco ASA.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g. https://192.168.0.1)__
    * __Credentials__
    * __Use system proxy settings__
    * __Trust any certificate (not secure)__
    * __is ASAv__
4. Click __Test__ to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cisco-asa-list-rules
2. cisco-asa-backup
3. cisco-asa-get-rule-by-id
4. cisco-asa-create-rule
5. cisco-asa-delete-rule
6. cisco-asa-edit-rule
7. cisco-asa-list-network-objects
8. cisco-asa-create-network-object
9. cisco-asa-list-interfaces
### 1. cisco-asa-list-rules
---
Gets a list all rules for the supplied interface.

##### Base Command

`cisco-asa-list-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interface_name | The name of the interface from which to get rules. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global"  | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 


##### Command Example
```!cisco-asa-list-rules interface_type="Global"```

##### Context Example
```
{
    "CiscoASA.Rules": [
        {
            "SourceService": "tcp", 
            "DestService": "tcp", 
            "Source": "Windows10", 
            "Dest": "2.2.2.2", 
            "Remarks": [], 
            "InterfaceType": "Global", 
            "Permit": true, 
            "Interface": null, 
            "Position": 1, 
            "ID": "924049783", 
            "IsActive": true
        }, 
        {
            "SourceService": "ip", 
            "DestService": "ip", 
            "Source": "1.1.1.1", 
            "Dest": "2.2.2.2", 
            "Remarks": [], 
            "InterfaceType": "Global", 
            "Permit": false, 
            "Interface": null, 
            "Position": 2, 
            "ID": "3156543720", 
            "IsActive": true
        }
    ]
}
```

##### Human Readable Output
### Rules:
|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|destService|
|---|---|---|---|---|---|---|---|---|---|
| 924049783 | Windows10 | 2.2.2.2 | true |  | Global | true | 1 | tcp |  |
| 3156543720 | 1.1.1.1 | 2.2.2.2 | false |  | Global | true | 2 | ip |  |


### 2. cisco-asa-backup
---
Creates a backup of the current settings (i.e., the backup.cfg file).
 
##### Base Command

`cisco-asa-backup`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| backup_name | The name of the backup. | Required | 
| passphrase | Passphrase for backup. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
``` ```

##### Human Readable Output


### 3. cisco-asa-get-rule-by-id
---
Gets a specific rule by rule ID.

##### Base Command

`cisco-asa-get-rule-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. | Required | 
| interface_name | The name of the interface | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID.	 | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 


##### Command Example
```!cisco-asa-get-rule-by-id rule_id=3156543720 interface_type=Global```

##### Context Example
```
{
  "CiscoASA.Rules": [
    {
      "Dest": "2.2.2.2",
      "DestService": "ip",
      "ID": "3156543720",
      "Interface": "",
      "InterfaceType": "Global",
      "IsActive": true,
      "Permit": false,
      "Position": 2,
      "Remarks": [],
      "Source": "1.1.1.1",
      "SourceService": "ip"
    }
  ]
}
```

##### Human Readable Output
### Rule 3156543720:
|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|destService|
|---|---|---|---|---|---|---|---|---|---|
| 3156543720 | 1.1.1.1 | 2.2.2.2 | false |  | Global | true | 2 | ip |  |\n"

### 4. cisco-asa-create-rule
---
Creates a rule.
 
##### Base Command

`cisco-asa-create-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | The source. Can be the value of an IPv4, an address block, or the name of a network object. object. | Required | 
| destination | The destination. Can be the value of an IPv4, an address block, or the name of a network object. object. | Required | 
| permit | Whether the rule is a permit. If True, the rule is a permit. | Required | 
| remarks | A list of remarks for the rule. | Optional | 
| position | The position in which to create the rule.  | Optional | 
| log_level | The log level of the rule.  Can be "Default", "Emergencies", "Alerts", "Critical", "Errors", "Warnings", "Notifications", "Informational", or "Debugging".| Optional | 
| active | Whether the rule will be active. If True, the rule will be active. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". | Required | 
| interface_name | The interface name. | Optional | 
| service | The service of the rule. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 


##### Command Example
```!cisco-asa-create-rule destination=4.4.4.4 interface_type=Global permit=False source=2.2.2.2```

##### Context Example
```
{
  "CiscoASA.Rules": [
    {
      "Dest": "4.4.4.4",
      "DestService": "ip",
      "ID": "507330730",
      "Interface": "",
      "InterfaceType": "Global",
      "IsActive": true,
      "Permit": false,
      "Position": 4,
      "Remarks": [],
      "Source": "2.2.2.2",
      "SourceService": "ip"
    }
  ]
}
```
##### Human Readable Output
### Created new rule. ID: 507330730
|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|destService|
|---|---|---|---|---|---|---|---|---|---|
| 507330730 | 2.2.2.2 | 4.4.4.4 | false |  | Global | true | 4 | ip |  |"

### 5. cisco-asa-delete-rule
---
Deletes a rule.
 
##### Base Command

`cisco-asa-delete-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID. | Required | 
| interface_name | The name of the interface. | Optional | 
| interface_type | The interface type. Can be "In", "Out", or "Global". | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!cisco-asa-delete-rule interface_type=Global rule_id=507330730```

##### Human Readable Output
```Rule 507330730 deleted successfully.```

### 6. cisco-asa-edit-rule
---
Updates an existing rule.
##### Base Command

`cisco-asa-edit-rule`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| interface_type | The interface type. Can be "In", "Out", or "Global". | Required | 
| interface_name | The interface name. | Optional | 
| rule_id | The rule ID. | Required | 
| active | Whether the rule will be active. If True, the rule will be active. | Optional | 
| log_level | The log level of the rule.  Can be "Default", "Emergencies", "Alerts", "Critical", "Errors", "Warnings", "Notifications", "Informational", or "Debugging".| Optional | 
| position | The position the rule will be in.  | Optional | 
| remarks | A list of remarks for the rule. | Optional | 
| permit | Whether the rule is a permit. If True, the rule is a permit. | Optional | 
| destination | The destination. Can be the value of an IPv4, an address block, or the name of a network object. | Optional | 
| source | The source. Can be the value of an IPv4, an address block, or the name of a network object. object. | Optional | 
| service | The service of the rule. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Rules.Source | String | The rule's source. | 
| CiscoASA.Rules.Dest | String | The rule's destination. | 
| CiscoASA.Rules.InterfaceType | String | The interface type. Can be "In", "Out", or "Global". | 
| CiscoASA.Rules.IsActive | Boolean | Whether the rule is active. | 
| CiscoASA.Rules.Interface | String | The name of the interface. | 
| CiscoASA.Rules.Position | Number | The position of the rule. | 
| CiscoASA.Rules.ID | String | The rule ID. | 
| CiscoASA.Rules.Remarks | Unknown | A list of all rule remarks. | 
| CiscoASA.Rules.Permit | Boolean | Whether the rule permits traffic from source to destination. | 
| CiscoASA.Rules.DestService | String | The destination service. | 
| CiscoASA.Rules.SourceService | String | The source service. | 


##### Command Example
```!cisco-asa-edit-rule interface_type=Global rule_id=1536327057 ```

#### Context Example
```
{
  "CiscoASA.Rules": [
    {
      "Dest": "4.4.4.4",
      "DestService": "ip",
      "ID": "1536327057",
      "Interface": "",
      "InterfaceType": "Global",
      "IsActive": true,
      "Permit": false,
      "Position": 3,
      "Remarks": [
        "Wow"
      ],
      "Source": " 1.1.1.1",
      "SourceService": "ip"
    }
  ]
}
```

##### Human Readable Output
### Edited rule 1536327057
|ID|Source|Dest|Permit|Interface|InterfaceType|IsActive|Position|SourceService|destService|
|---|---|---|---|---|---|---|---|---|---|
| 1536327057 |  1.1.1.1 | 4.4.4.4 | false |  | Global | true | 3 | ip |  |

### 7. cisco-asa-list-network-objects
---
Gets a list all configured network objects.

##### Base Command

`cisco-asa-list-network-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_name | A comma-separated list of network object names for which to get the network.~~~~ | Optional | 
| object_id | A comma-separated list of object IDs for which to get the network object. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.NetworkObject.ID | String | The ID of the network object. | 
| CiscoASA.NetworkObject.Host | String | The host information of the network object. | 
| CiscoASA.NetworkObject.Description | String | A description of the network object, if exists. | 
| CiscoASA.NetworkObject.Name | String | The name of the network object. | 


##### Command Example
```!cisco-asa-list-network-objects ```

##### Context Example
```
{
  "CiscoASA.NetworkObject(val.ID == obj.ID)": [
    {
      "Host": {
        "kind": "IPv4Address",
        "value": "1.1.1.1"
      },
      "ID": "ASA_Demo_NObj_1190",
      "Name": "ASA_Demo_NObj_1190"
    },
    {
      "Description": "Cisco ASA",
      "Host": {
        "kind": "IPv4Address",
        "value": "8.8.8.8"
      },
      "ID": "CiscoASA",
      "Name": "CiscoASA"
    }
  ]
}
```

##### Human Readable Output
### Network Objects
|ID|Name|Host|Description|
|---|---|---|---|
| ASA_Demo_NObj_1190 | ASA_Demo_NObj_1190 | kind: IPv4Address<br/>value: 1.1.1.1 |  |
| CiscoASA | CiscoASA | kind: IPv4Address<br/>value:8.8.8.8. | Cisco ASA |
### 8. cisco-asa-create-network-object
---
Creates network object.
##### Base Command

`cisco-asa-create-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of network object to create. | Required | 
| object_name | The name of the object to create. | Required | 
| object_value | The value of the network object to create. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.NetworkObject.ID | String | The ID of the network object. | 
| CiscoASA.NetworkObject.Host | String | The host information of the network object. | 
| CiscoASA.NetworkObject.Description | String | A description of the network object, if exists. | 
| CiscoASA.NetworkObject.Name | String | The name of the network object. | 


##### Command Example
```!cisco-asa-create-network-object object_name="Object" object_type="IPv4" object_value="1.1.1.1" debug-mode=true```

##### Context Example
```
{
  "CiscoASA.NetworkObject": [
    {
      "Host": {
        "kind": "IPv4Address",
        "value": "1.1.1.1"
      },
      "ID": "Object",
      "Name": "Object"
    }
  ]
}
```

##### Human Readable Output
### Network Objects
|ID|Name|Host|Description|
|---|---|---|---|
| Object | Object | kind: IPv4Address<br/>value: 1.1.1.1 |  |"

### 9. cisco-asa-list-interfaces
---
Gets a list of all interfaces.

##### Base Command

`cisco-asa-list-interfaces`
##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoASA.Interface.ID | String | The interface ID. | 
| CiscoASA.Interface.Name | String | The inteface name. | 
| CiscoASA.Interface.Type | String | The interface type. Can be "In", "Out", or "Global". | 


##### Command Example
```!cisco-asa-list-interfaces```

##### Context Example
```
{
  "CiscoASA.Interface": [
    {
      "ID": "-1",
      "Name": null,
      "Type": "Global"
    },
    {
      "ID": "GigabitEthernet0_API_SLASH_0",
      "Name": "INSIDE",
      "Type": "In"
    }
  ]
}
```
##### Human Readable Output
### Interfaces
|Type|ID|Name|
|---|---|---|
| Global | -1 |  |
| In | GigabitEthernet0_API_SLASH_0 | INSIDE |
