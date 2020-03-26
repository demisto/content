## Overview
---

Use the Cisco Firepower integration for unified management of firewalls, application control, intrusion prevention, URL filtering, and advanced malware protection.
This integration was integrated and tested with version xx of Cisco Firepower

## Use Cases
---

## Configure Cisco Firepower on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Cisco Firepower.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL (e.g., https://192.168.0.1)__
    * __Username__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. ciscofp-list-zones
2. ciscofp-list-ports
3. ciscofp-list-url-categories
4. ciscofp-get-network-object
5. ciscofp-create-network-object
6. ciscofp-update-network-object
7. ciscofp-get-network-groups-object
8. ciscofp-create-network-groups-objects
9. ciscofp-update-network-groups-objects
10. ciscofp-delete-network-groups-objects
11. ciscofp-get-host-object
12. ciscofp-create-host-object
13. ciscofp-update-host-object
14. ciscofp-delete-network-object
15. ciscofp-delete-host-object
16. ciscofp-get-access-policy
17. ciscofp-create-access-policy
18. ciscofp-update-access-policy
19. ciscofp-delete-access-policy
20. ciscofp-list-security-group-tags
21. ciscofp-list-ise-security-group-tag
22. ciscofp-list-vlan-tags
23. ciscofp-list-vlan-tags-group
24. ciscofp-list-applications
25. ciscofp-get-access-rules
26. ciscofp-create-access-rules
27. ciscofp-update-access-rules
28. ciscofp-delete-access-rules
29. ciscofp-list-policy-assignments
30. ciscofp-create-policy-assignments
31. ciscofp-update-policy-assignments
32. ciscofp-get-deployable-devices
33. ciscofp-get-device-records
34. ciscofp-deploy-to-devices
35. ciscofp-get-task-status
### 1. ciscofp-list-zones
---
Retrieves a list of all security zone objects.

##### Base Command

`ciscofp-list-zones`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return.<br>The default is 50 | Optional | 
| offset | Index of the first item to return.<br>The default is 0. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Zone.ID | String | Zone ID. | 
| CiscoFP.Zone.Name | String | Zone name. | 
| CiscoFP.Zone.InterfaceMode | String | Zone interface mode. | 
| CiscoFP.Zone.Interfaces.Name | String | Name of interfaces belonging to the security zone. | 
| CiscoFP.Zone.Interfaces.ID | String | ID of interfaces belonging to the security zone. | 


##### Command Example
```!ciscofp-list-zones```

##### Human Readable Output


### 2. ciscofp-list-ports
---
Retrieves list of all port objects.

##### Base Command

`ciscofp-list-ports`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>by default is 0 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Port.ID | String | Port ID. | 
| CiscoFP.Port.Name | String | Port name. | 
| CiscoFP.Port.Protocol | String | Port protocol. | 
| CiscoFP.Port.Port | String | Port number. | 


##### Command Example
```!ciscofp-list-ports```

##### Human Readable Output


### 3. ciscofp-list-url-categories
---
Retrieves a list of all URL category objects.

##### Base Command

`ciscofp-list-url-categories`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Category.ID | String | ID of the category. | 
| CiscoFP.Category.Name | String | Name of the category. | 


##### Command Example
```!ciscofp-list-url-categories```

##### Human Readable Output


### 4. ciscofp-get-network-object
---
Retrieves the network objects associated with the specified ID. If not supplied, retrieves a list of all network objects.

##### Base Command

`ciscofp-get-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | Object ID. | Optional | 
| limit | The number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of network object | 
| CiscoFP.Network.Name | String | Name of network object | 
| CiscoFP.Network.Value | String | CIDR | 
| CiscoFP.Network.Overrideable | String | Boolean indicating whether object can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-get-network-object object_id="000C29A8-BA3B-0ed3-0000-133143986657"```

##### Human Readable Output


### 5. ciscofp-create-network-object
---
Creates a network object.

##### Base Command

`ciscofp-create-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new object. | Required | 
| value | CIDR | Required | 
| description | The object description. | Optional | 
| overridable | Boolean indicating whether objects can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of network object. | 
| CiscoFP.Network.Name | String | Name of network object. | 
| CiscoFP.Network.Value | String | CIDR. | 
| CiscoFP.Network.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-create-network-object name="playbookTest" value="10.0.0.0/22" description="my playbook test" overridable="false"```

##### Human Readable Output


### 6. ciscofp-update-network-object
---
Updates the specified network object.

##### Base Command

`ciscofp-update-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to update. | Required | 
| name | The object name. | Required | 
| value | CIDR | Required | 
| description | The object description. | Optional | 
| overridable | Boolean indicating whether the object can be overridden. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of the network object. | 
| CiscoFP.Network.Name | String | Name of the network object. | 
| CiscoFP.Network.Value | String | CIDR. | 
| CiscoFP.Network.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-update-network-object id="000C29A8-BA3B-0ed3-0000-133143986657" name="playbookTestUpdate" value="10.0.0.0/23" description="my playbook test" overridable="true"```

##### Human Readable Output


### 7. ciscofp-get-network-groups-object
---
Retrieves the groups of network objects and addresses associated with the specified ID. If not supplied, retrieves a list of all network objects.

##### Base Command

`ciscofp-get-network-groups-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object group for which to return groups and addresses. | Optional | 
| limit | The number of items to return.<br>The default is 50. | Optional | 
| offset | Index of the first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address / CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name. | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-get-network-groups-object id="000C29A8-BA3B-0ed3-0000-133143986735"```

##### Human Readable Output


### 8. ciscofp-create-network-groups-objects
---
Creates a group of network objects.

##### Base Command

`ciscofp-create-network-groups-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The group name. | Required | 
| network_objects_id_list | A comma-separated list of object IDs to add to the group. | Optional | 
| network_address_list | A comma-separated list of IP addresses or CIDR ranges to add the group. | Optional | 
| description | The object description. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether the object can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name. | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-create-network-groups-objects name="playbookTest3" network_objects_id_list="000C29A8-BA3B-0ed3-0000-133143986657" network_address_list="8.8.8.8,4.4.4.4" description="my playbook test" overridable="true"```

##### Human Readable Output


### 9. ciscofp-update-network-groups-objects
---
Updates a group of network objects.

##### Base Command

`ciscofp-update-network-groups-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the group to update. | Required | 
| network_objects_id_list | A comma-separated list of object IDs to add the group. | Optional | 
| network_address_list | A comma-separated list of IP addresses or CIDR ranges to add the group. | Optional | 
| description | The new description for the object. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 
| name | The group name. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether objects can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name. | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-update-network-groups-objects id="000C29A8-BA3B-0ed3-0000-133143986735" network_objects_id_list="000C29A8-BA3B-0ed3-0000-133143986696" network_address_list="1.2.3.4,1.2.3.5" description="my playbook test" overridable="true" name="playbookTestUpdate3"```

##### Human Readable Output


### 10. ciscofp-delete-network-groups-objects
---
Deletes a group of network objects.

##### Base Command

`ciscofp-delete-network-groups-objects`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.NetworkGroups.ID | String | The group ID. | 
| CiscoFP.NetworkGroups.Name | String | The group name. | 
| CiscoFP.NetworkGroups.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.NetworkGroups.Description | String | The group description. | 
| CiscoFP.NetworkGroups.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.NetworkGroups.Addresses.Type | String | The address type. | 
| CiscoFP.NetworkGroups.Objects.Name | String | The object name | 
| CiscoFP.NetworkGroups.Objects.ID | String | The object ID. | 
| CiscoFP.NetworkGroups.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-delete-network-groups-objects id="000C29A8-BA3B-0ed3-0000-133143986735"```

##### Human Readable Output


### 11. ciscofp-get-host-object
---
Retrieves the groups of host objects associated with the specified ID. If no ID is passed, the input ID retrieves a list of all network objects.

##### Base Command

`ciscofp-get-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_id | ID of the object for which to retrieve host objects. | Optional | 
| limit | Number of items to return.<br>The default is 50 | Optional | 
| offset | Index of the first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of host object. | 
| CiscoFP.Host.Value | String | The IP address. | 
| CiscoFP.Host.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Host.Description | String | A description of the host object. | 


##### Command Example
```!ciscofp-get-host-object object_id="000C29A8-BA3B-0ed3-0000-133143986696"```

##### Human Readable Output


### 12. ciscofp-create-host-object
---
Creates a host object.
##### Base Command

`ciscofp-create-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new object. | Required | 
| value | The IP address. | Required | 
| description | A description of the new object. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of the host object. | 
| CiscoFP.Host.Value | String | The IP address. | 
| CiscoFP.Host.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Host.Description | String | Description of the host object. | 


##### Command Example
```!ciscofp-create-host-object name="playbookTest2" value="1.2.3.4" description="my playbook test" overridable="false"```

##### Human Readable Output


### 13. ciscofp-update-host-object
---
Updates the specified host object.

##### Base Command

`ciscofp-update-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to update. | Required | 
| name | Name of the object. | Required | 
| value | The IP address. | Required | 
| description | Description of the object. | Optional | 
| overridable | Boolean indicating whether object values can be overridden. Can be "true" or "false". The default is "false". | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of the host object. | 
| CiscoFP.Host.Value | String | The IP address. | 
| CiscoFP.Host.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Host.Description | String | Description of the host object. | 


##### Command Example
```!ciscofp-update-host-object id="000C29A8-BA3B-0ed3-0000-133143986696" name="playbookTestUpdate2" value="1.2.3.5" description="my playbook test" overridable="true"```

##### Human Readable Output


### 14. ciscofp-delete-network-object
---
Deletes the specified network object.

##### Base Command

`ciscofp-delete-network-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the object to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Network.ID | String | ID of the network object. | 
| CiscoFP.Network.Name | String | Name of the network object. | 
| CiscoFP.Network.Value | String | CISR range. | 
| CiscoFP.Network.Overridable | String | Boolean indicating whether object values can be overridden. | 
| CiscoFP.Network.Description | String | Description of the network object. | 


##### Command Example
```!ciscofp-delete-network-object id="000C29A8-BA3B-0ed3-0000-133143986657"```

##### Human Readable Output


### 15. ciscofp-delete-host-object
---
Deletes the specified host object.

##### Base Command

`ciscofp-delete-host-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the host object to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Host.ID | String | ID of the host object. | 
| CiscoFP.Host.Name | String | Name of the host object. | 
| CiscoFP.Host.Value | String | CIDR range. | 
| CiscoFP.Host.Overridable | String | Whether the  object can be overridden. | 
| CiscoFP.Host.Description | String | Description of the host object. | 


##### Command Example
```!ciscofp-delete-host-object id="000C29A8-BA3B-0ed3-0000-133143986696"```

##### Human Readable Output


### 16. ciscofp-get-access-policy
---
Retrieves the access control policy associated with the specified ID. If no access policy ID is passed, all access control policies are returned.

##### Base Command

`ciscofp-get-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the access policy. | Optional | 
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-get-access-policy```

##### Human Readable Output


### 17. ciscofp-create-access-policy
---
Creates an access control policy.

##### Base Command

`ciscofp-create-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new access policy. | Required | 
| action | The action to take. Can be "BLOCK", "TRUST", "PERMIT", or "NETWORK_DISCOVERY". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-create-access-policy name="playbookTest4" action="BLOCK"```

##### Human Readable Output


### 18. ciscofp-update-access-policy
---
Updates the specified access control policy.

##### Base Command

`ciscofp-update-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The access policy name. | Required | 
| id | ID of the access policy. | Required | 
| default_action_id | ID of the default action. | Required | 
| action | The action to take. Can be "BLOCK", "TRUST", "PERMIT", or "NETWORK_DISCOVERY". | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-update-access-policy name="playbookTestUpdate4" id="[\"000C29A8-BA3B-0ed3-0000-133143986773\"]" default_action_id="[\"000C29A8-BA3B-0ed3-0000-000268444672\"]" action="PERMIT"```

##### Human Readable Output


### 19. ciscofp-delete-access-policy
---
Deletes the specified access control policy.

##### Base Command

`ciscofp-delete-access-policy`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the access policy. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Policy.ID | String | The policy ID. | 
| CiscoFP.Policy.Name | String | The name of the policy. | 
| CiscoFP.Policy.DefaultActionID | String | The default action ID of the policy. | 


##### Command Example
```!ciscofp-delete-access-policy id="000C29A8-BA3B-0ed3-0000-133143986773"```

##### Human Readable Output


### 20. ciscofp-list-security-group-tags
---
Retrieves a list of all custom security group tag objects.

##### Base Command

`ciscofp-list-security-group-tags`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50 | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.SecurityGroupTags.ID | String | ID of security group tag. | 
| CiscoFP.SecurityGroupTags.Name | String | Name of security group tag. | 
| CiscoFP.SecurityGroupTags.Tag | Number | The tag number. | 


##### Command Example
```!ciscofp-list-security-group-tags ```

##### Human Readable Output


### 21. ciscofp-list-ise-security-group-tag
---
Retrieves a list of all ISE security group tag objects.

##### Base Command

`ciscofp-list-ise-security-group-tag`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.SecurityGroupTags.ID | String | ID of security group tag. | 
| CiscoFP.SecurityGroupTags.Name | String | Name of security group tag. | 
| CiscoFP.SecurityGroupTags.Tag | Number | The tag number. | 


##### Command Example
```!ciscofp-list-ise-security-group-tag```

##### Human Readable Output


### 22. ciscofp-list-vlan-tags
---
Retrieves a list of all vlantag objects.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`ciscofp-list-vlan-tags`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.VlanTags.ID | String | ID of the vlan tag. | 
| CiscoFP.VlanTags.Name | String | Name of the vlan tag. | 
| CiscoFP.VlanTags.Overridable | Boolean | Boolean indicating whether object values can be overridden. | 
| CiscoFP.VlanTags.Description | String | Description of the vlan tag. | 
| CiscoFP.VlanTags.StartTag | Number | Start tag number. | 
| CiscoFP.VlanTags.EndTag | Number | End tag number. | 


##### Command Example
```!ciscofp-list-vlan-tags```

##### Human Readable Output


### 23. ciscofp-list-vlan-tags-group
---
Retrieves a list of all vlan group tag objects.

##### Base Command

`ciscofp-list-vlan-tags-group`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.VlanTagsGroup.Name | String | Name of the group. | 
| CiscoFP.VlanTagsGroup.ID | String | ID of the group. | 
| CiscoFP.VlanTagsGroup.Description | String | Description of the object. | 
| CiscoFP.VlanTagsGroup.Overridable | Boolean | Boolean indicating whether object values can be overridden. | 
| CiscoFP.VlanTagsGroup.Objects.Name | String | Name of the object. | 
| CiscoFP.VlanTagsGroup.Objects.ID | String | ID of the object. | 
| CiscoFP.VlanTagsGroup.Objects.Description | String | Description of the vlan tag. | 
| CiscoFP.VlanTagsGroup.Objects.Overridable | Boolean | Boolean indicating whether object values can be overridden. | 
| CiscoFP.VlanTagsGroup.Objects.StartTag | Number | Start tag number. | 
| CiscoFP.VlanTagsGroup.Objects.EndTag | Number | End tag number. | 


##### Command Example
```!ciscofp-list-vlan-tags-group```

##### Human Readable Output


### 24. ciscofp-list-applications
---
Retrieves a list of all application objects.

##### Base Command

`ciscofp-list-applications`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Applications.Name | String | Name of the application. | 
| CiscoFP.Applications.ID | String | ID of the application. | 
| CiscoFP.Applications.Risk | String | Risk of the application. | 
| CiscoFP.Applications.AppProductivity | String | AppProductivity of the application. | 
| CiscoFP.Applications.ApplicationTypes | String | The application type. | 
| CiscoFP.Applications.AppCategories.ID | String | AppCategory ID. | 
| CiscoFP.Applications.AppCategories.Name | String | AppCategory name. | 
| CiscoFP.Applications.AppCategories.Count | String | AppCategory count. | 


##### Command Example
```!ciscofp-list-applications```

##### Human Readable Output


### 25. ciscofp-get-access-rules
---
Retrieves the access control rule associated with the specified policy ID and rule ID. If no rule ID is specified, retrieves a list of all access rules associated with the specified policy ID.

##### Base Command

`ciscofp-get-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Policy ID. | Required | 
| rule_id | Rule ID. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | Rule action. | 
| CiscoFP.Rule.Applications.ID | String | Application object ID. | 
| CiscoFP.Rule.Applications.Name | String | Application object name. | 
| CiscoFP.Rule.Category | String | Category of rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | Address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | Object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | Object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | Port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | Port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | Port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | Port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | Port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | Port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | Zone ID. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | Zone name. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | Zone type. | 
| CiscoFP.Rule.Enabled | Number | Whether the rule is enabled. | 
| CiscoFP.Rule.ID | String | Rule ID. | 
| CiscoFP.Rule.Name | String | Rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | IP address or CIDR range. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | Object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | Port number. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | Port protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | Object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | Object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | Object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | Object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | Object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | Object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | Object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | Object type. | 


##### Command Example
``` !ciscofp-get-access-rules policy_id="000C29A8-BA3B-0ed3-0000-133143986773"```

##### Human Readable Output


### 26. ciscofp-create-access-rules
---
Creates an access control rule.
##### Base Command

`ciscofp-create-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The rule's traffic. Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or "BLOCK_RESET_INTERACTIVE". | Required | 
| rule_name | The rule name. | Required | 
| enabled | Boolean indicating whether to enable the access control rule. | Optional | 
| source_zone_object_ids | A list of source zone object IDs. To get IDs use the ciscofp-list-zones command. | Optional | 
| policy_id | The policy ID in which to create the new rule. | Required | 
| destination_zone_object_ids | A list of destination zone object IDs. To get IDs, use the ciscofp-list-zones command. | Optional | 
| vlan_tag_object_ids | A list of vlan tag object IDs. To get IDs, use the ciscofp-list-vlan-tags command. | Optional | 
| source_network_object_ids | A list of network object IDs. To get IDs, use the ciscofp-get-network-groups-object command. | Optional | 
| source_network_addresses | A list of source IP addresses or CIDR ranges. To get the addresses or ranges, use the ciscofp-get-network-object or ciscofp-get-host-object command, respectively. | Optional | 
| destination_network_object_ids | A list of destination IP addresses or CIDR ranges. To get the addresses or ranges, use the ciscofp-get-network-object or ciscofp-get-host-object command, respectively. | Optional | 
| destination_network_addresses | A list of destination addresses. | Optional | 
| source_port_object_ids | A list of port object IDs. To get IDs,  use the ciscofp-get-network-object or ciscofp-get-host-object commands. | Optional | 
| destination_port_object_ids | A list of port object IDs. To get IDs, use the ciscofp-list-ports command. | Optional | 
| source_security_group_tag_object_ids | A list of security group tag object IDs. To get IDs, use the ciscofp-list-security-group-tags command. | Optional | 
| application_object_ids | A list of application object IDs. To get IDs, use the ciscofp-list-applications command. | Optional | 
| url_object_ids | A list of URL object IDs. To get IDs, use the ciscofp-list-url-categories command. | Optional | 
| url_addresses | A list of URL addresses. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The zone ID. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The zone name. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The zone type. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether to enable the rule. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-create-access-rules action="ALLOW" rule_name="playbookTest5" enabled="true" policy_id="000C29A8-BA3B-0ed3-0000-133143986773" source_network_object_ids="000C29A8-BA3B-0ed3-0000-133143986735" source_network_addresses="1.2.3.4" destination_network_object_ids="000C29A8-BA3B-0ed3-0000-133143986696" destination_network_addresses="1.2.3.5" url_addresses="www.google.com"```

##### Human Readable Output


### 27. ciscofp-update-access-rules
---
Updates the specified access control rule.

##### Base Command

`ciscofp-update-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| update_strategy | The method by which to update the rule. Can be "merge" or "override".<br>If merge, will add the changes requested to the existing rule.<br>If override, will override the fields with the inputs provided and will delete any fields that were not provided. | Required | 
| action | The rule action that determines how the system handles matching traffic. Can be "ALLOW", "TRUST", "BLOCK", "MONITOR", "BLOCK_RESET", "BLOCK_INTERACTIVE", or "BLOCK_RESET_INTERACTIVE". | Optional | 
| rule_name | The rule name. | Optional | 
| enabled | Boolean indicating whether to enable the rule. The default is "true". | Optional | 
| source_zone_object_ids | A list of source zones object IDs. | Optional | 
| policy_id | The policy ID for which to create the new rule. | Required | 
| destination_zone_object_ids | A list of destination zones object IDs. | Optional | 
| vlan_tag_object_ids | A list of vlan tag object IDs. | Optional | 
| source_network_object_ids | A list of source network object IDs. | Optional | 
| source_network_addresses | A list of addresses. | Optional | 
| destination_network_object_ids | A list of destination network object IDs. | Optional | 
| destination_network_addresses | A list of addresses. | Optional | 
| source_port_object_ids | A list of port object IDs. | Optional | 
| destination_port_object_ids | A list of port object IDs. | Optional | 
| source_security_group_tag_object_ids | A list of security group tag object IDs. | Optional | 
| application_object_ids | A list of application object IDs. | Optional | 
| url_object_ids | A list of URL object IDs. | Optional | 
| url_addresses | A list of URL addresses. | Optional | 
| rule_id | The ID of the rule to update. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of the rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The destination zone object IDs. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The destination zone object names. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The destination zone object types. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether the rule is enabled. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-update-access-rules update_strategy="merge" action="BLOCK" rule_name="playbookTestUpdate5" enabled="true" policy_id="[\"000C29A8-BA3B-0ed3-0000-133143986773\"]" source_network_object_ids="000C29A8-BA3B-0ed3-0000-133143986657" destination_network_addresses="8.8.8.6" url_addresses="www.google.co.il" rule_id="000C29A8-BA3B-0ed3-0000-000268444673"```

##### Human Readable Output


### 28. ciscofp-delete-access-rules
---
Deletes the specified access control rule.

##### Base Command

`ciscofp-delete-access-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required | 
| rule_id | The ID of the rule to delete. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Rule.Action | String | The action that determines how the system handles matching traffic. | 
| CiscoFP.Rule.Applications.ID | String | The application object ID. | 
| CiscoFP.Rule.Applications.Name | String | The application object name. | 
| CiscoFP.Rule.Category | String | The category of the rule. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.DestinationNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.DestinationNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.DestinationNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Port | String | The port number. | 
| CiscoFP.Rule.DestinationPorts.Addresses.Protocol | String | The port protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.ID | String | The port object ID. | 
| CiscoFP.Rule.DestinationPorts.Objects.Name | String | The port object name. | 
| CiscoFP.Rule.DestinationPorts.Objects.Protocol | String | The port object protocol. | 
| CiscoFP.Rule.DestinationPorts.Objects.Type | String | The port object type. | 
| CiscoFP.Rule.DestinationZones.Objects.ID | String | The zone IDs. | 
| CiscoFP.Rule.DestinationZones.Objects.Name | String | The zone names. | 
| CiscoFP.Rule.DestinationZones.Objects.Type | String | The zone types. | 
| CiscoFP.Rule.Enabled | Number | Boolean indicating whether the rule is enabled. | 
| CiscoFP.Rule.ID | String | The rule ID. | 
| CiscoFP.Rule.Name | String | The rule name. | 
| CiscoFP.Rule.RuleIndex | Number | The index of the rule. | 
| CiscoFP.Rule.Section | String | The section of the rule. | 
| CiscoFP.Rule.SendEventsToFMC | Number | Boolean indicating whether the device will send events to Cisco Firepower. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Type | String | The address type. | 
| CiscoFP.Rule.SourceNetworks.Addresses.Value | String | The address value. | 
| CiscoFP.Rule.SourceNetworks.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceNetworks.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceNetworks.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourcePorts.Addresses.Port | String | The address port. | 
| CiscoFP.Rule.SourcePorts.Addresses.Protocol | String | The address protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourcePorts.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourcePorts.Objects.Protocol | String | The object protocol. | 
| CiscoFP.Rule.SourcePorts.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceSecurityGroupTags.Objects.Type | String | The object type. | 
| CiscoFP.Rule.SourceZones.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.SourceZones.Objects.Name | String | The object name. | 
| CiscoFP.Rule.SourceZones.Objects.Type | String | The object type. | 
| CiscoFP.Rule.Urls.Addresses.URL | String | The URL address. | 
| CiscoFP.Rule.Urls.Objects.ID | String | The URL object ID. | 
| CiscoFP.Rule.Urls.Objects.Name | String | The URL object name. | 
| CiscoFP.Rule.VlanTags.Numbers.EndTag | Number | The vlan tag number end tag. | 
| CiscoFP.Rule.VlanTags.Numbers.StartTag | Number | The vlan tag number start tag. | 
| CiscoFP.Rule.VlanTags.Objects.ID | String | The object ID. | 
| CiscoFP.Rule.VlanTags.Objects.Name | String | The object name. | 
| CiscoFP.Rule.VlanTags.Objects.Type | String | The object type. | 


##### Command Example
```!ciscofp-delete-access-rules policy_id="000C29A8-BA3B-0ed3-0000-133143986773"```

##### Human Readable Output


### 29. ciscofp-list-policy-assignments
---
Retrieves a list of all policy assignments to target devices.
##### Base Command

`ciscofp-list-policy-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50 | Optional | 
| offset | Index of first item to return.<br>The default is 0 | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.PolicyAssignments.ID | String | The policy assignments ID. | 
| CiscoFP.PolicyAssignments.Name | String | The policy assignments name. | 
| CiscoFP.PolicyAssignments.PolicyDescription | String | The policy description. | 
| CiscoFP.PolicyAssignments.PolicyID | String | The policy ID. | 
| CiscoFP.PolicyAssignments.PolicyName | String | The policy name. | 
| CiscoFP.PolicyAssignments.Targets.ID | String | The targets ID. | 
| CiscoFP.PolicyAssignments.Targets.Name | String | The targets name. | 
| CiscoFP.PolicyAssignments.Targets.Type | String | The targets type. | 


##### Command Example
``` ```

##### Human Readable Output


### 30. ciscofp-create-policy-assignments
---
Creates policy assignments to target devices.
##### Base Command

`ciscofp-create-policy-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Required | 
| device_ids | A list of device IDs. | Optional | 
| device_group_ids | A list of device group IDs. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.PolicyAssignments.ID | String | The policy assignments ID. | 
| CiscoFP.PolicyAssignments.Name | String | The policy assignments name. | 
| CiscoFP.PolicyAssignments.PolicyDescription | String | The policy description. | 
| CiscoFP.PolicyAssignments.PolicyID | String | The policy ID. | 
| CiscoFP.PolicyAssignments.PolicyName | String | The policy name. | 
| CiscoFP.PolicyAssignments.Targets.ID | String | The targets ID. | 
| CiscoFP.PolicyAssignments.Targets.Name | String | The targets name. | 
| CiscoFP.PolicyAssignments.Targets.Type | String | The targets type. | 


##### Command Example
```!ciscofp-create-policy-assignments policy_id="[\"000C29A8-BA3B-0ed3-0000-133143986773\"]" device_ids="43e032dc-07c5-11ea-b83d-d5fdc079bf65"```

##### Human Readable Output


### 31. ciscofp-update-policy-assignments
---
Updates the specified policy assignments to target devices.
##### Base Command

`ciscofp-update-policy-assignments`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The policy ID. | Optional | 
| device_ids | A list of device IDs. | Optional | 
| device_group_ids | A list of device group IDs. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.PolicyAssignments.ID | String | The policy assignments ID. | 
| CiscoFP.PolicyAssignments.Name | String | The policy assignments name. | 
| CiscoFP.PolicyAssignments.PolicyDescription | String | The policy description. | 
| CiscoFP.PolicyAssignments.PolicyID | String | The policy ID. | 
| CiscoFP.PolicyAssignments.PolicyName | String | The policy name. | 
| CiscoFP.PolicyAssignments.Targets.ID | String | The targets ID. | 
| CiscoFP.PolicyAssignments.Targets.Name | String | The targets name. | 
| CiscoFP.PolicyAssignments.Targets.Type | String | The targets type. | 


##### Command Example
```!ciscofp-update-policy-assignments policy_id="[\"000C29A8-BA3B-0ed3-0000-124554066053\"]" device_ids="43e032dc-07c5-11ea-b83d-d5fdc079bf65"```

##### Human Readable Output


### 32. ciscofp-get-deployable-devices
---
Retrieves a list of all devices with configuration changes that are ready to deploy.
##### Base Command

`ciscofp-get-deployable-devices`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.DeployableDevices.CanBeDeployed | String | Can be deployed. | 
| CiscoFP.DeployableDevices.UpToDate | String | Up to date. | 
| CiscoFP.DeployableDevices.DeviceID | String | Device ID. | 
| CiscoFP.DeployableDevices.DeviceName | String | Device name. | 
| CiscoFP.DeployableDevices.DeviceType | String | Device type. | 
| CiscoFP.DeployableDevices.Version | String | Device version. | 


##### Command Example
```!ciscofp-get-deployable-devices```

##### Human Readable Output


### 33. ciscofp-get-device-records
---
Retrieves list of all device records.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`ciscofp-get-device-records`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of items to return.<br>The default is 50. | Optional | 
| offset | Index of first item to return.<br>The default is 0. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.DeviceRecords.DeviceGroupID | String | The device group ID. | 
| CiscoFP.DeviceRecords.HostName | String | The device host. | 
| CiscoFP.DeviceRecords.ID | String | The device ID. | 
| CiscoFP.DeviceRecords.Name | String | The device name. | 
| CiscoFP.DeviceRecords.Type | String | The device type. | 


##### Command Example
``` ```

##### Human Readable Output


### 34. ciscofp-deploy-to-devices
---
Creates a request for deploying configuration changes to devices.

##### Base Command

`ciscofp-deploy-to-devices`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| force_deploy | Boolean indicating whether to force deployment. Can be "true" or "false". | Required | 
| ignore_warning | Boolean indicating whether to ignore warning. Can be "true" or "false". | Required | 
| device_ids | A list of device IDs. | Required | 
| version | The version to deploy. To get versions, use the ciscofp-get-deployable-devices command. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.Deploy.TaskID | String | The task ID. | 
| CiscoFP.Deploy.ForceDeploy | String | Whether to force deploy. | 
| CiscoFP.Deploy.IgnoreWarning | String | Whether to ignore warning. | 
| CiscoFP.Deploy.Version | String | The version of the policy. | 
| CiscoFP.Deploy.DeviceList | String | The list of devices. | 


##### Command Example
```!ciscofp-deploy-to-devices force_deploy=true ignore_warning=false version="1" device_ids="1"```

##### Human Readable Output


### 35. ciscofp-get-task-status
---
Retrieves information about a previously submitted pending job or task with the specified ID. Used for deploying.
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`ciscofp-get-task-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| task_id | The ID of the task for which to check the status. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoFP.TaskStatus.Status | String | task status | 


##### Command Example
```!ciscofp-get-task-status task_id="1"```

##### Human Readable Output


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* 'No valid access token'
* Cisco Firepower - Could not delete the object.'
* Cisco Firepower - Could not create new group, Missing value or ID.'
* Cisco Firepower - Could not update the group, Missing value or ID.'
