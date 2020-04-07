## Overview
---

Allow integration with Zabbix api
This integration was integrated and tested with version xx of Zabbix
## Zabbix Playbook
---

## Use Cases
---

## Configure Zabbix on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Zabbix.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Url__
    * __Credentials__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. execute_command
2. test-module
3. hostgroup_get
4. host_get
5. trigger_get
6. event_get
### 1. execute_command
---
Execute command on Zabbix API
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`execute_command`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | Method to call on Zabbix API | Required | 
| params | JSON with params to send with call | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| result | Unknown | result | 


##### Command Example
```!execute_command method="host.get"
```

##### Context Example
```
{
    "Zabbix.execute_command": [
        {
            "jmx_available": "0", 
            "tls_connect": "1", 
            "maintenance_type": "0", 
            "ipmi_errors_from": "0", 
            "ipmi_username": "", 
            "snmp_disable_until": "0", 
            "ipmi_authtype": "-1", 
            "ipmi_disable_until": "0", 
            "lastaccess": "0", 
            "snmp_error": "", 
            "tls_psk": "", 
            "ipmi_privilege": "2", 
            "jmx_error": "", 
            "status": "0", 
            "maintenanceid": "0", 
            "snmp_available": "0", 
            "proxy_address": "", 
            "tls_psk_identity": "", 
            "available": "2", 
            "description": "", 
            "tls_accept": "1", 
            "auto_compress": "1", 
            "host": "Zabbix server", 
            "disable_until": "1586289490", 
            "ipmi_password": "", 
            "templateid": "0", 
            "tls_issuer": "", 
            "ipmi_available": "0", 
            "maintenance_status": "0", 
            "snmp_errors_from": "0", 
            "ipmi_error": "", 
            "proxy_hostid": "0", 
            "hostid": "10084", 
            "name": "Zabbix server", 
            "jmx_errors_from": "0", 
            "jmx_disable_until": "0", 
            "flags": "0", 
            "error": "Get value from agent failed: cannot connect to [[127.0.0.1]:10050]: [111] Connection refused", 
            "maintenance_from": "0", 
            "tls_subject": "", 
            "errors_from": "1585321618"
        }
    ]
}
```

##### Human Readable Output
### execute_command, {'method': 'host.get'}
|auto_compress|available|description|disable_until|error|errors_from|flags|host|hostid|ipmi_authtype|ipmi_available|ipmi_disable_until|ipmi_error|ipmi_errors_from|ipmi_password|ipmi_privilege|ipmi_username|jmx_available|jmx_disable_until|jmx_error|jmx_errors_from|lastaccess|maintenance_from|maintenance_status|maintenance_type|maintenanceid|name|proxy_address|proxy_hostid|snmp_available|snmp_disable_until|snmp_error|snmp_errors_from|status|templateid|tls_accept|tls_connect|tls_issuer|tls_psk|tls_psk_identity|tls_subject|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2 |  | 1586289490 | Get value from agent failed: cannot connect to [[127.0.0.1]:10050]: [111] Connection refused | 1585321618 | 0 | Zabbix server | 10084 | -1 | 0 | 0 |  | 0 |  | 2 |  | 0 | 0 |  | 0 | 0 | 0 | 0 | 0 | 0 | Zabbix server |  | 0 | 0 | 0 |  | 0 | 0 | 0 | 1 | 1 |  |  |  |  |


### 2. test-module
---
Test if module is working
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`test-module`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

There is no context output for this command.

##### Command Example
```!test-module method="host.get"
```

##### Human Readable Output
ok

### 3. hostgroup_get
---
Get host groups
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`hostgroup_get`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| params_graphids | Return only host groups that contain hosts or templates with the given graphs. | Optional | 
| params_groupids | Return only host groups with the given host group IDs. | Optional | 
| params_hostids | Return only host groups that contain the given hosts. | Optional | 
| params_maintenanceids | Return only host groups that are affected by the given maintenances. | Optional | 
| params_monitored_hosts | Return only host groups that contain monitored hosts. | Optional | 
| params_real_hosts | Return only host groups that contain hosts. | Optional | 
| params_templated_hosts | Return only host groups that contain templates. | Optional | 
| params_templateids | Return only host groups that contain the given templates. | Optional | 
| params_triggerids | Return only host groups that contain hosts or templates with the given triggers. | Optional | 
| params_with_applications | Return only host groups that contain hosts with applications. | Optional | 
| params_with_graphs | Return only host groups that contain hosts with graphs. | Optional | 
| params_with_hosts_and_templates | Return only host groups that contain hosts or templates. | Optional | 
| params_with_httptests | Return only host groups that contain hosts with web checks. | Optional | 
| params_with_items | Return only host groups that contain hosts or templates with items. | Optional | 
| params_with_monitored_httptests | Return only host groups that contain hosts with enabled web checks. | Optional | 
| params_with_monitored_items | Return only host groups that contain hosts or templates with enabled items. | Optional | 
| params_with_monitored_triggers | Return only host groups that contain hosts with enabled triggers. All of the items used in the trigger must also be enabled. | Optional | 
| params_with_simple_graph_items | Return only host groups that contain hosts with numeric items. | Optional | 
| params_with_triggers | Return only host groups that contain hosts with triggers. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zabbix.hostgroup_get.groupid | string | ID of the host group | 
| Zabbix.hostgroup_get.name | string | Name of the host group | 
| Zabbix.hostgroup_get.flags | number | Origin of the host group | 
| Zabbix.hostgroup_get.internal | number | Whether the group is used internally by the system. | 


##### Command Example
```!hostgroup_get params_real_hosts="True"
```

##### Context Example
```
{
    "Zabbix.hostgroup_get": [
        {
            "internal": "0", 
            "flags": "0", 
            "groupid": "4", 
            "name": "Zabbix servers"
        }
    ]
}
```

##### Human Readable Output
### hostgroup_get, {'params_real_hosts': 'True'}
|flags|groupid|internal|name|
|---|---|---|---|
| 0 | 4 | 0 | Zabbix servers |


### 4. host_get
---
Get hosts
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`host_get`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| params_groupids | Return only hosts that belong to the given groups. | Optional | 
| params_applicationids | Return only hosts that have the given applications. | Optional | 
| params_dserviceids | Return only hosts that are related to the given discovered services. | Optional | 
| params_graphids | Return only hosts that have the given graphs. | Optional | 
| params_hostids | Return only hosts with the given host IDs. | Optional | 
| params_httptestids | Return only hosts that have the given web checks. | Optional | 
| params_interfaceids | Return only hosts that use the given interfaces. | Optional | 
| params_itemids | Return only hosts that have the given items. | Optional | 
| params_maintenanceids | Return only hosts that are affected by the given maintenances. | Optional | 
| params_monitored_hosts | Return only monitored hosts. | Optional | 
| params_proxy_hosts | Return only proxies. | Optional | 
| params_proxyids | Return only hosts that are monitored by the given proxies. | Optional | 
| params_templated_hosts | Return both hosts and templates. | Optional | 
| params_templateids | Return only hosts that are linked to the given templates. | Optional | 
| params_triggerids | Return only hosts that have the given triggers. | Optional | 
| params_with_items | Return only hosts that have items. | Optional | 
| params_with_applications | Return only hosts that have applications. | Optional | 
| params_with_graphs | Return only hosts that have graphs. | Optional | 
| params_with_httptests | Return only hosts that have web checks. | Optional | 
| params_with_monitored_httptests | Return only hosts that have enabled web checks. | Optional | 
| params_with_monitored_items | Return only hosts that have enabled items. | Optional | 
| params_with_monitored_triggers | Return only hosts that have enabled triggers. All of the items used in the trigger must also be enabled. | Optional | 
| params_with_simple_graph_items | Return only hosts that have items with numeric type of information. | Optional | 
| params_with_triggers | Return only hosts that have triggers. | Optional | 
| params_withInventory | Return only hosts that have inventory data. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zabbix.host_get.hostid | string | ID of the host. | 
| Zabbix.host_get.host | string | Technical name of the host. | 
| Zabbix.host_get.available | number | Availability of Zabbix agent. | 
| Zabbix.host_get.description | string | Description of the host. | 
| Zabbix.host_get.disable_until | date | The next polling time of an unavailable Zabbix agent. | 
| Zabbix.host_get.error | string | Error text if Zabbix agent is unavailable. | 
| Zabbix.host_get.errors_from | date | Time when Zabbix agent became unavailable. | 
| Zabbix.host_get.flags | number | Origin of the host. | 
| Zabbix.host_get.inventory_mode | number | (writeonly) Host inventory population mode. | 
| Zabbix.host_get.ipmi_authtype | number | IPMI authentication algorithm. | 
| Zabbix.host_get.ipmi_available | number | Availability of IPMI agent. | 
| Zabbix.host_get.ipmi_disable_until | date | The next polling time of an unavailable IPMI agent. | 
| Zabbix.host_get.ipmi_error | string | Error text if IPMI agent is unavailable. | 
| Zabbix.host_get.ipmi_errors_from | date | Time when IPMI agent became unavailable. | 
| Zabbix.host_get.ipmi_password | string | IPMI password. | 
| Zabbix.host_get.ipmi_privilege | number | IPMI privilege level. | 
| Zabbix.host_get.ipmi_username | string | IPMI username. | 
| Zabbix.host_get.jmx_available | number | Availability of JMX agent. | 
| Zabbix.host_get.jmx_disable_until | date | The next polling time of an unavailable JMX agent. | 
| Zabbix.host_get.jmx_error | string | Error text if JMX agent is unavailable. | 
| Zabbix.host_get.jmx_errors_from | date | Time when JMX agent became unavailable. | 
| Zabbix.host_get.maintenance_from | date | Starting time of the effective maintenance. | 
| Zabbix.host_get.maintenance_status | number | Effective maintenance status. | 
| Zabbix.host_get.maintenance_type | number | Effective maintenance type. | 
| Zabbix.host_get.maintenanceid | string | ID of the maintenance that is currently in effect on the host. | 
| Zabbix.host_get.name | string | Visible name of the host. | 
| Zabbix.host_get.proxy_hostid | string | ID of the proxy that is used to monitor the host. | 
| Zabbix.host_get.snmp_available | number | Availability of SNMP agent. | 
| Zabbix.host_get.snmp_disable_until | date | The next polling time of an unavailable SNMP agent. | 
| Zabbix.host_get.snmp_error | string | Error text if SNMP agent is unavailable. | 
| Zabbix.host_get.snmp_errors_from | date | Time when SNMP agent became unavailable. | 
| Zabbix.host_get.status | number | Status and function of the host. | 
| Zabbix.host_get.tls_connect | number | Connections to host. | 
| Zabbix.host_get.tls_accept | number | Connections from host. | 
| Zabbix.host_get.tls_issuer | string | Certificate issuer. | 
| Zabbix.host_get.tls_subject | string | Certificate subject. | 
| Zabbix.host_get.tls_psk_identity | string | PSK identity. Required if either tls_connect or tls_accept has PSK enabled. | 
| Zabbix.host_get.tls_psk | string | The preshared key, at least 32 hex digits. Required if either tls_connect or tls_accept has PSK enabled. | 


##### Command Example
```!host_get params_groupids="4"
```

##### Context Example
```
{
    "Zabbix.host_get": [
        {
            "jmx_available": "0", 
            "tls_connect": "1", 
            "maintenance_type": "0", 
            "ipmi_errors_from": "0", 
            "ipmi_username": "", 
            "snmp_disable_until": "0", 
            "ipmi_authtype": "-1", 
            "ipmi_disable_until": "0", 
            "lastaccess": "0", 
            "snmp_error": "", 
            "tls_psk": "", 
            "ipmi_privilege": "2", 
            "jmx_error": "", 
            "status": "0", 
            "maintenanceid": "0", 
            "snmp_available": "0", 
            "proxy_address": "", 
            "tls_psk_identity": "", 
            "available": "2", 
            "description": "", 
            "tls_accept": "1", 
            "auto_compress": "1", 
            "host": "Zabbix server", 
            "disable_until": "1586289490", 
            "ipmi_password": "", 
            "templateid": "0", 
            "tls_issuer": "", 
            "ipmi_available": "0", 
            "maintenance_status": "0", 
            "snmp_errors_from": "0", 
            "ipmi_error": "", 
            "proxy_hostid": "0", 
            "hostid": "10084", 
            "name": "Zabbix server", 
            "jmx_errors_from": "0", 
            "jmx_disable_until": "0", 
            "flags": "0", 
            "error": "Get value from agent failed: cannot connect to [[127.0.0.1]:10050]: [111] Connection refused", 
            "maintenance_from": "0", 
            "tls_subject": "", 
            "errors_from": "1585321618"
        }
    ]
}
```

##### Human Readable Output
### host_get, {'params_groupids': '4'}
|auto_compress|available|description|disable_until|error|errors_from|flags|host|hostid|ipmi_authtype|ipmi_available|ipmi_disable_until|ipmi_error|ipmi_errors_from|ipmi_password|ipmi_privilege|ipmi_username|jmx_available|jmx_disable_until|jmx_error|jmx_errors_from|lastaccess|maintenance_from|maintenance_status|maintenance_type|maintenanceid|name|proxy_address|proxy_hostid|snmp_available|snmp_disable_until|snmp_error|snmp_errors_from|status|templateid|tls_accept|tls_connect|tls_issuer|tls_psk|tls_psk_identity|tls_subject|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2 |  | 1586289490 | Get value from agent failed: cannot connect to [[127.0.0.1]:10050]: [111] Connection refused | 1585321618 | 0 | Zabbix server | 10084 | -1 | 0 | 0 |  | 0 |  | 2 |  | 0 | 0 |  | 0 | 0 | 0 | 0 | 0 | 0 | Zabbix server |  | 0 | 0 | 0 |  | 0 | 0 | 0 | 1 | 1 |  |  |  |  |


### 5. trigger_get
---
Get triggers
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`trigger_get`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| params_triggerids | Return only triggers with the given IDs. | Optional | 
| params_groupids | Return only triggers that belong to hosts from the given host groups. | Optional | 
| params_templateids | Return only triggers that belong to the given templates. | Optional | 
| params_hostids | Return only triggers that belong to the given hosts. | Optional | 
| params_itemids | Return only triggers that contain the given items. | Optional | 
| params_applicationids | Return only triggers that contain items from the given applications. | Optional | 
| params_functions | Return only triggers that use the given functions. | Optional | 
| params_group | Return only triggers that belong to hosts from the host group with the given name. | Optional | 
| params_host | Return only triggers that belong to host with the given name. | Optional | 
| params_inherited | If set to true return only triggers inherited from a template. | Optional | 
| params_templated | If set to true return only triggers that belong to templates. | Optional | 
| params_monitored | Return only enabled triggers that belong to monitored hosts and contain only enabled items. | Optional | 
| params_active | Return only enabled triggers that belong to monitored hosts. | Optional | 
| params_maintenance | If set to true return only enabled triggers that belong to hosts in maintenance. | Optional | 
| params_withUnacknowledgedEvents | Return only triggers that have unacknowledged events. | Optional | 
| params_withAcknowledgedEvents | Return only triggers with all events acknowledged. | Optional | 
| params_withLastEventUnacknowledged | Return only triggers with the last event unacknowledged. | Optional | 
| params_skipDependent | Skip triggers in a problem state that are dependent on other triggers. Note that the other triggers are ignored if disabled, have disabled items or disabled item hosts. | Optional | 
| params_lastChangeSince | Return only triggers that have changed their state after the given time. | Optional | 
| params_lastChangeTill | Return only triggers that have changed their state before the given time. | Optional | 
| params_only_true | Return only triggers that have recently been in a problem state. | Optional | 
| params_min_severity | Return only triggers with severity greater or equal than the given severity. | Optional | 
| params_evaltype | Rules for tag searching. | Optional | 
| params_tags | Return only triggers with given tags. Exact match by tag and case-sensitive or case-insensitive search by tag value depending on operator value. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zabbix.triggers_get.triggerid | string | ID of the trigger. | 
| Zabbix.triggers_get.description | string | Name of the trigger. | 
| Zabbix.triggers_get.expression | string | Reduced trigger expression. | 
| Zabbix.triggers_get.comments | string | Additional description of the trigger. | 
| Zabbix.triggers_get.error | string | Error text if there have been any problems when updating the state of the trigger. | 
| Zabbix.triggers_get.flags | number | Origin of the trigger. | 
| Zabbix.triggers_get.lastchange | date | Time when the trigger last changed its state. | 
| Zabbix.triggers_get.priority | number | Severity of the trigger. | 
| Zabbix.triggers_get.state | number | State of the trigger. | 
| Zabbix.triggers_get.status | number | Whether the trigger is enabled or disabled. | 
| Zabbix.triggers_get.templateid | string | ID of the parent template trigger. | 
| Zabbix.triggers_get.type | number | Whether the trigger can generate multiple problem events. | 
| Zabbix.triggers_get.url | string | URL associated with the trigger. | 
| Zabbix.triggers_get.value | number | Whether the trigger is in OK or problem state. | 
| Zabbix.triggers_get.recovery_mode | number | OK event generation mode. | 
| Zabbix.triggers_get.recovery_expression | string | Reduced trigger recovery expression. | 
| Zabbix.triggers_get.correlation_mode | number | OK event closes. | 
| Zabbix.triggers_get.correlation_tag | string | Tag for matching. | 
| Zabbix.triggers_get.manual_close | number | Allow manual close. | 


##### Command Example
```!trigger_get params_only_true="True"
```

##### Context Example
```
{
    "Zabbix.trigger_get": [
        {
            "status": "0", 
            "value": "1", 
            "recovery_mode": "0", 
            "description": "Zabbix agent on {HOST.NAME} is unreachable for 5 minutes", 
            "state": "0", 
            "url": "", 
            "type": "0", 
            "templateid": "10047", 
            "lastchange": "1585321941", 
            "comments": "", 
            "priority": "3", 
            "correlation_tag": "", 
            "flags": "0", 
            "triggerid": "13491", 
            "error": "", 
            "correlation_mode": "0", 
            "expression": "{12900}=1", 
            "recovery_expression": "", 
            "manual_close": "0"
        }
    ]
}
```

##### Human Readable Output
### trigger_get, {'params_only_true': 'True'}
|comments|correlation_mode|correlation_tag|description|error|expression|flags|lastchange|manual_close|priority|recovery_expression|recovery_mode|state|status|templateid|triggerid|type|url|value|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|  | 0 |  | Zabbix agent on {HOST.NAME} is unreachable for 5 minutes |  | {12900}=1 | 0 | 1585321941 | 0 | 3 |  | 0 | 0 | 0 | 10047 | 13491 | 0 |  | 1 |


### 6. event_get
---
Get events
##### Required Permissions
**FILL IN REQUIRED PERMISSIONS HERE**
##### Base Command

`event_get`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| params_eventids | Return only events with the given IDs. | Optional | 
| params_groupids | Return only events created by objects that belong to the given host groups. | Optional | 
| params_hostids | Return only events created by objects that belong to the given hosts. | Optional | 
| params_objectids | Return only events created by the given objects. | Optional | 
| params_applicationids | Return only events created by objects that belong to the given applications. Applies only if object is trigger or item. | Optional | 
| params_source | Return only events with the given type. | Optional | 
| params_object | Return only events created by objects of the given type. | Optional | 
| params_acknowledged | If set to true return only acknowledged events. | Optional | 
| params_suppressed | true - return only suppressed events; | Optional | 
| params_severities | Return only events with given event severities. Applies only if object is trigger. | Optional | 
| params_evaltype | Rules for tag searching. | Optional | 
| params_tags | Return only events with given tags. Exact match by tag and case-insensitive search by value and operator. | Optional | 
| params_eventid_from | Return only events with IDs greater or equal to the given ID. | Optional | 
| params_eventid_till | Return only events with IDs less or equal to the given ID. | Optional | 
| params_time_from | Return only events that have been created after or at the given time. | Optional | 
| params_time_till | Return only events that have been created before or at the given time. | Optional | 
| params_problem_time_from | Returns only events that were in the problem state starting with problem_time_from. Applies only if the source is trigger event and object is trigger. Mandatory if problem_time_till is specified. | Optional | 
| params_problem_time_till | Returns only events that were in the problem state until problem_time_till. Applies only if the source is trigger event and object is trigger. Mandatory if problem_time_from is specified. | Optional | 
| params_value | Return only events with the given values. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zabbix.event_get.eventid | string | ID of the event. | 
| Zabbix.event_get.source | number | Type of the event. | 
| Zabbix.event_get.object | number | Type of object that is related to the event. | 
| Zabbix.event_get.objectid | string | ID of the related object. | 
| Zabbix.event_get.acknowledged | number | Whether the event has been acknowledged. | 
| Zabbix.event_get.clock | date | Time when the event was created. | 
| Zabbix.event_get.ns | number | Nanoseconds when the event was created. | 
| Zabbix.event_get.name | string | Resolved event name. | 
| Zabbix.event_get.value | number | State of the related object. | 
| Zabbix.event_get.severity | number | Event current severity. | 
| Zabbix.event_get.r_eventid | string | Recovery event ID | 
| Zabbix.event_get.c_eventid | string | ID of the event that was used to override (close) current event under global correlation rule. See correlationid to identify exact correlation rule. | 
| Zabbix.event_get.correlationid | string | ID of the correlation rule that generated closing of the problem. | 
| Zabbix.event_get.userid | string | User ID if the event was manually closed. | 
| Zabbix.event_get.suppressed | number | Whether the event is suppressed. | 


##### Command Example
```!event_get params_time_from="1583020800"```

##### Context Example
```
{
    "Zabbix.event_get": [
        {
            "eventid": "12", 
            "name": "Zabbix agent on Zabbix server is unreachable for 5 minutes", 
            "objectid": "13491", 
            "clock": "1585321941", 
            "c_eventid": "0", 
            "userid": "0", 
            "object": "0", 
            "acknowledged": "0", 
            "value": "1", 
            "source": "0", 
            "ns": "248457478", 
            "suppressed": "0", 
            "r_eventid": "0", 
            "correlationid": "0", 
            "severity": "3"
        }, 
        {
            "eventid": "13", 
            "name": "Zabbix task manager processes more than 75% busy", 
            "objectid": "13560", 
            "clock": "1585589604", 
            "c_eventid": "0", 
            "userid": "0", 
            "object": "0", 
            "acknowledged": "0", 
            "value": "1", 
            "source": "0", 
            "ns": "554931714", 
            "suppressed": "0", 
            "r_eventid": "15", 
            "correlationid": "0", 
            "severity": "3"
        }, 
        {
            "eventid": "15", 
            "name": "Zabbix task manager processes more than 75% busy", 
            "objectid": "13560", 
            "clock": "1585589664", 
            "c_eventid": "0", 
            "userid": "0", 
            "object": "0", 
            "acknowledged": "0", 
            "value": "0", 
            "source": "0", 
            "ns": "596351852", 
            "suppressed": "0", 
            "r_eventid": "0", 
            "correlationid": "0", 
            "severity": "0"
        }
    ]
}
```

##### Human Readable Output
### event_get, {'params_time_from': '1583020800'}
|acknowledged|c_eventid|clock|correlationid|eventid|name|ns|object|objectid|r_eventid|severity|source|suppressed|userid|value|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 0 | 1585321941 | 0 | 12 | Zabbix agent on Zabbix server is unreachable for 5 minutes | 248457478 | 0 | 13491 | 0 | 3 | 0 | 0 | 0 | 1 |
| 0 | 0 | 1585589604 | 0 | 13 | Zabbix task manager processes more than 75% busy | 554931714 | 0 | 13560 | 15 | 3 | 0 | 0 | 0 | 1 |
| 0 | 0 | 1585589664 | 0 | 15 | Zabbix task manager processes more than 75% busy | 596351852 | 0 | 13560 | 0 | 0 | 0 | 0 | 0 | 0 |


## Additional Information
Using execute_command you can do anything available on Zabbix API.

You can use the oficcial API documentation on https://www.zabbix.com/documentation/current/manual/api

## Known Limitations
No current known limitations

## Troubleshooting
Verify if the user has the necessary permissions to execute the operation


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* "Unknown command " + command
* str(e
