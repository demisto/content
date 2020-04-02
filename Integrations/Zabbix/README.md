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
```!execute_command method=host.get```

##### Human Readable Output
{"jsonrpc": "2.0", "id": 1, "result": [{"jmx_available": "0", "tls_connect": "1", "maintenance_type": "0", "ipmi_errors_from": "0", "ipmi_username": "", "snmp_disable_until": "0", "ipmi_authtype": "-1", "ipmi_disable_until": "0", "lastaccess": "0", "snmp_error": "", "tls_psk": "", "ipmi_privilege": "2", "jmx_error": "", "status": "0", "maintenanceid": "0", "snmp_available": "0", "proxy_address": "", "tls_psk_identity": "", "available": "2", "description": "", "tls_accept": "1", "auto_compress": "1", "host": "Zabbix server", "disable_until": "1585850016", "ipmi_password": "", "templateid": "0", "tls_issuer": "", "ipmi_available": "0", "maintenance_status": "0", "snmp_errors_from": "0", "ipmi_error": "", "proxy_hostid": "0", "hostid": "10084", "name": "Zabbix server", "jmx_errors_from": "0", "jmx_disable_until": "0", "flags": "0", "error": "Get value from agent failed: cannot connect to [[127.0.0.1]:10050]: [111] Connection refused", "maintenance_from": "0", "tls_subject": "", "errors_from": "1585321618"}]}

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
```!test-module method=host.get
```

##### Human Readable Output
ok

## Additional Information
---

## Known Limitations
---

## Troubleshooting
---


## Possible Errors (DO NOT PUBLISH ON ZENDESK):
* "Unknown command " + command
* str(e
