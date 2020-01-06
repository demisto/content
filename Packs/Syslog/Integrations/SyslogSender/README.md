## Overview
---

Use the Syslog Sender integration to send messages and mirror incident war room entries to Syslog.


## Use Cases
---
* Send messages to syslog via TCP, UDP or Unix.
* Mirror incident war room entries to syslog.

## Configure Syslog Sender on Demisto
---
To allow sending messages to syslog via Demisto, the following lines have to be in the syslog configuration:

For TCP:
```
module(load="imtcp")
input(type="imtcp" port="<port>")
```

For UDP:
```
module(load="imudp")
input(type="imudp" port="<port>")
```

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Syslog Sender.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __IP Address (e.g. 127.0.0.1)__
    * __Port__
    * __Protocol (TCP / UDP)__
    * __Minimum severity of incidents to send messages on__
    * __Log level to send__
    * __Facility__
    * __Long running instance. Required for investigation mirroring.__
    * __Incident type__
4. Click __Test__ to validate the URLs, token, and connection.


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. mirror-investigation
2. send-notification
### 1. mirror-investigation
---
Mirrors the investigation's War Room to syslog.
##### Base Command

`mirror-investigation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mirror-investigation```

##### Human Readable Output
Investigation mirrored successfully.

### 2. send-notification
---
Sends a message to syslog.
##### Base Command

`send-notification`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message content. | Optional | 
| entry | An entry ID to send as a link. | Optional | 
| ignoreAddURL | Whether to include a URL to the relevant component in Demisto. | Optional | 
| level | Log level to send | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!send-notification message=Test ignoreAddURL=true```

##### Human Readable Output
Message sent to syslog successfully.


### 3. syslog-send
---
Send a message to syslog

##### Base Command

`syslog-send`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message content. | Optional | 
| level | The log level. | Optional | 
| address | The syslog server address. | Optional | 
| protocol | The protocol to use | Optional | 
| port | The syslog server port (required for TCP or UDP protocols). | Optional | 
| facility | The syslog facility. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!syslog-send address=127.0.0.1 port=514 protocol=TCP message=yo level=ERROR```

##### Human Readable Output
Message sent to Syslog successfully.

## Troubleshooting
---
Make sure you can access the syslog server on the provided IP address and the port is open.
If you're experiencing further issues, contact us at [support@demisto.com](mailto:support@demisto.com)
