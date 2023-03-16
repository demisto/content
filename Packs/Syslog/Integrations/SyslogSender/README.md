## Overview
---

Use the Syslog Sender integration to send messages in RFC 5424 message format and mirror incident War Room entries to Syslog.


## Use Cases
---
* Send messages to Syslog via TCP or UDP or TLS.
* Mirror incident war room entries to Syslog.

## Configure Syslog Sender on Cortex XSOAR
---

### Usage example for rsyslog
To allow sending messages to rsyslog via Cortex XSOAR, the following lines have to be in the rsyslog configuration:

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

### Integration configuration

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
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| ignoreAddURL | Whether to include a URL to the relevant component in Cortex XSOAR. Can be "true" or "false". The default value is "false'. | Optional | 
| level | Log level to send. Can be "DEBUG", "INFO", "WARNING", "ERROR", or "CRITICAL". | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!send-notification message=Test ignoreAddURL=true```

##### Human Readable Output
Message sent to Syslog successfully.


### 3. syslog-send
---
Send a message to Syslog

##### Base Command

`syslog-send`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message content. | Optional | 
| level | The log level to send. Can be "DEBUG", "INFO", "WARNING", "ERROR", or "CRITICAL". | Optional | 
| address | The Syslog server address. | Optional | 
| protocol | The protocol to use | Optional | 
| port | The Syslog server port (required for TCP or UDP protocols). | Optional | 
| facility | The Syslog facility. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!syslog-send address=127.0.0.1 port=514 protocol=TCP message=yo level=ERROR```

##### Human Readable Output
Message sent to Syslog successfully.

## Troubleshooting
---
Make sure you can access the Syslog server on the provided IP address and the port is open.

## Demo Video
---
<video controls>
    <source src="https://github.com/demisto/content-assets/raw/7982404664dc68c2035b7c701d093ec026628802/Assets/Syslog/syslog-sender-demo.mp4"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/blob/7982404664dc68c2035b7c701d093ec026628802/Assets/Syslog/syslog-sender-demo.mp4 
</video>