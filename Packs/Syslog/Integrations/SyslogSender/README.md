## Overview

---

Use the Syslog Sender integration to send messages in RFC 5424 message format and mirror incident War Room entries to Syslog.

## Use Cases

---

* Send messages to Syslog via TCP or UDP or TLS.
* Mirror incident war room entries to Syslog.
* Track any activity from the Playground and War Room to your SIEM for improved visibility. This activity should be logged and attributed to the specific analyst.

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

### Usage example for sending War Room/Playground actions to Syslog

1. From the Incidents page, click an incident.
2. Run the ***!mirror-investigation type="all"*** command.
If you receive an *Investication mirrored to Syslog successfully* response, any action in the War Room will be sent to Syslog.

For example:
Run the command !Print value="test msg"

```
<14>1 2023-09-19T13:49:38.140870+00:00 a1427a8493b5 SysLogLogger 1 - - 29, 105@29, admin:   !Print value=" incident owner is ${incident.owner}"
<14>1 2023-09-19T13:49:38.162145+00:00 a4140f2eb707 SysLogLogger 1 - - 29, 106@29, DBot:    incident owner is admin
```

Syslog already contains the analyst name - admin (the user who performed the action).
The action is: !Print value="test msg"
The action result appears on the second line.

If you run the same command with a different user on the same Cortex XSOAR instance, the output will be:

```
<14>1 2023-09-19T13:56:02.152486+00:00 a1427a8493b5 SysLogLogger 1 - - 8069, 86@8069, jsmith:   !Print value=" incident owner is ${incident.owner}"
<14>1 2023-09-19T13:56:02.180858+00:00 a4140f2eb707 SysLogLogger 1 - - 8069, 87@8069, DBot:    incident owner is admin
```

Username (analyst) is present and located before each command.  In this case, jsmith.
The timestamp is present and loacated at the beginning of each string.
To determine the execution time (duration), calculate the difference between the second timestamp and the first.

### Integration configuration

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Syslog Sender.
3. Click **Add instance** to create and configure a new integration instance.
    * **Name**: a textual name for the integration instance.
    * **IP Address (e.g. 127.0.0.1)**
    * **Port**
    * **Protocol (TCP / UDP)**
    * **Minimum severity of incidents to send messages on**
    * **Log level to send**
    * **Facility**
    * **Long running instance. Required for investigation mirroring.**
    * **Incident type**
4. Click **Test** to validate the URLs, token, and connection.

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
