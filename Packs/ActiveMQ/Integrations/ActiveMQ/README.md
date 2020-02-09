## Overview
---

Integration with ActiveMQ.
This integration uses ActiveMQ STOMP protocol, that must be enabled (usually port 61613 by default) in order to work.
Fetch incidents is based on using Durable Topic Subscribers, in order to fetch messages, and convert to Demisto incidents.


## Use Cases
---
- Send messages to queue or topic
- Read messages from queue or topic
- Fetch messages from queue or topic and create incidents in Demisto per message

## Configure ActiveMQ on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for ActiveMQ.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server IP (e.g. 192.168.0.1)__
    * __Port__
    * __Use system proxy settings__
    * __Client ID__
    * __Username__
    * __Client certificate (.pem)__
    * __Client certificate key (.key)__
    * __Root Certificate__
    * __Subscription ID__
    * __Fetch incidents__
    * __Incident type__
    * __Topic Name (for subscription)__
    * __Queue Name (for subscription)__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
Returns the messages in the queue or topic. Creates incidents in Demisto and populate the incident `details` field 
with the message content.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. activemq-send
2. activemq-subscribe
### 1. activemq-send
---
Send message

##### Base Command

`activemq-send`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination | The message destination (such as a message queue - for example ‘/queue/test’ - or a message topic) | Required | 
| body | The content of the message to be sent | Required | 
| headers | Set custom headers Format {XCorrelationId: uid, nosotros generamos XReplyTo demisto:es:connectors, XType com.elevenpaths.sandas.ra.connector.CreateTicketConnectorRequest, XVersion : "3.0", persitent : True} | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!activemq-send destination="/topic/demisto-test" body="send the message to topic"```

```!activemq-send destination="/queue/demisto-test" body="send the message to queue"```

##### Human Readable Output
Message sent to ActiveMQ destination: /topic/demisto-test with transaction ID: 69726a84-ee17-4db5-a6da-5171da9986d3

### 2. activemq-subscribe
---
Subscribe and read messages from topic or queue. Must provide queue-name or topic-name. Can't provide both.

##### Base Command

`activemq-subscribe`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription-id | The identifier to uniquely identify the subscription | Required | 
| topic-name | The topic to subscribe to | Optional | 
| queue-name | The queue to subscribe to | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!activemq-subscribe subscription-id=1 topic-name=demisto-test```

##### Human Readable Output
send to topic message

## Additional Information
---

## Known Limitations
---

## Troubleshooting
---

