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

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ActiveMQ.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Server IP Address (e.g., 192.168.0.1) | True |
| port | Port | False |
| proxy | Use system proxy settings | False |
| client-id | Client ID | False |
| credentials | Username | False |
| client_cert | Client certificate (.pem) | False |
| client_key | Client certificate key (.key) | False |
| root_ca | Root Certificate | False |
| subscription-id | Subscription ID | False |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| topic-name | Topic Name (for subscription) | False |
| queue_name | Queue Name (for subscription) | False |

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
Sends a message to the specified destination.
##### Base Command

`activemq-send`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination |  The message destination. For example, a message queue in the format: "/queue/test", or a message topic.  | Required | 
| body | The content of the message to send. | Required | 
| headers | The customer headers for the message, in the format: {XCorrelationId: uid, nosotros generamos XReplyTo demisto:es:connectors, XType com.elevenpaths.sandas.ra.connector.CreateTicketConnectorRequest, XVersion : "3.0", persistent : True} | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!activemq-send destination="/topic/demisto-test" body="send the message to topic"```

```!activemq-send destination="/queue/demisto-test" body="send the message to queue"```

##### Human Readable Output
Message sent to ActiveMQ destination: /topic/demisto-test with transaction ID: 69726a84-ee17-4db5-a6da-5171da9986d3

### activemq-subscribe
***
Subscribes to and reads messages from a topic or queue. Must provide either queue-name or topic-name. You can't provide both.
##### Base Command

`activemq-subscribe`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription-id | The subscription unique identifier. | Required | 
| topic-name | The topic to subscribe to. | Optional | 
| queue-name | The queue to subscribe to. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!activemq-subscribe subscription-id=1 topic-name=demisto-test```

##### Human Readable Output
send to topic message


