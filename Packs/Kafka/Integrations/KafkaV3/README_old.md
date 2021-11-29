Use the Kafka integration to manage messages and partitions.

This integration was integrated and tested with version 2.7 of Kafka.

This integration is fully compatible with the Kafka v2 integration.

Configure Kafka v3 on Cortex XSOAR
----------------------------------

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for Kafka v3.
3.  Click **Add instance** to create and configure a new integration instance.  
    *   **Name**: a meaningful name for the integration instance.
    *   **Use proxy**
    *   **CSV list of Kafka brokers to connect to**, e.g., `ip:port,ip2:port2`
    *   **Do not validate server certificate (insecure)**
    *   **CA certificate of Kafka server (.cer)**
    *   **Client certificate (.cer)**
    *   **Client certificate key (.key)**
    *   **Additional password (if required)**
    *   **Topic to fetch incidents from**
    *   **Offset to fetch incidents from**
    *   **Max number of messages to fetch**
    *   **Incident type**
    *   **Enable debug (will post Kafka connection logs to the War Room)**
4.  Click **Test** to validate the URLs, token, and connection.

Commands
--------

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1.  Print all partitions for a topic: kafka-print-topics
2.  Publish a message to Kafka: kafka-publish-msg
3.  Consume a single Kafka message: kafka-consume-msg
4.  Print all partitions for a topic: kafka-fetch-partitions

### 1\. Print all partitions for a topic

* * *

Prints all partitions of a topic.

##### Base Command

`kafka-print-topics`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_offsets | Whether to fetch topics available offsets or not, defaults to 'true' | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Topic name |
| Kafka.Topic.Partitions.ID | Number | Topic partition ID |
| Kafka.Topic.Partitions.EarliestOffset | Number | Topic partition earliest offset |
| Kafka.Topic.Partitions.LatestOffset | Number | Topic partition latest offset. |


##### Command Example

`!kafka-print-topics`

##### Context Example

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip2.png)

##### Human Readable Output

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip3.png)

### 2\. Publish a message to Kafka

* * *

Publishes a message to Kafka. 

##### Base Command

`kafka-publish-msg`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to filter by | Required |
| value | Message value (string) | Required |
| partition | Message partition (number) | Optional |

##### Context Output

There is no context output for this command.

##### Command Example

`!kafka-publish-msg topic=test value="test message"`

##### Human Readable Output

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip4.png)

### 3\. Consume a single Kafka message

* * *

Consumes a single Kafka message.

##### Base Command

`kafka-consume-msg`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to filter by | Required |
| offset | Message offset to filter by ("Earliest", "Latest", or any other offset number) | Optional |
| partition | Partition (number) | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Topic name |
| Kafka.Topic.Message.Value | string | Message value |
| Kafka.Topic.Message.Offset | number | Offset of the value in the topic |

##### Command Example

`!kafka-consume-msg topic=test offset=latest`

##### Context Example

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip5.png)

##### Human Readable Output

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip6.png)

### 4\. Print all partitions for a topic

* * *

Prints all partitions for a topic.

##### Base Command

`kafka-fetch-partitions`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to filter by | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Topic name | 
| Kafka.Topic.Partition | number | Number of partitions for the topic | 

##### Command Example

`!kafka-fetch-partitions topic=test`

##### Context Example

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip7.png)

##### Human Readable Output

![](https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/Kafka_V2_mceclip8.png)