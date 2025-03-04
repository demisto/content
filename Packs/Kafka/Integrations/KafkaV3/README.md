Use the Kafka integration to manage messages and partitions and to fetch Kafka messages to create incidents in Cortex XSOAR.

This integration was integrated and tested with version 2.7.1 of Kafka.

This integration is fully compatible with the Kafka v2 integration.

## Configure Kafka v3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| CSV list of Kafka brokers to connect to, e.g., 172.16.20.207:9092,172.16.20.234:9093 |  | True |
| Consumer group ID | This group ID will be used when fetching incidents and preforming consumer commands. If not set the group id 'xsoar_group' will be used. | False |
| Use TLS for connection |  | False |
| Use SASL PLAIN for connection (using SSL) |  |  |
| Trust any certificate (not secure) |  | False |
| CA certificate of Kafka server (.cer) |  | False |
| Client certificate (.cer) |  | False |
| Client certificate key (.key) |  | False |
| Client certificate key password (if required) |  | False |
| SASL PLAIN Username |  | False |
| SASL PLAIN Password |  | False |
| Topic to fetch incidents from (Required for fetch incidents) |  | False |
| CSV list of partitions to fetch messages from |  | False |
| Offset to fetch messages from (Exclusive) | The initial offset to start fetching from, not including the value set \(e.g., if 3 is set, the first event that will be fetched will be from offset 4\). If you want to start from the earliest or latest, type in 'earliest' or 'latest'. | False |
| Maximum number of messages to fetch |  | False |
| Stop consuming upon timeout | When fetching a significant number of messages \(100\+\), it's advisable to halt message consumption upon timeout. This ensures that the fetch terminates if no messages are received after a specified duration, instead of requesting messages until reaching the maximum number of messages to fetch. | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| Maximum number of bytes per message | The maximum number of message bytes to retrieve in each attempted fetch request. Should be in multiples of 1024. If the fetching process takes a long time, consider increasing this value. Default is '1048576'. | False |
| Schema Registry URL |  | False |
| Schema Registry Username |  | False |
| Schema Registry Password |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### kafka-print-topics
***
Prints all topics and their partitions.


#### Base Command

`kafka-print-topics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_offsets | Whether to include the first and last offset for a topic, when printing a list of topics and partitions. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | String | Kafka topic name. | 
| Kafka.Topic.Partitions.ID | Number | Topic partition ID. | 
| Kafka.Topic.Partitions.EarliestOffset | Number | Topic partition earliest offset. | 
| Kafka.Topic.Partitions.LatestOffset | Number | Topic partition latest offset. | 


#### Command Example
```!kafka-print-topics```

#### Context Example
```
{
    "Kafka": {
        "Topic": [
            {
                "Name": "test-topic1", 
                "Partitions": [
                    {
                        "ID": 0
                    }
                ]
            }, 
            {
                "Name": "test-topic2", 
                "Partitions": [
                    {
                        "ID": 0
                    },
                    {
                        "ID": 1
                    }
                ]
            } 
        ]
    }
}
```

#### Human Readable Output
##### Kafka Topics
| **Name** | **Partitions** |
| --- | --- |
| test-topic1 | {'ID': 0} |
| test-topic2 | {'ID': 0, 'EarliestOffset': 0, 'OldestOffset': 3}, {'ID': 1, 'EarliestOffset': 0, 'OldestOffset': 4} | 

### kafka-publish-msg

***
Publishes a message to Kafka.

#### Base Command

`kafka-publish-msg`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to publish messages to. | Required | 
| value | Message value (string). | Required | 
| partitioning_key | Message partition (number). | Optional | 
| value_schema_type | Value schema type. If not set, no schema is used, and schema-related arguments are ignored. Possible values are: AVRO. | Optional | 
| value_schema_str | Value schema in string format. Used only if `schema_type` is provided and `schema_subject_name` is not. Mutually exclusive with `schema_subject_name`. | Optional | 
| value_schema_subject_name | Value schema subject name to retrieve the latest schema version from the registry. Used only if `schema_type` is provided and `schema_str` is not. Mutually exclusive with `schema_str`. | Optional | 

#### Context Output

There is no context output for this command.

#### Command Example

```!kafka-publish-msg topic=test-topic value="test message"```

#### Human Readable Output

Message was successfully produced to topic 'test-topic', partition 0

### kafka-consume-msg
***
Consumes a single Kafka message.


#### Base Command

`kafka-consume-msg`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to get messages from. | Required | 
| offset | Message offset to filter by. Acceptable values are 'Earliest', 'Latest', or any other offest number. Default is Earliest. | Optional | 
| partition | Partition (number). | Optional | 
| poll_timeout | Poll timeout to consume the message. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Name of the topic. | 
| Kafka.Topic.Message.Value | string | Value of the message. | 
| Kafka.Topic.Message.Offset | number | Offset of the value in the topic. | 


#### Command Example
```!kafka-consume-msg topic=test-topic offset=latest```

#### Context Example
```
{
    "Kafka": {
        "Topic": {
            "Message": {
                "Value": "test message", 
                "Offset": 11
            }, 
            "Name": "test-topic"
        }
    }
}
```

#### Human Readable Output
##### Message consumed from topic 'test'
| **Offset** | **Message** |
| --- | --- |
| 11 | test message |


### kafka-fetch-partitions
***
Fetches partitions for a topic.


#### Base Command

`kafka-fetch-partitions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to fetch partitions for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Name of topic. | 
| Kafka.Topic.Partition | number | Prints all partitions for a topic. | 


#### Command Example
```!kafka-fetch-partitions topic=test```

### Context Example
```
{
    "Kafka": {
        "Topic": {
            "Partition": [
                0,
                1,
                2
            ], 
            "Name": "test"
        }
    }
}
```

#### Human Readable Output
##### Available partitions for topic 'test'
| **Partitions** |
| --- |
| 0 |
| 1 |
| 2 |

## Configuration of SASL_SSL PLAIN:
1. Make sure you have the broker port which supports SSL connection.
2. Add 'broker_address:port' to the brokers list.
3. Provide the CA root certificate in the 'CA certificate of Kafka server (.cer)' section.
4. If your client certificate is password protected, provide the password in the 'Client certificate key password (if required)' section.
5. Provide SASL PLAIN Username and SASL PLAIN Password

Note: SASL is supported only when used in combination with SSL.

Important:
This integration also supports users with consumer only permissions.