The Open source distributed streaming platform
This integration was integrated and tested with version xx of KafkaV3

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-kafka-v3).

## Configure Kafka v3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Kafka v3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | CSV list of Kafka brokers to connect to, e.g. 172.16.20.207:9092,172.16.20.234:9093 |  | True |
    | Use TLS for connection |  | False |
    | Trust any certificate (not secure) |  | False |
    | CA certificate of Kafka server (.cer) |  | False |
    | Client certificate (.cer) |  | False |
    | Client certificate key (.key) |  | False |
    | Client certificate key password (if required) |  | False |
    | Password |  | False |
    | Topic to fetch incidents from (Required for fetch incidents) |  | False |
    | CSV list of partitions to fetch messages from |  | False |
    | Offset to fetch messages from (Exclusive) | The initial offset to start fetching from, not including the value set \(e.g. if 3 is set, the first event that will be fetched will be with offset 4\). If you want to start from the earliest or latest, type in 'earliest' or 'latest' accordingly. | False |
    | Max number of messages to fetch |  | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Max number of bytes per message | The max number of message bytes to retrieve in each attempted fetch request. Should be in multiples of 1024. If the fetching process is taking a long time, you should consider increasing this value. Default is '1048576'. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### kafka-print-topics
***
Prints all partitions of a topic.


#### Base Command

`kafka-print-topics`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_offsets | Whether to fetch topics available offsets or not. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | String | Kafka topic name | 
| Kafka.Topic.Partitions.ID | Number | Topic partition ID | 
| Kafka.Topic.Partitions.EarliestOffset | Number | Topic partition earliest offset | 
| Kafka.Topic.Partitions.LatestOffset | Number | Topic partition latest offset | 


#### Command Example
``` ```

#### Human Readable Output



### kafka-publish-msg
***
Publishes a message to Kafka.


#### Base Command

`kafka-publish-msg`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to filter messages by. | Required | 
| value | Message value (string). | Required | 
| partitioning_key | Message partition (number). | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### kafka-consume-msg
***
Consumes a single Kafka message.


#### Base Command

`kafka-consume-msg`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to filter by. | Required | 
| offset | Message offset to filter by. Acceptable values are 'Earliest', 'Latest', or any other offest number. Default is Earliest. | Optional | 
| partition | Partition (number). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Name of the topic. | 
| Kafka.Topic.Message.Value | string | Value of the message. | 
| Kafka.Topic.Message.Offset | number | Offset of the value in the topic. | 


#### Command Example
``` ```

#### Human Readable Output



### kafka-fetch-partitions
***
Fetch partitions for a topic.


#### Base Command

`kafka-fetch-partitions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| topic | A topic to filter by. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kafka.Topic.Name | string | Name of topic. | 
| Kafka.Topic.Partition | number | Prints all partitions for a topic. | 


#### Command Example
``` ```

#### Human Readable Output



## Breaking changes from the previous version of this integration - Kafka v3
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
