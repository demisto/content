import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests


import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client:
    """Client class to interact with various Kafka clients."""

    def __init__(self):
        pass


''' HELPER FUNCTIONS '''


def check_params(topic, old_offset=None, old_partition=None):
    """
    :param topic: topic to check
    :type topic: :class: `pykafka.topic.Topic`
    :param offset: offset to check if is in the topic (and cast it to in if needed)
    :type offset: int, str, unicode or None
    :param partition: partition to check if is in the topic (and cast to int if needed)
    :type partition: int or str or unicode or None
    :returns: new_offset, new_partition
    :rtype: int, int
    """
    partition = None
    offset = None
    # Casting
    if old_partition:
        # Casting
        if isinstance(old_partition, (unicode, str)):
            if old_partition.isdigit():
                partition = int(old_partition)
            else:
                return_error('Supplied partition is not a number')
        if isinstance(old_partition, int):
            partition = old_partition
    if old_offset:
        # Casting
        if isinstance(old_offset, (unicode, str)):
            if old_offset.isdigit():
                offset = int(old_offset)
                offset = OffsetType.EARLIEST if offset == 0 else offset - 1
            elif old_offset.lower() == 'earliest':
                offset = OffsetType.EARLIEST
            elif old_offset.lower() == 'latest':
                offset = check_latest_offset(topic, partition_number=partition) - 1
            else:
                return_error('Supplied offset is not a number')
            if check_latest_offset(topic, partition_number=partition) <= offset:
                return_error('Offset is out of bounds')
        else:
            return_error('Offset is not a number, earliest or latest')
    return offset, partition


def create_incident(message, topic):
    """
    Creates incident
    :param message: Kafka message to create incident from
    :type message: :class:`pykafka.common.Message`
    :param topic: Message's topic
    :type topic: str
    :return incident:
    """
    raw = {
        'Topic': topic,
        'Partition': message.partition_id,
        'Offset': message.offset,
        'Message': message.value
    }
    incident = {
        'name': 'Kafka {} partition:{} offset:{}'.format(topic, message.partition_id, message.offset),
        'details': message.value,
        'rawJSON': json.dumps(raw)
    }
    if message.timestamp_dt:
        incident['occurred'] = message.timestamp_dt
    return incident


def check_latest_offset(topic, partition_number=None):
    """
    :param topic: topic to check the latest offset
    :type topic: :class:`pykafka.topic.Topic`
    :param partition_number: partition to take latest offset from
    :type partition_number: int, str
    :return latest_offset: last message offset
    :rtype: int
    """
    partitions = topic.latest_available_offsets()
    latest_offset = 0
    if partition_number is not None:
        partition = partitions.get(str(partition_number))
        if partitions:
            latest_offset = partition[0][0]
        else:
            return_error('Partition does not exist')
    else:
        for partition in partitions.values():
            if latest_offset < partition[0][0]:
                latest_offset = partition[0][0]
    return latest_offset - 1


def create_certificate(ca_cert=None, client_cert=None, client_cert_key=None, password=None):
    """
    Creating certificate
    :return certificate:
    :return type: :class: `pykafka.connection.SslConfig`
    """
    ca_path = None
    client_path = None
    client_key_path = None
    if ca_cert:
        ca_path = 'ca.cert'  # type: ignore
        with open(ca_path, 'wb') as file:
            file.write(ca_cert)
            ca_path = os.path.abspath(ca_path)
    if client_cert:
        client_path = 'client.cert'
        with open(client_path, 'wb') as file:
            file.write(client_cert)
            client_path = os.path.abspath(client_path)
    if client_cert_key:
        client_key_path = 'client_key.key'
        with open(client_key_path, 'wb') as file:
            file.write(client_cert_key)
    return SslConfig(
        cafile=ca_path,
        certfile=client_path,
        keyfile=client_key_path,
        password=password
    )


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    """Test getting available topics using AdminClient
    """
    if client.get_topics() is not None:
        demisto.results('ok')


def print_topics(client):
    """
    Prints available topics in Broker
    """
    include_offsets = demisto.args().get('include_offsets', 'true') == 'true'
    kafka_topics = client.get_topics().values()
    if kafka_topics:
        topics = []
        for topic in kafka_topics:
            partitions = []
            for partition in topic.partitions.values():
                partition_output = {'ID': partition.id}
                if include_offsets:
                    partition_output['EarliestOffset'], partition_output['OldestOffset'] = client.get_watermark_offsets(
                        partition=partition)
                partitions.append(partition_output)

            topics.append({
                'Name': topic.topic,
                'Partitions': partitions
            })

        ec = {
            'Kafka.Topic(val.Name === obj.Name)': topics
        }

        md = tableToMarkdown('Kafka Topics', topics)

        demisto.results({
            'Type': entryTypes['note'],
            'Contents': topics,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })
    else:
        demisto.results('No topics found.')


def produce_message(client):
    """
    Producing message to kafka topic
    """
    topic = demisto.args().get('topic')
    value = demisto.args().get('value')
    partitioning_key = demisto.args().get('partitioning_key')

    partitioning_key = str(partitioning_key)
    if partitioning_key.isdigit():
        partitioning_key = int(partitioning_key)  # type: ignore
    else:
        partitioning_key = None  # type: ignore

    if topic in client.topics:
        kafka_topic = client.topics[topic]
        with kafka_topic.get_sync_producer() as producer:
            producer.produce(
                message=str(value),
                partition_key=partitioning_key
            )
        demisto.results(f'Message was successfully produced to topic \'{topic}\'')
    else:
        return_error(f'Topic {topic} was not found in Kafka')


def consume_message(client):
    """
    Consuming one message from topic
    """
    topic = demisto.args().get('topic')
    offset = demisto.args().get('offset')
    partition = demisto.args().get('partition')

    if topic in client.topics:
        kafka_topic = client.topics[topic]
        offset, partition = check_params(kafka_topic, old_offset=offset, old_partition=partition)
        consumer = kafka_topic.get_simple_consumer(
            auto_offset_reset=offset,
            reset_offset_on_start=True
        )
        message = consumer.consume()
        md = tableToMarkdown(
            name='Message consumed from topic \'{}\''.format(topic),
            t={
                'Offset': message.offset,
                'Message': message.value
            },
            headers=[
                'Offset',
                'Message'
            ]
        )
        ec = {
            'Kafka.Topic(val.Name === obj.Name)': {
                'Name': topic,
                'Message': {
                    'Value': message.value,
                    'Offset': message.offset
                }
            }
        }
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': {
                'Message': message.value,
                'Offset': message.offset
            },
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })
    else:
        return_error('Topic {} was not found in Kafka'.format(topic))


def fetch_partitions(client):
    """
    Fetching available partitions in given topic
    """
    topic = demisto.args().get('topic')
    if topic in client.topics:
        kafka_topic = client.topics[topic]
        partitions = kafka_topic.partitions.keys()

        md = tableToMarkdown(
            name='Available partitions for topic \'{}\''.format(topic),
            t=partitions,
            headers='Partitions'
        )
        ec = {
            'Kafka.Topic(val.Name === obj.Name)': {
                'Name': topic,
                'Partition': partitions
            }
        }
        contents = {
            topic: partitions
        }
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': contents,
            'ContentsFormat': formats['json'],
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': ec
        })
    else:
        return_error('Topic {} was not found in Kafka'.format(topic))


def fetch_incidents(client):
    """
    Fetches incidents
    """
    topic = demisto.params().get('topic', '')
    partition_to_fetch_from = argToList(demisto.params().get('partition', ''))
    offset_to_fetch_from = demisto.params().get('offset', -2)
    message_max_bytes = int(demisto.params().get("max_bytes_per_message", 1048576))

    try:
        offset_to_fetch_from = int(offset_to_fetch_from)
    except ValueError as e:
        demisto.error('Received invalid offset: {}. Using default of -2. Err: {}'.format(offset_to_fetch_from, e))
        offset_to_fetch_from = -2
    max_messages = demisto.params().get('max_messages', 50)
    try:
        max_messages = int(max_messages)
    except ValueError:
        max_messages = 50

    last_fetched_partitions_offset = json.loads(demisto.getLastRun().get('last_fetched_partitions_offset', '{}'))
    incidents = []

    message_counter = 0

    if topic in client.topics:
        kafka_topic = client.topics[topic]

        consumer_args = {
            'consumer_timeout_ms': 2000,  # wait max 2 seconds for new messages
            'reset_offset_on_start': True,
            'auto_offset_reset': offset_to_fetch_from,
            'fetch_message_max_bytes': message_max_bytes
        }

        if partition_to_fetch_from:
            partitions = []
            for partition in kafka_topic.partitions.values():
                partition_id = str(partition.id)
                if partition_id in partition_to_fetch_from:
                    partitions.append(partition)
            consumer_args['partitions'] = partitions  # type: ignore

        consumer = kafka_topic.get_simple_consumer(**consumer_args)

        offsets = [(p, last_fetched_partitions_offset.get(str(p.id), offset_to_fetch_from)) for p in consumer._partitions]
        consumer.reset_offsets(offsets)

        for message in consumer:
            if message and message.value:
                incidents.append(create_incident(message=message, topic=kafka_topic.name))
                if message.offset > last_fetched_partitions_offset.get(str(message.partition_id), offset_to_fetch_from):
                    last_fetched_partitions_offset[str(message.partition_id)] = message.offset
                message_counter += 1
            if message_counter == max_messages:
                break
        consumer.stop()
    else:
        return_error('No such topic \'{}\' to fetch incidents from.'.format(topic))

    demisto.setLastRun({'last_fetched_partitions_offset': json.dumps(last_fetched_partitions_offset)})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    command = demisto.command()
    demisto_params = demisto.params()
    demisto.debug(f'Command being called is {command}')
    brokers = demisto_params.get('brokers')

    # Should we use SSL
    use_ssl = demisto_params.get('use_ssl', False)

    # Certificates
    ca_cert = demisto_params.get('ca_cert', None)
    client_cert = demisto_params.get('client_cert', None)
    client_cert_key = demisto_params.get('client_cert_key', None)
    password = demisto_params.get('additional_password', None)
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module(client)
        elif demisto.command() == 'kafka-print-topics':
            print_topics(client)
        elif demisto.command() == 'kafka-publish-msg':
            produce_message(client)
        elif demisto.command() == 'kafka-consume-msg':
            consume_message(client)
        elif demisto.command() == 'kafka-fetch-partitions':
            fetch_partitions(client)
        elif demisto.command() == 'fetch-incidents':
            fetch_incidents(client)

    except Exception as e:
        debug_log = 'Debug logs:\n\n{0}'.format(log_stream.getvalue() if log_stream else '')
        error_message = str(e)
        if demisto.command() != 'test-module':
            stacktrace = traceback.format_exc()
            if stacktrace:
                debug_log += f'\nFull stacktrace:\n\n{stacktrace}'
        return_error(f'{error_message}\n\n{debug_log}')

    finally:
        if os.path.isfile('ca.cert'):
            os.remove(os.path.abspath('ca.cert'))
        if os.path.isfile('client.cert'):
            os.remove(os.path.abspath('client.cert'))
        if os.path.isfile('client_key.key'):
            os.remove(os.path.abspath('client_key.key'))


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
