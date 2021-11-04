import demistomock as demisto
from CommonServerPython import *
from confluent_kafka.admin import AdminClient
from confluent_kafka import Consumer, TopicPartition, Producer, KafkaException, TIMESTAMP_NOT_AVAILABLE

''' IMPORTS '''
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

SUPPORTED_GENERAL_OFFSETS = ['smallest', 'earliest', 'beginning', 'largest', 'latest', 'end', 'error']

''' CLIENT CLASS '''


class KafkaCommunicator:
    """Client class to interact with Kafka."""
    conf_producer = None
    conf_consumer = None

    def __init__(self, brokers: str, offset: str = 'earliest', group_id: str = 'xsoar_group',
                 message_max_bytes: int = None, enable_auto_commit: bool = False, ca_cert=None,
                 client_cert=None, client_cert_key=None, ssl_password=None):
        self.conf_producer = {'bootstrap.servers': brokers}

        if offset not in SUPPORTED_GENERAL_OFFSETS:
            return_error(f'General offset {offset} not found in supported offsets: {SUPPORTED_GENERAL_OFFSETS}')

        self.conf_consumer = {'bootstrap.servers': brokers,
                              'session.timeout.ms': 2000,
                              'auto.offset.reset': offset,
                              'group.id': group_id,  # TODO: Need to sort this
                              'enable.auto.commit': enable_auto_commit}

        if message_max_bytes:
            self.conf_consumer.update({'message.max.bytes': int(message_max_bytes)})

        if ca_cert:
            ca_path = 'ca.cert'  # type: ignore
            with open(ca_path, 'wb') as file:
                file.write(ca_cert)
                ca_path = os.path.abspath(ca_path)
            self.conf_producer.update({'ssl.ca.location': ca_path})
            self.conf_consumer.update({'ssl.ca.location': ca_path})
        if client_cert:
            client_path = 'client.cert'
            with open(client_path, 'wb') as file:
                file.write(client_cert)
                client_path = os.path.abspath(client_path)
            self.conf_producer.update({'ssl.certificate.location': client_path})
            self.conf_consumer.update({'ssl.certificate.location': client_path})
        if client_cert_key:
            client_key_path = 'client_key.key'
            with open(client_key_path, 'wb') as file:
                file.write(client_cert_key)
                self.conf_producer.update({'ssl.key.location': client_key_path})
                self.conf_consumer.update({'ssl.key.location': client_key_path})
        if ssl_password:
            self.conf_producer.update({'ssl.key.password': ssl_password})
            self.conf_consumer.update({'ssl.key.password': ssl_password})

    def test_connection(self):
        try:
            # AdminClient(self.conf_producer)  # doesn't work!
            Consumer(self.conf_consumer)
            Producer(self.conf_producer)
            # self.get_topics(AdminClient(self.conf_producer))
            self.get_topics(Consumer(self.conf_consumer))
            self.get_topics(Producer(self.conf_producer))

        except Exception as e:
            raise DemistoException(f'Error connecting to kafka: {str(e)}\n{traceback.format_exc()}')

        return 'ok'

    @staticmethod
    def delivery_report(err, msg):
        if err is not None:
            demisto.debug(f'Kafka v3 - Message {msg} delivery failed: {err}')
            raise DemistoException(f'Message delivery failed: {err}')
        else:
            return_results(f'Message was successfully produced to '
                            f'topic \'{msg.topic()}\', partition {msg.partition()}')

    def get_topics(self, client=None):
        if not client:
            client = Producer(self.conf_producer)
        cluster_metadata = client.list_topics()
        return cluster_metadata.topics

    def get_partition_offsets(self, topic, partition):
        kafka_consumer = Consumer(self.conf_consumer)
        partition = TopicPartition(topic=topic, partition=partition)
        return kafka_consumer.get_watermark_offsets(partition=partition)

    def produce(self, topic, value, partition):
        kafka_producer = Producer(self.conf_producer)
        if partition:
            kafka_producer.produce(topic=topic, value=value, partition=partition,
                                   on_delivery=self.delivery_report)
        else:
            kafka_producer.produce(topic=topic, value=value,
                                   on_delivery=self.delivery_report)
        kafka_producer.flush()

    def consume(self, topic: str, partition: int = -1, offset='0'):
        kafka_consumer = Consumer(self.conf_consumer)
        kafka_consumer.assign(self.get_topic_partitions(kafka_consumer, topic, partition, offset))
        polled_msg = kafka_consumer.poll(1.0)
        demisto.debug(f"polled {polled_msg}")
        kafka_consumer.close()
        return polled_msg

    def get_offset_for_partition(self, topic, partition, offset):
        earliest_offset, oldest_offset = self.get_partition_offsets(topic=topic, partition=partition)
        offset = str(offset)
        if offset.lower() == 'earliest':
            offset = earliest_offset
        elif offset.lower() == 'latest':
            offset = oldest_offset - 1
        else:
            offset = int(offset)
            if offset < int(earliest_offset) or offset >= int(oldest_offset):
                return_error(f'Offset {offset} for topic {topic} and partition {partition} is out of bounds '
                             f'[{earliest_offset}, {oldest_offset})')
        return offset

    def get_topic_partitions(self, client, topic, partition, offset):
        topic_partitions = []
        if partition != -1 and type(partition) is not list:
            offset = self.get_offset_for_partition(topic, int(partition), offset)
            topic_partitions = [TopicPartition(topic=topic, partition=int(partition), offset=offset)]

        elif type(partition) is list:
            for single_partition in partition:
                try:
                    offset = self.get_offset_for_partition(topic, single_partition, offset)
                    topic_partitions += [TopicPartition(topic=topic, partition=int(single_partition), offset=offset)]
                except KafkaException as e:
                    if 'Unknown partition' not in str(e):
                        raise e

        else:
            topics = self.get_topics(client=client)
            topic_metadata = topics[topic]
            for metadata_partition in topic_metadata.partitions.values():
                try:
                    offset = self.get_offset_for_partition(topic, metadata_partition.id, offset)
                    topic_partitions += [TopicPartition(topic=topic, partition=metadata_partition.id, offset=offset)]
                except KafkaException as e:
                    if 'Unknown partition' not in str(e):
                        raise e

        return topic_partitions


''' HELPER FUNCTIONS '''


def create_incident(message, topic):
    """
    Creates incident
    :param message: Kafka message to create incident from
    :type message: :class:`pykafka.common.Message`
    :param topic: Message's topic
    :type topic: str
    :return incident:
    """
    message_value = message.value()
    raw = {
        'Topic': topic,
        'Partition': message.partition(),
        'Offset': message.offset(),
        'Message': message_value.decode('utf-8')
    }
    incident = {
        'name': 'Kafka {} partition:{} offset:{}'.format(topic, message.partition(), message.offset()),
        'details': message_value.decode('utf-8'),
        'rawJSON': json.dumps(raw)
    }

    timestamp = message.timestamp()  # returns a list of [timestamp_type, timestamp]
    if timestamp and timestamp[0] != TIMESTAMP_NOT_AVAILABLE:
        incident['occurred'] = timestamp_to_datestring(timestamp[1])

    demisto.debug(f"Creating incident from topic {topic} partition {message.partition()} offset {message.offset()}")
    return incident


''' COMMANDS '''


def test_module(kafka):
    """Test getting available topics using AdminClient
    """
    connection_test = kafka.test_connection()
    demisto.results(connection_test)


def print_topics(kafka, demisto_args):
    """
    Prints available topics in Broker
    """
    include_offsets = demisto_args.get('include_offsets', 'true') == 'true'
    kafka_topics = kafka.get_topics().values()
    if kafka_topics:
        topics = []
        for topic in kafka_topics:
            partitions = []
            for partition in topic.partitions.values():
                partition_output = {'ID': partition.id}
                if include_offsets:
                    try:
                        partition_output['EarliestOffset'], partition_output['OldestOffset'] = kafka.get_partition_offsets(
                            topic=topic.topic, partition=partition.id)
                    except KafkaException as e:
                        if 'Unknown partition' not in str(e):
                            raise e
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


def produce_message(kafka, demisto_args):
    """
    Producing message to kafka topic
    """
    topic = demisto_args.get('topic')
    value = demisto_args.get('value')
    partitioning_key = demisto.args().get('partitioning_key')

    partitioning_key = str(partitioning_key)
    if partitioning_key.isdigit():
        partitioning_key = int(partitioning_key)  # type: ignore
    else:
        partitioning_key = None  # type: ignore

    kafka.produce(
        value=str(value),
        topic=topic,
        partition=partitioning_key
    )


def consume_message(kafka, demisto_args):
    """
    Consuming one message from topic
    """
    topic = demisto_args.get('topic')
    partition = int(demisto_args.get('partition', -1))
    offset = demisto_args.get('offset', '0')

    message = kafka.consume(topic=topic, partition=partition, offset=offset)
    demisto.debug(f"got message {message} from kafka")
    if not message:
        demisto.results('No message was consumed.')
    else:
        message_value = message.value()
        dict_for_debug = [{'Offset': message.offset(), 'Message': message_value.decode('utf-8')}]
        demisto.debug(f"The dict for debug: {dict_for_debug}")
        message_value = message.value()
        readable_output = tableToMarkdown(f'Message consumed from topic {topic}',
                                          [{'Offset': message.offset(), 'Message': message_value.decode("utf-8")}])
        entry_context = {
            'Kafka.Topic(val.Name === obj.Name)': {
                'Name': topic,
                'Message': {
                    'Value': message_value.decode('utf-8'),
                    'Offset': message.offset()
                }
            }
        }
        demisto.results({
            'Type': EntryType.NOTE,
            'Contents': {
                'Message': message_value.decode('utf-8'),
                'Offset': message.offset()
            },
            'ContentsFormat': formats['json'],
            'HumanReadable': readable_output,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': entry_context
        })


def fetch_partitions(kafka, demisto_args):
    """
    Fetching available partitions in given topic
    """
    # TODO: check params
    topic = demisto_args.get('topic')
    kafka_topics = kafka.get_topics()
    if topic in kafka_topics:
        kafka_topic = kafka_topics[topic]
        partition_objects = kafka_topic.partitions.values()
        partitions = [partition.id for partition in partition_objects]

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


def handle_empty(value, default_value):
    if not value:
        return default_value
    return value


def fetch_incidents(demisto_params):
    """
    Fetches incidents
    """
    topic = demisto_params.get('topic', '')
    partitions = handle_empty(argToList(demisto_params.get('partition', '')), -1)
    brokers = demisto_params.get('brokers')
    offset = handle_empty(demisto_params.get('offset', 'earliest'), 'earliest')
    message_max_bytes = int(handle_empty(demisto_params.get("max_bytes_per_message", 1048576), 1048576))
    max_messages = int(handle_empty(demisto_params.get('max_messages', 50), 50))
    last_fetched_offsets = demisto.getLastRun().get('last_fetched_offsets', {})
    demisto.debug(f"Starting fetch incidents with last_fetched_offsets: {last_fetched_offsets}")
    incidents = []

    kafka = KafkaCommunicator(brokers=brokers, offset=offset, enable_auto_commit=True,
                              message_max_bytes=message_max_bytes)

    kafka_consumer = Consumer(kafka.conf_consumer)
    for partition in partitions:
        specific_offset = handle_empty(last_fetched_offsets.get(partition), offset)
        demisto.debug(f'Getting last offset for partition {partition}, specific offset is {specific_offset}\n')
        if type(specific_offset) is int:
            specific_offset += 1
            earliest_offset, latest_offset = kafka.get_partition_offsets(topic=topic, partition=int(partition))
            if specific_offset >= latest_offset:
                continue
        topic_partitions = kafka.get_topic_partitions(client=kafka_consumer, topic=topic, partition=int(partition),
                                                      offset=specific_offset)
        demisto.debug(f"The topic partitions assigned to the consumer are: {topic_partitions}")
        kafka_consumer.assign(topic_partitions)

    for message_num in range(max_messages):
        polled_msg = kafka_consumer.poll(1.0)
        if polled_msg:
            incidents.append(create_incident(message=polled_msg, topic=topic))
            last_fetched_offsets[polled_msg.partition()] = polled_msg.offset()

    kafka_consumer.close()

    last_run = {'last_fetched_offsets': last_fetched_offsets}
    demisto.debug(f"Fetching finished, setting last run to {last_run}")
    demisto.setLastRun(last_run)

    demisto.incidents(incidents)


def create_certificate(ca_cert=None, client_cert=None, client_cert_key=None, password=None):
    """Create certificate"""
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
    return {
        'ssl.ca.location': ca_path,
        'ssl.certificate.location': client_path,
        'ssl.key.location': client_key_path,
        'ssl.key.password': password
    }


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    command = demisto.command()
    demisto_params = demisto.params()
    demisto_args = demisto.args()
    demisto.debug(f'Command being called is {command}')
    brokers = demisto_params.get('brokers')
    offset = handle_empty(demisto_params.get('offset', 'earliest'), 'earliest')

    # Should we use SSL
    use_ssl = demisto_params.get('use_ssl', False)

    if use_ssl:
        # Add Certificates
        ca_cert = demisto_params.get('ca_cert', None)
        client_cert = demisto_params.get('client_cert', None)
        client_cert_key = demisto_params.get('client_cert_key', None)
        ssl_password = demisto_params.get('additional_password', None)
        kafka = KafkaCommunicator(brokers=brokers, ca_cert=ca_cert, client_cert=client_cert,
                                  client_cert_key=client_cert_key, ssl_password=ssl_password, offset=offset)
    else:
        kafka = KafkaCommunicator(brokers=brokers, offset=offset)

    demisto_command = demisto.command()

    try:
        if demisto_command == 'test-module':
            test_module(kafka)
        elif demisto_command == 'kafka-print-topics':
            print_topics(kafka, demisto_args)
        elif demisto_command == 'kafka-publish-msg':
            produce_message(kafka, demisto_args)
        elif demisto_command == 'kafka-consume-msg':
            consume_message(kafka, demisto_args)
        elif demisto_command == 'kafka-fetch-partitions':
            fetch_partitions(kafka, demisto_args)
        elif demisto_command == 'fetch-incidents':
            fetch_incidents(demisto_params)

    except Exception as e:
        debug_log = 'Debug logs:'
        error_message = str(e)
        if demisto_command != 'test-module':
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
