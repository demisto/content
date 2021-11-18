import demistomock as demisto
from CommonServerPython import *
from confluent_kafka import Consumer, TopicPartition, Producer, KafkaException, TIMESTAMP_NOT_AVAILABLE, Message
from typing import Tuple, Union

''' IMPORTS '''
import uuid
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

SUPPORTED_GENERAL_OFFSETS = ['smallest', 'earliest', 'beginning', 'largest', 'latest', 'end', 'error']

''' CLIENT CLASS '''


class KConsumer(Consumer):
    """Empty inheritance class for C-typed class in order to make mocking work."""
    pass


class KProducer(Producer):
    """Empty inheritance class for C-typed class in order to make mocking work."""
    pass


class KafkaCommunicator:
    """Client class to interact with Kafka."""
    conf_producer = None
    conf_consumer = None
    ca_path = None
    client_cert_path = None
    client_key_path = None

    def __init__(self, brokers: str, offset: str = 'earliest', group_id: str = 'xsoar_group',
                 message_max_bytes: int = None, enable_auto_commit: bool = False, ca_cert=None,
                 client_cert=None, client_cert_key=None, ssl_password=None, trust_any_cert=False):
        """Set configuration dicts for consumer and producer.

        Args:
            brokers: The broker ips:ports to connect to.
            offset: The offset to start consuming from.
            group_id: The consumer group id.
            message_max_bytes: The maximum bytes a message can have.
            enable_auto_commit: Wether to auto commit offsets after consuming messages.
            ca_cert: The contents of the CA certificate.
            client_cert: The contents of the client certificate.
            client_cert_key: The contents of the client certificate's key
            ssl_password: The password with which the client certificate is protected by.
        """
        self.conf_producer = {'bootstrap.servers': brokers}

        if offset not in SUPPORTED_GENERAL_OFFSETS:
            demisto.debug(f'General offset {offset} not found in supported offsets. '
                          f'Setting general offset to \'earliest\'')
            offset = 'earliest'

        self.conf_consumer = {'bootstrap.servers': brokers,
                              'session.timeout.ms': 5000,
                              'auto.offset.reset': offset,
                              'group.id': group_id,
                              'enable.auto.commit': enable_auto_commit}

        if trust_any_cert:
            self.conf_consumer.update({'enable.ssl.certificate.verification': False})  # type: ignore
            self.conf_producer.update({'enable.ssl.certificate.verification': False})  # type: ignore

        if message_max_bytes:
            self.conf_consumer.update({'message.max.bytes': int(message_max_bytes)})

        if ca_cert:
            self.ca_path = str(uuid.uuid4())  # Generate file name for key
            with open(self.ca_path, 'w') as file:
                file.write(ca_cert)  # lgtm [py/clear-text-storage-sensitive-data]
                ca_path = os.path.abspath(self.ca_path)
            self.conf_producer.update({'ssl.ca.location': ca_path})
            self.conf_consumer.update({'ssl.ca.location': ca_path})
        if client_cert:
            self.client_cert_path = str(uuid.uuid4())  # Generate file name for key
            with open(self.client_cert_path, 'w') as file:
                file.write(client_cert)  # lgtm [py/clear-text-storage-sensitive-data]
                client_path = os.path.abspath(self.client_cert_path)
            self.conf_producer.update({'ssl.certificate.location': client_path,
                                       'security.protocol': 'ssl'})
            self.conf_consumer.update({'ssl.certificate.location': client_path,
                                       'security.protocol': 'ssl'})
        if client_cert_key:
            self.client_key_path = str(uuid.uuid4())  # Generate file name for key
            with open(self.client_key_path, 'w') as file:
                file.write(client_cert_key)  # lgtm [py/clear-text-storage-sensitive-data]
                client_key_path = os.path.abspath(self.client_key_path)
            self.conf_producer.update({'ssl.key.location': client_key_path})
            self.conf_consumer.update({'ssl.key.location': client_key_path})
        if ssl_password:
            self.conf_producer.update({'ssl.key.password': ssl_password})
            self.conf_consumer.update({'ssl.key.password': ssl_password})

    def update_conf_for_fetch(self, offset: str = 'earliest', message_max_bytes: int = None,
                              enable_auto_commit: bool = False):
        """Update consumer configurations for fetching messages

        Args:
            offset: The general offset to start fetching from
            message_max_bytes: The maximum message bytes to fetch
            enable_auto_commit: Auto commit the offset when consuming messages.

        Raise DemistoException if consumer was not initialized before.
        """
        if self.conf_consumer:
            if message_max_bytes:
                self.conf_consumer.update({'message.max.bytes': int(message_max_bytes)})

            self.conf_consumer.update({'auto.offset.reset': offset,
                                       'enable.auto.commit': enable_auto_commit})
        else:
            raise DemistoException('Kafka consumer was not yet initialized.')

    def test_connection(self) -> str:
        """Test getting topics with the consumer and producer configurations."""
        try:
            KConsumer(self.conf_consumer)
            KProducer(self.conf_producer)
            self.get_topics(consumer=True)
            self.get_topics(consumer=False)  # Checks the KProducer

        except Exception as e:
            raise DemistoException(f'Error connecting to kafka: {str(e)}\n{traceback.format_exc()}')

        return 'ok'

    @staticmethod
    def delivery_report(err: KafkaException, msg: Message) -> None:
        """Callback function for producer. It is called when producer.flush() is called."""
        if err is not None:
            demisto.debug(f'Kafka v3 - Message {msg} delivery failed: {err}')
            raise DemistoException(f'Message delivery failed: {err}')
        else:
            return_results(f'Message was successfully produced to '
                           f'topic \'{msg.topic()}\', partition {msg.partition()}')

    def get_topics(self, consumer: bool = False) -> dict:
        """Get Kafka topics

        Args:
            consumer: Whether to get topics using the consumer configuration (True) or producer configuration (False).

        Return topics metadata object as described in confluent-kafka API
        """
        if consumer:
            client = KConsumer(self.conf_consumer)
        else:
            client = KProducer(self.conf_producer)
        cluster_metadata = client.list_topics(timeout=3.0)
        return cluster_metadata.topics

    def get_partition_offsets(self, topic: str, partition: int) -> Tuple[int, int]:
        """Get earliest and latest offsets for the specified partition in the specified topic.

        Return (earliest offset, latest offset)
        """
        kafka_consumer = KConsumer(self.conf_consumer)
        partition = TopicPartition(topic=topic, partition=partition)
        return kafka_consumer.get_watermark_offsets(partition=partition, timeout=3.0)

    def produce(self, topic: str, value: str, partition: Union[int, None]) -> None:
        """Produce in to kafka

        Args:
            topic: The topic to produce to
            value: The message/value to write
            partition: The partition to produce to.

        The delivery_report is called after production.
        """
        kafka_producer = KProducer(self.conf_producer)
        if partition is not None:
            kafka_producer.produce(topic=topic, value=value, partition=partition,
                                   on_delivery=self.delivery_report)
        else:
            kafka_producer.produce(topic=topic, value=value,
                                   on_delivery=self.delivery_report)
        kafka_producer.flush()

    def consume(self, topic: str, partition: int = -1, offset: str = '0') -> Message:
        """Consume a message from kafka

        Args:
            topic: The topic to consume from
            partition: The partition to consume from
            offset: The offset to start consuming from

        Return the consumed kafka message in the confluent_kafka API's format.
        """
        kafka_consumer = KConsumer(self.conf_consumer)
        kafka_consumer.assign(self.get_topic_partitions(topic, partition, offset, True))
        polled_msg = kafka_consumer.poll(1.0)
        demisto.debug(f"polled {polled_msg}")
        kafka_consumer.close()
        return polled_msg

    def get_offset_for_partition(self, topic: str, partition: int, offset: Union[int, str]) -> int:
        """Get the numerical offset from a partition of a topic

        Args:
            topic: The relavant topic
            partition: The relevant partition
            offset: Which offset to retrieve 'earliest'/ 'latest'

        Return the numerical value of the specified offset.
        """
        earliest_offset, oldest_offset = self.get_partition_offsets(topic=topic, partition=partition)
        offset = str(offset)
        if offset.lower() == 'earliest':
            return earliest_offset
        elif offset.lower() == 'latest':
            return oldest_offset - 1  # type: ignore
        else:
            number_offset = int(offset)  # type: ignore
            if number_offset < int(earliest_offset) or number_offset >= int(oldest_offset):  # type: ignore
                raise DemistoException(f'Offset {offset} for topic {topic} and partition {partition} is out of bounds '
                                       f'[{earliest_offset}, {oldest_offset})')
            return number_offset

    def get_topic_partitions(self, topic: str, partition: Union[int, list],
                             offset: Union[str, int], consumer: bool = False) -> list:
        """Get relevant TopicPartiton structures to specify for the consumer.

        Args:
            topic: The topic
            partition: The partition
            offset: The offset could be either int or 'earliest' / 'latest'
            consumer: True to use consumer configuration when connecting to kafka False for producer configuration.

        Return a list of TopicPartition objects, ready for consumer assign command.
        """
        topic_partitions = []
        if partition != -1 and type(partition) is not list:
            offset = self.get_offset_for_partition(topic, int(partition), offset)  # type: ignore
            topic_partitions = [TopicPartition(topic=topic, partition=int(partition), offset=offset)]  # type: ignore

        elif type(partition) is list:
            for single_partition in partition:  # type: ignore
                try:
                    offset = self.get_offset_for_partition(topic, single_partition, offset)
                    topic_partitions += [TopicPartition(topic=topic, partition=int(single_partition), offset=offset)]
                except KafkaException as e:
                    if 'Unknown partition' not in str(e):
                        raise e

        else:
            topics = self.get_topics(consumer=consumer)
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


def create_incident(message: Message, topic: str) -> dict:
    """Create incident from kafka's message.

    Args:
        message: Kafka message to create incident from
        topic: Message's topic

    Return incident
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


def command_test_module(kafka: KafkaCommunicator, demisto_params: dict) -> str:
    """Test getting available topics using consumer and producer configurations.
    Validate the fetch parameters.

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_params: The demisto parameters.

    Return 'ok' if everything went well, 'Failed' otherwise
    """
    valid_fetch = True
    connection_test = kafka.test_connection()
    if demisto_params.get('isFetch', False):
        valid_fetch = check_params(kafka=kafka,
                                   topic=demisto_params.get('topic', None),
                                   partitions=handle_empty(argToList(demisto_params.get('partition', None)), None),
                                   offset=handle_empty(demisto_params.get('offset', 'earliest'), 'earliest'))
    if connection_test != 'ok':
        return connection_test
    elif not valid_fetch:
        return 'Failed'
    else:
        return 'ok'


def print_topics(kafka: KafkaCommunicator, demisto_args: dict) -> Union[CommandResults, str]:
    """Print available topics in Broker

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_args: The demisto command arguments.

    Return CommandResults withe the detailed topics, 'No topics found.' if no topics were found.
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

        readable_output = tableToMarkdown('Kafka Topics', topics)

        return CommandResults(
            outputs_prefix='Kafka.Topic',
            outputs_key_field='Name',
            outputs=topics,
            readable_output=readable_output,
        )

    else:
        return 'No topics found.'


def produce_message(kafka: KafkaCommunicator, demisto_args: dict) -> None:
    """Producing message to kafka topic

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_args: The demisto command arguments.

    kafka.delivery_report is called when producing is done and it returns the relevant results.
    """
    topic = demisto_args.get('topic')
    value = demisto_args.get('value')
    partition = demisto_args.get('partition')

    partition = str(partition)
    if partition.isdigit():
        partition = int(partition)  # type: ignore
    else:
        partition = None  # type: ignore

    kafka.produce(
        value=str(value),
        topic=str(topic),
        partition=partition  # type: ignore
    )


def consume_message(kafka: KafkaCommunicator, demisto_args: dict) -> Union[CommandResults, str]:
    """Consume one message from topic

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_args: The demisto command arguments.

    Return CommandResults with the relevant message from kafka.
    """
    topic = str(demisto_args.get('topic'))
    partition = int(demisto_args.get('partition', -1))
    offset = demisto_args.get('offset', '0')

    message = kafka.consume(topic=topic, partition=partition, offset=offset)
    demisto.debug(f"got message {message} from kafka")
    if not message:
        return 'No message was consumed.'
    else:
        message_value = message.value()
        dict_for_debug = [{'Offset': message.offset(), 'Message': message_value.decode('utf-8')}]
        demisto.debug(f"The dict for debug: {dict_for_debug}")
        message_value = message.value()
        readable_output = tableToMarkdown(f'Message consumed from topic {topic}',
                                          [{'Offset': message.offset(), 'Message': message_value.decode("utf-8")}])
        content = {
            'Name': topic,
            'Message': {
                'Value': message_value.decode('utf-8'),
                'Offset': message.offset()
            }
        }

        return CommandResults(
            outputs=content,
            readable_output=readable_output,
            outputs_key_field='Name',
            outputs_prefix='Kafka.Topic'
        )


def fetch_partitions(kafka: KafkaCommunicator, demisto_args: dict) -> CommandResults:
    """Get available partitions in a given topic

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_args: The demisto command arguments.

    Return CommandResults with the relevant partitions.
    """
    topic = demisto_args.get('topic')
    kafka_topics = kafka.get_topics()
    if topic in kafka_topics:
        kafka_topic = kafka_topics[topic]
        partition_objects = kafka_topic.partitions.values()
        partitions = [partition.id for partition in partition_objects]

        readable_output = tableToMarkdown(
            name='Available partitions for topic \'{}\''.format(topic),
            t=partitions,
            headers='Partitions'
        )
        return CommandResults(outputs_prefix='Kafka.Topic',
                              outputs_key_field='Name',
                              outputs={'Name': topic, 'Partition': partitions},
                              readable_output=readable_output)
    else:
        raise DemistoException(f'Topic {topic} was not found in Kafka')


def handle_empty(value: Any, default_value: Any) -> Any:
    """If value is empty return default_value."""
    if not value:
        return default_value
    return value


def check_params(kafka: KafkaCommunicator, topic: str, partitions: list = None,
                 offset: str = None, consumer: bool = False) -> bool:
    """Check that partitions exist in topic and that offset matches the available ones.

    Args:
        kafka: Initialized KafkaCommunicator object to preform actions with.
        topic: The topic
        partitions: list of partitions
        offset: The offset
        consumer: consumer: Whether to get topics using the consumer's configuration (True) or producer's (False).

    Return True if everything is valid, raise relevant exception otherwise.
    """
    check_offset = False
    topics = kafka.get_topics(consumer=consumer)
    if topic not in topics.keys():
        raise DemistoException(f"Did not find topic {topic} in kafka topics.")

    if offset and str(offset).lower() not in SUPPORTED_GENERAL_OFFSETS:
        if offset.isdigit():
            offset = int(offset)  # type: ignore
            check_offset = True
        else:
            raise DemistoException(f'Offset {offset} is not in supported format.')

    if partitions:
        topic_metadata = topics[topic]
        available_partitions = topic_metadata.partitions.values()
        available_partitions_ids = [available_partition.id for available_partition in available_partitions]
        for partition in partitions:
            if int(partition) not in available_partitions_ids:
                raise DemistoException(f"Partition {partition} is not assigned to kafka topic {topic} available "
                                       f"{available_partitions_ids}.")
            if check_offset:
                earliest_offset, oldest_offset = kafka.get_partition_offsets(topic=topic, partition=int(partition))
                if offset < int(earliest_offset) or offset >= int(oldest_offset):  # type: ignore
                    raise DemistoException(f'Offset {offset} for topic {topic} and partition {partition} '
                                           f'is out of bounds [{earliest_offset}, {oldest_offset})')

    return True


def fetch_incidents(kafka: KafkaCommunicator, demisto_params: dict) -> None:
    """Fetch incidents as kafka messages from a specific topic.

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_params: The demisto parameters.
    """
    topic = demisto_params.get('topic', '')
    partitions = handle_empty(argToList(demisto_params.get('partition', '')), -1)
    offset = handle_empty(demisto_params.get('first_fetch', 'earliest'), 'earliest')
    message_max_bytes = int(handle_empty(demisto_params.get("max_bytes_per_message", 1048576), 1048576))
    max_messages = int(handle_empty(demisto_params.get('max_fetch', 50), 50))
    last_fetched_offsets = demisto.getLastRun().get('last_fetched_offsets', {})
    last_topic = demisto.getLastRun().get('last_topic', '')
    demisto.debug(f"Starting fetch incidents with last_fetched_offsets: {last_fetched_offsets}")
    incidents = []

    kafka.update_conf_for_fetch(offset=offset, enable_auto_commit=True, message_max_bytes=message_max_bytes)

    kafka_consumer = KConsumer(kafka.conf_consumer)
    check_params(kafka, topic, partitions, offset, True)

    if topic != last_topic:
        last_fetched_offsets = {}

    topic_partitions = []
    for partition in partitions:
        specific_offset = handle_empty(last_fetched_offsets.get(partition), offset)
        demisto.debug(f'Getting last offset for partition {partition}, specific offset is {specific_offset}\n')
        if type(specific_offset) is int:
            specific_offset += 1
            earliest_offset, latest_offset = kafka.get_partition_offsets(topic=topic, partition=int(partition))
            if specific_offset >= latest_offset:
                continue
        topic_partitions += kafka.get_topic_partitions(topic=topic, partition=int(partition),
                                                       offset=specific_offset)
    demisto.debug(f"The topic partitions assigned to the consumer are: {topic_partitions}")
    if topic_partitions:
        kafka_consumer.assign(topic_partitions)

    for message_num in range(max_messages):
        polled_msg = kafka_consumer.poll(1.0)
        if polled_msg:
            incidents.append(create_incident(message=polled_msg, topic=topic))
            last_fetched_offsets[f'{polled_msg.partition()}'] = polled_msg.offset()

    kafka_consumer.close()

    last_run = {'last_fetched_offsets': last_fetched_offsets, 'last_topic': topic}
    demisto.debug(f"Fetching finished, setting last run to {last_run}")
    demisto.setLastRun(last_run)

    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    demisto_command = demisto.command()
    demisto_params = demisto.params()
    demisto_args = demisto.args()
    demisto.debug(f'Command being called is {demisto_command}')
    brokers = demisto_params.get('brokers')
    offset = handle_empty(demisto_params.get('offset', 'earliest'), 'earliest')
    trust_any_cert = demisto_params.get('insecure', False)

    # Should we use SSL
    use_ssl = demisto_params.get('use_ssl', False)

    if use_ssl:
        # Add Certificates
        ca_cert = demisto_params.get('ca_cert', None)
        client_cert = demisto_params.get('client_cert', None)
        client_cert_key = demisto_params.get('client_cert_key', None)
        ssl_password = demisto_params.get('additional_password', None)
        kafka = KafkaCommunicator(brokers=brokers, ca_cert=ca_cert, client_cert=client_cert,
                                  client_cert_key=client_cert_key, ssl_password=ssl_password, offset=offset,
                                  trust_any_cert=False)
    else:
        kafka = KafkaCommunicator(brokers=brokers, offset=offset, trust_any_cert=trust_any_cert)

    try:
        if demisto_command == 'test-module':
            return_results(command_test_module(kafka, demisto_params))
        elif demisto_command == 'kafka-print-topics':
            return_results(print_topics(kafka, demisto_args))
        elif demisto_command == 'kafka-publish-msg':
            produce_message(kafka, demisto_args)
        elif demisto_command == 'kafka-consume-msg':
            return_results(consume_message(kafka, demisto_args))
        elif demisto_command == 'kafka-fetch-partitions':
            return_results(fetch_partitions(kafka, demisto_args))
        elif demisto_command == 'fetch-incidents':
            fetch_incidents(kafka, demisto_params)
        else:
            raise NotImplementedError(f'Command {demisto_command} not found in command list')

    except Exception as e:
        debug_log = 'Debug logs:'
        error_message = str(e)
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
