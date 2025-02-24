import demistomock as demisto
from CommonServerPython import *
from confluent_kafka.serialization import SerializationContext, MessageField
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka import Consumer, TopicPartition, Producer, KafkaException, TIMESTAMP_NOT_AVAILABLE, Message
from collections.abc import Callable
from io import StringIO

''' IMPORTS '''
import json
import tempfile
import urllib3
import traceback
import logging

# Disable insecure warnings
urllib3.disable_warnings()

SUPPORTED_GENERAL_OFFSETS = ['smallest', 'earliest', 'beginning', 'largest', 'latest', 'end', 'error']

''' CLIENT CLASS '''


class KConsumer(Consumer):
    """Empty inheritance class for C-typed class in order to make mocking work."""


class KProducer(Producer):
    """Empty inheritance class for C-typed class in order to make mocking work."""


class KSchemaRegistryClient(SchemaRegistryClient):
    """Empty inheritance class for C-typed class in order to make mocking work."""


class KafkaCommunicator:
    """Client class to interact with Kafka."""
    conf_producer: Optional[dict[str, Any]] = None
    conf_consumer: Optional[dict[str, Any]] = None
    conf_schema_registry: Optional[dict[str, Any]] = None
    ca_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    kafka_logger: Optional[logging.Logger] = None

    SESSION_TIMEOUT: int = 10000
    REQUESTS_TIMEOUT: float = 10.0
    POLL_TIMEOUT: float = 1.0
    POLL_TIMEOUT_STOP_UPON_TIMEOUT = 10.0
    # which caused test playbook failures in builds.
    MAX_POLLS_FOR_LOG: int = 100

    def __init__(self, brokers: str, use_ssl: bool, plain_password: Optional[str] = None, plain_username: Optional[str] = None,
                 use_sasl: bool = False, offset: str = 'earliest', group_id: str = 'xsoar_group',
                 message_max_bytes: Optional[int] = None,
                 ca_cert: Optional[str] = None,
                 client_cert: Optional[str] = None, client_cert_key: Optional[str] = None,
                 ssl_password: Optional[str] = None, trust_any_cert: bool = False,
                 kafka_logger: Optional[logging.Logger] = None,
                 schema_registry_url: Optional[str] = None,
                 schema_registry_username: Optional[str] = None,
                 schema_registry_password: Optional[str] = None):
        """Set configuration dicts for consumer and producer.

        Args:
            brokers: The broker ips:ports to connect to.
            offset: The offset to start consuming from.
            group_id: The consumer group id.
            message_max_bytes: The maximum bytes a message can have.
            ca_cert: The contents of the CA certificate.
            client_cert: The contents of the client certificate.
            client_cert_key: The contents of the client certificate's key
            ssl_password: The password with which the client certificate is protected by.
            schema_registry_url: The URL of the schema registry.
            schema_registry_username: The username for the schema registry.
            schema_registry_password: The password for the schema registry.
        """

        # Set producer conf dict
        self.conf_producer = {}
        self.update_client_dict(self.conf_producer, trust_any_cert, use_ssl, ca_cert, client_cert,
                                client_cert_key, ssl_password, use_sasl, plain_username, plain_password, brokers)

        if offset not in SUPPORTED_GENERAL_OFFSETS:
            raise DemistoException(f'General offset {offset} not found in supported offsets: '
                                   f'{SUPPORTED_GENERAL_OFFSETS}')

        # Set consumer conf dict
        self.conf_consumer = {'session.timeout.ms': self.SESSION_TIMEOUT,
                              'auto.offset.reset': offset,
                              'group.id': group_id,
                              'enable.auto.commit': False}

        self.update_client_dict(self.conf_consumer, trust_any_cert, use_ssl, ca_cert, client_cert,
                                client_cert_key, ssl_password, use_sasl, plain_username, plain_password, brokers)

        self.kafka_logger = kafka_logger

        if message_max_bytes:
            self.conf_consumer.update({'message.max.bytes': int(message_max_bytes)})

        demisto.debug(f"The consumer configuration is \n{self.conf_consumer}\n")
        demisto.debug(f"The producer configuration is \n{self.conf_producer}\n")

        # Set schema registry conf dict
        if schema_registry_url:
            self.conf_schema_registry = {
                'url': schema_registry_url,
            }
            if schema_registry_username and schema_registry_password:
                self.conf_schema_registry['basic.auth.user.info'] = f'{schema_registry_username}:{schema_registry_password}'

            demisto.debug(f"The schema registry configuration is  \n{self.conf_schema_registry}\n")

    def update_client_dict(self, client_dict, trust_any_cert, use_ssl, ca_cert, client_cert, client_cert_key, ssl_password,
                           use_sasl, plain_username, plain_password, brokers):
        """
        Updates the conf_producer or conf_consumer configuration based on the specified authentication method.
        It assumes that all required parameters have been validated by the validate_params function.

        Args:
            client_dict (dict): The configuration dictionary to be updated.
            This should be either the producer's or consumer's conf_dict.
        """

        client_dict.update({'bootstrap.servers': brokers})

        if use_ssl and not use_sasl:
            if self.ca_path:
                client_dict.update({'ssl.ca.location': self.ca_path, 'ssl.certificate.location': self.client_cert_path,
                                    'ssl.key.location': self.client_key_path, 'security.protocol': 'ssl'})
            else:
                # temporary creating ca certification file
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as ca_descriptor:
                    self.ca_path = ca_descriptor.name
                    ca_descriptor.write(ca_cert)
                client_dict.update({'ssl.ca.location': self.ca_path})

                # temporary creating client certification file
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as client_cert_descriptor:
                    self.client_cert_path = client_cert_descriptor.name
                    client_cert_descriptor.write(client_cert)
                client_dict.update({'ssl.certificate.location': self.client_cert_path})

                # temporary creating client certification's key file
                with tempfile.NamedTemporaryFile(mode="w", delete=False) as client_key_descriptor:
                    self.client_key_path = client_key_descriptor.name
                    client_key_descriptor.write(client_cert_key)
                client_dict.update({'ssl.key.location': self.client_key_path,
                                    'security.protocol': 'ssl'})

            if ssl_password:
                client_dict.update({'ssl.key.password': ssl_password})

        # SASL with SSL
        elif use_sasl:
            client_dict.update({'security.protocol': 'SASL_SSL',
                                'sasl.mechanism': 'PLAIN',
                                'sasl.username': plain_username,
                                'sasl.password': plain_password})

            if trust_any_cert:
                client_dict.update({'ssl.endpoint.identification.algorithm': 'none',
                                    'enable.ssl.certificate.verification': False})
            else:  # ca_cert
                if self.ca_path:
                    client_dict.update({'ssl.ca.location': self.ca_path})
                else:
                    with tempfile.NamedTemporaryFile(mode="w", delete=False) as ca_descriptor:
                        self.ca_path = ca_descriptor.name
                        ca_descriptor.write(ca_cert)
                    client_dict.update({'ssl.ca.location': self.ca_path})

                if ssl_password:
                    client_dict.update({'ssl.key.password': ssl_password})

    def get_kafka_consumer(self) -> KConsumer:
        if self.kafka_logger:
            return KConsumer(self.conf_consumer, logger=self.kafka_logger)
        return KConsumer(self.conf_consumer)

    def get_kafka_producer(self) -> KProducer:
        if self.kafka_logger:
            return KProducer(self.conf_producer, logger=self.kafka_logger)
        return KProducer(self.conf_producer)

    def get_kafka_schema_registry(self) -> Optional[KSchemaRegistryClient]:
        if self.conf_schema_registry:
            return KSchemaRegistryClient(self.conf_schema_registry)
        return None

    def update_conf_for_fetch(self, message_max_bytes: Optional[int] = None):
        """Update consumer configurations for fetching messages

        Args:
            message_max_bytes: The maximum message bytes to fetch

        Raise DemistoException if consumer was not initialized before.
        """
        if self.conf_consumer:
            if message_max_bytes:
                self.conf_consumer.update({'message.max.bytes': int(message_max_bytes)})

        else:
            raise DemistoException('Kafka consumer was not yet initialized.')

    def test_connection(self, log_stream: Optional[StringIO] = None) -> str:
        """Test getting topics with the consumer and producer configurations."""
        error_msg = ''
        consumer: Optional[KConsumer] = None
        producer: Optional[KProducer] = None
        schema_registry: Optional[KSchemaRegistryClient] = None

        try:
            consumer = self.get_kafka_consumer()
            consumer_topics = consumer.list_topics(timeout=self.REQUESTS_TIMEOUT)
            consumer_topics.topics

        except Exception as e:
            error_msg = f'Error connecting to kafka using consumer: {str(e)}\n{traceback.format_exc()}'
        finally:
            try:
                if error_msg and consumer:
                    demisto.debug('Polling consumer for debug logs')
                    consumer.poll(1.0)  # For the logger to be updated with consumer errors.
                    if log_stream:
                        polls = 0
                        while not log_stream.getvalue() and polls < self.MAX_POLLS_FOR_LOG:
                            polls += 1
                            consumer.poll(1.0)
            finally:
                if error_msg:
                    raise DemistoException(error_msg)

        try:
            producer = self.get_kafka_producer()
            producer_topics = producer.list_topics(timeout=self.REQUESTS_TIMEOUT)
            producer_topics.topics

        except Exception as e:
            error_msg = f'Error connecting to kafka using producer: {str(e)}\n{traceback.format_exc()}'
        finally:
            try:
                if error_msg and producer:
                    demisto.debug('Polling producer for debug logs')
                    producer.flush()  # For the logger to updated with producer errors.
                    if log_stream:
                        polls = 0
                        while not log_stream.getvalue() and polls < self.MAX_POLLS_FOR_LOG:
                            polls += 1
                            producer.flush()
            finally:
                if error_msg:
                    raise DemistoException(error_msg)

        try:
            schema_registry = self.get_kafka_schema_registry()
            if schema_registry:
                schema_registry.get_subjects()

        except Exception as e:
            raise DemistoException(f'Error connecting to kafka schema registry: {str(e)}\n{traceback.format_exc()}')

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

    def get_topics(self, consumer: bool = True) -> dict:
        """Get Kafka topics

        Args:
            consumer: Whether to get topics using the consumer configuration (True) or producer configuration (False).

        Return topics metadata object as described in confluent-kafka API
        """
        if consumer:
            client = self.get_kafka_consumer()
        else:
            client = self.get_kafka_producer()
        cluster_metadata = client.list_topics(timeout=self.REQUESTS_TIMEOUT)
        return cluster_metadata.topics

    def get_partition_offsets(self, topic: str, partition: int) -> tuple[int, int]:
        """Get earliest and latest offsets for the specified partition in the specified topic.

        Return (earliest offset, latest offset)
        """
        kafka_consumer = self.get_kafka_consumer()
        partition = TopicPartition(topic=topic, partition=partition)
        return kafka_consumer.get_watermark_offsets(partition=partition, timeout=self.REQUESTS_TIMEOUT)

    def produce(
        self,
        topic: str,
        value: str,
        value_schema_type: Optional[str],
        value_schema_str: Optional[str],
        value_schema_subject_name: Optional[str],
        partition: Optional[int]
    ) -> None:
        """Produce in to kafka

        Args:
            topic: The topic to produce to
            value: The message/object to write
            value_schema_type: The schema type of the value
            value_schema_str: The schema str of the value
            value_schema_subject_name: The schema subject name of the value
            partition: The partition to produce to.

        The delivery_report is called after production.
        """
        kafka_producer = self.get_kafka_producer()
        serialized_value = value

        if value_schema_type:
            kafka_schema_registry_client = self.get_kafka_schema_registry()
            if not kafka_schema_registry_client:
                raise DemistoException(
                    "Kafka Schema Registry client is not configured. Please configure one to use schema validation.")
            if not value_schema_str and not value_schema_subject_name:
                raise DemistoException("Schema is not provided. Please provide one.")
            if value_schema_str and value_schema_subject_name:
                raise DemistoException(
                    "Both value_schema_str and value_schema_subject_name are provided. Please provide only one.")

            resolved_schema_str = value_schema_str
            # Retrieve schema from schema registry
            if value_schema_subject_name:
                registered_schema = kafka_schema_registry_client.get_latest_version(subject_name=value_schema_subject_name)
                if registered_schema.schema.schema_type != value_schema_type:
                    raise DemistoException(
                        f"Unsupported schema type '{registered_schema.schema.schema_type}'. "
                        f"Expected '{value_schema_type}'."
                    )
                resolved_schema_str = registered_schema.schema.schema_str

            if value_schema_type == 'AVRO':
                avro_serializer = AvroSerializer(
                    schema_str=resolved_schema_str,
                    schema_registry_client=kafka_schema_registry_client
                )
                serialized_value = avro_serializer(json.loads(value), SerializationContext(topic, MessageField.VALUE))

        kafka_producer.produce(
            topic=topic,
            value=serialized_value,
            partition=partition if partition is not None else None,
            on_delivery=self.delivery_report
        )
        kafka_producer.flush()

    def consume(self, poll_timeout: float, topic: str, partition: int = -1, offset: str = '0') -> Message:
        """Consume a message from kafka

        Args:
            topic: The topic to consume from
            partition: The partition to consume from
            offset: The offset to start consuming from

        Return the consumed kafka message in the confluent_kafka API's format.
        """
        kafka_consumer = self.get_kafka_consumer()
        kafka_consumer.assign(self.get_topic_partitions(topic, partition, offset, True))
        polled_msg = kafka_consumer.poll(poll_timeout)
        demisto.debug(f"polled {polled_msg} with {poll_timeout=}")
        kafka_consumer.close()
        return polled_msg

    def get_offset_for_partition(self, topic: str, partition: int, offset: int | str) -> int:
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
            return oldest_offset - 1
        else:
            number_offset = int(offset)
            if number_offset < int(earliest_offset) or number_offset >= int(oldest_offset):
                raise DemistoException(f'Offset {offset} for topic {topic} and partition {partition} is out of bounds '
                                       f'[{earliest_offset}, {oldest_offset})')
            return number_offset

    @logger
    def get_topic_partitions(self, topic: str, partition: int | list,
                             offset: str | int, consumer: bool = False) -> list:
        """Get relevant TopicPartiton structures to specify for the consumer.

        Args:
            topic: The topic
            partition: The partition
            offset: The offset could be either int or 'earliest' / 'latest'
            consumer: True to use consumer configuration when connecting to kafka False for producer configuration.

        Return a list of TopicPartition objects, ready for consumer assign command.
        """
        topic_partitions = []
        if partition != -1 and not isinstance(partition, list):
            demisto.debug(f"Got single partition {partition}, getting offsets with offset {offset}")
            updated_offset = self.get_offset_for_partition(topic, int(partition), offset)
            topic_partitions = [TopicPartition(topic=topic, partition=int(partition), offset=updated_offset)]

        elif isinstance(partition, list):
            demisto.debug(f"Got partition list {partition}, getting offsets with offset {offset}")
            for single_partition in partition:
                try:
                    updated_offset = self.get_offset_for_partition(topic, int(single_partition), offset)
                    topic_partitions += [TopicPartition(topic=topic, partition=int(single_partition),
                                                        offset=updated_offset)]
                except KafkaException as e:
                    # Sometimes listing topics can return uninitialized partitions.
                    # If that's the case, ignore them and continue.
                    if 'Unknown partition' not in str(e):
                        raise e

        else:
            topics = self.get_topics(consumer=consumer)
            topic_metadata = topics[topic]
            demisto.debug(f"Got no partition, getting all partitions and offsets with offset {offset}")
            for metadata_partition in topic_metadata.partitions.values():
                try:
                    updated_offset = self.get_offset_for_partition(topic, metadata_partition.id, offset)
                    topic_partitions += [TopicPartition(topic=topic, partition=metadata_partition.id,
                                                        offset=updated_offset)]
                except KafkaException as e:
                    # Sometimes listing topics can return uninitialized partitions.
                    # If that's the case, ignore them and continue.
                    if 'Unknown partition' not in str(e):
                        raise e

        return topic_partitions


''' HELPER FUNCTIONS '''


def validate_params(
    use_ssl,
    use_sasl,
    trust_any_cert,
    plain_username,
    plain_password,
    brokers,
    ca_cert,
    client_cert,
    client_cert_key
):
    """
        The function validates parameters for SSL and SASL_SSL authentication methods and raises an error if any invalid
        configurations are detected.

        For SSL authentication, it checks if use_ssl is True and requires ca_cert, client_cert, and client_cert_key parameters.

        For SASL_SSL authentication, it checks if use_sasl is True and requires plain_username, plain_password

        The brokers parameter is mandatory for both authentication methods.
    """

    # Check if brokers are provided
    if not brokers:
        raise DemistoException('Please specify a CSV list of Kafka brokers to connect to.')

    # Helper function to check for missing parameters

    def check_missing_params(params, missing):
        for param, param_name in params:
            if not param:
                missing.append(param_name)

    missing: List[str] = []

    # Check SSL requirements
    if use_ssl:
        ssl_params = [(ca_cert, 'CA certificate of Kafka server (.cer)'),
                      (client_cert, 'Client certificate (.cer)'),
                      (client_cert_key, 'Client certificate key (.key)')]
        check_missing_params(ssl_params, missing)

    # Check SASL_PLAIN requirements
    if use_sasl:
        sasl_params = [(plain_username, 'SASL PLAIN Username'),
                       (plain_password, 'SASL PLAIN Password')]
        if not trust_any_cert:
            sasl_params.append((ca_cert, 'CA certificate of Kafka server (.cer)'))

        check_missing_params(sasl_params, missing)

    if missing:
        missing_items = ', '.join(missing)
        raise DemistoException(f"Missing required parameters: {missing_items}. Please provide them.")


def capture_logs(func: Callable):
    """Capture confluent kafka logs and add them when raising exceptions.

    Args:
        func: Has to support kafka_logger and log_stream kwargs

    return: the func's result
    """
    def wrapper(*args, **kwargs):
        logging.raiseExceptions = False
        log_stream = StringIO()
        log_handler = logging.StreamHandler(stream=log_stream)
        log_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        kafka_logger = logging.getLogger()
        kafka_logger.addHandler(log_handler)
        kafka_logger.setLevel(logging.DEBUG)
        debug_log = ''

        try:
            kwargs['kafka_logger'] = kafka_logger
            kwargs['log_stream'] = log_stream
            result = func(*args, **kwargs)
        except Exception as e:
            captured_logs = log_stream.getvalue()
            if captured_logs:
                debug_log = f'\n{str(e)}\nDebug logs:\n{captured_logs}\n'
            else:
                debug_log = f'\n{str(e)}\n'
        finally:
            if log_stream:
                try:
                    logging.getLogger().removeHandler(log_handler)
                    log_stream.close()
                except Exception as e:
                    debug_log = f'Kafka v3: unexpected exception when trying to remove log handler:{e}\n\n' \
                                f'Other Exceptions:{debug_log}'
                finally:
                    if debug_log:
                        raise DemistoException(debug_log)

        return result
    return wrapper


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
        'name': f'Kafka {topic} partition:{message.partition()} offset:{message.offset()}',
        'details': message_value.decode('utf-8'),
        'rawJSON': json.dumps(raw)
    }

    timestamp = message.timestamp()  # returns a list of [timestamp_type, timestamp]
    if timestamp and len(timestamp) == 2 and timestamp[0] != TIMESTAMP_NOT_AVAILABLE:
        incident['occurred'] = timestamp_to_datestring(timestamp[1])

    demisto.debug(f"Creating incident from topic {topic} partition {message.partition()} offset {message.offset()}")
    return incident


''' COMMANDS '''


def command_test_module(kafka: KafkaCommunicator, demisto_params: dict, log_stream: Optional[StringIO] = None) -> str:
    """Test getting available topics using consumer and producer configurations.
    Validate the fetch parameters.

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_params: The demisto parameters.


    Return 'ok' if everything went well, raise relevant exception otherwise
    """
    kafka.test_connection(log_stream=log_stream)
    if demisto_params.get('isFetch', False):
        check_params(kafka=kafka,
                     topic=demisto_params.get('topic', None),
                     partitions=handle_empty(argToList(demisto_params.get('partition', None)), None),
                     offset=handle_empty(demisto_params.get('offset', 'earliest'), 'earliest'))
    return 'ok'


def print_topics(kafka: KafkaCommunicator, demisto_args: dict) -> Union[CommandResults, str]:
    """Print available topics in Broker

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_args: The demisto command arguments.

    Return CommandResults with the detailed topics, 'No topics found.' if no topics were found.
    """
    include_offsets = argToBoolean(demisto_args.get('include_offsets', 'true'))
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
                        # Sometimes listing topics can return uninitialized partitions.
                        # If that's the case, ignore them and continue.
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
    value_schema_type = demisto_args.get('value_schema_type')
    value_schema_str = demisto_args.get('value_schema_str')
    value_schema_subject_name = demisto_args.get('value_schema_subject_name')
    partition_arg = demisto_args.get('partitioning_key')

    partition = None
    if partition_arg is not None and str(partition_arg).isdigit():
        partition = int(partition_arg)

    try:
        kafka.produce(
            value=str(value),
            topic=str(topic),
            value_schema_type=value_schema_type,
            value_schema_str=value_schema_str,
            value_schema_subject_name=value_schema_subject_name,
            partition=partition
        )
    except Exception as e:
        if 'Topic authorization failed' in str(e):
            raise DemistoException(f"Error: {str(e)}\n"
                                   "Check if you have permission to produce messages."
                                   "Your access might be restricted to consumer-only.")
        else:
            raise DemistoException(e)


def consume_message(kafka: KafkaCommunicator, demisto_args: dict) -> CommandResults | str:
    """Consume one message from topic

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_args: The demisto command arguments.

    Return CommandResults with the relevant message from kafka.
    """
    topic = str(demisto_args.get('topic'))
    partition = int(demisto_args.get('partition', -1))
    offset = demisto_args.get('offset', '0')

    message = kafka.consume(float(demisto_args.get('poll_timeout') or kafka.POLL_TIMEOUT),
                            topic=topic, partition=partition, offset=offset)
    if not message:
        return 'No message was consumed.'
    else:
        message_value = message.value()
        if 'Group authorization failed' in message_value.decode('utf-8'):
            raise DemistoException(f'{message_value} Make sure you configured the right Consumer group ID.')
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
            name=f'Available partitions for topic \'{topic}\'',
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


def check_params(kafka: KafkaCommunicator, topic: str, partitions: Optional[list] = None,
                 offset: Optional[str] = None, consumer: bool = False, check_offset: bool = True) -> bool:
    """Check that partitions exist in topic and that offset matches the available ones.

    Args:
        kafka: Initialized KafkaCommunicator object to preform actions with.
        topic: The topic
        partitions: list of partitions
        offset: The offset
        consumer: consumer: Whether to get topics using the consumer's configuration (True) or producer's (False).

    Return True if everything is valid, raise relevant exception otherwise.
    """
    checkable_offset = False
    numerical_offset = 0
    topics = kafka.get_topics(consumer=consumer)
    if topic not in topics:
        raise DemistoException(f"Did not find topic {topic} in kafka topics.")

    if offset and str(offset).lower() not in SUPPORTED_GENERAL_OFFSETS:
        if offset.isdigit():
            numerical_offset = int(offset)
            checkable_offset = True
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
            if check_offset and checkable_offset:
                earliest_offset, oldest_offset = kafka.get_partition_offsets(topic=topic, partition=int(partition))
                if numerical_offset < int(earliest_offset) or numerical_offset >= int(oldest_offset):
                    raise DemistoException(f'Error checking params: Offset {numerical_offset} for topic {topic} and '
                                           f'partition {partition} is out of bounds [{earliest_offset}, '
                                           f'{oldest_offset})')

    return True


def get_topic_partition_if_relevant(kafka: KafkaCommunicator, topic: str, partition: str,
                                    specific_offset: str | int) -> list:
    """Return the TopicPartition if topic, partition and specific_offset are valid otherwise return []

    Args:
        kafka: The KafkaCommunicator object
        topic: The topic of the TopicPartition to retrieve
        partition: The partition of the TopicPartition to retrieve
        specific_offset: The offset of the TopicPartition to retrieve

    """
    demisto.debug(f'Getting last offset for partition {partition}, specific offset is {specific_offset}\n')
    add_topic_partition = True
    if isinstance(specific_offset, int):
        specific_offset += 1
        earliest_offset, latest_offset = kafka.get_partition_offsets(topic=topic, partition=int(partition))

        if specific_offset >= latest_offset or specific_offset < earliest_offset:
            add_topic_partition = False
            demisto.debug(f'Skipping partition {partition}, due to specific offset mismatch: '
                          f'{specific_offset} not in [{earliest_offset}, {latest_offset}) \n')

    if add_topic_partition:
        return kafka.get_topic_partitions(topic=topic, partition=int(partition), offset=specific_offset, consumer=True)
    return []


def get_fetch_topic_partitions(kafka: KafkaCommunicator, topic: str, offset: str | int,
                               last_fetched_offsets: dict) -> List[TopicPartition]:
    """Get topic partitions for fetching incidents without a specified partitions.

    If fetched from those partitions before chose offset accordingly.

    Args:
        kafka: The KafkaCommunicator object
        topic: The topic of the TopicPartitions to retrieve
        offset: The general offset to start fetching from
        last_fetched_offsets: The dictionary with the last fetched offsets

    Return a list of topic partitions
    """
    demisto.debug(f"Getting all topic partitions for topic {topic} and offset {offset}")
    all_topic_partitions = kafka.get_topic_partitions(topic=topic, partition=-1, offset=offset, consumer=True)
    if not last_fetched_offsets:
        demisto.debug("Did not fetch from this topic previously, returning all available topic partitions")
        return all_topic_partitions

    topic_partitions_in_system = []

    demisto.debug("Going over last fetched offsets")
    for partition in last_fetched_offsets:
        specific_offset = last_fetched_offsets.get(partition, offset)
        topic_partitions_in_system += get_topic_partition_if_relevant(kafka, topic, partition, specific_offset)

        for topic_partition in all_topic_partitions:
            if topic_partition.partition == int(partition):
                demisto.debug(f"Updating topic {topic} and partition {partition} to fetch from "
                              f"previous offset {specific_offset}")
                all_topic_partitions.remove(topic_partition)

    return topic_partitions_in_system + all_topic_partitions


def fetch_incidents(kafka: KafkaCommunicator, demisto_params: dict) -> None:
    """Fetch incidents as kafka messages from a specific topic.

    Args:
        kafka: initialized KafkaCommunicator object to preform actions with.
        demisto_params: The demisto parameters.
    """
    topic = demisto_params.get('topic', '')
    partitions = handle_empty(argToList(demisto_params.get('partition', '')), [])
    offset = handle_empty(demisto_params.get('first_fetch', 'earliest'), 'earliest')
    message_max_bytes = int(handle_empty(demisto_params.get("max_bytes_per_message", 1048576), 1048576))
    max_messages = int(handle_empty(demisto_params.get('max_fetch', 50), 50))
    last_fetched_offsets = demisto.getLastRun().get('last_fetched_offsets', {})
    last_topic = demisto.getLastRun().get('last_topic', '')
    stop_consuming_upon_timeout = argToBoolean(demisto_params.get('stop_consuming_upon_timeout', False))
    poll_timeout = kafka.POLL_TIMEOUT_STOP_UPON_TIMEOUT if stop_consuming_upon_timeout else kafka.POLL_TIMEOUT
    demisto.debug(f"Starting fetch incidents with:\n last_topic: {last_topic}, "
                  f"last_fetched_offsets: {last_fetched_offsets}, "
                  f"topic: {topic}, partitions: {partitions}, offset: {offset}, "
                  f"message_max_bytes: {message_max_bytes}, max_messages: {max_messages}\n")
    incidents = []

    kafka.update_conf_for_fetch(message_max_bytes=message_max_bytes)

    kafka_consumer = kafka.get_kafka_consumer()
    demisto.debug('Checking params')
    check_params(kafka, topic, partitions, offset, True, False)

    if topic != last_topic:
        demisto.debug(f'Topic changed from {last_topic} to {topic}, resetting last fetched offsets from '
                      f'{last_fetched_offsets} to empty dict.')
        last_fetched_offsets = {}

    if offset.isdigit():
        offset = int(offset)

    topic_partitions = []
    for partition in partitions:
        specific_offset = last_fetched_offsets.get(partition, offset) if partition in last_fetched_offsets else offset
        topic_partitions += get_topic_partition_if_relevant(kafka, topic, partition, specific_offset)

    if not partitions:
        if isinstance(offset, int):
            offset += 1
        demisto.debug(f'No partitions were set, getting all available partitions for topic {topic}')
        topic_partitions = get_fetch_topic_partitions(kafka, topic, offset, last_fetched_offsets)

    try:
        demisto.debug(f"The topic partitions assigned to the consumer are: {topic_partitions}")

        if topic_partitions:
            kafka_consumer.assign(topic_partitions)

            demisto.debug("Beginning to poll messages from kafka")
            num_polled_msg = 0
            for _ in range(max_messages):
                # Initial message consumption may take up to
                # `session.timeout.ms` for the consumer group to
                # rebalance and start consuming
                polled_msg = kafka_consumer.poll(poll_timeout)
                if polled_msg:
                    num_polled_msg += 1
                    demisto.debug(f"Received a message {num_polled_msg}# from Kafka.")
                    incidents.append(create_incident(message=polled_msg, topic=topic))
                    last_fetched_offsets[f'{polled_msg.partition()}'] = polled_msg.offset()
                elif stop_consuming_upon_timeout and (not polled_msg):
                    demisto.debug(f"Didn't get a message after {poll_timeout} seconds"
                                  f", stop_consuming_upon_timeout is true, break the loop. {num_polled_msg=}")
                    break

    finally:
        if kafka_consumer:
            kafka_consumer.close()

    last_run = {'last_fetched_offsets': last_fetched_offsets, 'last_topic': topic}
    demisto.debug(f"Fetching finished, setting last run to {last_run}")
    demisto.setLastRun(last_run)

    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


@capture_logs
def commands_manager(kafka_kwargs: dict, demisto_params: dict, demisto_args: dict,  # pragma: no cover
                     demisto_command: str, kafka_logger: Optional[logging.Logger] = None,
                     log_stream: Optional[StringIO] = None) -> None:
    """Start command function according to demisto command."""

    kafka_kwargs['kafka_logger'] = kafka_logger
    kafka = KafkaCommunicator(**kafka_kwargs)

    try:
        if demisto_command == 'test-module':
            return_results(command_test_module(kafka, demisto_params, log_stream))
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
    finally:
        if kafka.ca_path and os.path.isfile(kafka.ca_path):
            os.remove(os.path.abspath(kafka.ca_path))
        if kafka.client_cert_path and os.path.isfile(kafka.client_cert_path):
            os.remove(os.path.abspath(kafka.client_cert_path))
        if kafka.client_key_path and os.path.isfile(kafka.client_key_path):
            os.remove(os.path.abspath(kafka.client_key_path))


def main():  # pragma: no cover
    demisto_command = demisto.command()
    demisto_params = demisto.params()
    demisto_args = demisto.args()
    demisto.debug(f'Command being called is {demisto_command}')
    brokers = demisto_params.get('brokers')
    group_id = demisto_params.get('group_id', 'xsoar_group')
    offset = handle_empty(demisto_params.get('offset', 'earliest'), 'earliest')
    trust_any_cert = demisto_params.get('insecure', False)

    # Should we use SSL
    use_ssl = demisto_params.get('use_ssl', False)
    # Should we use SASL (with SSL and PLAIN)
    use_sasl = demisto_params.get('use_sasl', False)

    ca_cert = demisto_params.get('ca_cert', None)
    client_cert = demisto_params.get('client_cert', None)
    client_cert_key = demisto_params.get('client_cert_key', None)
    ssl_password = demisto_params.get('additional_password', None)
    plain_username = demisto_params.get('credentials', {}).get('identifier')
    plain_password = demisto_params.get('credentials', {}).get('password')
    schema_registry_url = demisto_params.get('schema_registry_url', None)
    schema_registry_username = demisto_params.get('schema_registry_credentials', {}).get('identifier', None)
    schema_registry_password = demisto_params.get('schema_registry_credentials', {}).get('password', None)
    validate_params(
        use_ssl=use_ssl,
        use_sasl=use_sasl,
        trust_any_cert=trust_any_cert,
        plain_username=plain_username,
        plain_password=plain_password,
        brokers=brokers,
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_cert_key=client_cert_key
    )

    kafka_kwargs = {'use_ssl': use_ssl, 'brokers': brokers, 'ca_cert': ca_cert, 'offset': offset,
                    'use_sasl': use_sasl, 'group_id': group_id,
                    'trust_any_cert': trust_any_cert,
                    'client_cert': client_cert, 'client_cert_key': client_cert_key,
                    'plain_username': plain_username, 'plain_password': plain_password,
                    'schema_registry_url': schema_registry_url,
                    'schema_registry_username': schema_registry_username,
                    'schema_registry_password': schema_registry_password}
    if ssl_password:
        kafka_kwargs['ssl_password'] = ssl_password

    try:
        commands_manager(kafka_kwargs, demisto_params, demisto_args, demisto_command)

    except Exception as e:
        debug_log = ''
        stacktrace = traceback.format_exc()
        if stacktrace:
            debug_log += f'Debug logs:\nFull stacktrace:\n\n{stacktrace}'
        return_error(f'{str(e)}\n\n{debug_log}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
