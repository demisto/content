import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
from pykafka import KafkaClient, SslConfig
from pykafka.common import OffsetType
import logging
from cStringIO import StringIO
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

BROKERS = demisto.params().get('brokers')

# Should we use SSL
VERIFY_SSL = not demisto.params().get('insecure', False)

# Certificates
CA_CERT = demisto.params().get('ca_cert', None)
CLIENT_CERT = demisto.params().get('client_cert', None)
CLIENT_CERT_KEY = demisto.params().get('client_cert_key', None)
PASSWORD = demisto.params().get('additional_password', None)

# Incidents configuration
OFFSET = demisto.params().get('offset')
TOPIC = demisto.params().get('topic')
PARTITION = demisto.params().get('partition')

# Logging
log_stream = None
log_handler = None

''' HELPER FUNCTIONS '''


def start_logging():
    logging.raiseExceptions = False
    global log_stream
    global log_handler
    if log_stream is None:
        log_stream = StringIO()
        log_handler = logging.StreamHandler(stream=log_stream)
        log_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))
        logger = logging.getLogger()
        logger.addHandler(log_handler)
        logger.setLevel(logging.DEBUG)


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
    return {
        'name': 'Kafka {} partition:{} offset:{}'.format(topic, message.partition_id, message.offset),
        'occurred': timestamp_to_datestring(int(time.time())),
        'details': message.value,
        'rawJSON': json.dumps(raw)
    }


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


def create_certificate():
    """
    Creating certificate
    :return certificate:
    :return type: :class: `pykafka.connection.SslConfig`
    """
    ca_path = 'ca.cert'  # type: ignore
    client_path = 'client.cert'
    client_key_path = 'client_key.key'
    if CA_CERT:
        with open(ca_path, 'wb') as file:
            file.write(CA_CERT)
            ca_path = os.path.abspath(ca_path)
        if CLIENT_CERT:
            with open(client_path, 'wb') as file:
                file.write(CLIENT_CERT)
                client_path = os.path.abspath(client_path)
        else:
            client_path = None  # type: ignore
        if CLIENT_CERT_KEY:
            with open(client_key_path, 'wb') as file:
                file.write(CLIENT_CERT_KEY)
        else:
            client_key_path = None  # type: ignore
    else:
        ca_path = None  # type: ignore

    return SslConfig(
        cafile=ca_path,
        certfile=client_path,
        keyfile=client_key_path,
        password=PASSWORD
    )


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    If we got here, the instance is working without any error
    """
    if KAFKA_CLIENT.topics is not None:
        demisto.results('ok')


def print_topics():
    """
    Prints available topics in Broker
    """

    kafka_topics = KAFKA_CLIENT.topics.values()
    if kafka_topics:
        topics = []
        for topic in KAFKA_CLIENT.topics.values():
            partitions = []
            for partition in topic.partitions.values():
                partitions.append({
                    'ID': partition.id,
                    'EarliestOffset': partition.earliest_available_offset(),
                    'OldestOffset': partition.latest_available_offset()
                })

            topics.append({
                'Name': topic.name,
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


def produce_message():
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

    if topic in KAFKA_CLIENT.topics:
        kafka_topic = KAFKA_CLIENT.topics[topic]
        with kafka_topic.get_sync_producer() as producer:
            producer.produce(
                message=str(value),
                partition_key=partitioning_key
            )
        demisto.results('Message was successfully produced to topic \'{}\''.format(topic))
    else:
        return_error('Topic {} was not found in Kafka'.format(topic))


def consume_message():
    """
    Consuming one message from topic
    """
    topic = demisto.args().get('topic')
    offset = demisto.args().get('offset')
    partition = demisto.args().get('partition')

    if topic in KAFKA_CLIENT.topics:
        kafka_topic = KAFKA_CLIENT.topics[topic]
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


def fetch_partitions():
    """
    Fetching available partitions in given topic
    """
    topic = demisto.args().get('topic')
    if topic in KAFKA_CLIENT.topics:
        kafka_topic = KAFKA_CLIENT.topics[topic]
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


def fetch_incidents():
    """
    Fetches incidents
    """
    incidents = list()

    # Check for topic in Kafka
    if TOPIC in KAFKA_CLIENT.topics:
        queued_max_messages = int(demisto.params().get('max_messages', 50))
        demisto.info(queued_max_messages)
        kafka_topic = KAFKA_CLIENT.topics[TOPIC]
        offset, partition = check_params(kafka_topic, old_offset=OFFSET, old_partition=PARTITION)
        last_offset = demisto.getLastRun().get('last_offset')
        last_fetch = last_offset if last_offset > offset else offset

        # If need to fetch
        latest_offset = check_latest_offset(kafka_topic, partition)
        if latest_offset > last_fetch:
            consumer = kafka_topic.get_simple_consumer(
                auto_offset_reset=last_fetch,
                reset_offset_on_start=True,
                queued_max_messages=queued_max_messages
            )
            for i in range(last_fetch, latest_offset):
                """
                consumer.consume() will consume only one message from the given offset.
                """
                message = consumer.consume()
                incidents.append(create_incident(message=message, topic=TOPIC))
                if message.offset == latest_offset:
                    break
            demisto.setLastRun({'last_offset': latest_offset})
        demisto.incidents(incidents)
    else:
        return_error('No such topic \'{}\' to fetch incidents from.'.format(TOPIC))


''' COMMANDS MANAGER / SWITCH PANEL '''

LOG('Command being called is %s' % (demisto.command()))

try:
    start_logging()

    # Initialize KafkaClient
    if VERIFY_SSL:
        ssl_config = create_certificate()
        KAFKA_CLIENT = KafkaClient(hosts=BROKERS, ssl_config=ssl_config)
    else:
        KAFKA_CLIENT = KafkaClient(hosts=BROKERS)

    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
    elif demisto.command() == 'kafka-print-topics':
        print_topics()
    elif demisto.command() == 'kafka-publish-msg':
        produce_message()
    elif demisto.command() == 'kafka-consume-msg':
        consume_message()
    elif demisto.command() == 'kafka-fetch-partitions':
        fetch_partitions()
    elif demisto.command() == 'fetch-incidents':
        fetch_incidents()

except Exception as e:
    debug_log = 'Debug logs:\n\n{0}'.format(log_stream.getvalue() if log_stream else '')
    error_message = str(e)
    if demisto.command() != 'test-module':
        stacktrace = traceback.format_exc()
        if stacktrace:
            debug_log += '\nFull stacktrace:\n\n{0}'.format(stacktrace)
    return_error('{0}\n\n{1}'.format(error_message, debug_log))

finally:
    if os.path.isfile('ca.cert'):
        os.remove(os.path.abspath('ca.cert'))
    if os.path.isfile('client.cert'):
        os.remove(os.path.abspath('client.cert'))
    if os.path.isfile('client_key.key'):
        os.remove(os.path.abspath('client_key.key'))
    if log_stream:
        try:
            logging.getLogger().removeHandler(log_handler)  # type: ignore
            log_stream.close()
            log_stream = None
        except Exception as e:
            demisto.error('Kafka v2: unexpected exception when trying to remove log handler: {}'.format(e))
