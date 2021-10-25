import demistomock as demisto
from CommonServerPython import *
from confluent_kafka.admin import AdminClient
from confluent_kafka import Consumer, TopicPartition, Producer, KafkaError, KafkaException

''' IMPORTS '''
import requests
import traceback


import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CLIENT CLASS '''


class KafkaCommunicator:
    """Client class to interact with Kafka."""
    conf_admin = None
    conf_consumer = None

    def __init__(self, brokers: str, offset: str = 'earliest', group_id: str = 'my_group'):
        self.conf_admin = {'bootstrap.servers': brokers}
        self.conf_consumer = {'bootstrap.servers': brokers,
                              'session.timeout.ms': 2000,
                              'auto.offset.reset': offset,
                              'group.id': group_id}

    def test_connection(self):
        try:
            AdminClient(self.conf_admin)  # doesn't work!
            Consumer(self.conf_consumer)
            Producer(self.conf_admin)
            self.get_topics(AdminClient(self.conf_admin))
            self.get_topics(Consumer(self.conf_consumer))
            self.get_topics(Producer(self.conf_admin))

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
            client = AdminClient(self.conf_admin)
        cluster_metadata = client.list_topics()
        return cluster_metadata.topics

    def get_partition_offsets(self, topic, partition):
        kafka_consumer = Consumer(self.conf_consumer)
        partition = TopicPartition(topic=topic, partition=partition)
        return kafka_consumer.get_watermark_offsets(partition=partition)

    def produce(self, topic, value, partition):
        kafka_producer = Producer(self.conf_admin)
        if partition:
            kafka_producer.produce(topic=topic, value=value, partition=partition,
                                   on_delivery=self.delivery_report)
        else:
            kafka_producer.produce(topic=topic, value=value,
                                   on_delivery=self.delivery_report)
        kafka_producer.flush()

    def consume(self, topic, partition=-1, offset='earliest'):
        kafka_consumer = Consumer(self.conf_consumer)
        topic_partitions = []
        if partition != -1:
            topic_partitions = [TopicPartition(topic=topic, partition=partition, offset=0)]
        else:
            topics = self.get_topics(client=kafka_consumer)
            topic_metadata = topics[topic]
            for metadata_partition in topic_metadata.partitions.values():
                topic_partitions += [TopicPartition(topic=topic, partition=metadata_partition.id, offset=0)]

        kafka_consumer.assign(topic_partitions)
        return kafka_consumer.consume(timeout=60)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(kafka):
    """Test getting available topics using AdminClient
    """
    connection_test = kafka.test_connection()
    demisto.results(connection_test)


def print_topics(kafka):
    """
    Prints available topics in Broker
    """
    include_offsets = demisto.args().get('include_offsets', 'true') == 'true'
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


def produce_message(kafka):
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

    kafka.produce(
        value=str(value),
        topic=topic,
        partition=partitioning_key
    )


def consume_message(kafka):
    """
    Consuming one message from topic
    """
    topic = demisto.args().get('topic')
    offset = demisto.args().get('offset', 0)
    partition = int(demisto.args().get('partition', -1))

    #kafka_topics = kafka.get_topics().values()
    #partitions = topic.partitions.values()

    message = kafka.consume(topic=topic, partition=partition, offset=offset)
    if not message:
        return_results('No message was consumed.')
    else:
        markdown = tableToMarkdown(
            name=f'Message consumed from topic \'{topic}\'',
            t={
                'Offset': message.offset(),
                'Message': message.value()
            },
            headers=[
                'Offset',
                'Message'
            ]
        )
        entry_context = {
            'Kafka.Topic(val.Name === obj.Name)': {
                'Name': topic,
                'Message': {
                    'Value': message.value(),
                    'Offset': message.offset()
                }
            }
        }
        demisto.results({
            'Type': EntryType.NOTE,
            'Contents': {
                'Message': message.value(),
                'Offset': message.offset()
            },
            'ContentsFormat': formats['json'],
            'HumanReadable': markdown,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': entry_context
        })


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    command = demisto.command()
    demisto_params = demisto.params()
    demisto.debug(f'Command being called is {command}')
    brokers = demisto_params.get('brokers')
    offset = demisto.args().get('offset', 'earliest')

    # Should we use SSL
    use_ssl = demisto_params.get('use_ssl', False)

    # Certificates
    ca_cert = demisto_params.get('ca_cert', None)
    client_cert = demisto_params.get('client_cert', None)
    client_cert_key = demisto_params.get('client_cert_key', None)
    password = demisto_params.get('additional_password', None)

    kafka = KafkaCommunicator(brokers=brokers, offset=offset)

    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module(kafka)
        elif demisto.command() == 'kafka-print-topics':
            print_topics(kafka)
        elif demisto.command() == 'kafka-publish-msg':
            produce_message(kafka)
        elif demisto.command() == 'kafka-consume-msg':
            consume_message(kafka)
        # elif demisto.command() == 'kafka-fetch-partitions':
        #     fetch_partitions(client)
        # elif demisto.command() == 'fetch-incidents':
        #     fetch_incidents(client)

    except Exception as e:
        debug_log = 'Debug logs:'
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
