import demistomock as demisto
from CommonServerPython import *
from confluent_kafka.admin import AdminClient
from confluent_kafka import Consumer, TopicPartition

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

        except Exception as e:
            raise DemistoException(f'Error connecting to kafka: {str(e)}\n{traceback.format_exc()}')

        return 'ok'

    def get_topics(self):
        kafka_admin = AdminClient(self.conf_admin)
        cluster_metadata = kafka_admin.list_topics()
        return cluster_metadata.topics

    def get_partition_offsets(self, topic, partition):
        kafka_consumer = Consumer(self.conf_consumer)
        partition = TopicPartition(topic=topic, partition=partition)
        return kafka_consumer.get_watermark_offsets(partition=partition)


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
                    partition_output['EarliestOffset'], partition_output['OldestOffset'] = kafka.get_partition_offsets(
                        topic=topic.topic, partition=partition.id)
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

    kafka = KafkaCommunicator(brokers=brokers)

    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module(kafka)
        elif demisto.command() == 'kafka-print-topics':
            print_topics(kafka)
        # elif demisto.command() == 'kafka-publish-msg':
        #     produce_message(client)
        # elif demisto.command() == 'kafka-consume-msg':
        #     consume_message(client)
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
