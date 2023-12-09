from CommonServerPython import DemistoException, demisto

from KafkaV3 import KafkaCommunicator, command_test_module, KConsumer, KProducer, print_topics, fetch_partitions, \
    consume_message, produce_message, fetch_incidents
from confluent_kafka.admin import ClusterMetadata, TopicMetadata, PartitionMetadata
from confluent_kafka import KafkaError, TopicPartition, TIMESTAMP_NOT_AVAILABLE, TIMESTAMP_CREATE_TIME

import pytest
import KafkaV3
import os

KAFKA = KafkaCommunicator(brokers=['some_broker_ip'])


def test_passing_simple_test_module(mocker):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - testing the module without fetch
    Then:
        - Assert 'ok' if ClusterMetadata object is returned from Kafka
    """
    mocker.patch.object(KafkaV3, 'KConsumer')
    mocker.patch.object(KafkaV3, 'KProducer')
    mocker.patch.object(KConsumer, 'list_topics', return_value=ClusterMetadata())
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    assert command_test_module(KAFKA, {'isFetch': False}) == 'ok'


def test_failing_simple_test_module(mocker):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - testing the module without fetch
    Then:
        - Assert relevant error is raised if communication failed.
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    mocker.patch.object(KProducer, '__init__', return_value=None)

    def raise_kafka_error():
        raise Exception('Some connection error')

    mocker.patch.object(KConsumer, 'list_topics', return_value=ClusterMetadata(), side_effect=raise_kafka_error)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata(), side_effect=raise_kafka_error)
    with pytest.raises(DemistoException) as exception_info:
        command_test_module(KAFKA, {'isFetch': False})
    assert 'Error connecting to kafka' in str(exception_info.value)


def create_cluster_metadata(topic_partitions):
    """Create ClusterMetada out of a dict structure for easier mocking.

    topic_partitions should be in the format of {'topic1': [partition1, partition2], 'topic2': [partition3]...}
    """
    cluster_metadata = ClusterMetadata()
    topics_dict = {}
    for topic in topic_partitions.keys():
        topic_metadata = TopicMetadata()
        partitions = topic_partitions[topic]
        partitions_dict = {}
        for partition in partitions:
            partition_metadata = PartitionMetadata()
            partition_metadata.id = partition
            partitions_dict.update({partition: partition_metadata})
        topic_metadata.partitions = partitions_dict
        topic_metadata.topic = topic
        topics_dict.update({topic: topic_metadata})
    cluster_metadata.topics = topics_dict
    return cluster_metadata


@pytest.mark.parametrize('demisto_params, cluster_tree', [
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1'}, {'some-topic': [1]}),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': 'earliest'}, {'some-topic': [1]}),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': 'latest'}, {'some-topic': [1]}),
    ({'isFetch': True, 'topic': 'some-topic'}, {'some-topic': [1]}),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1,2'}, {'some-topic': [1, 2]}),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1'}, {'some-topic': [1, 2]}),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1'}, {'some-topic': [1, 2], 'some-other-topic': [2]})])
def test_passing_test_module_with_fetch(mocker, demisto_params, cluster_tree):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - testing the module with fetch without offset
    Then:
        - Assert everything is 'ok'
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    assert command_test_module(KAFKA, demisto_params) == 'ok'


@pytest.mark.parametrize('demisto_params, cluster_tree, first_offset, last_offset', [
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '5'}, {'some-topic': [1]}, 1, 7),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '1'}, {'some-topic': [1]}, 1, 7)])
def test_passing_test_module_with_fetch_and_offset_as_num(mocker, demisto_params, cluster_tree, first_offset,
                                                          last_offset):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - testing the module with fetch with offset
    Then:
        - Assert everything is 'ok'
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(first_offset, last_offset))
    assert command_test_module(KAFKA, demisto_params) == 'ok'


@pytest.mark.parametrize('demisto_params, cluster_tree, expected_failure', [
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '2'}, {'some-topic': [1]},
     'Partition 2 is not assigned to kafka topic some-topic'),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': 'some-bad-offset'}, {'some-topic': [1]},
     'Offset some-bad-offset is not in supported format'),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '2'}, {'some-other-topic': [1]},
     'Did not find topic some-topic in kafka topics')
])
def test_failing_test_module_with_fetch(mocker, demisto_params, cluster_tree, expected_failure):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - testing the module with fetch without offset
    Then:
        - Assert the relevant error is raised when the fetch parameters are bad.
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    with pytest.raises(DemistoException) as exception_info:
        command_test_module(KAFKA, demisto_params)
    assert expected_failure in str(exception_info.value)


@pytest.mark.parametrize('demisto_params, cluster_tree, first_offset, last_offset, expected_failure', [
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '5'}, {'some-topic': [1]}, 6, 7,
     'Offset 5 for topic some-topic and partition 1 is out of bounds [6, 7)'),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '10'}, {'some-topic': [1]}, 6, 7,
     'Offset 10 for topic some-topic and partition 1 is out of bounds [6, 7)'),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '7'}, {'some-topic': [1]}, 6, 7,
     'Offset 7 for topic some-topic and partition 1 is out of bounds [6, 7)')
])
def test_failing_test_module_with_fetch_and_offset_as_num(mocker, demisto_params, cluster_tree, first_offset,
                                                          last_offset, expected_failure):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - testing the module with fetch with offset
    Then:
        - Assert the relevant error is raised when the fetch parameters are bad.
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(first_offset, last_offset))
    with pytest.raises(DemistoException) as exception_info:
        command_test_module(KAFKA, demisto_params)
    assert expected_failure in str(exception_info.value)


@pytest.mark.parametrize('demisto_args, cluster_tree', [
    ({'include_offsets': 'false'}, {'some-topic': [1]}),
    ({'include_offsets': 'false'}, {'some-topic': [1], 'some-other-topic': [1]}),
    ({'include_offsets': 'false'}, {'some-topic': [2], 'some-other-topic': [1, 3]}),
    ({'include_offsets': 'false'}, {'some-topic': [1, 2]})])
def test_print_topics_without_offsets(mocker, demisto_args, cluster_tree):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-print-topics command
    Then:
        - Assert all the topics and partitions are in the command results.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    result = print_topics(KAFKA, demisto_args)
    for topic in cluster_tree.keys():
        topic_partitions = [{'ID': partition} for partition in cluster_tree[topic]]
        assert {'Name': topic, 'Partitions': topic_partitions} in result.outputs


@pytest.mark.parametrize('demisto_args, first_offset, last_offset', [
    ({'include_offsets': 'true'}, 0, 1),
    ({'include_offsets': 'true'}, 1, 5),
    ({'include_offsets': 'true'}, 0, 2)])
def test_print_topics_with_offsets(mocker, demisto_args, first_offset, last_offset):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-print-topics command with include_offsets=True
    Then:
        - Assert all the topics, partitions and offsets are in the command results.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata({'some-topic': [1]})
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(first_offset, last_offset))
    result = print_topics(KAFKA, demisto_args)
    expected = {'Name': 'some-topic',
                'Partitions': [{'ID': 1, 'EarliestOffset': first_offset, 'OldestOffset': last_offset}]}
    assert expected in result.outputs


@pytest.mark.parametrize('demisto_args', [{'include_offsets': 'true'}, {'include_offsets': 'false'}])
def test_print_topics_no_topics(mocker, demisto_args):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-print-topics command without any topics
    Then:
        - Assert the 'No topics found.' response and that no errors are raised.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    assert print_topics(KAFKA, demisto_args) == 'No topics found.'


@pytest.mark.parametrize('demisto_args, cluster_tree, topic', [
    ({'topic': 'some-topic'}, {'some-topic': [1]}, 'some-topic'),
    ({'topic': 'some-topic'}, {'some-topic': [1], 'some-other-topic': [1]}, 'some-topic'),
    ({'topic': 'some-topic'}, {'some-topic': [1, 2]}, 'some-topic')])
def test_fetch_partitions(mocker, demisto_args, cluster_tree, topic):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running fetch-partitions command
    Then:
        - Assert the fetched partitions are in the command results.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    result = fetch_partitions(KAFKA, demisto_args)
    assert {'Name': topic, 'Partition': cluster_tree[topic]} == result.outputs


@pytest.mark.parametrize('demisto_args', [{'topic': 'some-topic'}, {'topic': None}])
def test_fetch_partitions_no_topics(mocker, demisto_args):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running fetch-partitions command without topics in kafka
    Then:
        - Assert the relevant error was raised.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    with pytest.raises(DemistoException) as exception_info:
        fetch_partitions(KAFKA, demisto_args)
    assert f'Topic {demisto_args["topic"]} was not found in Kafka' in str(exception_info.value)


class MessageMock(object):
    """Mocked message class for easier mocking"""
    message = None
    offset_value = None
    topic_value = None
    partition_value = None

    def __init__(self, message=None, offset=None, topic=None, partition=None, timestamp=None):
        self.message = message.encode('utf-8')
        self.offset_value = offset
        self.topic_value = topic
        self.partition_value = partition
        self.timestamp_value = timestamp

    def value(self):
        return self.message

    def offset(self):
        return self.offset_value

    def topic(self):
        return self.topic_value

    def partition(self):
        return self.partition_value

    def timestamp(self):
        return self.timestamp_value


@pytest.mark.parametrize('demisto_args, topic_partitions', [
    ({'topic': 'some-topic', 'partition': 0, 'offset': 0},
     [TopicPartition(topic='some-topic', partition=0, offset=0)]),
    ({'topic': 'some-topic', 'partition': 0, 'offset': 1},
     [TopicPartition(topic='some-topic', partition=0, offset=1)]),
    ({'topic': 'some-topic', 'partition': 0, 'offset': 'latest'},
     [TopicPartition(topic='some-topic', partition=0, offset=1)]),
    ({'topic': 'some-topic', 'partition': 0},
     [TopicPartition(topic='some-topic', partition=0, offset=0)])])
def test_consume_message(mocker, demisto_args, topic_partitions):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-consume-message command with partition
    Then:
        - Assert the message and topic are in the command results.
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    assign_mock = mocker.patch.object(KConsumer, 'assign')
    polled_msg = MessageMock(message='polled_msg', offset=0)
    poll_mock = mocker.patch.object(KConsumer, 'poll', return_value=polled_msg)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(0, 2))
    close_mock = mocker.patch.object(KConsumer, 'close')

    result = consume_message(KAFKA, demisto_args)

    msg_value = polled_msg.value()
    msg_value = msg_value.decode('utf-8')
    assert result.outputs['Message'] == {'Value': msg_value, 'Offset': polled_msg.offset()}
    assert result.outputs['Name'] == 'some-topic'

    assign_mock.assert_called_once_with(topic_partitions)
    called_topic_partitions = assign_mock.call_args.args[0]
    for partition_num in range(len(topic_partitions)):
        assert called_topic_partitions[partition_num].topic == topic_partitions[partition_num].topic
        assert called_topic_partitions[partition_num].partition == topic_partitions[partition_num].partition
        assert called_topic_partitions[partition_num].offset == topic_partitions[partition_num].offset

    poll_mock.assert_called_once()
    close_mock.assert_called_once()


@pytest.mark.parametrize('demisto_args, topic_partitions, cluster', [
    ({'topic': 'some-topic'},
     [TopicPartition(topic='some-topic', partition=1, offset=0)],
     {'some-topic': [1]}),
    ({'topic': 'some-topic'},
     [TopicPartition(topic='some-topic', partition=0, offset=0),
      TopicPartition(topic='some-topic', partition=1, offset=0)],
     {'some-topic': [0, 1]})])
def test_consume_message_without_partition(mocker, demisto_args, topic_partitions, cluster):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-consume-message command without partition
    Then:
        - Assert the message and topic are in the command results.
        - Assert the consumer was assigned to all available partitions.
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    assign_mock = mocker.patch.object(KConsumer, 'assign')
    polled_msg = MessageMock(message='polled_msg', offset=0)
    poll_mock = mocker.patch.object(KConsumer, 'poll', return_value=polled_msg)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(0, 2))
    close_mock = mocker.patch.object(KConsumer, 'close')
    cluster_metadata = create_cluster_metadata(cluster)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)

    result = consume_message(KAFKA, demisto_args)

    msg_value = polled_msg.value()
    msg_value = msg_value.decode('utf-8')
    assert result.outputs['Message'] == {'Value': msg_value, 'Offset': polled_msg.offset()}
    assert result.outputs['Name'] == 'some-topic'

    assign_mock.assert_called_once_with(topic_partitions)
    called_topic_partitions = assign_mock.call_args.args[0]
    for partition_num in range(len(topic_partitions)):
        assert called_topic_partitions[partition_num].topic == topic_partitions[partition_num].topic
        assert called_topic_partitions[partition_num].partition == topic_partitions[partition_num].partition
        assert called_topic_partitions[partition_num].offset == topic_partitions[partition_num].offset

    poll_mock.assert_called_once()
    close_mock.assert_called_once()


def test_nothing_in_consume_message(mocker):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-consume-message command without a response.
    Then:
        - Assert the 'No message was consumed.' result.
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    demisto_args = {'topic': 'some-topic', 'partition': 0, 'offset': 0}
    topic_partitions = [TopicPartition(topic='some-topic', partition=0, offset=0)]
    assign_mock = mocker.patch.object(KConsumer, 'assign')
    poll_mock = mocker.patch.object(KConsumer, 'poll', return_value=None)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(0, 2))
    close_mock = mocker.patch.object(KConsumer, 'close')

    result = consume_message(KAFKA, demisto_args)
    assert result == 'No message was consumed.'

    assign_mock.assert_called_once_with(topic_partitions)
    called_topic_partitions = assign_mock.call_args.args[0]
    for partition_num in range(len(topic_partitions)):
        assert called_topic_partitions[partition_num].topic == topic_partitions[partition_num].topic
        assert called_topic_partitions[partition_num].partition == topic_partitions[partition_num].partition
        assert called_topic_partitions[partition_num].offset == topic_partitions[partition_num].offset
    poll_mock.assert_called_once()
    close_mock.assert_called_once()


@pytest.mark.parametrize('partition_number', [0, 1])
def test_produce_message(mocker, partition_number):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-produce-msg command.
    Then:
        - Assert the relevant results are returned when everything works.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    demisto_args = {'topic': 'some-topic', 'partitioning_key': partition_number, 'value': 'some-value'}
    produce_mock = mocker.patch.object(KProducer, 'produce')

    def run_delivery_report():
        message = MessageMock(message='some-value', offset=0, topic='some-topic', partition=partition_number)
        KafkaCommunicator.delivery_report(None, message)

    flush_mock = mocker.patch.object(KProducer, 'flush', side_effect=run_delivery_report)
    return_results_mock = mocker.patch.object(KafkaV3, 'return_results')

    produce_message(KAFKA, demisto_args)

    produce_mock.assert_called_once_with(topic='some-topic', partition=partition_number, value='some-value',
                                         on_delivery=KAFKA.delivery_report)
    flush_mock.assert_called_once()
    return_results_mock.assert_called_once_with(f"Message was successfully produced to topic 'some-topic', "
                                                f"partition {partition_number}")


def test_produce_error_message(mocker):
    """
    Given:
        - initialized KafkaCommunicator
    When:
        - running kafka-produce-msg command without a bad response.
    Then:
        - Assert the relevant exception is raised.
    """
    mocker.patch.object(KProducer, '__init__', return_value=None)
    demisto_args = {'topic': 'some-topic', 'partitioning_key': 1, 'value': 'some-value'}
    produce_mock = mocker.patch.object(KProducer, 'produce')
    kafka_error = KafkaError(1)

    def run_delivery_report():
        message = MessageMock(message='some-value', offset=0, topic='some-topic', partition=1)
        KafkaCommunicator.delivery_report(kafka_error, message)

    flush_mock = mocker.patch.object(KProducer, 'flush', side_effect=run_delivery_report)

    with pytest.raises(DemistoException) as exception_info:
        produce_message(KAFKA, demisto_args)

    assert 'Message delivery failed:' in str(exception_info.value)
    assert str(kafka_error) in str(exception_info.value)

    produce_mock.assert_called_once_with(topic='some-topic', partition=1, value='some-value',
                                         on_delivery=KAFKA.delivery_report)
    flush_mock.assert_called_once()


@pytest.mark.parametrize(
    'demisto_params, last_run, cluster_tree, topic_partitions, incidents, next_run, polled_msgs, offsets',
    [pytest.param(
        {'topic': 'some-topic',
         'partition': '0',
         'first_fetch': 'earliest',
         'max_fetch': '1'}, {}, {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=0)],
        [{'name': 'Kafka some-topic partition:0 offset:0',
          'details': 'polled_msg',
          'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 0, '
                     '"Message": "polled_msg"}'}],
        {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
        [MessageMock(message='polled_msg', partition=0, offset=0,
                     timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2)], id="first run"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0',
             'first_fetch': 'earliest',
             'max_fetch': '1'}, {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=1)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2), (0, 2)], id="second run"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0',
             'first_fetch': 'earliest',
             'max_fetch': '2'
             }, {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=1)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'},
             {'name': 'Kafka some-topic partition:0 offset:2',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 2, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 2}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0)),
             MessageMock(message='polled_msg', partition=0, offset=2,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2), (0, 2)], id="1 partition 2/2 messages"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0',
             'first_fetch': 'earliest',
             'max_fetch': '3'},
            {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=1)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'},
             {'name': 'Kafka some-topic partition:0 offset:2',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 2, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 2}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0)),
             MessageMock(message='polled_msg', partition=0, offset=2,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0)),
             None], [(0, 2), (0, 2)], id="1 partition 2/3 messages"),
        pytest.param({  # second run changed topic
            'topic': 'some-topic',
            'partition': '0',
            'first_fetch': 'earliest',
            'max_fetch': '1'
        }, {'last_fetched_offsets': {'0': 5}, 'last_topic': 'some-other-topic'},
            {'some-topic': [0], 'some-other-topic': [0]},
            [TopicPartition(topic='some-topic', partition=0, offset=0)],
            [{'name': 'Kafka some-topic partition:0 offset:0',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 0, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=0,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2)], id="Changed topic"),
        pytest.param({  # second run no message
            'topic': 'some-topic',
            'partition': '0',
            'first_fetch': 'earliest',
            'max_fetch': '1'
        }, {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=1)],
            [], {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'}, [None], [(0, 2), (0, 2)],
            id="No message"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0,1',
             'first_fetch': 'earliest',
             'max_fetch': '2'
             }, {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            {'some-topic': [0, 1]}, [TopicPartition(topic='some-topic', partition=0, offset=1),
                                     TopicPartition(topic='some-topic', partition=1, offset=0)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'},
             {'name': 'Kafka some-topic partition:1 offset:0',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 1, "Offset": 0, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 1, '1': 0}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0)),
             MessageMock(message='polled_msg', partition=1, offset=0,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))],
            [(0, 3), (0, 3), (0, 3)], id="2 partitions, 1 message each"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0',
             'first_fetch': '2',
             'max_fetch': '1'}, {}, {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=3)],
            [{'name': 'Kafka some-topic partition:0 offset:3',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 3, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 3}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=3,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))],
            [(0, 5), (0, 5), (0, 5)], id="first run later offset"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0',
             'first_fetch': 'earliest',
             'max_fetch': '1'
             }, {}, {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=0)],
            [{'name': 'Kafka some-topic partition:0 offset:0',
              'occurred': '2021-11-15T10:31:08.000Z',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 0, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 0}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=0,
                         timestamp=(TIMESTAMP_CREATE_TIME, 1636972268435))],
            [(0, 2)], id="first run add timestamp"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '',
             'first_fetch': '0',
             'max_fetch': '1'}, {}, {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=1)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2), (0, 2), (0, 2)],
            id="No partition in params"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '',
             'first_fetch': '0',
             'max_fetch': '1'}, {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'},
            {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=2)],
            [{'name': 'Kafka some-topic partition:0 offset:2',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 2, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 2}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=2,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 3), (0, 3), (0, 3)],
            id="No partition in params but with history"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '',
             'first_fetch': '0',
             'max_fetch': '1'}, {}, {'some-topic': [0, 1]}, [TopicPartition(topic='some-topic', partition=0, offset=1),
                                                             TopicPartition(topic='some-topic', partition=1, offset=1)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2), (0, 2), (0, 2)],
            id="No partition in params, 2 partitions in kafka"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '',
             'first_fetch': 'earliest',
             'max_fetch': '1'}, {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'},
            {'some-topic': [0, 1]}, [TopicPartition(topic='some-topic', partition=0, offset=2),
                                     TopicPartition(topic='some-topic', partition=1, offset=0)],
            [{'name': 'Kafka some-topic partition:0 offset:2',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 2, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 2}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=2,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 3), (0, 3), (0, 3), (0, 3), (0, 3), (0, 3)],
            id="No partition in params, 2 partitions in kafka, mixed fetch history"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '0,1',
             'first_fetch': '1',
             'max_fetch': '1'}, {}, {'some-topic': [0, 1]}, [TopicPartition(topic='some-topic', partition=1, offset=2)],
            [{'name': 'Kafka some-topic partition:1 offset:2',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 1, "Offset": 2, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'1': 2}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=1, offset=2,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2), (0, 3), (0, 3), (0, 3), (0, 3), (0, 3)],
            id="2 partitions, one to skip due to offset out of bounds"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '',
             'first_fetch': '',
             'max_fetch': '1'}, {}, {'some-topic': [0, 1]}, [TopicPartition(topic='some-topic', partition=0, offset=4),
                                                             TopicPartition(topic='some-topic', partition=1, offset=0)],
            [{'name': 'Kafka some-topic partition:1 offset:2',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 1, "Offset": 2, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'1': 2}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=1, offset=2,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(4, 4), (0, 3), (0, 3), (0, 3), (0, 3), (0, 3)],
            id="2 partitions, earliest offset of one is later than the last of the other"),
        pytest.param(
            {'topic': 'some-topic',
             'partition': '',
             'first_fetch': '0',
             'max_fetch': '1'}, {}, {'some-topic': [0]}, [TopicPartition(topic='some-topic', partition=0, offset=1)],
            [{'name': 'Kafka some-topic partition:0 offset:1',
              'details': 'polled_msg',
              'rawJSON': '{"Topic": "some-topic", "Partition": 0, "Offset": 1, '
                         '"Message": "polled_msg"}'}],
            {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'},
            [MessageMock(message='polled_msg', partition=0, offset=1,
                         timestamp=(TIMESTAMP_NOT_AVAILABLE, 0))], [(0, 2), (0, 2), (0, 2)], id="first run, offset is 0")])
def test_fetch_incidents(mocker, demisto_params, last_run, cluster_tree, topic_partitions,
                         incidents, next_run, polled_msgs, offsets):
    """
    Given:
        - initialized KafkaCommunicator
        - demisto_params
        - last_run dict
        - available cluster tree
    When:
        - fetching incidents
    Then:
        - Assert the relevant topicPartitions are assigned to the consumer
        - Assert the polled messages are the right amount
        - Assert the created incidents are as expected
        - Assert setting the last run
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    assign_mock = mocker.patch.object(KConsumer, 'assign')
    poll_mock = mocker.patch.object(KConsumer, 'poll', side_effect=polled_msgs)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', side_effect=offsets)
    close_mock = mocker.patch.object(KConsumer, 'close')
    set_last_run_mock = mocker.patch.object(demisto, 'setLastRun')
    incidents_mock = mocker.patch.object(demisto, 'incidents')

    fetch_incidents(KAFKA, demisto_params)

    assign_mock.assert_called_once_with(topic_partitions)
    called_topic_partitions = assign_mock.call_args.args[0]
    for partition_num in range(len(topic_partitions)):
        assert called_topic_partitions[partition_num].topic == topic_partitions[partition_num].topic
        assert called_topic_partitions[partition_num].partition == topic_partitions[partition_num].partition
        assert called_topic_partitions[partition_num].offset == topic_partitions[partition_num].offset

    assert len(polled_msgs) == poll_mock.call_count
    close_mock.assert_called_once()
    incidents_mock.assert_called_once_with(incidents)
    set_last_run_mock.assert_called_once_with(next_run)


@pytest.mark.parametrize('demisto_params, last_run, cluster_tree', [
    pytest.param(
        {'topic': 'some-topic',
         'partition': '0',
         'first_fetch': 'earliest',
         'max_fetch': '1'},
        {'last_fetched_offsets': {'0': 1}, 'last_topic': 'some-topic'}, {'some-topic': [0]}, id="out of bounds offset")
])
def test_fetch_incidents_no_messages(mocker, demisto_params, last_run, cluster_tree):
    """
    Given:
        - initialized KafkaCommunicator
        - demisto_params
        - last_run dict
        - available cluster tree
    When:
        - fetching incidents without new messages
    Then:
        - Assert no topicPartitions are assigned to the consumer
        - Assert no new created incidents
        - Assert setting the last run to be the same as before
    """
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    assign_mock = mocker.patch.object(KConsumer, 'assign')
    poll_mock = mocker.patch.object(KConsumer, 'poll', return_value=None)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(0, 2))
    close_mock = mocker.patch.object(KConsumer, 'close')
    set_last_run_mock = mocker.patch.object(demisto, 'setLastRun')
    incidents_mock = mocker.patch.object(demisto, 'incidents')

    fetch_incidents(KAFKA, demisto_params)

    assign_mock.assert_not_called()
    poll_mock.assert_not_called()
    close_mock.assert_called_once()
    incidents_mock.assert_called_once_with([])
    set_last_run_mock.assert_called_once_with(last_run)


def test_ssl_configuration():
    """
    Given:
        - Kafka initialization parameters
    When:
        - Initializing KafkaCommunicator object
    Then:
        - Assert initialization is as expected.
    """
    kafka = KafkaCommunicator(brokers='brokers',
                              ca_cert='ca_cert',
                              client_cert='client_cert',
                              client_cert_key='client_cert_key',
                              ssl_password='ssl_password',
                              offset='earliest',
                              trust_any_cert=False)
    expected_consumer_conf = {
        'auto.offset.reset': 'earliest',
        'bootstrap.servers': 'brokers',
        'enable.auto.commit': False,
        'group.id': 'xsoar_group',
        'security.protocol': 'ssl',
        'session.timeout.ms': 10000,
        'ssl.ca.location': os.path.abspath(kafka.ca_path),
        'ssl.certificate.location': os.path.abspath(kafka.client_cert_path),
        'ssl.key.location': os.path.abspath(kafka.client_key_path),
        'ssl.key.password': 'ssl_password'
    }
    expected_producer_conf = {
        'bootstrap.servers': 'brokers',
        'security.protocol': 'ssl',
        'ssl.ca.location': os.path.abspath(kafka.ca_path),
        'ssl.certificate.location': os.path.abspath(kafka.client_cert_path),
        'ssl.key.location': os.path.abspath(kafka.client_key_path),
        'ssl.key.password': 'ssl_password'
    }
    assert kafka.conf_consumer == expected_consumer_conf
    assert kafka.conf_producer == expected_producer_conf
    with open(kafka.ca_path, 'r') as f:
        assert f.read() == 'ca_cert'
    with open(kafka.client_cert_path, 'r') as f:
        assert f.read() == 'client_cert'
    with open(kafka.client_key_path, 'r') as f:
        assert f.read() == 'client_cert_key'
    os.remove(kafka.ca_path)
    os.remove(kafka.client_cert_path)
    os.remove(kafka.client_key_path)
