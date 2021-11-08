from CommonServerPython import DemistoException

from Kafka_v3 import KafkaCommunicator, command_test_module, KConsumer, KProducer, print_topics, fetch_partitions,\
    consume_message, produce_message
from confluent_kafka.admin import ClusterMetadata, TopicMetadata, PartitionMetadata
from confluent_kafka import KafkaError, TopicPartition

import pytest
import Kafka_v3

KAFKA = KafkaCommunicator(brokers=['some_broker_ip'])


def test_passing_simple_test_module(mocker):
    mocker.patch.object(Kafka_v3, 'KConsumer')
    mocker.patch.object(Kafka_v3, 'KProducer')
    mocker.patch.object(KConsumer, 'list_topics', return_value=ClusterMetadata())
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    assert command_test_module(KAFKA, {'isFetch': False}) == 'ok'


def test_failing_simple_test_module(mocker):
    mocker.patch.object(KConsumer, '__init__', return_value=None)
    mocker.patch.object(KProducer, '__init__', return_value=None)

    def raise_kafka_error():
        raise KafkaError('Some connection error')
    mocker.patch.object(KConsumer, 'list_topics', return_value=ClusterMetadata(), side_effect=raise_kafka_error)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata(), side_effect=raise_kafka_error)
    with pytest.raises(DemistoException) as exception_info:
        command_test_module(KAFKA, {'isFetch': False})
    assert 'Error connecting to kafka' in str(exception_info.value)


def create_cluster_metadata(topic_partitions):
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
    mocker.patch.object(KProducer, '__init__', return_value=None)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    assert print_topics(KAFKA, demisto_args) == 'No topics found.'


@pytest.mark.parametrize('demisto_args, cluster_tree, topic', [
                        ({'topic': 'some-topic'}, {'some-topic': [1]}, 'some-topic'),
                        ({'topic': 'some-topic'}, {'some-topic': [1], 'some-other-topic': [1]}, 'some-topic'),
                        ({'topic': 'some-topic'}, {'some-topic': [1, 2]}, 'some-topic')])
def test_fetch_partitions(mocker, demisto_args, cluster_tree, topic):
    mocker.patch.object(KProducer, '__init__', return_value=None)
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    result = fetch_partitions(KAFKA, demisto_args)
    assert {'Name': topic, 'Partition': cluster_tree[topic]} == result.outputs


@pytest.mark.parametrize('demisto_args', [{'topic': 'some-topic'}, {'topic': None}])
def test_fetch_partitions_no_topics(mocker, demisto_args):
    mocker.patch.object(KProducer, '__init__', return_value=None)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    with pytest.raises(DemistoException) as exception_info:
        fetch_partitions(KAFKA, demisto_args)
    assert f'Topic {demisto_args["topic"]} was not found in Kafka' in str(exception_info.value)


class MessageMock(object):
    message = None
    offset_value = None
    topic_value = None
    partition_value = None

    def __init__(self, message=None, offset=None, topic=None, partition=None):
        self.message = message.encode('utf-8')
        self.offset_value = offset
        self.topic_value = topic
        self.partition_value = partition

    def value(self):
        return self.message

    def offset(self):
        return self.offset_value

    def topic(self):
        return self.topic_value

    def partition(self):
        return self.partition_value


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
    poll_mock.assert_called_once()
    close_mock.assert_called_once()


def test_nothing_in_consume_message(mocker):
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
    poll_mock.assert_called_once()
    close_mock.assert_called_once()


@pytest.mark.parametrize('partition_number', [0, 1])
def test_produce_message(mocker, partition_number):
    mocker.patch.object(KProducer, '__init__', return_value=None)
    demisto_args = {'topic': 'some-topic', 'partition': partition_number, 'value': 'some-value'}
    produce_mock = mocker.patch.object(KProducer, 'produce')

    def run_delivery_report():
        message = MessageMock(message='some-value', offset=0, topic='some-topic', partition=partition_number)
        KafkaCommunicator.delivery_report(None, message)

    flush_mock = mocker.patch.object(KProducer, 'flush', side_effect=run_delivery_report)
    return_results_mock = mocker.patch.object(Kafka_v3, 'return_results')

    produce_message(KAFKA, demisto_args)

    produce_mock.assert_called_once_with(topic='some-topic', partition=partition_number, value='some-value',
                                         on_delivery=KAFKA.delivery_report)
    flush_mock.assert_called_once()
    return_results_mock.assert_called_once_with(f"Message was successfully produced to topic 'some-topic', "
                                                f"partition {partition_number}")


def test_produce_error_message(mocker):
    mocker.patch.object(KProducer, '__init__', return_value=None)
    demisto_args = {'topic': 'some-topic', 'partition': 1, 'value': 'some-value'}
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
