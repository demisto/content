from CommonServerPython import DemistoException

from Kafka_v3 import KafkaCommunicator, test_module, KConsumer, KProducer, print_topics, fetch_partitions
from confluent_kafka.admin import ClusterMetadata, TopicMetadata, PartitionMetadata
from confluent_kafka import KafkaError

import pytest

KAFKA = KafkaCommunicator(brokers=['some_broker_ip'])


def test_passing_simple_test_module(mocker):
    mocker.patch.object(KConsumer, 'list_topics', return_value=ClusterMetadata())
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    assert test_module(KAFKA, {'isFetch': False}) == 'ok'


def test_failing_simple_test_module(mocker):
    def raise_kafka_error():
        raise KafkaError('Some connection error')
    mocker.patch.object(KConsumer, 'list_topics', return_value=ClusterMetadata(), side_effect=raise_kafka_error)
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata(), side_effect=raise_kafka_error)
    with pytest.raises(DemistoException) as exception_info:
        test_module(KAFKA, {'isFetch': False})
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
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    assert test_module(KAFKA, demisto_params) == 'ok'


@pytest.mark.parametrize('demisto_params, cluster_tree, first_offset, last_offset', [
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '5'}, {'some-topic': [1]}, 1, 7),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': '1'}, {'some-topic': [1]}, 1, 7)])
def test_passing_test_module_with_fetch_and_offset_as_num(mocker, demisto_params, cluster_tree, first_offset,
                                                          last_offset):
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(first_offset, last_offset))
    assert test_module(KAFKA, demisto_params) == 'ok'


@pytest.mark.parametrize('demisto_params, cluster_tree, expected_failure', [
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '2'}, {'some-topic': [1]},
     'Partition 2 is not assigned to kafka topic some-topic'),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '1', 'offset': 'some-bad-offset'}, {'some-topic': [1]},
     'Offset some-bad-offset is not in supported format'),
    ({'isFetch': True, 'topic': 'some-topic', 'partition': '2'}, {'some-other-topic': [1]},
     'Did not find topic some-topic in kafka topics')
])
def test_failing_test_module_with_fetch(mocker, demisto_params, cluster_tree, expected_failure):
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    with pytest.raises(DemistoException) as exception_info:
        test_module(KAFKA, demisto_params)
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
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KConsumer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(first_offset, last_offset))
    with pytest.raises(DemistoException) as exception_info:
        test_module(KAFKA, demisto_params)
    assert expected_failure in str(exception_info.value)


@pytest.mark.parametrize('demisto_args, cluster_tree', [
                        ({'include_offsets': 'false'}, {'some-topic': [1]}),
                        ({'include_offsets': 'false'}, {'some-topic': [1], 'some-other-topic': [1]}),
                        ({'include_offsets': 'false'}, {'some-topic': [2], 'some-other-topic': [1, 3]}),
                        ({'include_offsets': 'false'}, {'some-topic': [1, 2]})])
def test_print_topics_without_offsets(mocker, demisto_args, cluster_tree):
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    result = print_topics(KAFKA, demisto_args)
    for topic in cluster_tree.keys():
        topic_partitions = [{'ID': partition} for partition in cluster_tree[topic]]
        assert {'Name': topic, 'Partitions': topic_partitions} in result['Contents']


@pytest.mark.parametrize('demisto_args, first_offset, last_offset', [
                        ({'include_offsets': 'true'}, 0, 1),
                        ({'include_offsets': 'true'}, 1, 5),
                        ({'include_offsets': 'true'}, 0, 2)])
def test_print_topics_with_offsets(mocker, demisto_args, first_offset, last_offset):
    cluster_metadata = create_cluster_metadata({'some-topic': [1]})
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    mocker.patch.object(KConsumer, 'get_watermark_offsets', return_value=(first_offset, last_offset))
    result = print_topics(KAFKA, demisto_args)
    expected = {'Name': 'some-topic',
                'Partitions': [{'ID': 1, 'EarliestOffset': first_offset, 'OldestOffset': last_offset}]}
    assert expected in result['Contents']


@pytest.mark.parametrize('demisto_args', [
                        {'include_offsets': 'true'}, {'include_offsets': 'false'}])
def test_print_topics_no_topics(mocker, demisto_args):
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    assert print_topics(KAFKA, demisto_args) == 'No topics found.'


@pytest.mark.parametrize('demisto_args, cluster_tree, topic', [
                        ({'topic': 'some-topic'}, {'some-topic': [1]}, 'some-topic'),
                        ({'topic': 'some-topic'}, {'some-topic': [1], 'some-other-topic': [1]}, 'some-topic'),
                        ({'topic': 'some-topic'}, {'some-topic': [1, 2]}, 'some-topic')])
def test_fetch_partitions(mocker, demisto_args, cluster_tree, topic):
    cluster_metadata = create_cluster_metadata(cluster_tree)
    mocker.patch.object(KProducer, 'list_topics', return_value=cluster_metadata)
    result = fetch_partitions(KAFKA, demisto_args)
    assert {topic: cluster_tree[topic]} == result['Contents']


@pytest.mark.parametrize('demisto_args', [{'topic': 'some-topic'}, {'topic': None}])
def test_fetch_partitions_no_topics(mocker, demisto_args):
    mocker.patch.object(KProducer, 'list_topics', return_value=ClusterMetadata())
    with pytest.raises(DemistoException) as exception_info:
        fetch_partitions(KAFKA, demisto_args)
    assert f'Topic {demisto_args["topic"]} was not found in Kafka' in str(exception_info.value)