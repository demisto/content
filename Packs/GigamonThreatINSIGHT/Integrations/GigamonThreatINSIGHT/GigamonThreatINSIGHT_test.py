"""Gigamon-ThreatINSIGHT Integration for Cortex XSOAR - Unit Tests file
"""

from CommonServerPython import *
import json
import io
from datetime import datetime, timedelta
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


"""
Tests helpers
"""


def test_encode_args():
    from GigamonThreatINSIGHT import encodeArgsToURL
    args = {'arg1': 'test1', 'arg2': 2}
    url = encodeArgsToURL(args)
    assert url == "?arg1=test1&arg2=2"


"""
Tests for Sensor API related commands
"""


def test_test_module(requests_mock):
    from GigamonThreatINSIGHT import Client, SensorClient, commandTestModule

    client: SensorClient = Client.getClient('Sensors', '')
    response = commandTestModule(client)
    assert response == 'FAILING'

    mock_response = {
        'result_count': 10,
        'sensors': []
    }
    requests_mock.get('https://sensor.icebrg.io/v1/sensors', json=mock_response)

    response = commandTestModule(client)
    assert response == 'OK'


def test_get_sensors(requests_mock):
    from GigamonThreatINSIGHT import Client, SensorClient, commandGetSensors
    mock_response = util_load_json('test_data/sensors_results.json')
    requests_mock.get('https://sensor.icebrg.io/v1/sensors', json=mock_response)

    client: SensorClient = Client.getClient('Sensors', '')
    response: CommandResults = commandGetSensors(client)

    assert response.outputs_prefix == 'Insight.Sensors'
    assert response.outputs_key_field == 'sensors'
    assert response.outputs == mock_response[response.outputs_key_field]


def test_get_device_list(requests_mock):
    from GigamonThreatINSIGHT import Client, SensorClient, commandGetDevices
    mock_response = util_load_json('test_data/device_list_result.json')
    requests_mock.get('https://sensor.icebrg.io/v1/devices', json=mock_response)

    client: SensorClient = Client.getClient('Sensors', '')
    response: CommandResults = commandGetDevices(client)

    assert response.outputs_prefix == 'Insight.Devices'
    assert response.outputs_key_field == 'device_list'
    assert response.outputs == mock_response['devices'][response.outputs_key_field]


def test_get_tasks(requests_mock):
    from GigamonThreatINSIGHT import Client, SensorClient, commandGetTasks
    mock_response = util_load_json('test_data/tasks_results.json')
    requests_mock.get('https://sensor.icebrg.io/v1/pcaptasks', json=mock_response)

    client: SensorClient = Client.getClient('Sensors', '')
    response: CommandResults = commandGetTasks(client, {})

    assert response.outputs_prefix == 'Insight.Tasks'
    assert response.outputs_key_field == 'pcaptasks'
    assert response.outputs == mock_response[response.outputs_key_field]

    mock_response = util_load_json('test_data/task_result.json')
    requests_mock.get('https://sensor.icebrg.io/v1/pcaptasks/task_uuid', json=mock_response)

    client: SensorClient = Client.getClient('Sensors', '')
    response: CommandResults = commandGetTasks(client, {'task_uuid': 'task_uuid'})

    assert response.outputs_prefix == 'Insight.Tasks'
    assert response.outputs_key_field == 'pcap_task'
    assert response.outputs == mock_response[response.outputs_key_field]


def test_create_task(requests_mock):
    from GigamonThreatINSIGHT import Client, SensorClient, commandCreateTask
    requests_mock.post('https://sensor.icebrg.io/v1/pcaptasks', json="{'status': 200}")

    client: SensorClient = Client.getClient('Sensors', '')

    with pytest.raises(Exception):
        commandCreateTask(client, {})

    response: CommandResults = commandCreateTask(client, {'sensor_ids': 'test1,test2'})
    assert response.readable_output == 'Task created successfully'


"""
Tests for Detections API related commands
"""


def test_get_detections(requests_mock):
    from GigamonThreatINSIGHT import Client, DetectionClient, commandGetDetections

    mock_response = util_load_json('test_data/detections_results_large.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)

    detectionClient: DetectionClient = Client.getClient('Detections', '')
    response = commandGetDetections(detectionClient, {'include': 'rules'})

    assert response.outputs_prefix == 'Insight.Detections'
    assert response.outputs_key_field == 'detections'
    assert len(response.outputs) == 6
    for detection in response.outputs:
        assert 'rule_name' in detection
        assert 'rule_severity' in detection

    mock_response = util_load_json('test_data/detections_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)

    response = commandGetDetections(detectionClient, {"include": "rules"})

    assert response.outputs_prefix == 'Insight.Detections'
    assert response.outputs_key_field == 'detections'
    assert len(response.outputs) == 3
    for detection in response.outputs:
        assert 'rule_name' in detection
        assert 'rule_severity' in detection


def test_fetch_incidents(requests_mock):
    from GigamonThreatINSIGHT import Client, DetectionClient, commandFetchIncidents
    mock_response = util_load_json('test_data/detections_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)

    client: DetectionClient = Client.getClient('Detections', '')
    next_fetch, incidents = commandFetchIncidents(client, 'account_id', 3, {}, datetime.now() - timedelta(days=365))

    assert len(incidents) == 3
    for detection in incidents:
        assert 'name' in detection
        assert 'occurred' in detection
    assert 'last_fetch' in next_fetch
    assert next_fetch['last_fetch'] == "2022-05-31T00:00:00.000000Z"

    next_fetch, incidents = commandFetchIncidents(client, 'account_id', 3, next_fetch, datetime.now())
    assert len(incidents) == 0
    assert 'last_fetch' in next_fetch
    assert next_fetch['last_fetch'] == "2022-05-31T00:00:00.000000Z"


def test_get_detection_events(requests_mock):
    from GigamonThreatINSIGHT import Client, DetectionClient, commandGetDetectionRuleEvents

    mock_response = util_load_json('test_data/events_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/rules/rule_uuid/events', json=mock_response)

    client: DetectionClient = Client.getClient('Detections', '')

    with pytest.raises(Exception):
        response: CommandResults = commandGetDetectionRuleEvents(client, {})

    response: CommandResults = commandGetDetectionRuleEvents(client, {'rule_uuid': 'rule_uuid'})

    assert response.outputs_prefix == 'Insight.Detections'
    assert response.outputs_key_field == 'events'
    assert response.outputs == mock_response[response.outputs_key_field]


def test_create_detection_rule(requests_mock):
    from GigamonThreatINSIGHT import Client, DetectionClient, commandCreateDetectionRule
    requests_mock.post('https://detections.icebrg.io/v1/rules', json="{'status': 200}")

    client: DetectionClient = Client.getClient('Detections', '')

    with pytest.raises(Exception):
        commandCreateDetectionRule(client, {})

    response: CommandResults = commandCreateDetectionRule(client, {'run_account_uuids': 'test1,test2', 'device_ip_fields': ''})
    assert response.readable_output == 'Rule created successfully'


def test_resolve_detection(requests_mock):
    from GigamonThreatINSIGHT import Client, DetectionClient, commandResolveDetection
    requests_mock.put('https://detections.icebrg.io/v1/detections/detection_uuid/resolve', json="{'status': 200}")

    client: DetectionClient = Client.getClient('Detections', '')

    with pytest.raises(Exception):
        commandResolveDetection(client, {'resolution': 'resolution', 'resolution_comment': 'resolution_comment'})

    response: CommandResults = commandResolveDetection(client, {'detection_uuid': 'detection_uuid', 'resolution': 'resolution',
                                                                'resolution_comment': 'resolution_comment'})
    assert response.readable_output == 'Detection resolved successfully'


"""
Tests for Entity API related commands
"""


def test_get_entity_summary(requests_mock):
    from GigamonThreatINSIGHT import Client, EntityClient, commandGetEntitySummary
    mock_response = util_load_json('test_data/entity_summary_results.json')
    requests_mock.get('https://entity.icebrg.io/v1/entity/8.8.8.8/summary', json=mock_response)

    client: EntityClient = Client.getClient('Entity', '')
    response: CommandResults = commandGetEntitySummary(client, '8.8.8.8')

    assert response.outputs_prefix == 'Insight.Entity.Summary'
    assert response.outputs_key_field == 'summary'
    assert response.outputs == mock_response[response.outputs_key_field]


def test_get_entity_file(requests_mock):
    from GigamonThreatINSIGHT import Client, EntityClient, commandGetEntityFile
    mock_response = util_load_json('test_data/entity_file_results.json')
    requests_mock.get('https://entity.icebrg.io/v1/entity/725d4b987107aa0f797f2aad4daaf8cd/file', json=mock_response)

    client: EntityClient = Client.getClient('Entity', '')
    response: CommandResults = commandGetEntityFile(client, '725d4b987107aa0f797f2aad4daaf8cd')

    assert response.outputs_prefix == 'Insight.Entity.File'
    assert response.outputs_key_field == 'file'
    assert response.outputs == mock_response[response.outputs_key_field]


"""
Tests for Event API related commands
"""


def test_get_events(requests_mock):
    from GigamonThreatINSIGHT import Client, EventClient, formatEvents, commandGetEvents
    mock_response = formatEvents(util_load_json('test_data/events_results.json'), 'events')
    requests_mock.get('https://events.icebrg.io/v2/query/events', json=mock_response)

    client: EventClient = Client.getClient('Events', '')
    response: CommandResults = commandGetEvents(client, {"query": "test"})

    assert response.outputs_prefix == 'Insight.Events'
    assert response.outputs_key_field == 'events'
    assert response.outputs == mock_response[response.outputs_key_field]
    assert len(response.outputs) == 2
    for event in response.outputs:
        assert 'src_ip' in event
        assert 'src_internal' in event
        if 'sensor_ids' in event:
            assert event['sensor_ids'] == '["test"]'

    mock_response = formatEvents(util_load_json('test_data/events_results.json'), 'events')
    requests_mock.get('https://events.icebrg.io/v2/query/events', json=mock_response)

    response: CommandResults = commandGetEvents(client, {"response_type": "other", "query": "test"})

    assert response.outputs_prefix == 'Insight.Events'
    assert response.outputs_key_field == 'events'
    assert response.outputs == mock_response[response.outputs_key_field]
    assert len(response.outputs) == 2


def test_get_events_aggregates(requests_mock):
    from GigamonThreatINSIGHT import Client, EventClient, formatEvents, commandGetEvents
    mock_response = formatEvents(util_load_json('test_data/aggregations_results.json'), 'aggregations')
    requests_mock.get('https://events.icebrg.io/v2/query/events', json=mock_response)

    client: EventClient = Client.getClient('Events', '')
    response: CommandResults = commandGetEvents(client, {"response_type": "aggregations", "query": "test GROUP BY sensor_id"})

    assert response.outputs_prefix == 'Insight.Events'
    assert response.outputs_key_field == 'data'
    assert response.outputs == mock_response[response.outputs_key_field]
    assert len(response.outputs) == 1
    for aggr in response.outputs:
        assert 'sensor_id' in aggr
        assert 'count' in aggr
        assert aggr['sensor_id'] == 'test'
        assert aggr['count'] == 7

    mock_response = formatEvents(util_load_json('test_data/aggregations_results.json'), 'metadata')
    requests_mock.get('https://events.icebrg.io/v2/query/events', json=mock_response)

    response: CommandResults = commandGetEvents(client, {"response_type": "metadata", "query": "test group by sensor_id"})

    assert response.outputs_prefix == 'Insight.Events'
    assert response.outputs_key_field == 'data'
    assert response.outputs == mock_response[response.outputs_key_field]
    assert len(response.outputs) == 1
