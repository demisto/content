"""Gigamon-ThreatINSIGHT Integration for Cortex XSOAR - Unit Tests file
"""

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


#  test for test_module command
def test_test_module(requests_mock):
    from GigamonThreatINSIGHT import sendRequest
    mock_response = {
        'result_count': 10,
        'sensors': []
    }
    requests_mock.get('https://sensor.icebrg.io/v1/sensors', json=mock_response)
    response = sendRequest('GET', 'Sensors', 'sensors')
    assert response == mock_response


#  test for sensor api insight_get_sensors command
def test_get_sensors(requests_mock):
    from GigamonThreatINSIGHT import sendRequest
    mock_response = util_load_json('test_data/sensors_results.json')
    requests_mock.get('https://sensor.icebrg.io/v1/sensors', json=mock_response)
    response = sendRequest('GET', 'Sensors', 'sensors')
    assert response == mock_response


def test_get_device_list(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, responseToEntry
    mock_response = util_load_json('test_data/device_list_result.json')
    requests_mock.get('https://sensor.icebrg.io/v1/devices', json=mock_response)
    response = sendRequest('GET', 'Sensors', 'devices')
    assert response == mock_response
    data, context = responseToEntry(response, 'Devices', 'Device List')
    assert len(data) == 3
    assert 'Insight.Devices' in context


def test_get_tasks(requests_mock):
    from GigamonThreatINSIGHT import commandGetTasks
    mock_response = util_load_json('test_data/tasks_results.json')
    requests_mock.get('https://sensor.icebrg.io/v1/pcaptasks', json=mock_response)
    data, context = commandGetTasks({})
    assert len(data) == 2
    assert 'Insight.Tasks' in context
    mock_response = util_load_json('test_data/task_result.json')
    requests_mock.get('https://sensor.icebrg.io/v1/pcaptasks/task_uuid', json=mock_response)
    data, context = commandGetTasks({'task_uuid': 'task_uuid'})
    assert len(data) == 1
    assert 'Insight.Tasks' in context


def test_create_task(requests_mock):
    from GigamonThreatINSIGHT import commandCreateTask
    requests_mock.post('https://sensor.icebrg.io/v1/pcaptasks', json="{'status': 200}")
    with pytest.raises(Exception):
        commandCreateTask({})
    commandCreateTask({'sensor_ids': 'test1,test2'})


"""
Tests for Detections API related commands
"""


def test_fetch_incidents(requests_mock):
    from GigamonThreatINSIGHT import fetchIncidents
    mock_response = util_load_json('test_data/detections_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)
    next_fetch, incidents = fetchIncidents('account_id', 3, {}, datetime.now() - timedelta(days=365))
    assert len(incidents) == 3
    for detection in incidents:
        assert 'name' in detection
        assert 'occurred' in detection
    assert 'last_fetch' in next_fetch
    assert next_fetch['last_fetch'] == "2022-05-31T00:00:00.000000Z"
    next_fetch, incidents = fetchIncidents('account_id', 3, next_fetch, datetime.now())
    assert len(incidents) == 0
    assert 'last_fetch' in next_fetch
    assert next_fetch['last_fetch'] == "2022-05-31T00:00:00.000000Z"


def test_get_detections(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, getDetectionsInc, addDetectionRules, commandGetDetections
    mock_response = util_load_json('test_data/detections_results_large.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)
    response = sendRequest('GET', 'Detections', 'detections', None, None)
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)
    response = getDetectionsInc(response, {'include': 'rules'})
    assert 'detections' in response
    assert len(response['detections']) == 6
    response = addDetectionRules(response)
    for detection in response['detections']:
        assert 'rule_name' in detection
        assert 'rule_severity' in detection
    mock_response = util_load_json('test_data/detections_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)
    data, context = commandGetDetections({"include": "rules"})
    assert len(data) == 3
    for detection in data:
        assert 'rule_name' in detection
        assert 'rule_severity' in detection
    assert 'Insight.Detections' in context


def test_get_detection_events(requests_mock):
    from GigamonThreatINSIGHT import commandGetDetectionRuleEvents
    mock_response = util_load_json('test_data/events_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/rules/rule_uuid/events', json=mock_response)
    with pytest.raises(Exception):
        data, context = commandGetDetectionRuleEvents({})
    data, context = commandGetDetectionRuleEvents({'rule_uuid': 'rule_uuid'})
    assert 'Insight.Detections' in context


def test_create_detection_rule(requests_mock):
    from GigamonThreatINSIGHT import commandCreateDetectionRule
    requests_mock.post('https://detections.icebrg.io/v1/rules', json="{'status': 200}")
    with pytest.raises(Exception):
        commandCreateDetectionRule({})
    commandCreateDetectionRule({'run_account_uuids': 'test1,test2', 'device_ip_fields': ''})


"""
Tests for Entity API related commands
"""


#  test for get-entity-summary
def test_get_entity_summary(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, responseToEntry
    mock_response = util_load_json('test_data/entity_summary_results.json')
    requests_mock.get('https://entity.icebrg.io/v1/entity/8.8.8.8/summary', json=mock_response)
    response = sendRequest('GET', 'Entity', "8.8.8.8/summary")
    assert response == mock_response
    data, context = responseToEntry(response, 'Entity.Summary', 'Summary')
    assert len(data) == 1
    assert 'Insight.Entity.Summary' in context


#  test for get-entity-summary
def test_get_entity_file(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, responseToEntry
    mock_response = util_load_json('test_data/entity_file_results.json')
    requests_mock.get('https://entity.icebrg.io/v1/entity/725d4b987107aa0f797f2aad4daaf8cd/file', json=mock_response)
    response = sendRequest('GET', 'Entity', "725d4b987107aa0f797f2aad4daaf8cd/file")
    assert response == mock_response
    data, context = responseToEntry(response, 'Entity.File', 'File')
    assert len(data) == 1
    assert 'Insight.Entity.File' in context


"""
Tests for Event API related commands
"""


def test_get_events(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, formatEvents, responseToEntry, commandGetEvents
    mock_response = util_load_json('test_data/events_results.json')
    requests_mock.post('https://events.icebrg.io/v2/query/', json=mock_response)
    response = sendRequest('POST', 'Events', None, {"query": "test"})
    assert response == mock_response
    response = formatEvents(response, "events")
    assert 'total' in response
    assert 'events' in response
    assert isinstance(response['events'], list)
    assert len(response['events']) == 2
    for event in response['events']:
        assert 'src_ip' in event
        assert 'src_internal' in event
        if 'sensor_ids' in event:
            assert event['sensor_ids'] == '["test"]'
    data, context = responseToEntry(response, 'Events', 'Events')
    assert len(data) == 2
    assert 'Insight.Events' in context
    mock_response = util_load_json('test_data/events_results.json')
    requests_mock.post('https://events.icebrg.io/v2/query/', json=mock_response)
    data, context = commandGetEvents({"response_type": "other", "query": "test"})
    assert 'Insight.Events' in context
    assert len(data) == 2


def test_get_events_aggregates(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, formatEvents, responseToEntry, commandGetEvents
    mock_response = util_load_json('test_data/aggregations_results.json')
    requests_mock.post('https://events.icebrg.io/v2/query/', json=mock_response)
    response = sendRequest('POST', 'Events', None, {"query": "test"})
    assert response == mock_response
    formatted_response = formatEvents(response, "aggregations")
    assert 'total' in formatted_response
    assert 'data' in formatted_response
    assert len(formatted_response['data']) == 1
    for aggr in formatted_response['data']:
        assert 'sensor_id' in aggr
        assert 'count' in aggr
        assert aggr['sensor_id'] == 'test'
        assert aggr['count'] == 7
    data, context = responseToEntry(formatted_response, 'Events', 'Data')
    assert 'Insight.Events' in context
    formatted_response = formatEvents(response, "metadata")
    assert len(data) == 1
    requests_mock.post('https://events.icebrg.io/v2/query/', json=mock_response)
    data, context = commandGetEvents({"response_type": "aggregations", "query": "group by"})
    assert 'Insight.Events' in context
    assert len(data) == 1
