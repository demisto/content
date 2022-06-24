"""Gigamon-ThreatINSIGHT Integration for Cortex XSOAR - Unit Tests file
"""

import json
import io
from datetime import datetime, timedelta


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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


#  test for insight-get-detections, get-detection-rules
def test_get_detections(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, addDetectionRules

    mock_response = util_load_json('test_data/detections_results.json')
    requests_mock.get('https://detections.icebrg.io/v1/detections', json=mock_response)
    response = sendRequest('GET', 'Detections', 'detections')
    assert response == mock_response
    response = addDetectionRules(response)
    assert 'detections' in response
    for detection in response['detections']:
        assert 'rule_name' in detection
        assert 'rule_severity' in detection
    assert len(response['detections']) == 3


"""
Tests for Entity API related commands
"""


#  test for get-entity-summary
def test_get_entity_summary(requests_mock):
    from GigamonThreatINSIGHT import sendRequest
    mock_response = util_load_json('test_data/entity_summary_results.json')
    requests_mock.get('https://entity.icebrg.io/v1/entity/8.8.8.8/summary', json=mock_response)
    response = sendRequest('GET', 'Entity', "8.8.8.8/summary")
    assert response == mock_response


"""
Tests for Event API related commands
"""


def test_get_events(requests_mock):
    from GigamonThreatINSIGHT import sendRequest, formatEvents
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

    mock_response = util_load_json('test_data/aggregations_results.json')
    requests_mock.post('https://events.icebrg.io/v2/query/', json=mock_response)
    response = sendRequest('POST', 'Events', None, {"query": "test"})
    assert response == mock_response
    response = formatEvents(response, "aggregations")
    assert 'total' in response
    assert 'data' in response
    assert len(response['data']) == 1
    for aggr in response['data']:
        assert 'sensor_id' in aggr
        assert 'count' in aggr
        assert aggr['sensor_id'] == 'test'
        assert aggr['count'] == 7
