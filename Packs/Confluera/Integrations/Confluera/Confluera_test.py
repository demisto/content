''' IMPORTS '''
from CommonServerPython import *
from CommonServerUserPython import *

import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def util_mock_login(requests_mock):
    mock_response = util_load_json('test_data/login.json')
    requests_mock.post(
        'https://test.com/login',
        json=mock_response)


def test_fetch_detections(mocker, requests_mock):
    from Confluera import Client, fetch_detections_command

    util_mock_login(requests_mock)
    mock_response1 = util_load_json('test_data/fetch_detections.json')

    args = {
        'hours': '72'
    }
    detections_url = 'https://test.com/#/detections'

    requests_mock.get(
        'https://test.com/ioc-detections/72',
        json=mock_response1)

    client = Client(
        base_url="https://test.com",
        username={"identifier": "user@confluera.com"},
        password={"identifier": "userpassword"},
        verify=False,
        proxy=False)

    integration_cotext = {
        'access_token': "eFjyTwjisflSI90sfjkI",
        'expires': 19237845,
    }
    set_integration_context(integration_cotext)

    response = fetch_detections_command(client, args)

    assert response[0].outputs["Detections URL"] == detections_url
    assert response[1].outputs_prefix == "Confluera.Detections"
    assert response[1].outputs == mock_response1


def test_fetch_progressions(mocker, requests_mock):
    from Confluera import Client, fetch_progressions_command

    util_mock_login(requests_mock)
    mock_response = util_load_json('test_data/fetch_progressions.json')

    args = {
        'hours': '72'
    }
    progressions_url = 'https://test.com/#/monitor/cyber-attacks/active'

    requests_mock.get(
        'https://test.com/trails/72',
        json=mock_response)

    client = Client(
        base_url="https://test.com",
        username={"identifier": "user@confluera.com"},
        password={"identifier": "userpassword"},
        verify=False,
        proxy=False)

    response = fetch_progressions_command(client, args)

    assert response[0].outputs["Progressions URL"] == progressions_url
    assert response[1].outputs_prefix == "Confluera.Progressions"
    assert response[1].outputs == mock_response


def test_fetch_trail_details(mocker, requests_mock):
    from Confluera import Client, fetch_trail_details_command

    util_mock_login(requests_mock)
    mock_response = util_load_json('test_data/fetch_progressions.json')

    requests_mock.get(
        'https://test.com/trails/prod_0_11_.agent-11:17869700',
        json=mock_response)

    client = Client(
        base_url="https://test.com",
        username={"identifier": "user@confluera.com"},
        password={"identifier": "userpassword"},
        verify=False,
        proxy=False)

    args = {
        'trail_id': 'prod_0_11_.agent-11:17869700'
    }

    response = fetch_trail_details_command(client, args)

    assert response.outputs_prefix == "Confluera.TrailDetails"
    assert response.outputs == mock_response
