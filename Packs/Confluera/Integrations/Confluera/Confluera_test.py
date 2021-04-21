import json
import io
# import requests_mock


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_login(requests_mock):
    from Confluera import Client, login_command

    mock_response = util_load_json('test_data/login.json')
    requests_mock.post(
        'https://test.com/login',
        json=mock_response)

    client = Client(
        base_url="https://test.com",
        verify=False,
        proxy=False)

    username = 'Admin'
    password = 'Admin'

    response = login_command(client, username, password)

    assert response.outputs_prefix == 'Confluera.LoginData'
    assert response.outputs_key_field == 'access_token'
    assert response.outputs == mock_response


def test_fetch_detections(mocker, requests_mock):
    from Confluera import Client, fetch_detections_command

    mock_response = util_load_json('test_data/fetch_detections.json')

    args = {
        'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MTgyMzkzNjQsIm5iZiI6MTYxODIzO...',
        'hours': '24',
    }
    detections_url = 'https://test.com/ioc-detections/24'

    requests_mock.get(
        'https://test.com/ioc-detections/24',
        json=mock_response)

    client = Client(
        base_url="https://test.com",
        verify=False,
        auth=("test", "test"),
        proxy=False)

    response = fetch_detections_command(client, args, detections_url)

    assert response[0].outputs["Detections URL"] == detections_url
    assert response[1].outputs_prefix == "Confluera.Detections"
    assert response[1].outputs == mock_response


def test_fetch_progressions(mocker, requests_mock):
    from Confluera import Client, fetch_progressions_command

    mock_response = util_load_json('test_data/fetch_progressions.json')

    args = {
        'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MTgyMzkzNjQsIm5iZiI6MTYxODIzO...',
        'hours': '24',
    }
    progressions_url = 'https://test.com/ioc-detections/24'

    requests_mock.get(
        'https://test.com/trails/24',
        json=mock_response)

    client = Client(
        base_url="https://test.com",
        verify=False,
        auth=("test", "test"),
        proxy=False)

    response = fetch_progressions_command(client, args, progressions_url)

    assert response[0].outputs["Progressions URL"] == progressions_url
    assert response[1].outputs_prefix == "Confluera.Progressions"
    assert response[1].outputs == mock_response


def test_fetch_trail_details(mocker, requests_mock):
    from Confluera import Client, fetch_trail_details_command

    mock_response = util_load_json('test_data/fetch_progressions.json')

    requests_mock.get(
        'https://test.com/trails/prod_0_11_.agent-11:17869700',
        json=mock_response)

    client = Client(
        base_url="https://test.com",
        verify=False,
        auth=("test", "test"),
        proxy=False)

    args = {
        'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MTgyMzkzNjQsIm5iZiI6MTYxODIzO...',
        'trail_id': 'prod_0_11_.agent-11:17869700'
    }

    response = fetch_trail_details_command(client, args)

    assert response.outputs_prefix == "Confluera.TrailDetails"
    assert response.outputs == mock_response
