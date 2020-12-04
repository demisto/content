import json
import io


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


"""*****HELPER FUNCTIONS****"""


"""*****COMMAND FUNCTIONS****"""


def test_get_breach(requests_mock):
    """Tests darktrace-get-breach command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, get_breach_command

    # GIVEN an integration is configured to Darktrace
    mock_api_response = util_load_json('test_data/get_breach.json')
    requests_mock.get('https://mock.darktrace.com/modelbreaches?pbid=95',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 95
    args = {
        'pbid': '95',
    }

    integration_response = get_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_get_breach.json')

    # THEN the response should be returned and formatted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pbid'


def test_get_comments(requests_mock):
    """Tests darktrace-get-comments command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, get_comments_command

    # GIVEN an integration is configured and comments are desired
    mock_api_response = util_load_json('test_data/get_comments.json')
    requests_mock.get('https://mock.darktrace.com/modelbreaches/46/comments',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 46
    args = {
        'pbid': '46',
    }

    integration_response = get_comments_command(client, args)
    expected_response = util_load_json('test_data/formatted_get_comments.json')

    # THEN the comments should be returned and formatted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pid'


def test_acknowledge(requests_mock):
    """Tests darktrace-acknowledge command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, acknowledge_breach_command

    # GIVEN an integration is configured and you would like to acknowledge a breach
    mock_api_response = util_load_json('test_data/ack_success.json')
    requests_mock.post('https://mock.darktrace.com/modelbreaches/111/acknowledge?acknowledge=true', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 111
    args = {
        'pbid': '111',
    }

    integration_response = acknowledge_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_ack_success.json')

    # THEN the breach should be acknowledged, context updated, and message posted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pbid'


def test_unacknowledge(requests_mock):
    """Tests darktrace-unacknowledge command function.

    Configures requests_mock instance to generate the appropriate
    get_alerts API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, unacknowledge_breach_command

    # GIVEN an integration is configured and you would like to unacknowledge a breach
    mock_api_response = util_load_json('test_data/ack_success.json')
    requests_mock.post('https://mock.darktrace.com/modelbreaches/111/unacknowledge?unacknowledge=true', json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the desired model breach has id 111
    args = {
        'pbid': '111',
    }

    integration_response = unacknowledge_breach_command(client, args)
    expected_response = util_load_json('test_data/formatted_unack_success.json')

    # THEN the breach should be acknowledged, context updated, and message posted
    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ModelBreach'
    assert integration_response.outputs_key_field == 'pbid'


def test_fetch_incidents(requests_mock):
    """Tests the fetch-incidents command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, fetch_incidents

    # GIVEN an integration is configured and fetch incidents
    mock_response = util_load_json('test_data/fetch_breach.json')
    requests_mock.get('https://usw1-51965-01.cloud.darktrace.com/modelbreaches?minscore=0.0&starttime=1598932817000',
                      json=mock_response)

    client = Client(
        base_url='https://usw1-51965-01.cloud.darktrace.com/',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the most recent call was made on Mon, Aug 31, 2020 9 PM Pacific
    last_run = {
        'last_fetch': 1598932817000  # Mon, Aug 31, 2020 9 PM Pacific
    }

    _, integration_response = fetch_incidents(
        client=client,
        max_alerts=20,
        last_run=last_run,
        first_fetch_time='1 day ago',
        min_score=0
    )

    # THEN the relevant information will be fetched and pulled
    expected_response = util_load_json('test_data/formatted_fetch_breach.json')

    assert integration_response == expected_response
    assert len(integration_response) == 2


def test_list_similar_devices(requests_mock):
    """Tests the list-similar-devices command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, list_similar_devices_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/similar_devices.json')
    requests_mock.get('https://mock.darktrace.com/similardevices?did=1&count=2',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'did': '1',
        'max_results': '2'
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = list_similar_devices_command(client, args)
    expected_response = util_load_json('test_data/formatted_similar_devices.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.SimilarDevices'
    assert integration_response.outputs_key_field == 'did'
    assert integration_response.outputs['did'] == 1


def test_get_external_endpoint_details(requests_mock):
    """Tests the get-external-endpoint-details command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, get_external_endpoint_details_command

    # GIVEN an integration is configured and you would like to get external endpoint details
    mock_api_response = util_load_json('test_data/endpoint_details.json')
    requests_mock.get('https://mock.darktrace.com/endpointdetails?hostname=cats.com&additionalinfo=true&devices=true&score=true',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN full information is desired about a specific hostname, cats.com
    args = {
        'endpoint_type': 'hostname',
        'endpoint_value': 'cats.com',
        'additional_info': 'true',
        'devices': 'true',
        'score': 'true'
    }

    # THEN the context will be updated and information about the external endpoint will be displayed
    integration_response = get_external_endpoint_details_command(client, args)
    expected_response = util_load_json('test_data/formatted_endpoint_details.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.ExternalEndpointDetails'


def test_get_device_connection_info(requests_mock):
    """Tests the get-device-connection-info command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, get_device_connection_info_command

    # GIVEN an integration is configured and you would like to get device connection info
    mock_api_response = util_load_json('test_data/conn_info.json')
    requests_mock.get('https://mock.darktrace.com/deviceinfo?did=1&datatype=co'
                      '&showallgraphdata=false&fulldevicedetails=false',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN connection information is desired for device with id 1
    args = {
        'did': '1',
        'data_type': 'co'
    }

    # THEN the context will be updated and information to graph the device's connections will be presented
    integration_response = get_device_connection_info_command(client, args)
    expected_response = util_load_json('test_data/formatted_conn_info.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.DeviceConnectionInfo'


def test_get_device_identity_info(requests_mock):
    """Tests the get-device-identity-info command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, get_device_identity_info_command

    # GIVEN an integration is configured and you would like to get device identity info
    mock_api_response = util_load_json('test_data/id_info.json')
    requests_mock.get('https://mock.darktrace.com/devicesearch?query=osSensor',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN connection information is desired about osSensor type devices
    args = {
        'query': 'osSensor'
    }

    # THEN the context will be updated and information about the device's connections will be presented
    integration_response = get_device_identity_info_command(client, args)
    expected_response = util_load_json('test_data/formatted_id_info.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.DeviceIdentityInfo'
    assert integration_response.outputs_key_field == 'devices.did'


def test_get_entity_details(requests_mock):
    """Tests the get-entity-details command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from Darktrace import Client, get_entity_details_command

    # GIVEN an integration is configured and you would like to query for entity details
    mock_api_response = util_load_json('test_data/entity_details.json')
    requests_mock.get('https://mock.darktrace.com/details?did=1&count=10',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN a query about a device with id 1 is specified, and results 5 through 15 are desired
    args = {
        'query': 'did=1,count=10',
        'offset': '5'
    }

    # THEN the context will be updated and information about the entity is displayed
    integration_response = get_entity_details_command(client, args)
    expected_response = util_load_json('test_data/formatted_entity_details.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.EntityDetails'
