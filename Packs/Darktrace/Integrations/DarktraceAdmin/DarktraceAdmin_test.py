import json


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


"""*****HELPER FUNCTIONS****"""


"""*****COMMAND FUNCTIONS****"""


def test_get_similar_devices(requests_mock):
    """Tests the get_similar_devices command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, get_similar_devices_command

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
        'deviceId': '1',
        'maxResults': '2'
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = get_similar_devices_command(client, args)
    expected_response = util_load_json('test_data/formatted_similar_devices.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Device'
    assert integration_response.outputs_key_field == 'deviceId'
    assert integration_response.outputs['deviceId'] == 1


def test_get_external_endpoint_details(requests_mock):
    """Tests the get-external-endpoint-details command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, get_external_endpoint_details_command

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
        'endpointType': 'hostname',
        'endpointValue': 'cats.com',
        'additionalInfo': 'true',
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
    from DarktraceAdmin import Client, get_device_connection_info_command

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
        'deviceId': '1',
        'dataType': 'co'
    }

    # THEN the context will be updated and information to graph the device's connections will be presented
    integration_response = get_device_connection_info_command(client, args)
    expected_response = util_load_json('test_data/formatted_conn_info.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.DeviceConnectionInfo'


def test_run_advanced_search_analysis(requests_mock):
    """Tests the run_advanced_search_analysis command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, run_advanced_search_analysis_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/advanced_search_analysis.json')
    requests_mock.get('https://mock.darktrace.com/advancedsearch/api/analyze/@fields.source_ip/'
                      + 'score/eyJzZWFyY2giOiAiQHR5cGU6Y29ubiIsICJmaWVsZHMiOiBbXSwgIm9mZnNldCI6ICIwIi'
                      + 'wgInRpbWVmcmFtZSI6ICJjdXN0b20iLCAiZ3JhcGhtb2RlIjogImNvdW50IiwgInRpbWUiOiB7ImZ'
                      + 'yb20iOiAiMjAyMi0xMi0xMFQwOTowMDowMFoiLCAidG8iOiAiMjAyMi0xMi0xMVQwODowMDowMFoiL'
                      + 'CAidXNlcl9pbnRlcnZhbCI6ICIwIn0sICJtb2RlIjogIiIsICJhbmFseXplX2ZpZWxkIjogIiJ9',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'query': '@type:conn',
        'offset': 0,
        'initialDate': '2022-12-10',
        'endDate': '2022-12-11',
        'initialTime': '09:00:00',
        'endTime': '08:00:00',
        'metric': '@fields.source_ip',
        'operation': 'score'
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = run_advanced_search_analysis_command(client, args)
    expected_response = util_load_json('test_data/formatted_advanced_search_analysis.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.AdvancedSearch'


def test_post_to_watched_list(requests_mock):
    """Tests the post_to_watched_list command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, post_to_watched_list_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/watched_list_post.json')
    requests_mock.post('https://mock.darktrace.com/intelfeed',
                       json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'endpointsToWatch': '8.8.8.8',
        'description': 'Add the ip to watched domain list'
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = post_to_watched_list_command(client, args)
    expected_response = util_load_json('test_data/formatted_watched_list_post.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Endpoint'


def test_get_tagged_devices(requests_mock):
    """Tests the get_tagged_devices command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, get_tagged_devices_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/tagged_devices.json')
    requests_mock.get('https://mock.darktrace.com/tags/entities?tag=Admin&fulldevicedetails=true',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'tagName': 'Admin',
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = get_tagged_devices_command(client, args)
    expected_response = util_load_json('test_data/formatted_tagged_devices.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Device'


def test_get_tags_for_device(requests_mock):
    """Tests the get_tags_for_device command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, get_tags_for_device_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/device_tags.json')
    requests_mock.get('https://mock.darktrace.com/tags/entities?did=1',
                      json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'deviceId': '1',
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = get_tags_for_device_command(client, args)
    expected_response = util_load_json('test_data/formatted_device_tags.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Device'


def test_post_tag_to_device(requests_mock):
    """Tests the post_tag_to_device command function.

    Configures requests_mock instance to generate the appropriate
    get_alert API response, loaded from a local JSON file. Checks
    the output of the command function with the expected output.
    """
    from DarktraceAdmin import Client, post_tag_to_device_command

    # GIVEN an integration is configured and you would like to find similar devices
    mock_api_response = util_load_json('test_data/device_tag_post.json')
    requests_mock.post('https://mock.darktrace.com/tags/entities',
                       json=mock_api_response)

    client = Client(
        base_url='https://mock.darktrace.com',
        verify=False,
        auth=('examplepub', 'examplepri')
    )

    # WHEN the specified device id is 1 and there are 2 results max desired
    args = {
        'tagName': 'Admin',
        'deviceId': 2
    }

    # THEN the context will be updated and information about similar devices will be fetched and pulled
    integration_response = post_tag_to_device_command(client, args)
    expected_response = util_load_json('test_data/formatted_device_tag_post.json')

    assert integration_response.outputs == expected_response
    assert integration_response.outputs_prefix == 'Darktrace.Device'
