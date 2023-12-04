def create_client():
    from CarbonBlackEndpointStandard import Client
    client = Client(base_url='example.com',
                    verify=False,
                    proxies=1234,
                    api_secret_key="api_secret_key",
                    api_key="api_key",
                    policy_api_key="policy_api_key",
                    policy_api_secret_key="policy_api_secret_key",
                    organization_key="organization_key")
    return client


def test_get_alert_details_command(mocker):
    """
    Given:
        Alert by id to be searched
    When:
        get_alert_by_id is running
    Then:
        Assert that the output is we are expected
    """
    mocker_result = {'id': '1234', 'severity': 7, 'category': 'THREAT', 'device_username': 'demo'}
    expected_result = {
        'CarbonBlackDefense.Alert(val.id && val.id == obj.id)': {
            'id': '1234', 'severity': 7, 'category': 'THREAT', 'device_username': 'demo'
        }
    }
    client = create_client()
    mocker.patch.object(client, 'get_alert_by_id', return_value=mocker_result)
    from CarbonBlackEndpointStandard import get_alert_details_command

    command_results = get_alert_details_command(client, {'alertId': 1234})
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result


def test_device_search_command(mocker):
    """
    Given:
        Devices to be searched
    When:
        get_devices is running
    Then:
        Assert that the output is we are expected
    """
    mocker_result = {
        "results": [
            {'id': 1234, 'name': 'carbon-black-integration-endpoint', 'os': 'MAC'}
        ]
    }
    expected_result = {
        'CarbonBlackDefense.Device(val.id && val.id == obj.id)': [
            {'id': 1234, 'name': 'carbon-black-integration-endpoint', 'os': 'MAC'}
        ]
    }
    client = create_client()
    mocker.patch.object(client, 'get_devices', return_value=mocker_result)
    from CarbonBlackEndpointStandard import device_search_command

    command_results = device_search_command(client, {'device_id': '1234', 'os': 'MAC', 'status': 'sleep'})
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result


def test_find_events_command(mocker):
    """
    Given:
        Events to be searched
    When:
        get_events is running
    Then:
        Assert that the output is we are expected
    """
    mocker_result = {'job_id': '123456'}
    expected_result = {
        'CarbonBlackDefense.Events.Search(val.job_id && val.job_id == obj.job_id)': {'job_id': '123456'}
    }
    client = create_client()
    mocker.patch.object(client, 'get_events', return_value=mocker_result)
    from CarbonBlackEndpointStandard import find_events_command

    command_results = find_events_command(client, {})
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result


def test_find_processes_command(mocker):
    """
    Given:
        Processes to be searched
    When:
        get_processes is running
    Then:
        Assert that the output is we are expected
    """
    mocker_result = {'job_id': '123456'}
    expected_result = {
        'CarbonBlackDefense.Process.Search(val.job_id && val.job_id == obj.job_id)': {'job_id': '123456'}
    }
    client = create_client()
    mocker.patch.object(client, 'get_processes', return_value=mocker_result)
    from CarbonBlackEndpointStandard import find_processes_command

    command_results = find_processes_command(client, {})
    output = command_results.to_context().get('EntryContext', {})

    assert output == expected_result
