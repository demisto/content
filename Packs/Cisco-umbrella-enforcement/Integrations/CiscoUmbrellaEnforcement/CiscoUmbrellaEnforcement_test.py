from CiscoUmbrellaEnforcement import prepare_suffix, Client


def test_domains_list_suffix():
    """Unit test
            Given
            - fetch incidents command
            - command args
            When
            - mock the Clients's get token function.
            - mock the Demisto's getIntegrationContext.
            - mock the set_shaping function.
            Then
            - run the fetch incidents command using the Client
            Validate when a day has passed since last update of shaping, Then the shaping will be checked again.
            Validate That the shaping is set to new shaping.
    """
    page = '1'
    limit = '50'
    suffix = prepare_suffix(page=page, limit='')
    assert 'page=1' in suffix
    suffix = prepare_suffix(page=page, limit=limit)
    assert 'page=1' in suffix and 'limit=50' in suffix


def test_domain_event_add_command_happy_path(mocker):
    """
    Given:
    - All required and optional arguments for adding a new event.
    When:
    - Calling domain_event_add_command function.
    Then:
    - Ensure the function returns the expected result.
    """
    from CiscoUmbrellaEnforcement import domain_event_add_command
    client = Client(base_url='https://test.com', api_key='123', verify=False, proxy=False)
    args = {'alert_time': '2022-01-01T00:00:00Z',
            'device_id': '1234',
            'destination_domain': 'example.com',
            'destination_url': 'https://example.com',
            'device_version': '1.0',
            'destination_ip': '1.1.1.1',
            'event_severity': 'high',
            'event_type': 'malware',
            'event_description': 'test event',
            'file_name': 'test.exe',
            'file_hash': '1234567890abcdef',
            'source': 'test'}
    mocker.patch.object(client, '_http_request', return_value={'id': 123})
    result = domain_event_add_command(client, args)
    assert result == "New event was added successfully, The Event id is 123."


def test_domains_list_command_valid_input_params(mocker):
    """
    Given:
    - Valid input parameters.
    When:
    - Calling domains_list_command function.
    Then:
    - Ensure the function returns the expected CommandResults object.
    """
    from CiscoUmbrellaEnforcement import domains_list_command
    client = Client(base_url='https://test.com', api_key='123', verify=False, proxy=False)
    mocker.patch.object(client, 'get_domains_list', return_value=[{'id': '1', 'name': 'test.com'}])
    args = {'page': '1', 'limit': '10'}
    results = domains_list_command(client, args)
    assert results.readable_output == '### List of Domains\n|id|name|\n|---|---|\n| 1 | test.com |\n'
    assert results.outputs_prefix == 'UmbrellaEnforcement.Domains'
    assert results.outputs == [{'id': '1', 'name': 'test.com'}]


def test_domain_delete_command_with_name(mocker):
    """
    Given:
    - A domain name to delete.
    - A client object.
    When:
    - Calling the domain_delete_command function.
    Then:
    - Ensure the domain is deleted successfully.
    - Ensure the CommandResults object is returned with the correct readable_output and outputs.
    """
    from CiscoUmbrellaEnforcement import domain_delete_command
    import demistomock as demisto
    from unittest.mock import Mock
    client_mock = Mock(Client)
    client_mock.delete_domains.return_value = Mock(status_code=204)
    mocker.patch.object(demisto, 'dt', return_value={'name': 'example.com', 'IsDeleted': True})
    args = {'name': 'example.com'}
    result = domain_delete_command(client_mock, args)
    assert result.readable_output == 'example.com domain was removed from blacklist'
    assert result.outputs_prefix == 'UmbrellaEnforcement.Domains'
    assert result.outputs_key_field == 'id'
    assert result.outputs == {'name': 'example.com', 'IsDeleted': True}


def test_module_valid_api_key(mocker):
    """
    Given:
    - Valid API key.
    When:
    - Running the 'test-module' command.
    Then:
    - Ensure the function returns 'ok'.
    """
    from CiscoUmbrellaEnforcement import test_module
    client = Client(base_url='https://test.com/1.0/', api_key='valid_api_key', verify=True, proxy=False)
    mocker.patch.object(client, 'get_domains_list', return_value=[{'id': '1', 'name': 'test.com'}])
    mocker.patch.object(client, '_http_request', return_value={'data': [], 'meta': {}})
    mocker.patch.object(client, 'add_event_to_domain', return_value={'id': '123'})
    mocker.patch.object(client, 'delete_domains', return_value={'status_code': 204})
    assert test_module(client) == 'ok'


def test_umbrella_domain_event_add_valid_args(mocker):
    """
    Given:
    - Valid arguments for the 'umbrella-domain-event-add' command.
    When:
    - Running the command.
    Then:
    - Ensure the function returns a confirmation message.
    """
    import demistomock as demisto
    from CiscoUmbrellaEnforcement import main
    mocker.patch.object(demisto, 'params', return_value={
                        'url': 'https://test.com', 'cred_api_key': {'password': 'valid_api_key'}})
    mocker.patch.object(demisto, 'command', return_value='umbrella-domain-event-add')
    mocker.patch.object(demisto, 'args', return_value={
        'alert_time': '2022-01-01T00:00:00Z',
        'device_id': '123',
        'destination_domain': 'example.com',
        'destination_url': 'https://example.com',
        'device_version': '1.0',
        'destination_ip': '1.1.1.1',
        'event_severity': 'high',
        'event_type': 'malware',
        'event_description': 'Malware detected',
        'file_name': 'malware.exe',
        'file_hash': '1234567890abcdef',
        'source': 'test'
    })
    mocker.patch.object(Client, 'add_event_to_domain', return_value={'id': '123'})
    # mocker.patch('client.add_event_to_domain', return_value={'id': '123'})
    mocker.patch.object(demisto, 'results')
    main()
