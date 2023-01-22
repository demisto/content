import pytest
import json
from CommonServerPython import DemistoException
from MicrosoftGraphDeviceManagement import MsGraphClient, build_device_object, try_parse_integer, find_managed_devices_command

with open('test_data/raw_device.json', 'r') as json_file:
    data: dict = json.load(json_file)
    raw_device = data.get('value')

with open('test_data/device_hr.json', 'r') as json_file:
    device_hr: dict = json.load(json_file)

with open('test_data/device.json', 'r') as json_file:
    device: dict = json.load(json_file)


def test_build_device_object():
    assert build_device_object(raw_device) == device


def test_try_parse_integer():
    assert try_parse_integer('8', '') == 8
    assert try_parse_integer(8, '') == 8
    with pytest.raises(DemistoException, match='parse failure'):
        try_parse_integer('a', 'parse failure')


def test_find_managed_devices_command(mocker):
    args = {'device_name': 'Managed Device Name value'}

    with open('test_data/raw_device.json', 'r') as json_file:
        data: dict = json.load(json_file)
        raw_device = [data.get('value')]

    client = MsGraphClient(False, 'tenant_id', 'auth_and_token_url', 'enc_key', 'app_name', 'base_url',
                           True, False, (200,), 'certificate_thumbprint',
                           'private_key')
    mocker.patch.object(
        client,
        'find_managed_devices',
        return_value=(raw_device, data),
    )
    outputs = mocker.patch('MicrosoftGraphDeviceManagement.return_outputs')

    find_managed_devices_command(client, args=args)
    context_output = outputs.call_args.args[0]
    assert context_output is not None


def test_test_module_command_with_managed_identities(mocker, requests_mock):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """
    from MicrosoftGraphDeviceManagement import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import demistomock as demisto

    managed_id_mocked_uri = MANAGED_IDENTITIES_TOKEN_URL.format(resource=Resources.graph,
                                                                client_id='test_client_id')

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    requests_mock.get(managed_id_mocked_uri, json=mock_token)

    params = {
        'managed_identities_client_id': 'test_client_id',
        'authentication_type': 'Azure Managed Identities'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)

    main()

    assert 'ok' in demisto.results.call_args[0][0]
