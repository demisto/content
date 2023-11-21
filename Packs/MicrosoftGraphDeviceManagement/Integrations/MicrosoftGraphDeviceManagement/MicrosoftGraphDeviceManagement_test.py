import pytest
import json
from CommonServerPython import DemistoException
from MicrosoftGraphDeviceManagement import MsGraphClient, build_device_object, try_parse_integer, find_managed_devices_command

with open('test_data/raw_device.json') as json_file:
    data: dict = json.load(json_file)
    raw_device = data.get('value')

with open('test_data/device_hr.json') as json_file:
    device_hr: dict = json.load(json_file)

with open('test_data/device.json') as json_file:
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

    with open('test_data/raw_device.json') as json_file:
        data: dict = json.load(json_file)
        raw_device = [data.get('value')]

    client = MsGraphClient(self_deployed=False, tenant_id='123', auth_and_token_url='abc', enc_key='abc', app_name='abc',
                           azure_cloud=None, use_ssl=True, proxy=False, ok_codes=(200),
                           certificate_thumbprint='abc', private_key='abc', managed_identities_client_id=None)
    mocker.patch.object(
        client,
        'find_managed_devices',
        return_value=(raw_device, data),
    )
    outputs = mocker.patch('MicrosoftGraphDeviceManagement.return_outputs')

    find_managed_devices_command(client, args=args)
    context_output = outputs.call_args.args[0]
    assert context_output is not None
    assert client.base_url == 'https://graph.microsoft.com/v1.0'


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
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

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in demisto.results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
