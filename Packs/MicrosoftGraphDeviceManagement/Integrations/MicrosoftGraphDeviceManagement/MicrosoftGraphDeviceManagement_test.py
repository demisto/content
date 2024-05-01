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


def test_get_managed_device_physical_memory_command(mocker):
    """
    Given:
        - device_id
    When:
        - running get_managed_device_physical_memory_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from MicrosoftGraphDeviceManagement import get_managed_device_physical_memory_command
    client = MsGraphClient(self_deployed=False, tenant_id='123', auth_and_token_url='abc', enc_key='abc', app_name='abc',
                           azure_cloud=None, use_ssl=True, proxy=False, ok_codes=(200),
                           certificate_thumbprint='abc', private_key='abc', managed_identities_client_id=None)
    response_client = {"device_id": '1'}, {'@odata.context':
                                           'https://graph.microsoft.com/v1.0/$metadata#deviceManagement/managedDevices\
                                           (id,physicalMemoryInBytes,deviceName)/$entity',
                                           'id': '1111111-1111-1111-1111-11111111',
                                           'physicalMemoryInBytes': 1, 'deviceName': 'Test'}, {"### Managed device DC1ENV11XPC01\
                                            \n|physicalMemoryInBytes|id|\n\
                                            |---|---|\n| 1 | 1111111-1111-1111-1111-11111111\
                                            |\n"}

    mocker.patch.object(client, 'get_managed_device_physical_memory', return_value=(response_client, '1'))
    mocker.patch('MicrosoftGraphDeviceManagement.build_device_object', return_value={'ID': '1111111-1111-1111-1111-11111111',
                                                                                     'Name': 'Test',
                                                                                     'PhysicalMemoryInBytes': 1})
    outputs = mocker.patch('MicrosoftGraphDeviceManagement.return_outputs')
    get_managed_device_physical_memory_command(client, {"device_id": '1'})
    assert outputs.call_args.args[0] == '### Managed device Test\n|PhysicalMemoryInBytes|\n|---|\n| 1 |\n'


def test_get_managed_device_physical_memory_command_error(mocker):
    """
    Given:
        - device_id
    When:
        - running get_managed_device_physical_memory_command
    Then:
        - The http request is called with the right arguments, and returns the right command result.
    """
    from MicrosoftGraphDeviceManagement import get_managed_device_physical_memory_command
    client = MsGraphClient(self_deployed=False, tenant_id='123', auth_and_token_url='abc', enc_key='abc', app_name='abc',
                           azure_cloud=None, use_ssl=True, proxy=False, ok_codes=(200),
                           certificate_thumbprint='abc', private_key='abc', managed_identities_client_id=None)

    mocker.patch.object(
        client,
        'get_managed_device_physical_memory',
        return_value=({"error": {"code": "ResourceNotFound"}}, '0'),
    )
    outputs = mocker.patch('MicrosoftGraphDeviceManagement.return_outputs')
    get_managed_device_physical_memory_command(client, {"device_id": '0'})
    assert outputs.call_args.args[0] == "Managed device 0 not found."


def test_list_managed_devices__with_page_size_and_limit(mocker):
    """
    Given:
        - page_size and limit
    When:
        - running list_managed_devices
    Then:
        - The http request is called with the page size value, since it should override the limit value.
    """
    client = MsGraphClient(self_deployed=False, tenant_id='tenant_id', auth_and_token_url='auth_and_token_url',
                           enc_key='enc_key', app_name='app_name', azure_cloud=None, use_ssl=True, proxy=False,
                           ok_codes=(200, 201, 202), certificate_thumbprint=None, private_key=None,
                           managed_identities_client_id=None)
    client.ms_client = mocker.Mock()
    client.ms_client.http_request.return_value = {}

    client.list_managed_devices(limit=2, page_size=1)
    assert client.ms_client.http_request.call_args[0][1] == '/deviceManagement/managedDevices?$top=1&'


def test_list_managed_devices__results_with_limit(mocker):
    """
    Given:
        - limit
    When:
        - running list_managed_devices
    Then:
        - The results are not sliced to the limit size,  since the page size overrides the limit value.
    """
    client = MsGraphClient(self_deployed=False, tenant_id='tenant_id', auth_and_token_url='auth_and_token_url',
                           enc_key='enc_key', app_name='app_name', azure_cloud=None, use_ssl=True, proxy=False,
                           ok_codes=(200, 201, 202), certificate_thumbprint=None, private_key=None,
                           managed_identities_client_id=None)
    client.ms_client = mocker.Mock()
    client.ms_client.http_request.return_value = {
        '@odata.nextLink': 'next_link',
        'value': ['device1', 'device2', 'device3']
    }

    devices, next_link, raw_response = client.list_managed_devices(
        limit=1, page_size=3, next_link='https://graph.microsoft.com/v1.0/test_link')
    assert devices == ['device1', 'device2', 'device3']
    assert next_link == 'next_link'
    assert raw_response == {'@odata.nextLink': 'next_link', 'value': ['device1', 'device2', 'device3']}


def test_list_managed_devices__with_next_link(mocker):
    """
    Given:
        - next_link
    When:
        - running list_managed_devices
    Then:
        - The http request is called with the sliced next limit link.
    """
    client = MsGraphClient(self_deployed=False, tenant_id='tenant_id', auth_and_token_url='auth_and_token_url',
                           enc_key='enc_key', app_name='app_name', azure_cloud=None, use_ssl=True, proxy=False,
                           ok_codes=(200, 201, 202), certificate_thumbprint=None, private_key=None,
                           managed_identities_client_id=None)
    client.ms_client = mocker.Mock()
    client.ms_client.http_request.return_value = {}

    client.list_managed_devices(2, 1, 'https://graph.microsoft.com/v1.0/test_link')
    assert client.ms_client.http_request.call_args[0][1] == '/test_link'
