import io

from pytest import raises, fixture

from CommonServerPython import *

MOCK_URL = 'https://core.mobileiron.com'
MOCK_PARAMS = {
    'admin_space_id': '1'
}


@fixture
def client():
    from MobileIronCORE import MobileIronCoreClient

    return MobileIronCoreClient(
        base_url=MOCK_URL,
        verify=False,
        auth=('test', 'p')
    )


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_validate_result():
    from MobileIronCORE import validate_action_response

    result = validate_action_response({'successful': True})
    assert result == 'Command has been executed successfully'


def test_replace_keys_in_data():
    from MobileIronCORE import replace_problematic_character_keys

    start_data = util_load_json('test_data/test_data_replace_characters.json')
    clean_data = util_load_json('test_data/test_data_replace_characters_clean.json')
    result = replace_problematic_character_keys(start_data)
    assert json.dumps(result) == json.dumps(clean_data)


def test_replace_keys_in_list_of_data():
    from MobileIronCORE import replace_problematic_character_keys

    start_data = [util_load_json('test_data/test_data_replace_characters.json')]
    clean_data = [util_load_json('test_data/test_data_replace_characters_clean.json')]
    result = replace_problematic_character_keys(start_data)
    assert json.dumps(result) == json.dumps(clean_data)


def test_validate_result_error():
    from MobileIronCORE import validate_action_response

    with raises(DemistoException):
        validate_action_response({'successful': False})


class TestClientGetDevicesData:

    @fixture
    def prepare_mock(self, requests_mock):
        mock_response_one = util_load_json('test_data/get_devices_response_page.json')
        mock_response_two = util_load_json('test_data/get_devices_response_page2.json')
        requests_mock.register_uri('GET', f'{MOCK_URL}/api/v2/devices',
                                   [{'json': mock_response_one, 'status_code': 200},
                                    {'json': mock_response_two, 'status_code': 200}])

    def test_client_get_devices_data(self, prepare_mock, client):
        response = client.get_devices_data(admin_space_id='1', query='any', fields='')
        assert len(response) == 3

    def test_client_get_devices_data_max_fetch(self, prepare_mock, client):
        response = client.get_devices_data(admin_space_id='1', query='any', fields='', max_fetch=2)
        assert len(response) == 2

    def test_client_get_devices_data_max_fetch_at_limit(self, prepare_mock, client):
        response = client.get_devices_data(admin_space_id='1', query='any', fields='', max_fetch=3)
        assert len(response) == 3


def test_execute_test_module_command(client, requests_mock):
    from MobileIronCORE import execute_test_module_command

    mock_response = util_load_json('test_data/ping.json')
    requests_mock.get(f'{MOCK_URL}/api/v2/ping', json=mock_response)

    result = execute_test_module_command(client)
    assert result == 'ok'


def test_execute_get_devices_data_command(mocker):
    """it will call the client with the correct attributes"""

    from MobileIronCORE import execute_get_devices_data_command, STANDARD_DEVICE_FIELDS

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'query': 'mock query',
        'additional_fields': 'common.other',
        'max_fetch': '1000'
    })
    client = mocker.Mock(name='client')
    client.get_devices_data.return_value = []

    result = execute_get_devices_data_command(client, query='mock query')

    client.get_devices_data.assert_called_once_with(query='mock query',
                                                    admin_space_id='1',
                                                    max_fetch=1000,
                                                    fields=f'{STANDARD_DEVICE_FIELDS},common.other')
    assert result.outputs_prefix == 'MobileIronCore.Device'
    assert result.outputs_key_field == 'common_id'
    assert result.outputs == []


def test_execute_get_device_by_uuid_command(client, mocker, requests_mock):
    from MobileIronCORE import execute_get_device_by_field_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mock_response_two = util_load_json('test_data/get_devices_response_page2.json')
    requests_mock.get(f'{MOCK_URL}/api/v2/devices', json=mock_response_two)

    result = execute_get_device_by_field_command(client, field_name='device_uuid', field_value='device_uuid_value')
    assert result.outputs_prefix == 'MobileIronCore.Device'
    assert result.outputs_key_field == 'common_id'
    assert result.outputs is not None


def test_execute_device_action_command(client, mocker, requests_mock):
    from MobileIronCORE import execute_device_action_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'device_id': 'device_id_value'
    })
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mock_response = util_load_json('test_data/action_response.json')
    requests_mock.put(f'{MOCK_URL}/api/v2/devices/wakeup', json=mock_response)

    result = execute_device_action_command(client, 'WAKE_UP')
    assert result == 'Command has been executed successfully'


def test_send_message_command(client, mocker, requests_mock):
    from MobileIronCORE import execute_send_message_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'device_id': 'device_id_value',
        'message': 'my message',
        'subject': 'my subject',
        'message_type': 'email'
    })
    spy = mocker.spy(client, 'send_message_action')
    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mock_response = util_load_json('test_data/action_response.json')
    requests_mock.post(f'{MOCK_URL}/api/v2/devices/action', json=mock_response)

    result = execute_send_message_command(client)
    assert result == 'Command has been executed successfully'
    spy.assert_called_once_with(device_id='device_id_value', admin_space_id='1',
                                message='my message', message_mode='email',
                                message_subject='my subject')


def test_fetch_incidents(client, requests_mock):
    from MobileIronCORE import fetch_incidents, SEVERITY_HIGH

    mock_response_two = util_load_json('test_data/get_devices_response_page2.json')
    requests_mock.get(f'{MOCK_URL}/api/v2/devices', json=mock_response_two)

    result = fetch_incidents(client, 'admin_space_id_value', 'MobileIron Core Device Incident', 1000)
    incident = result[0]
    assert incident['name'] == 'MobileIron Device Alert - Non-Compliant device'
    assert incident['severity'] == SEVERITY_HIGH
    assert incident['type'] == 'MobileIron Core Device Incident'
    assert incident['rawJSON'] is not None
