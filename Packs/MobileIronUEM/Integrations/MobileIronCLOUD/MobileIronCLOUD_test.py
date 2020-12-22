import io

from pytest import raises, fixture, mark

from CommonServerPython import *

MOCK_URL = 'https://eu1.mobileiron.com'
MOCK_PARAMS = {
    'partition_id': '12345'
}


@fixture
def client():
    from MobileIronCLOUD import MobileIronCloudClient

    return MobileIronCloudClient(
        base_url=MOCK_URL,
        verify=False,
        auth=('test', 'p')
    )


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


class TestGetPartitionId:
    from MobileIronCLOUD import get_partition_id

    @staticmethod
    def test_get_partition_id_return_param(mocker, client):
        """It returns the value of partition id from params"""

        mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
        result = TestGetPartitionId.get_partition_id(client)

        assert result == '12345'

    @staticmethod
    def test_get_partition_id_return_api(mocker, requests_mock, client):
        """It returns the value from API, in case param is not defined"""

        mocker.patch.object(demisto, 'params', return_value={
            'credentials': {
                'identifier': 'useremail'
            }
        })
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={})

        mock_response = util_load_json('test_data/tenant_spaces.json')
        requests_mock.get('/api/v1/tenant/partition/device', json=mock_response)

        result = TestGetPartitionId.get_partition_id(client)

        assert result == '100001'

    @staticmethod
    def test_get_partition_id_return_stored(mocker, client):
        """
        It returns the value from storage, in case param is not defined but the value was already fetched.
        """
        mocker.patch.object(demisto, 'params', return_value={
            'credentials': {
                'identifier': 'useremail'
            }
        })
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={
            'for_user': 'useremail',
            'default_partition_id': '10101'
        })
        result = TestGetPartitionId.get_partition_id(client)
        assert result == '10101'

    @staticmethod
    def test_get_partition_id_change_user(mocker, client, requests_mock):
        """
        It will call the api again to fetch the partition id value if the api user was changed
        """
        mocker.patch.object(demisto, 'params', return_value={
            'credentials': {
                'identifier': 'useremail'
            }
        })
        mocker.patch.object(demisto, 'getIntegrationContext', return_value={
            'for_user': 'otheremail',
        })
        mock_response = util_load_json('test_data/tenant_spaces.json')
        requests_mock.get('/api/v1/tenant/partition/device', json=mock_response)

        result = TestGetPartitionId.get_partition_id(client)

        assert result == '100001'


class TestClientGetDevicesData:

    @fixture
    def prepare_mock(self, requests_mock):
        mock_response_page_one = util_load_json('test_data/get_devices_response_page.json')
        mock_response_page_two = util_load_json('test_data/get_devices_response_page2.json')
        requests_mock.register_uri('GET', f'{MOCK_URL}/api/v1/device',
                                   [{'json': mock_response_page_one, 'status_code': 200},
                                    {'json': mock_response_page_two, 'status_code': 200}])

    def test_client_get_devices_data(self, client, prepare_mock):
        """"Making sure we can page through all the results if there are multiple pages of data"""
        results = client.get_devices_data(partition_id='123', query='any')
        assert len(results) == 3

    def test_client_get_devices_data_max_fetch(self, client, prepare_mock):
        """"Making sure we can page through all the results if there are multiple pages of data"""
        results = client.get_devices_data(partition_id='123', query='any', max_fetch=2)
        assert len(results) == 2


def test_get_devices_data_command(mocker):
    from MobileIronCLOUD import execute_get_devices_data_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'query': 'mock query',
        'max_fetch': '5'
    })

    client = mocker.Mock(name='client')
    client.get_devices_data.return_value = []
    result = execute_get_devices_data_command(client)
    client.get_devices_data.assert_called_once_with(query='mock query',
                                                    max_fetch=5,
                                                    partition_id='12345')

    assert result.outputs_prefix == 'MobileIronCloud.Device'
    assert result.outputs_key_field == 'id'
    assert len(result.outputs) == 0


def test_execute_get_device_by_field_command(mocker):
    from MobileIronCLOUD import execute_get_device_by_field_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    client = mocker.Mock(name='client')
    client.get_devices_data.return_value = []
    result = execute_get_device_by_field_command(client, field_name='name_of_field', field_value='value_of_field')
    client.get_devices_data.assert_called_once_with(query='name_of_field=value_of_field',
                                                    partition_id='12345')

    assert result.outputs_prefix == 'MobileIronCloud.Device'
    assert result.outputs_key_field == 'id'
    assert result.outputs is None


def test_get_device_by_id_command(client, mocker, requests_mock):
    from MobileIronCLOUD import execute_get_device_by_id_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'device_id': '1'
    })

    mock_response = util_load_json('test_data/device_response.json')

    requests_mock.get(f'{MOCK_URL}/api/v1/device/1', json=mock_response)

    result = execute_get_device_by_id_command(client)
    assert result.outputs_prefix == 'MobileIronCloud.Device'
    assert result.outputs_key_field == 'id'
    assert result.outputs is not None


def test_execute_device_action_command(client, requests_mock, mocker):
    from MobileIronCLOUD import execute_device_action_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'device_id': 'device_id_value'
    })

    requests_mock.put('/api/v1/device/unlock', json={'errors': None, 'result': 1})

    result = execute_device_action_command(client, 'unlock')
    assert result == 'Action was performed successfully'

    requests_mock.put('/api/v1/device/unlock', json={'errors': None, 'result': 0})

    with raises(ValueError):
        execute_device_action_command(client, 'unlock')


def test_execute_send_message_command(client, requests_mock, mocker):
    from MobileIronCLOUD import execute_send_message_command

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'device_id': 'device_id_value',
        'message_type': 'push',
        'message': 'message_value',
        'subject': 'subject_value'
    })

    requests_mock.put('/api/v1/device/message', json={'errors': None, 'result': 1})

    result = execute_send_message_command(client)
    assert result == 'Message was sent successfully'

    requests_mock.put('/api/v1/device/message', json={'errors': None, 'result': 0})

    with raises(ValueError):
        execute_send_message_command(client)


def test_execute_test_module_command(client, requests_mock):
    from MobileIronCLOUD import execute_test_module_command

    mock_response = util_load_json('test_data/tenant_spaces.json')
    requests_mock.get('/api/v1/tenant/partition/device', json=mock_response)
    result = execute_test_module_command(client)
    assert result == 'ok'


def test_fetch_incidents(client, requests_mock):
    from MobileIronCLOUD import fetch_incidents, SEVERITY_HIGH

    mock_response = util_load_json('test_data/get_devices_response_page2.json')
    requests_mock.get(f'{MOCK_URL}/api/v1/device', json=mock_response)

    result = fetch_incidents(client, 'partition_id_value', 'MobileIron Cloud Device Incident', 1000)
    incident = result[0]
    assert incident['name'] == 'MobileIron Device Alert - Non Compliant Device - Out of Contact'
    assert incident['severity'] == SEVERITY_HIGH
    assert incident['type'] == 'MobileIron Cloud Device Incident'
    assert incident['rawJSON'] is not None


def test_compose_non_compliance_message():
    from MobileIronCLOUD import compose_non_compliance_message

    mock_device = {
        'complianceState': False,
        'violatedPolicies': [
            'Out of Contact',
            'Compromised'
        ]
    }
    message = compose_non_compliance_message(mock_device)
    assert message == 'Non Compliant Device - Out of Contact, Compromised'

    mock_device = {
        'complianceState': False,
        'violatedPolicies': None
    }
    message = compose_non_compliance_message(mock_device)
    assert message == 'Non Compliant Device'
