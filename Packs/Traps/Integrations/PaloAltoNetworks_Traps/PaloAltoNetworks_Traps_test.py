import demistomock as demisto

SERVER_MOCK_URL = 'https://demisto.mock.mybrz.net/xapi/v1/'

integration_params = {
    "application_id": "bcab5b57-6ca4-43ee-a4c0-618a2246d4ac",
    "insecure": True,
    # fake data
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAyf1wyfSTygQ/Ogl/\n"
                   "B9DfMIszhnV/TwlygafjvwzruekpHDnJUQ9u+A7BD8zLAnLOaWgL94ioGlUpAXBa\n"
                   "ewC/0wIDAQABAkEAo+egaoConDkuBS5HglQfiAis2uLlV4FXBZby28jkT4pNqs/J\n"
                   "7wv9iRAjxJvV/K/GCa6wPcHqn7dN3XT1QODeQQIhAPaYlDmmqq2O+uftBm5y3ALG\n"
                   "NvFWI7OeO3l/K/I2H8cLAiEA0bFj9GBxmJWCxjk1kWoSNY3fZO9KiOqd5467KUuR\n"
                   "x1kCIH3jfOBFnqKF+L9H+N2P05Oy/z+LWySKZhBrhNLdILHrAiBLb+7OpreXNgpi\n"
                   "94fe9XLxk0WP0UpWMVl3SXDprUcXmQIgEVMV4W44YHywdmSEpzSOI+3YTedfVQzq\n"
                   "a7AVPWWb4tU=\n-----END PRIVATE KEY-----",
    "proxy": False,
    "url": "https://demisto.mock.mybrz.net"
}


def test_create_headers(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    from PaloAltoNetworks_Traps import create_headers
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    headers = create_headers(True)
    expect_headers = {
        'Content-Type': 'application/json',
        # fake data
        'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhcHBJZCI6ImJj'
                         'YWI1YjU3LTZjYTQtNDNlZS1hNGMwLTYxOGEyMjQ2ZDRhYyJ9.iM26FZt0FL6b7Eq95DMq'
                         'hoNzBCS06dPfayZTaBzFElycBbR0BSyXhmkzudOPui5NCEtyvJ3YxkpZvLK8LuIRYA'
    }
    assert headers == expect_headers


def test_parse_data_from_response(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    from PaloAltoNetworks_Traps import parse_data_from_response
    resp_obj = {
        'guid': 'd3339851f18f470182bf2bf98ad5db4b',
        'name': 'EC2AMAZ-8IEUJEN',
        'domain': 'WORKGROUP',
        'platform': 'windows',
        'status': 'active',
        'scanStatus': 'success',
        'trapsVersion': '6.1.0.13046',
        'contentVersion': '63-10484', 'ip': 'xxx.xx.xx.xxx',
        'computerSid': 'S-1-5-21-202186053-2642234773-3690463397', 'installStatus': 'installed',
        'installTime': '2019-09-05T10:51:35.000Z',
        'distributionId': {'guid': 'afbf42010b6233624ffc20ca95d51ff3'},
        'compromised': False, 'alias': None,
        'osVersion': '10.0.14393',
        'osProductType': 'server',
        'osProductName': '',
        'is64': True,
        'lastSeen': '2019-09-24T15:10:21.000Z',
        'provisioning': {'name': None, 'domain': None, 'ip': None},
        'lastUser': 'Administrator',
        'isLicensed': True,
        'vdi': 'none',
        'isolationStatus': 'isolated',
        'wsConnected': False,
        'capabilities': {
            'quarantine': True,
            'networkIsolation': True,
            'terminateProcess': True,
            'fileRetrieval': True,
            'liveTerminal': True,
            'scriptExecution': False
        }
    }
    endpoint_data = parse_data_from_response(resp_obj, 'get_endpoint_by_id')
    expected_endpoint_data = {
        'ID': 'd3339851f18f470182bf2bf98ad5db4b',
        'Name': 'EC2AMAZ-8IEUJEN',
        'Domain': 'WORKGROUP',
        'Platform': 'windows',
        'Status': 'active',
        'ScanStatus': 'success',
        'IP': 'xxx.xx.xx.xxx',
        'ComputerSid': 'S-1-5-21-202186053-2642234773-3690463397',
        'IsCompromised': False,
        'OsVersion': '10.0.14393',
        'OsProductType': 'server',
        'OsProductName': '',
        'Is64': True,
        'LastSeen': '2019-09-24T15:10:21.000Z',
        'LastUser': 'Administrator'
    }

    assert endpoint_data == expected_endpoint_data


def test_event_quarantine(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    from PaloAltoNetworks_Traps import event_quarantine
    event_id = '7dc177a4df1c41b19ca1e67e8573b6be'
    quarantine_path = f'events/{event_id}/quarantine'
    mock_resp_json = {'operationId': {'samMessageIds': ['80cf8859df7811e9acbf0245d8e950da']}}
    requests_mock.post(SERVER_MOCK_URL + quarantine_path, json=mock_resp_json)
    operations = event_quarantine(event_id)
    expected_operations = [{
        'EventID': '7dc177a4df1c41b19ca1e67e8573b6be',
        'Type': 'event-quarantine',
        'OperationID': '80cf8859df7811e9acbf0245d8e950da'
    }]
    assert expected_operations == operations


def test_endpoint_isolate(requests_mock, mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    from PaloAltoNetworks_Traps import endpoint_isolate
    endpoint_id = 'd3339851f18f470182bf2bf98ad5db4b'
    isolate_path = f'agents/{endpoint_id}/isolate'
    mock_resp_json = {'operationId': '458e2003dfb411e9acbf0245d8e950da'}
    requests_mock.post(SERVER_MOCK_URL + isolate_path, json=mock_resp_json)
    operation_obj = endpoint_isolate(endpoint_id)
    expected_operation = {
        'OperationID': '458e2003dfb411e9acbf0245d8e950da',
        'EndpointID': 'd3339851f18f470182bf2bf98ad5db4b',
        'Type': 'endpoint-isolate'
    }
    assert operation_obj == expected_operation
