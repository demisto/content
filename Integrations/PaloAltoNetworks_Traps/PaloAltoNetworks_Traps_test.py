from .PaloAltoNetworks_Traps import *


def test_create_headers():
    headers = create_headers(True)
    assert headers == {'Content-Type': 'application/json',
                       'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhcHBJZCI6ImMxZjI3MWQxLWMwNjUtNDc4OC04ZjBjLTdmYjcyOGFlODZjOSJ9.hiTTE0DwLIlxBSfbjIuEGw26JwRcu-yMl6h_nNn8B6LQv5Isld--feVCgqjhFXQzfD0hrq12m4X7RieKner7jg'}


def test():
    resp_obj = {'guid': 'd3339851f18f470182bf2bf98ad5db4b', 'name': 'EC2AMAZ-8IEUJEN', 'domain': 'WORKGROUP',
                'platform': 'windows', 'status': 'active', 'scanStatus': 'success', 'trapsVersion': '6.1.0.13046',
                'contentVersion': '63-10484', 'ip': '172.31.33.227',
                'computerSid': 'S-1-5-21-202186053-2642234773-3690463397', 'installStatus': 'installed',
                'installTime': '2019-09-05T10:51:35.000Z',
                'distributionId': {'guid': 'afbf42010b6233624ffc20ca95d51ff3'}, 'compromised': False, 'alias': None,
                'osVersion': '10.0.14393', 'osProductType': 'server', 'osProductName': '', 'is64': True,
                'lastSeen': '2019-09-24T15:10:21.000Z', 'provisioning': {'name': None, 'domain': None, 'ip': None},
                'lastUser': 'Administrator', 'isLicensed': True, 'vdi': 'none', 'isolationStatus': 'isolated',
                'wsConnected': False,
                'capabilities': {'quarantine': True, 'networkIsolation': True, 'terminateProcess': True,
                                 'fileRetrieval': True, 'liveTerminal': True, 'scriptExecution': False}}
    endpoint_data, raw_data = parse_data_from_response(resp_obj, 'get_endpoint_by_id')
    expectd_endpoint_data = {'ID': 'd3339851f18f470182bf2bf98ad5db4b', 'Name': 'EC2AMAZ-8IEUJEN', 'Domain': 'WORKGROUP',
                             'Platform': 'windows', 'Status': 'active', 'IP': '172.31.33.227',
                             'ComputerSid': 'S-1-5-21-202186053-2642234773-3690463397', 'IsCompromised': False,
                             'OsVersion': '10.0.14393', 'OsProductType': 'server', 'OsProductName': '', 'Is64': True,
                             'LastSeen': '2019-09-24T15:10:21.000Z', 'LastUser': 'Administrator'}
    expected_raw_data = {'guid': 'd3339851f18f470182bf2bf98ad5db4b', 'name': 'EC2AMAZ-8IEUJEN', 'domain': 'WORKGROUP',
                          'platform': 'windows', 'status': 'active', 'scanStatus': 'success',
                          'trapsVersion': '6.1.0.13046', 'contentVersion': '63-10484', 'ip': '172.31.33.227',
                          'computerSid': 'S-1-5-21-202186053-2642234773-3690463397', 'installStatus': 'installed',
                          'installTime': '2019-09-05T10:51:35.000Z',
                          'distributionId': {'guid': 'afbf42010b6233624ffc20ca95d51ff3'}, 'compromised': False,
                          'alias': None, 'osVersion': '10.0.14393', 'osProductType': 'server', 'osProductName': '',
                          'is64': True, 'lastSeen': '2019-09-24T15:10:21.000Z',
                          'provisioning': {'name': None, 'domain': None, 'ip': None}, 'lastUser': 'Administrator',
                          'isLicensed': True, 'vdi': 'none', 'isolationStatus': 'isolated', 'wsConnected': False,
                          'capabilities': {'quarantine': True, 'networkIsolation': True, 'terminateProcess': True,
                                           'fileRetrieval': True, 'liveTerminal': True, 'scriptExecution': False}}
    assert endpoint_data == expectd_endpoint_data
    assert raw_data == expected_raw_data
