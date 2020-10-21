import json
import io
from XMCyberIntegration import XM, Client, PAGE_SIZE, URLS, ip_command, hostname_command


TEST_URL = 'https://test.com/api'


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def get_xm_mock():
    client = Client(
        base_url=TEST_URL,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )
    return XM(client)


def mock_request_and_get_xm_mock(json_path, requests_mock, url_to_mock):
    json = util_load_json(json_path)
    requests_mock.get(url_to_mock, json=json)
    return get_xm_mock()

def test_affected_critical_assets_list(requests_mock):
    """Tests test_affected_critical_assets_list_command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """
    from XMCyberIntegration import affected_critical_assets_list_command
    mock_url = f'{TEST_URL}{URLS.Assets_At_Risk}?entityId=15553084234424912589&timeId=timeAgo_days_7&sort=attackComplexity&pageSize={PAGE_SIZE}&page=1'
    xm = mock_request_and_get_xm_mock('test_data/affected_assets.json', requests_mock, mock_url)

    response = affected_critical_assets_list_command(xm, {
        'entityId': '15553084234424912589'
    })

    assert response.outputs_prefix == 'XMCyber'
    assert response.outputs_key_field == 'entityId'
    assert response.outputs == [{
        'entityId': '15553084234424912589',
        'criticalAssetsAtRiskList': [
            {
                'average': 25.33,
                'minimum': 24, 
                'name': 'USERBB03'
            },
            {
                'average': 24.67,
                'minimum': 22, 
                'name': 'model-bucket-from-struts'
            }]
    }]

def test_affected_entities_list(requests_mock):
    """Tests test_affected_entities_list_command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """
    from XMCyberIntegration import affected_entities_list_command
    mock_url = f'{TEST_URL}{URLS.Entities_At_Risk}?entityId=awsUser-AIDA5HCBCYKFMAQHGI56Z&timeId=timeAgo_days_7&sort=attackComplexity&pageSize={PAGE_SIZE}&page=1'
    xm = mock_request_and_get_xm_mock('test_data/affected_entities.json', requests_mock, mock_url)

    response = affected_entities_list_command(xm, {
        'entityId': 'awsUser-AIDA5HCBCYKFMAQHGI56Z'
    })

    assert response.outputs_prefix == 'XMCyber'
    assert response.outputs_key_field == 'entityId'
    assert response.outputs == [{
        'entityId': 'awsUser-AIDA5HCBCYKFMAQHGI56Z',
        'entitiesAtRiskList': [
            {
                #'entityId': 'awsKmsKey-792168ed-fcf9-4d5c-ae31-f3de29f7e354',
                #'entityType': 'AWS KMS Key',
                'name': '792168ed-fcf9-4d5c-ae31-f3de29f7e354',
                'technique': 'AWS KMS Key Compromise'
            },
            {
                #'entityId': 'awsKmsKey-81f97e46-e80f-4a4d-a54e-1c7885c1c71d',
                #'entityType': 'AWS KMS Key',
                'name': '81f97e46-e80f-4a4d-a54e-1c7885c1c71d',
                'technique': 'AWS KMS Key Compromise'
            }]
    }]

def test_hostname(requests_mock):
    """Tests hostname_command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """

    mock_url = f'{TEST_URL}{URLS.Entities}?search=%2FCorporateDC%2Fi&page=1&pageSize={PAGE_SIZE}'
    xm = mock_request_and_get_xm_mock('test_data/hostname.json', requests_mock, mock_url)

    response = hostname_command(xm, {
        'hostname': 'CorporateDC'
    })

    assert response.outputs_prefix == 'XMCyber'
    assert response.outputs_key_field == 'entityId'
    assert response.outputs == {
        'entityId': '3110337924893579985',
        'name': 'CorporateDC',
        'affectedEntities': 29,
        'averageComplexity': 2,
        'criticalAssetsAtRisk': 14,
        'criticalAssetsAtRiskLevel': 'medium',
        'averageComplexityLevel': 'medium',
        'isAsset': True,
        'compromisingTechniques': [
            {'count': 46,'name': 'DNS Heap Overflow (CVE-2018-8626)'},
            {'count': 34, 'name': 'SIGRed (CVE-2020-1350)'}
        ],
        'entityType': 'Sensor'
    }

def test_ip(requests_mock):
    """Tests ip command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """

    mock_url = f'{TEST_URL}{URLS.Entities}?search=%2F172.0.0.1%2Fi&page=1&pageSize={PAGE_SIZE}'
    xm = mock_request_and_get_xm_mock('test_data/hostname.json', requests_mock, mock_url)

    response = ip_command(xm, {
        'ip': '172.0.0.1'
    })

    assert response.outputs_prefix == 'XMCyber'
    assert response.outputs_key_field == 'entityId'
    assert response.outputs == {
        'entityId': '3110337924893579985',
        'name': 'CorporateDC',
        'affectedEntities': 29,
        'averageComplexity': 2,
        'criticalAssetsAtRisk': 14,
        'criticalAssetsAtRiskLevel': 'medium',
        'averageComplexityLevel': 'medium',
        'isAsset': True,
        'compromisingTechniques': [
            {'count': 46,'name': 'DNS Heap Overflow (CVE-2018-8626)'},
            {'count': 34, 'name': 'SIGRed (CVE-2020-1350)'}
        ],
        'entityType': 'Sensor'
    }