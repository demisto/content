import json
import io
import datetime
from XMCyberIntegration import *


TEST_URL = 'https://test.com/api'

#### COMMON

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

def assert_response(response, prefix, key_field, outputs):
    assert response.outputs_prefix == prefix
    assert response.outputs_key_field == key_field
    assert response.outputs == outputs

def mock_request_and_get_xm_mock(json_path, requests_mock, url_to_mock):
    json = util_load_json(json_path)
    requests_mock.get(url_to_mock, json=json)
    return mock_requests_and_get_xm_mock(requests_mock, [{
        'json_path': json_path,
        'url_to_mock': url_to_mock
    }])

def mock_requests_and_get_xm_mock(requests_mock, mockArr):
    for mockData in mockArr:
        json = util_load_json(mockData['json_path'])
        requests_mock.get(mockData['url_to_mock'], json=json)
    return get_xm_mock()

### TESTS

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
    assert response.outputs == [{
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
        'entityType': 'Sensor',
        'entityReport': 'https://test.com/#/scenarioHub/entityReport/3110337924893579985?timeId=timeAgo_days_7'
    }]

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
    assert response.outputs == [{
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
        'entityType': 'Sensor',
        'entityReport': 'https://test.com/#/scenarioHub/entityReport/3110337924893579985?timeId=timeAgo_days_7'
    }]

def test_xmcyber_entity_get(requests_mock):
    """Tests xmcyber-entity-get command function.

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
    assert response.outputs == [{
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
        'entityType': 'Sensor',
        'entityReport': 'https://test.com/#/scenarioHub/entityReport/3110337924893579985?timeId=timeAgo_days_7'
    }]

def test_get_version(requests_mock):
    mock_url = f'{TEST_URL}{URLS.Version}'
    xm = mock_request_and_get_xm_mock('test_data/version.json', requests_mock, mock_url)

    assert_response(get_version_command(xm, {}), 'XMCyber.Version', 'system', {
        'updater': "1.4.134.11846",
        'system': "1.38.0.12821",
        'north': "1.0.3359+6496",
        'south': "2.1.966.348",
        'db': "4.2.3"
    })

def test_is_version_supported(requests_mock):
    mock_url = f'{TEST_URL}{URLS.Version}'

    valid_xm = mock_request_and_get_xm_mock('test_data/version.json', requests_mock, mock_url)
    valid_response = is_xm_version_supported_command(valid_xm, {})
    assert_response(valid_response, 'XMCyber.IsVersion', 'valid', { 'valid': True })

    invalid_xm = mock_request_and_get_xm_mock('test_data/invalid_version.json', requests_mock, mock_url)
    invalid_response = is_xm_version_supported_command(invalid_xm, {})
    assert_response(invalid_response, 'XMCyber.IsVersion', 'valid', { 'valid': False })

def test_base_url(requests_mock):
    assert_response(get_base_url(get_xm_mock(), {}), 'XMCyber', 'url', TEST_URL)

def test_fetch_incident(requests_mock):

    risk_score_mock_url = f'{TEST_URL}{URLS.Risk_Score}?timeId={DEFAULT_TIME_ID}&resolution=1'
    top_assets_at_risk_url = f'{TEST_URL}{URLS.Top_Assets_At_Risk}?timeId={DEFAULT_TIME_ID}&amountOfResults={TOP_ENTITIES}'
    choke_point_url = f'{TEST_URL}{URLS.Top_Choke_Points}?timeId={DEFAULT_TIME_ID}&amountOfResults={TOP_ENTITIES}'
    top_technique_url = f'{TEST_URL}{URLS.Techniques}?timeId={DEFAULT_TIME_ID}&page=1&pageSize={TOP_ENTITIES}'
    top_technique_previous_url = f'{TEST_URL}{URLS.Techniques}?timeId={PREVIOUS_DEFAULT_TIME_ID}&page=1&pageSize={TOP_ENTITIES}'

    xm = mock_requests_and_get_xm_mock(requests_mock, [
        { 'json_path': 'test_data/risk_score.json', 'url_to_mock': risk_score_mock_url },
        { 'json_path': 'test_data/top_assets.json', 'url_to_mock': top_assets_at_risk_url },
        { 'json_path': 'test_data/choke_point.json', 'url_to_mock': choke_point_url },
        { 'json_path': 'test_data/top_technique.json', 'url_to_mock': top_technique_url },
        { 'json_path': 'test_data/top_technique_previous.json', 'url_to_mock': top_technique_previous_url }
    ])

    xm.date_created = datetime.now()
    create_time = timestamp_to_datestring(xm.date_created.timestamp() * 1000)

    desired_response = [
        {
            'trend': 21,
            'current_grade': 'F', 
            'current_score': 41, 
            'name': 'XM Risk score', 
            'create_time': create_time,
            'type': 'XM Cyber Risk Score', 
            'severity': 'informational', 
            'linkToReport': 'https://test.com/api/#/dashboard'
        },
        {
            "entityId": "azureUser-5d49400b-bc26-4d36-8cff-640d1eeb6465",
            "entityType": "azureUser",
            "entityTypeDisplayName": "Azure User",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "azureUser",
                "displayValue": "Azure User"
            },
            "displayName": "Deployer",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "userPrincipalName",
                        "displayName": "User Principal Name",
                        "value": "deployer@domaine.model.cyberxm.com",
                        "displayValue": "deployer@domaine.model.cyberxm.com"
                    },
                    {
                        "name": "name",
                        "displayName": "User Name",
                        "value": "Deployer",
                        "displayValue": "Deployer"
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "tenantId",
                        "displayName": "Tenant ID",
                        "value": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                        "displayValue": "a23d3b89-7fd2-4579-89b7-51641b12265b"
                    }
                ]
            },
            "value": 0.53,
            "score": 0.53,
            "level": "low",
            "trend": None,
            "name": "XM Asset at risk",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/systemReport/entity?entityId=azureUser-5d49400b-bc26-4d36-8cff-640d1eeb6465&timeId=timeAgo_days_7',
            'type': 'XM Cyber Risk Score'
        },
        {
            "entityId": "azureVirtualMachine-4be55d60-136f-4410-9b0b-26f192e941ad",
            "name": "testwinvm2",
            "entityType": "azureVirtualMachine",
            "entityTypeDisplayName": "Azure Virtual Machine",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "azureVirtualMachine",
                "displayValue": "Azure Virtual Machine"
            },
            "displayName": "testwinvm2",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "name",
                        "displayName": "Virtual Machine Name",
                        "value": "testwinvm2",
                        "displayValue": "testwinvm2"
                    },
                    {
                        "name": "id",
                        "displayName": "Virtual Machine Id",
                        "value": "4be55d60-136f-4410-9b0b-26f192e941ad",
                        "displayValue": "4be55d60-136f-4410-9b0b-26f192e941ad"
                    },
                    {
                        "name": "location",
                        "displayName": "Virtual Machine Location",
                        "value": "eastus",
                        "displayValue": "eastus"
                    },
                    {
                        "name": "subscriptionId",
                        "displayName": "Subscription ID",
                        "value": "3bbab85a-c99a-4851-8e70-45d85d8378f0",
                        "displayValue": "3bbab85a-c99a-4851-8e70-45d85d8378f0"
                    },
                    {
                        "name": "resourceGroupName",
                        "displayName": "Resource Group",
                        "value": "TestResources",
                        "displayValue": "TestResources"
                    },
                    {
                        "name": "fqdn",
                        "displayName": "Fully Qualified Name",
                        "value": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/providers/Microsoft.Compute/virtualMachines/testwinvm2",
                        "displayValue": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/providers/Microsoft.Compute/virtualMachines/testwinvm2"
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "tenantId",
                        "displayName": "Tenant ID",
                        "value": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                        "displayValue": "a23d3b89-7fd2-4579-89b7-51641b12265b"
                    }
                ]
            },
            "value": 1.55,
            "score": 1.55,
            "level": "low",
            "trend": None,
            "name": "XM Asset at risk",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/systemReport/entity?entityId=azureVirtualMachine-4be55d60-136f-4410-9b0b-26f192e941ad&timeId=timeAgo_days_7',
            'type': 'XM Cyber Risk Score'
        },
        {
            "entityId": "azureVirtualMachine-9f9a1625-aa36-428c-b6bd-e9c7c476510a",
            "name": "testwinvm",
            "entityType": "azureVirtualMachine",
            "entityTypeDisplayName": "Azure Virtual Machine",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "azureVirtualMachine",
                "displayValue": "Azure Virtual Machine"
            },
            "displayName": "testwinvm",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "name",
                        "displayName": "Virtual Machine Name",
                        "value": "testwinvm",
                        "displayValue": "testwinvm"
                    },
                    {
                        "name": "id",
                        "displayName": "Virtual Machine Id",
                        "value": "9f9a1625-aa36-428c-b6bd-e9c7c476510a",
                        "displayValue": "9f9a1625-aa36-428c-b6bd-e9c7c476510a"
                    },
                    {
                        "name": "location",
                        "displayName": "Virtual Machine Location",
                        "value": "eastus",
                        "displayValue": "eastus"
                    },
                    {
                        "name": "subscriptionId",
                        "displayName": "Subscription ID",
                        "value": "3bbab85a-c99a-4851-8e70-45d85d8378f0",
                        "displayValue": "3bbab85a-c99a-4851-8e70-45d85d8378f0"
                    },
                    {
                        "name": "resourceGroupName",
                        "displayName": "Resource Group",
                        "value": "TestResources",
                        "displayValue": "TestResources"
                    },
                    {
                        "name": "fqdn",
                        "displayName": "Fully Qualified Name",
                        "value": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/providers/Microsoft.Compute/virtualMachines/testwinvm",
                        "displayValue": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/providers/Microsoft.Compute/virtualMachines/testwinvm"
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "tenantId",
                        "displayName": "Tenant ID",
                        "value": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                        "displayValue": "a23d3b89-7fd2-4579-89b7-51641b12265b"
                    }
                ]
            },
            "value": 1.91,
            "score": 1.91,
            "level": "low",
            "trend": None,
            "name": "XM Asset at risk",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/systemReport/entity?entityId=azureVirtualMachine-9f9a1625-aa36-428c-b6bd-e9c7c476510a&timeId=timeAgo_days_7',
            'type': 'XM Cyber Risk Score'
        },
        {
            "entityId": "15553084234424912589",
            "name": "USERBB21",
            "entityType": "node",
            "entityTypeDisplayName": "Sensor",
            "entitySubType": {
                "name": "osType",
                "displayName": "OS Type",
                "value": "windows",
                "displayValue": "Windows"
            },
            "displayName": "USERBB21",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "osName",
                        "displayName": "OS",
                        "value": "Windows 7 SP 1.0",
                        "displayValue": "Windows 7 SP 1.0"
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "ipv4",
                        "displayName": "Private IP Address",
                        "value": [
                            192,
                            168,
                            170,
                            133
                        ],
                        "displayValue": "192.168.170.133"
                    }
                ]
            },
            "value": 40,
            "score": 0.05,
            "level": "low",
            "trend": 20,
            "name": "XM Choke point",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/systemReport/entity?entityId=15553084234424912589&timeId=timeAgo_days_7',
            'type': 'XM Cyber Risk Score'
        },
        {
            "entityId": "872743867762485580",
            "name": "USERBB02",
            "entityType": "node",
            "entityTypeDisplayName": "Sensor",
            "entitySubType": {
                "name": "osType",
                "displayName": "OS Type",
                "value": "windows",
                "displayValue": "Windows"
            },
            "displayName": "USERBB02",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "osName",
                        "displayName": "OS",
                        "value": "Windows 7 SP 1.0",
                        "displayValue": "Windows 7 SP 1.0"
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "ipv4",
                        "displayName": "Private IP Address",
                        "value": [
                            192,
                            168,
                            170,
                            60
                        ],
                        "displayValue": "192.168.170.60"
                    }
                ]
            },
            "value": 36,
            "score": 0.05,
            "level": "low",
            "trend": 33,
            "name": "XM Choke point",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/systemReport/entity?entityId=872743867762485580&timeId=timeAgo_days_7',
            'type': 'XM Cyber Risk Score'
        },
        {
            "entityId": "file-163b4ecf80b8429583007386c77cae39",
            "name": "\\\\userbb40\\share\\script.bat",
            "entityType": "file",
            "entityTypeDisplayName": "File",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "file",
                "displayValue": "File"
            },
            "displayName": "script.bat",
            "fileHost": "USERBB40",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "path",
                        "displayName": "Path",
                        "value": "\\\\userbb40\\share\\script.bat",
                        "displayValue": "\\\\userbb40\\share\\script.bat"
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "pathHost",
                        "displayName": "File Location",
                        "value": "USERBB40",
                        "displayValue": "USERBB40"
                    }
                ]
            },
            "value": 36,
            "score": 0.05,
            "level": "low",
            "trend": 33,
            "name": "XM Choke point",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/systemReport/entity?entityId=file-163b4ecf80b8429583007386c77cae39&timeId=timeAgo_days_7',
            'type': 'XM Cyber Risk Score'
        },
        {
            "description": "Using credentials for privileged domain accounts (passwords, tokens or kerberos tickets), an attacker can move laterally within the network.\nAn authenticated administrator account can create a scheduled task, a new service, use WMI or RDP to execute code remotely.\n",
            "severity": {
                "level": "high"
            },
            "category": "User Access Management / Network Segmentation / Configuration Management",
            "mitre": [
                {
                    "name": "T1021",
                    "link": "https://attack.mitre.org/wiki/Technique/T1021"
                },
                {
                    "name": "T1075",
                    "link": "https://attack.mitre.org/wiki/Technique/T1075"
                },
                {
                    "name": "T1097",
                    "link": "https://attack.mitre.org/wiki/Technique/T1097"
                },
                {
                    "name": "T1175",
                    "link": "https://attack.mitre.org/wiki/Technique/T1175"
                },
                {
                    "name": "T1053",
                    "link": "https://attack.mitre.org/wiki/Technique/T1053"
                },
                {
                    "name": "T1035",
                    "link": "https://attack.mitre.org/wiki/Technique/T1035"
                },
                {
                    "name": "T1047",
                    "link": "https://attack.mitre.org/wiki/Technique/T1047"
                }
            ],
            "bestPractice": [
                "Implement a password management/password vault solution",
                "Use RDP's restrictedAdmin feature when connecting from trusted machines to untrusted machines. Avoid using it on untrusted machines",
                "Enforce max password age and password complexity policy",
                "Avoid using privileged domain accounts to execute services on domain devices",
                "Add privileged domain accounts to the Protected Users group",
                "Use Microsoft Protected Process Light to protect critical processes",
                "Use Microsoft Windows Defender Credential Guard when possible"
            ],
            "techniqueType": "hackingTechnique",
            "blockingParameters": [],
            "riskCategories": [
                "User Access Management",
                "Network Segmentation",
                "Configuration Management"
            ],
            "version": 1,
            "technique": "Exploit::DomainCredentials",
            "criticalAssets": 63,
            "entities": 563,
            "displayName": "Domain Credentials",
            "complexity": {
                "level": "low",
                "value": 2
            },
            "chokePoints": 116,
            "ratio": 0.0007349167094395969,
            "name": "XM Top technique",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/#/scenarioHub/systemReport/attackTechniques/Exploit::DomainCredentials?timeId=timeAgo_days_7',
            'type': 'XM Cyber Technique'
        },
        {
            "description": "Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.",
            "severity": {
                "level": "low"
            },
            "category": "User Access Management",
            "mitre": [
                {
                    "name": "T1221",
                    "link": "https://attack.mitre.org/wiki/Technique/T1221"
                }
            ],
            "bestPractice": [
                "Protect shared folders by minimizing users who have write access.",
                "Use utilities that detect or mitigate common features used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET)."
            ],
            "blockingParameters": [
                "endpoint",
                "path"
            ],
            "techniqueType": "hackingTechnique",
            "riskCategories": [
                "User Access Management"
            ],
            "version": 1,
            "technique": "taintSharedContent",
            "criticalAssets": 46,
            "entities": 360,
            "displayName": "Taint Shared Content",
            "complexity": {
                "level": "low",
                "value": 2
            },
            "chokePoints": 35,
            "ratio": 0.0017784651072878406,
            "name": "XM Top technique",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/#/scenarioHub/systemReport/attackTechniques/taintSharedContent?timeId=timeAgo_days_7',
            'type': 'XM Cyber Technique'
        },
        {
            "description": "EternalBlue is a SMB Server vulnerability allowing remote code execution on a target server by sending a specially crafted SMB packet.\nThe vulnerability became public as a part of the \"Equation Group\" tools leak and used in the notorious WannaCry attack of May 2017.\n",
            "severity": {
                "level": "critical"
            },
            "category": "Vulnerability Management",
            "mitre": [
                {
                    "name": "T1210",
                    "link": "https://attack.mitre.org/wiki/Technique/T1210"
                }
            ],
            "bestPractice": [
                "Apply appropriate patches from Microsoft",
                "Disable the outdated SMBv1 protocol (requires restart)"
            ],
            "techniqueType": "hackingTechnique",
            "blockingParameters": [],
            "riskCategories": [
                "Vulnerability Management"
            ],
            "version": 1,
            "technique": "Exploit::Ms17010",
            "criticalAssets": 43,
            "entities": 513,
            "displayName": "EternalBlue (CVE-2017-0144)",
            "complexity": {
                "level": "low",
                "value": 2
            },
            "chokePoints": 74,
            "ratio": 0.0007863072815711517,
            "name": "XM Top technique",
            "severity": 'informational',
            'create_time': create_time,
            'linkToReport': 'https://test.com/api/#/scenarioHub/systemReport/attackTechniques/Exploit::Ms17010?timeId=timeAgo_days_7',
            'type': 'XM Cyber Technique'
        }
    ]

    assert_response(fetch_incidents_command(xm, {}), 'XMCyber', 'create_time', desired_response)


