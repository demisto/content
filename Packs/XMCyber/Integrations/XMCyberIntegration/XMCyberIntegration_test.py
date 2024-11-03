import json
from datetime import datetime
from XMCyberIntegration import (
    enrich_from_entity_id,
    affected_entities_list_command,
    affected_critical_assets_list_command,
    enrich_entity_from_fields,
    get_version_command,
    is_xm_version_supported_command,
    enrich_from_ip,
)
from XMCyberIntegration import (
    Client,
    XM,
    URLS,
    PAGE_SIZE,
    DEFAULT_TIME_ID,
    TOP_ENTITIES,
    PREVIOUS_DEFAULT_TIME_ID,
)
from XMCyberIntegration import (
    SEVERITY,
    XM_CYBER_INCIDENT_TYPE_ASSET,
    XM_CYBER_INCIDENT_TYPE_TECHNIQUE,
)
from XMCyberIntegration import (
    XM_CYBER_INCIDENT_TYPE_CHOKE_POINT,
    XM_CYBER_INCIDENT_TYPE_SCORE,
)
from XMCyberIntegration import fetch_incidents_command
from CommonServerPython import *


TEST_URL = "https://test.com/api"

# COMMON


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def get_xm_mock():
    client = Client(
        base_url=TEST_URL,
        verify=False,
        headers={"Authentication": "Bearer some_api_key"},
    )
    xm = XM(client)
    xm.ignore_trend = True
    return xm


def assert_response(response, prefix, key_field, outputs):
    assert response.outputs_prefix == prefix
    assert response.outputs_key_field == key_field
    assert response.outputs == outputs


def mock_request_and_get_xm_mock(json_path, requests_mock, url_to_mock):
    json = util_load_json(json_path)
    requests_mock.get(url_to_mock, json=json)
    return mock_requests_and_get_xm_mock(
        requests_mock, [{"json_path": json_path, "url_to_mock": url_to_mock}]
    )


def mock_requests_and_get_xm_mock(requests_mock, mockArr):
    for mockData in mockArr:
        json = util_load_json(mockData["json_path"])
        requests_mock.get(mockData["url_to_mock"], json=json)
    return get_xm_mock()


# TESTS


def test_affected_critical_assets_list(requests_mock):
    """Tests test_affected_critical_assets_list_command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """
    req_params = "?timeId=timeAgo_days_7&sort=attackComplexity"
    mock_url = (
        f'{TEST_URL}{URLS.Critical_Assets_At_Risk.format(entity_id="15553084234424912589")}'
        f"{req_params}&pageSize={PAGE_SIZE}&page=1"
    )
    xm = mock_request_and_get_xm_mock(
        "test_data/affected_assets.json", requests_mock, mock_url
    )

    response = affected_critical_assets_list_command(
        xm, {"entityId": "15553084234424912589"}
    )

    assert_response(
        response,
        "XMCyber.Entity",
        "id",
        [
            {
                "id": "15553084234424912589",
                "criticalAssetsAtRiskList": [
                    {"average": 25.33, "minimum": 24, "name": "USERBB03"},
                    {
                        "average": 24.67,
                        "minimum": 22,
                        "name": "model-bucket-from-struts",
                    },
                ],
            }
        ],
    )


def test_affected_entities_list(requests_mock):
    """Tests test_affected_entities_list_command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function
    with the expected output.
    """
    req_params = "?timeId=timeAgo_days_7&sort=attackComplexity"
    mock_url = (
        f'{TEST_URL}{URLS.Affected_Entities.format(entity_id="gcpVirtualMachine-8891723672015628290")}'
        f"{req_params}&pageSize={PAGE_SIZE}&page=1"
    )
    xm = mock_request_and_get_xm_mock(
        "test_data/affected_entities.json", requests_mock, mock_url
    )

    response = affected_entities_list_command(
        xm, {"entityId": "gcpVirtualMachine-8891723672015628290"}
    )

    assert_response(
        response,
        "XMCyber.Entity",
        "id",
        [
            {
                "id": "gcpVirtualMachine-8891723672015628290",
                "entitiesAtRiskList": [
                    {
                        "entityId": "gcpServiceAccount-790383063640-compute@developer.gserviceaccount.com",
                        "entityType": "GCP Service Account",
                        "name": "projects/focused-module-278310/serviceAccounts/"
                        "790383063640-compute@developer.gserviceaccount.com",
                        "technique": "GCP Service Account From Resource",
                    },
                    {
                        "entityId": "17372558283486306102",
                        "entityType": "Sensor",
                        "name": "win-instance",
                        "technique": "GCP Virtual Machine from Compromised Node",
                    },
                ],
            }
        ],
    )


def test_enrich_from_entity_id(requests_mock):
    """
    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """

    mock_url = (
        f'{TEST_URL}{URLS.Entities}?filter={{"entityId": "3110337924893579985"}}'
        f"&pageSize={PAGE_SIZE}&page=1"
    )
    xm = mock_request_and_get_xm_mock(
        "test_data/entity_id.json", requests_mock, mock_url
    )

    response = enrich_from_entity_id(xm, {"entityId": "3110337924893579985"})

    assert_response(
        response[0],
        "XMCyber.Entity",
        "id",
        [
            {
                "id": "3110337924893579985",
                "name": "CorporateDC",
                "affectedEntities": 29,
                "averageComplexity": 2,
                "criticalAssetsAtRisk": 14,
                "criticalAssetsAtRiskLevel": "medium",
                "averageComplexityLevel": "medium",
                "isAsset": True,
                "compromisingTechniques": [
                    {"count": 46, "name": "DNS Heap Overflow (CVE-2018-8626)"},
                    {"count": 34, "name": "SIGRed (CVE-2020-1350)"},
                ],
                "type": "Sensor",
                "report": "https://test.com/#/report/entity/3110337924893579985?timeId=timeAgo_days_7",
                "OS": "Windows Server 2012 R2 (DC)",
            }
        ],
    )


def test_enrich_from_fields(requests_mock):
    """
    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """

    mock_url = (
        f'{TEST_URL}{URLS.Entities}?search={{"$regex":"/CorporateDC/i"}}'
        f'&filter={{"projectId": "focused-module-278310"}}&pageSize={PAGE_SIZE}&page=1'
    )
    xm = mock_request_and_get_xm_mock("test_data/entity_id.json", requests_mock, mock_url)

    response = enrich_entity_from_fields(
        xm,
        {
            "fields": ["name", "projectId"],
            "values": ["CorporateDC", "focused-module-278310"],
        },
    )

    assert_response(
        response[0],
        "XMCyber.Entity",
        "id",
        [
            {
                "id": "3110337924893579985",
                "name": "CorporateDC",
                "affectedEntities": 29,
                "averageComplexity": 2,
                "criticalAssetsAtRisk": 14,
                "criticalAssetsAtRiskLevel": "medium",
                "averageComplexityLevel": "medium",
                "isAsset": True,
                "compromisingTechniques": [
                    {"count": 46, "name": "DNS Heap Overflow (CVE-2018-8626)"},
                    {"count": 34, "name": "SIGRed (CVE-2020-1350)"},
                ],
                "type": "Sensor",
                "report": "https://test.com/#/report/entity/3110337924893579985?timeId=timeAgo_days_7",
                "OS": "Windows Server 2012 R2 (DC)",
            }
        ],
    )


def test_ip(requests_mock):
    """Tests ip command function.

    Configures requests_mock instance to generate the appropriate search
    API response. Checks the output of the command function with the expected output.
    """

    mock_url = f'{TEST_URL}{URLS.Entities}?filter={{"ipv4Str": "172.0.0.1"}}&pageSize={PAGE_SIZE}&page=1'
    xm = mock_request_and_get_xm_mock(
        "test_data/entity_id.json", requests_mock, mock_url
    )

    response = enrich_from_ip(xm, {"ip": "172.0.0.1"})

    assert response[0].outputs_prefix == "XMCyber.Entity"
    assert response[0].outputs_key_field == "id"
    assert response[0].outputs == [
        {
            "id": "3110337924893579985",
            "name": "CorporateDC",
            "affectedEntities": 29,
            "averageComplexity": 2,
            "criticalAssetsAtRisk": 14,
            "criticalAssetsAtRiskLevel": "medium",
            "averageComplexityLevel": "medium",
            "isAsset": True,
            "compromisingTechniques": [
                {"count": 46, "name": "DNS Heap Overflow (CVE-2018-8626)"},
                {"count": 34, "name": "SIGRed (CVE-2020-1350)"},
            ],
            "type": "Sensor",
            "report": "https://test.com/#/report/entity/3110337924893579985?timeId=timeAgo_days_7",
            "OS": "Windows Server 2012 R2 (DC)",
        }
    ]


def test_get_version(requests_mock):
    mock_url = f"{TEST_URL}{URLS.Version}"
    xm = mock_request_and_get_xm_mock("test_data/version.json", requests_mock, mock_url)

    assert_response(
        get_version_command(xm, {}),
        "XMCyber.Version",
        "entityId",
        {
            "updater": "1.4.134.11846",
            "system": "1.43.0.12821",
            "north": "1.0.3359+6496",
            "south": "2.1.966.348",
            "db": "4.2.3",
        },
    )


def test_version_supported(requests_mock):
    mock_url = f"{TEST_URL}{URLS.Version}"

    valid_xm = mock_request_and_get_xm_mock(
        "test_data/version.json", requests_mock, mock_url
    )
    valid_response = is_xm_version_supported_command(valid_xm, {})
    assert_response(valid_response, "XMCyber.IsVersion", "entityId", {"valid": True})

    invalid_xm = mock_request_and_get_xm_mock(
        "test_data/invalid_version.json", requests_mock, mock_url
    )
    invalid_response = is_xm_version_supported_command(invalid_xm, {})
    assert_response(invalid_response, "XMCyber.IsVersion", "entityId", {"valid": False})


def _get_risk_score_incidents(create_time):
    return [
        {
            "trend": 21,
            "current_grade": "F",
            "current_score": 41,
            "name": "XM Cyber security score - 41",
            "create_time": create_time,
            "type": XM_CYBER_INCIDENT_TYPE_SCORE,
            "severity": SEVERITY.Low,
            "linkToReport": "https://test.com/#/dashboard",
        }
    ]


def _get_entities_incidents(create_time):
    return [
        {
            "entityId": "azureUser-5d49400b-bc26-4d36-8cff-640d1eeb6465",
            "entityType": "azureUser",
            "entityTypeDisplayName": "Azure User",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "azureUser",
                "displayValue": "Azure User",
            },
            "displayName": "Deployer",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "userPrincipalName",
                        "displayName": "User Principal Name",
                        "value": "deployer@domaine.model.cyberxm.com",
                        "displayValue": "deployer@domaine.model.cyberxm.com",
                    },
                    {
                        "name": "name",
                        "displayName": "User Name",
                        "value": "Deployer",
                        "displayValue": "Deployer",
                    },
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "tenantId",
                        "displayName": "Tenant ID",
                        "value": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                        "displayValue": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                    }
                ],
            },
            "value": 0.53,
            "score": 0.53,
            "level": "low",
            "trend": None,
            "name": "XM Cyber critical asset at risk - Deployer",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/entity/"
            "azureUser-5d49400b-bc26-4d36-8cff-640d1eeb6465?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_ASSET,
        },
        {
            "entityId": "azureVirtualMachine-4be55d60-136f-4410-9b0b-26f192e941ad",
            "entityType": "azureVirtualMachine",
            "entityTypeDisplayName": "Azure Virtual Machine",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "azureVirtualMachine",
                "displayValue": "Azure Virtual Machine",
            },
            "displayName": "testwinvm2",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "name",
                        "displayName": "Virtual Machine Name",
                        "value": "testwinvm2",
                        "displayValue": "testwinvm2",
                    },
                    {
                        "name": "id",
                        "displayName": "Virtual Machine Id",
                        "value": "4be55d60-136f-4410-9b0b-26f192e941ad",
                        "displayValue": "4be55d60-136f-4410-9b0b-26f192e941ad",
                    },
                    {
                        "name": "location",
                        "displayName": "Virtual Machine Location",
                        "value": "eastus",
                        "displayValue": "eastus",
                    },
                    {
                        "name": "subscriptionId",
                        "displayName": "Subscription ID",
                        "value": "3bbab85a-c99a-4851-8e70-45d85d8378f0",
                        "displayValue": "3bbab85a-c99a-4851-8e70-45d85d8378f0",
                    },
                    {
                        "name": "resourceGroupName",
                        "displayName": "Resource Group",
                        "value": "TestResources",
                        "displayValue": "TestResources",
                    },
                    {
                        "name": "fqdn",
                        "displayName": "Fully Qualified Name",
                        "value": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/providers/"
                        "Microsoft.Compute/virtualMachines/testwinvm2",
                        "displayValue": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/"
                        "providers/Microsoft.Compute/virtualMachines/testwinvm2",
                    },
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "tenantId",
                        "displayName": "Tenant ID",
                        "value": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                        "displayValue": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                    }
                ],
            },
            "value": 1.55,
            "score": 1.55,
            "level": "low",
            "trend": None,
            "name": "XM Cyber critical asset at risk - testwinvm2",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/entity/"
            "azureVirtualMachine-4be55d60-136f-4410-9b0b-26f192e941ad?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_ASSET,
        },
        {
            "entityId": "azureVirtualMachine-9f9a1625-aa36-428c-b6bd-e9c7c476510a",
            "entityType": "azureVirtualMachine",
            "entityTypeDisplayName": "Azure Virtual Machine",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "azureVirtualMachine",
                "displayValue": "Azure Virtual Machine",
            },
            "displayName": "testwinvm",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "name",
                        "displayName": "Virtual Machine Name",
                        "value": "testwinvm",
                        "displayValue": "testwinvm",
                    },
                    {
                        "name": "id",
                        "displayName": "Virtual Machine Id",
                        "value": "9f9a1625-aa36-428c-b6bd-e9c7c476510a",
                        "displayValue": "9f9a1625-aa36-428c-b6bd-e9c7c476510a",
                    },
                    {
                        "name": "location",
                        "displayName": "Virtual Machine Location",
                        "value": "eastus",
                        "displayValue": "eastus",
                    },
                    {
                        "name": "subscriptionId",
                        "displayName": "Subscription ID",
                        "value": "3bbab85a-c99a-4851-8e70-45d85d8378f0",
                        "displayValue": "3bbab85a-c99a-4851-8e70-45d85d8378f0",
                    },
                    {
                        "name": "resourceGroupName",
                        "displayName": "Resource Group",
                        "value": "TestResources",
                        "displayValue": "TestResources",
                    },
                    {
                        "name": "fqdn",
                        "displayName": "Fully Qualified Name",
                        "value": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources/providers"
                        "/Microsoft.Compute/virtualMachines/testwinvm",
                        "displayValue": "/subscriptions/3bbab85a-c99a-4851-8e70-45d85d8378f0/resourceGroups/TestResources"
                        "/providers/Microsoft.Compute/virtualMachines/testwinvm",
                    },
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "tenantId",
                        "displayName": "Tenant ID",
                        "value": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                        "displayValue": "a23d3b89-7fd2-4579-89b7-51641b12265b",
                    }
                ],
            },
            "value": 1.91,
            "score": 1.91,
            "level": "low",
            "trend": None,
            "name": "XM Cyber critical asset at risk - testwinvm",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/entity/"
            "azureVirtualMachine-9f9a1625-aa36-428c-b6bd-e9c7c476510a?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_ASSET,
        },
        {
            "entityId": "15553084234424912589",
            "entityType": "node",
            "entityTypeDisplayName": "Sensor",
            "entitySubType": {
                "name": "osType",
                "displayName": "OS Type",
                "value": "windows",
                "displayValue": "Windows",
            },
            "displayName": "USERBB21",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "osName",
                        "displayName": "OS",
                        "value": "Windows 7 SP 1.0",
                        "displayValue": "Windows 7 SP 1.0",
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "ipv4",
                        "displayName": "Private IP Address",
                        "value": [192, 168, 170, 133],
                        "displayValue": "192.168.170.133",
                    }
                ],
            },
            "value": 40,
            "score": 0.05,
            "level": "low",
            "trend": 20,
            "name": "XM Cyber choke point - USERBB21",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/entity/15553084234424912589?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_CHOKE_POINT,
        },
        {
            "entityId": "872743867762485580",
            "entityType": "node",
            "entityTypeDisplayName": "Sensor",
            "entitySubType": {
                "name": "osType",
                "displayName": "OS Type",
                "value": "windows",
                "displayValue": "Windows",
            },
            "displayName": "USERBB02",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "osName",
                        "displayName": "OS",
                        "value": "Windows 7 SP 1.0",
                        "displayValue": "Windows 7 SP 1.0",
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "ipv4",
                        "displayName": "Private IP Address",
                        "value": [192, 168, 170, 60],
                        "displayValue": "192.168.170.60",
                    }
                ],
            },
            "value": 36,
            "score": 0.05,
            "level": "low",
            "trend": 33,
            "name": "XM Cyber choke point - USERBB02",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/entity/872743867762485580?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_CHOKE_POINT,
        },
        {
            "entityId": "file-163b4ecf80b8429583007386c77cae39",
            "entityType": "file",
            "entityTypeDisplayName": "File",
            "entitySubType": {
                "name": "entitySubType",
                "displayName": "Entity Subtype",
                "value": "file",
                "displayValue": "File",
            },
            "displayName": "script.bat",
            "fileHost": "USERBB40",
            "entityBasicData": {
                "entityFlavorProperties": [
                    {
                        "name": "path",
                        "displayName": "Path",
                        "value": "\\\\userbb40\\share\\script.bat",
                        "displayValue": "\\\\userbb40\\share\\script.bat",
                    }
                ],
                "entityNetworkIdentifierProperties": [
                    {
                        "name": "pathHost",
                        "displayName": "File Location",
                        "value": "USERBB40",
                        "displayValue": "USERBB40",
                    }
                ],
            },
            "value": 36,
            "score": 0.05,
            "level": "low",
            "trend": 33,
            "name": "XM Cyber choke point - script.bat",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/entity/file-163b4ecf80b8429583007386c77cae39?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_CHOKE_POINT,
        },
    ]


def _get_top_techniques_incidents(create_time):
    return [
        {
            "description": "Using credentials for privileged domain accounts (passwords, tokens or kerberos tickets), "
            "an attacker can move laterally within the network.\nAn authenticated administrator account can create "
            "a scheduled task, a new service, use WMI or RDP to execute code remotely.\n",
            "category": "User Access Management / Network Segmentation / Configuration Management",
            "mitre": [
                {
                    "name": "T1021",
                    "link": "https://attack.mitre.org/wiki/Technique/T1021",
                },
                {
                    "name": "T1075",
                    "link": "https://attack.mitre.org/wiki/Technique/T1075",
                },
                {
                    "name": "T1097",
                    "link": "https://attack.mitre.org/wiki/Technique/T1097",
                },
                {
                    "name": "T1175",
                    "link": "https://attack.mitre.org/wiki/Technique/T1175",
                },
                {
                    "name": "T1053",
                    "link": "https://attack.mitre.org/wiki/Technique/T1053",
                },
                {
                    "name": "T1035",
                    "link": "https://attack.mitre.org/wiki/Technique/T1035",
                },
                {
                    "name": "T1047",
                    "link": "https://attack.mitre.org/wiki/Technique/T1047",
                },
            ],
            "bestPractice": [
                "Implement a password management/password vault solution",
                "Use RDP's restrictedAdmin feature when connecting from trusted machines to untrusted machines. Avoid using "
                "it on untrusted machines",
                "Enforce max password age and password complexity policy",
                "Avoid using privileged domain accounts to execute services on domain devices",
                "Add privileged domain accounts to the Protected Users group",
                "Use Microsoft Protected Process Light to protect critical processes",
                "Use Microsoft Windows Defender Credential Guard when possible",
            ],
            "techniqueType": "hackingTechnique",
            "blockingParameters": [],
            "riskCategories": [
                "User Access Management",
                "Network Segmentation",
                "Configuration Management",
            ],
            "version": 1,
            "technique": "Exploit::DomainCredentials",
            "criticalAssets": 63,
            "criticalAssets_trend": 0,
            "entities": 563,
            "displayName": "Domain Credentials",
            "complexity": {"level": "low", "value": 2},
            "chokePoints": 116,
            "ratio": 0.0007349167094395969,
            "name": "XM Cyber technique impact - Domain Credentials",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/technique/Exploit::DomainCredentials?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_TECHNIQUE,
            "advices": [
                {
                    "text": "Use application allow list software (e.g AppLocker) to restrict password dumping tools",
                    "type": "Remediation",
                },
                {
                    "text": "Prevent the credential from being stored in the machine memory. This usually happens due to "
                    "interactive logins, whether its from the keyboard/mouse connected to the machine, RDP, or "
                    "service account. Using Event Viewer Security logs and "
                    "looking for 4624 and 4648 events can help identify the exact reason.",
                    "type": "Remediation",
                },
                {
                    "text": "Implement a multi-factor authentication solution",
                    "type": "Remediation",
                },
                {
                    "text": "Block incoming connections to ports 445, 139, 135 and 3389",
                    "type": "Remediation",
                },
                {
                    "text": "Remove the following users from the local Administrators and Remote Desktop Users groups",
                    "type": "Remediation",
                },
                {
                    "text": "Enable Protected Process Light for LSA",
                    "type": "Remediation",
                },
                {
                    "text": "Implement Credential Guard to protect the LSA secrets",
                    "type": "Remediation",
                },
                {
                    "text": "Implement a password management/password vault solution",
                    "type": "Best Practice",
                },
                {
                    "text": "Use RDP's restrictedAdmin feature when connecting from "
                    "trusted machines to untrusted machines. Avoid using it on untrusted machines",
                    "type": "Best Practice",
                },
                {
                    "text": "Enforce max password age and password complexity policy",
                    "type": "Best Practice",
                },
                {
                    "text": "Avoid using privileged domain accounts to execute services on domain devices",
                    "type": "Best Practice",
                },
                {
                    "text": "Add privileged domain accounts to the Protected Users group",
                    "type": "Best Practice",
                },
                {
                    "text": "Use Microsoft Protected Process Light to protect critical processes",
                    "type": "Best Practice",
                },
                {
                    "text": "Use Microsoft Windows Defender Credential Guard when possible",
                    "type": "Best Practice",
                },
            ],
        },
        {
            "description": "Content stored on network drives or in other shared locations may be tainted by adding malicious "
            "programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, "
            "the malicious portion can be executed to run the adversary's code on a remote system. Adversaries may use "
            "tainted shared content to move laterally.",
            "category": "User Access Management",
            "mitre": [
                {
                    "name": "T1221",
                    "link": "https://attack.mitre.org/wiki/Technique/T1221",
                }
            ],
            "bestPractice": [
                "Protect shared folders by minimizing users who have write access.",
                "Use utilities that detect or mitigate common features used in exploitation, such as the Microsoft Enhanced "
                "Mitigation Experience Toolkit (EMET).",
            ],
            "blockingParameters": ["endpoint", "path"],
            "techniqueType": "hackingTechnique",
            "riskCategories": ["User Access Management"],
            "version": 1,
            "technique": "taintSharedContent",
            "criticalAssets": 46,
            "criticalAssets_trend": 0,
            "entities": 360,
            "displayName": "Taint Shared Content",
            "complexity": {"level": "low", "value": 2},
            "chokePoints": 35,
            "ratio": 0.0017784651072878406,
            "name": "XM Cyber technique impact - Taint Shared Content",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/technique/taintSharedContent?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_TECHNIQUE,
            "advices": [
                {
                    "text": "Remove write permissions for the following users to the specified shared folder",
                    "type": "Remediation",
                },
                {
                    "text": "Use application allow list software (e.g AppLocker) to restrict password dumping tools",
                    "type": "Remediation",
                },
                {
                    "text": "Prevent the credential from being stored in the machine memory. This usually happens due to "
                    "interactive logins, whether its from the keyboard/mouse connected to the machine, RDP, or "
                    "service account. Using Event Viewer Security logs and "
                    "looking for 4624 and 4648 events can help identify the exact reason.",
                    "type": "Remediation",
                },
                {
                    "text": "Enable Protected Process Light for LSA",
                    "type": "Remediation",
                },
                {
                    "text": "Implement Credential Guard to protect the LSA secrets",
                    "type": "Remediation",
                },
                {
                    "text": "Block LLMNR (UDP port 5355) and NetBIOS (UDP port 137) traffic "
                    "using endpoint security software on the following computers:",
                    "type": "Remediation",
                },
                {
                    "text": "Disable LLMNR (using local computer policy settings or by "
                    "group policy) and NetBIOS (by changing each interface settings) on the the following computers:",
                    "type": "Remediation",
                },
                {
                    "text": "Protect shared folders by minimizing users who have write access.",
                    "type": "Best Practice",
                },
                {
                    "text": "Use utilities that detect or mitigate common features "
                    "used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET).",
                    "type": "Best Practice",
                },
            ],
        },
        {
            "description": "EternalBlue is a SMB Server vulnerability allowing remote code execution on a target server by "
            "sending a specially crafted SMB packet.\nThe vulnerability became public as a part of "
            'the "Equation Group" tools leak and used in the notorious WannaCry attack of May 2017.\n',
            "category": "Vulnerability Management",
            "mitre": [
                {
                    "name": "T1210",
                    "link": "https://attack.mitre.org/wiki/Technique/T1210",
                }
            ],
            "bestPractice": [
                "Apply appropriate patches from Microsoft",
                "Disable the outdated SMBv1 protocol (requires restart)",
            ],
            "techniqueType": "hackingTechnique",
            "blockingParameters": [],
            "riskCategories": ["Vulnerability Management"],
            "version": 1,
            "technique": "Exploit::Ms17010",
            "criticalAssets": 43,
            "criticalAssets_trend": 0,
            "entities": 513,
            "displayName": "EternalBlue (CVE-2017-0144)",
            "complexity": {"level": "low", "value": 2},
            "chokePoints": 74,
            "ratio": 0.0007863072815711517,
            "name": "XM Cyber technique impact - EternalBlue (CVE-2017-0144)",
            "severity": SEVERITY.Low,
            "create_time": create_time,
            "linkToReport": "https://test.com/#/report/technique/Exploit::Ms17010?timeId=timeAgo_days_7",
            "type": XM_CYBER_INCIDENT_TYPE_TECHNIQUE,
            "advices": [
                {
                    "text": "Remove write permissions for the following users to the specified shared folder",
                    "type": "Remediation",
                },
                {
                    "text": "Use application allow list software (e.g AppLocker) to restrict password dumping tools",
                    "type": "Remediation",
                },
                {
                    "text": "Prevent the credential from being stored in the machine memory. This usually happens due to "
                    "interactive logins, whether its from the keyboard/mouse connected to the machine, RDP, or "
                    "service account. Using Event Viewer Security logs and "
                    "looking for 4624 and 4648 events can help identify the exact reason.",
                    "type": "Remediation",
                },
                {
                    "text": "Enable Protected Process Light for LSA",
                    "type": "Remediation",
                },
                {
                    "text": "Implement Credential Guard to protect the LSA secrets",
                    "type": "Remediation",
                },
                {
                    "text": "Block LLMNR (UDP port 5355) and NetBIOS (UDP port 137) "
                    "traffic using endpoint security software on the "
                    "following computers:",
                    "type": "Remediation",
                },
                {
                    "text": "Disable LLMNR (using local computer policy settings or by group policy) "
                    "and NetBIOS (by changing each interface settings) on the the following computers:",
                    "type": "Remediation",
                },
                {
                    "text": "Protect shared folders by minimizing users who have write access.",
                    "type": "Best Practice",
                },
                {
                    "text": "Use utilities that detect or mitigate common features "
                    "used in exploitation, such as the Microsoft Enhanced Mitigation Experience Toolkit (EMET).",
                    "type": "Best Practice",
                },
            ],
        },
    ]


def test_fetch_incident(requests_mock):

    time_id_param = f"?timeId={DEFAULT_TIME_ID}"
    page_parm = f"&page=1&pageSize={TOP_ENTITIES}"
    amount_of_result_param = f"&amountOfResults={TOP_ENTITIES}"

    risk_score_mock_url = f"{TEST_URL}{URLS.Risk_Score}{time_id_param}&resolution=1"
    top_assets_at_risk_url = (
        f"{TEST_URL}{URLS.Top_Assets_At_Risk}{time_id_param}{amount_of_result_param}"
    )
    choke_point_url = (
        f"{TEST_URL}{URLS.Top_Choke_Points}{time_id_param}{amount_of_result_param}"
    )
    top_technique_url = f"{TEST_URL}{URLS.Techniques}{time_id_param}{page_parm}"
    top_technique_previous_url = (
        f"{TEST_URL}{URLS.Techniques}?timeId={PREVIOUS_DEFAULT_TIME_ID}{page_parm}"
    )
    domain_credentials_remediation_url = f"{TEST_URL}{URLS.Techniques}/Exploit::DomainCredentials/remediation{time_id_param}"
    taint_shared_content_remediation_url = (
        f"{TEST_URL}{URLS.Techniques}/taintSharedContent/remediation{time_id_param}"
    )
    exploit_ms_remediation_url = (
        f"{TEST_URL}{URLS.Techniques}/Exploit::Ms17010/remediation{time_id_param}"
    )

    xm = mock_requests_and_get_xm_mock(
        requests_mock,
        [
            {
                "json_path": "test_data/risk_score.json",
                "url_to_mock": risk_score_mock_url,
            },
            {
                "json_path": "test_data/top_assets.json",
                "url_to_mock": top_assets_at_risk_url,
            },
            {"json_path": "test_data/choke_point.json", "url_to_mock": choke_point_url},
            {
                "json_path": "test_data/top_technique.json",
                "url_to_mock": top_technique_url,
            },
            {
                "json_path": "test_data/top_technique_previous.json",
                "url_to_mock": top_technique_previous_url,
            },
            {
                "json_path": "test_data/domain_cred_remediation.json",
                "url_to_mock": domain_credentials_remediation_url,
            },
            {
                "json_path": "test_data/taint_shared_content_remediation.json",
                "url_to_mock": taint_shared_content_remediation_url,
            },
            {
                "json_path": "test_data/taint_shared_content_remediation.json",
                "url_to_mock": exploit_ms_remediation_url,
            },
        ],
    )

    xm.date_created = datetime.now()
    create_time = timestamp_to_datestring(xm.date_created.timestamp() * 1000)

    desired_response = (
        _get_risk_score_incidents(create_time)
        + _get_entities_incidents(create_time)
        + _get_top_techniques_incidents(create_time)
    )

    x = fetch_incidents_command(xm, {})
    assert_response(x, "XMCyber", "entityId", desired_response)
