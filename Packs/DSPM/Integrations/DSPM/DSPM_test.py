import json
import pytest
from unittest.mock import MagicMock
from CommonServerPython import *  # noqa: F401
from DSPM import (
    get_list_of_labels,
    get_list_of_assets,
    get_asset_files_by_id,
    test_module,
    get_list_risk_findings,
    get_asset_details,
    update_risk_finding_status,
    get_data_types,
    get_data_type_findings,
    get_list_of_alerts,
    update_dspm_alert_status,
    get_risk_finding_by_id,
    validate_parameter,
    dspm_list_risk_findings_command,
    dspm_list_assets_command,
    dspm_list_data_types_findings_command,
    dspm_list_alerts_command,
    dspm_get_list_of_asset_fields_command
)


def util_load_json(path):
    """Helper function to load JSON data from a file."""
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


# Helper function to mock HTTP request
def mock_http_request(method, url_suffix, params=None, headers=None, data=None, json_data=None):
    if url_suffix == '/v1/risk-findings':
        return util_load_json('test_data/risk-findings-response.json')
    elif url_suffix.startswith('/v1/assets/id?id='):
        return {'id': 'asset1', 'name': 'Test Asset'}
    elif url_suffix.startswith('/v1/risk-findings/') and '/status' in url_suffix:
        return {'status': 'updated'}
    return {}


@pytest.fixture
def client():
    """Mock Client class."""
    client = MagicMock()
    client.fetch_risk_findings = MagicMock(return_value=util_load_json('test_data/risk-findings-response.json'))
    client.get_asset_details = MagicMock(return_value={'id': 'asset1', 'name': 'Test Asset'})
    client.update_risk_status = MagicMock(return_value=MagicMock(status_code=200, text='Update successful'))
    client.get_data_types = MagicMock(return_value=["Type1", "Type2", "Type3"])
    client.get_labels = MagicMock(return_value=["label1", "label2", "label3"])
    client.get_data_type_findings = MagicMock(return_value=[
        {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"},
        {"dataTypeName": "PII"},
        {"dataTypeName": "CREDIT_CARD"},
        {"dataTypeName": "SSN"}
    ])
    return client


def test_test_module(client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
    result = test_module(client)
    assert result == 'ok'


def test_dspm_get_risk_findings(client):
    expected_output = {
        "id": "7e9a3891-8970-4c08-961a-03f49e239d68",
        "ruleName": "Sensitive asset without storage versioning",
        "severity": "MEDIUM",
        "asset": {
            "name": "****",
            "assetId": "****"
        },
        "status": "OPEN",
        "projectId": "****",
        "cloudProvider": "AZURE",
        "cloudEnvironment": "DEVELOPMENT",
        "firstDiscovered": "2024-04-25T17:08:11.020304Z",
        "complianceStandards": {}
    }
    args = {
        "rule_name_in": "InvalidRule,AnotherInvalidRule",
        "rule_name_equal": "NotARealRule",
        "dspm_tag_key_in": "InvalidKey,AnotherInvalidKey",
        "dspm_tag_key_equal": "NotARealKey",
        "dspm_tag_value_in": "InvalidValue,AnotherInvalidValue",
        "dspm_tag_value_equal": "NotARealValue",
        "projectId_in": "InvalidProjectID123",
        "projectId_equal": "NotARealProjectID",
        "cloud_provider_in": "AWS,AZURE",
        "cloud_provider_equal": "AZURE",
        "affects_in": "SECURITY,COMPLIANCE",
        "affects_equal": "SECURITY",
        "status_in": "OPEN",
        "status_equal": "OPEN",
        "sort": "status,desc"
    }
    result = get_list_risk_findings(client, args, page=0)
    finding = result[0]  # type: ignore

    assert isinstance(result, List)
    assert expected_output == finding

    # Check the structure of one finding
    required_keys = [
        'id', 'ruleName', 'severity', 'asset',
        'status', 'projectId', 'cloudProvider', 'cloudEnvironment',
        'firstDiscovered', 'complianceStandards'
    ]
    assert all(key in finding for key in required_keys)


def test_dspm_get_risk_findings_with_valid_args(client):
    expected_output = {
        "id": "7e9a3891-8970-4c08-961a-03f49e239d68",
        "ruleName": "Sensitive asset without storage versioning",
        "severity": "MEDIUM",
        "asset": {
            "name": "****",
            "assetId": "****"
        },
        "status": "OPEN",
        "projectId": "****",
        "cloudProvider": "AZURE",
        "cloudEnvironment": "DEVELOPMENT",
        "firstDiscovered": "2024-04-25T17:08:11.020304Z",
        "complianceStandards": {}
    }
    args = {
        "cloud_provider_in": "AWS,AZURE",
        "affects_in": "SECURITY,COMPLIANCE",
        "status_in": "OPEN,CLOSED",
        "sort": "records,asc"
    }
    result = get_list_risk_findings(client, args, page=0)

    assert isinstance(result, List)
    assert result[0] == expected_output

    args = {
        "cloud_provider_equal": "AWS",
        "affects_equal": "SECURITY",
        "status_equal": "OPEN",
        "sort": "records,desc"
    }
    result = get_list_risk_findings(client, args, page=0)

    assert isinstance(result, List)
    assert result[0] == expected_output


def test_dspm_get_risk_findings_with_invalid_args(client):

    test_cases = [
        ({"cloud_provider_in": "AWS,AZURE12"}, 'This "AZURE12" cloudProvider is not supported'),
        ({"cloud_provider_equal": "INVALID"}, 'This "INVALID" cloudProvider is not supported'),
        ({"affects_in": "SECURITY,INVALID"}, 'This "INVALID" affects is not supported'),
        ({"affects_equal": "WRONG"}, 'This "WRONG" affects is not supported'),
        ({"status_in": "INVALID,CLOSED"}, 'This "INVALID" status is not supported'),
        ({"status_equal": "IN"}, 'This "IN" status is not supported'),
        ({"sort": "records,wrongOrder"}, 'This "records,wrongOrder" sorting order is not supported'),
    ]

    # Iterate over the test cases
    for args, expected_error in test_cases:
        with pytest.raises(ValueError, match=expected_error):
            get_list_risk_findings(client, args, 0)


def test_get_list_of_assets_with_valid_args(client):
    mock_response = [
        {
            "id": "asset2",
            "projectId": "project1",
            "projectName": "Project One",
            "name": "Asset One",
            "cloudProvider": "GCP",
            "cloudEnvironment": "TESTING",
            "serviceType": "UNMANAGED_GCP_MS_SQL",
            "lifecycle": "RUNNING",
            "openRisksCount": 5,
            "openAlertsCount": 3,
            "encrypted": True,
            "openToWorld": False,
            "tags": {"example_tag_key": "example_tag_value"},
            "assetDigTags": [
                {"digTagId": 1, "key": "tag1", "value": "value1"},
                {"digTagId": 2, "key": "tag2", "value": "value2"}
            ]
        }]
    client.get_asset_lists = MagicMock(return_value=mock_response)

    args = {
        "cloud_provider_in": "AWS,AZURE",
        "service_type_in": "EFS,RDS",
        "lifecycle_in": "RUNNING,STOPPED",
        "sort": "status,DESC"
    }
    result = get_list_of_assets(client, args, page=0)

    assert isinstance(result, List)
    assert result[0].get('id') == "asset2"

    args = {
        "cloud_provider_equal": "AWS",
        "service_type_equal": "RDS",
        "lifecycle_equal": "RUNNING",
        "sort": "status,ASC"
    }
    result = get_list_of_assets(client, args, page=0)

    assert isinstance(result, List)
    assert result[0].get('id') == "asset2"


def test_get_list_of_assets_with_invalid_args(client):
    # List of invalid args and their expected error messages
    invalid_test_cases = [
        ({"cloud_provider_in": "INVALID_CLOUD_PROVIDER"}, 'This "INVALID_CLOUD_PROVIDER" cloudProvider is not supported'),
        ({"service_type_in": "INVALID_SERVICE_TYPE"}, 'This "INVALID_SERVICE_TYPE" serviceType is not supported'),
        ({"lifecycle_in": "INVALID_LIFECYCLE"}, 'This "INVALID_LIFECYCLE" lifecycle is not supported'),
        ({"sort": "invalid_sort_order"}, 'This "invalid_sort_order" sorting order is not supported'),
    ]

    # Loop through each invalid test case
    for invalid_args, expected_error in invalid_test_cases:
        with pytest.raises(ValueError, match=expected_error):
            get_list_of_assets(client, invalid_args, page=0)


def test_get_data_type_findings_with_valid_args(client):
    args = {"cloud_provider_in": "AWS,AZURE", "service_type_in": "DYNAMODB,RDS",
            "lifecycle_in": "DELETED,STOPPED", "sort": "records,DESC"}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    assert len(result) == 4

    args = {"cloud_provider_equal": "AWS", "service_type_equal": "DYNAMODB",
            "lifecycle_equal": "DELETED", "sort": "records,ASC"}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    assert len(result) == 4


def test_get_data_type_findings_with_invalid_args(client):
    # List of invalid args and their expected error messages
    invalid_test_cases = [
        ({"cloud_provider_in": "INVALID_CLOUD_PROVIDER"}, 'This "INVALID_CLOUD_PROVIDER" cloudProvider is not supported'),
        ({"service_type_in": "INVALID_SERVICE_TYPE"}, 'This "INVALID_SERVICE_TYPE" serviceType is not supported'),
        ({"lifecycle_in": "INVALID_LIFECYCLE"}, 'This "INVALID_LIFECYCLE" lifecycle is not supported'),
        ({"sort": "invalid_sort_order"}, 'This "invalid_sort_order" sorting order is not supported'),
    ]

    # Loop through each invalid test case
    for invalid_args, expected_error in invalid_test_cases:
        with pytest.raises(ValueError, match=expected_error):
            get_data_type_findings(client, invalid_args, page=0)


def test_get_list_of_alerts_with_valid_args(client):
    mock_response = [
        {
            "id": "274314608",
            "detectionTime": "2024-02-02T08:02:49.15636Z",
            "policyName": "Data asset transferred to foreign project",
            "assetName": "bpachauli-flowlog",
            "assetLabels": [
                {
                    "label": {
                        "id": 270802756,
                        "name": "Sensitive",
                                "description": "Sensitive information",
                                "color": "34A49A",
                                "prettyName": "Sensitive"
                    },
                    "connectedBy": "SYSTEM"
                }
            ],
            "cloudProvider": "AWS",
            "destinationProjects": {
                "188619942792": "Redlock"
            },
            "cloudEnvironment": "PRODUCTION",
            "policySeverity": "HIGH",
            "policyCategoryType": "ATTACK",
            "status": "UNIMPORTANT",
            "eventActor": "PrismaCloudReadWriteRoleWithDLP",
            "eventUserAgent": "[aws-sdk-java/1.12.565 Linux]",
            "eventActionMedium": "SDK",
            "eventSource": "*.**.**.***",
            "policyFrameWorks": [
                "MITRE-T1074",
                "MITRE-T1537"
            ],
            "eventRawData": ""
        }
    ]
    client.get_alerts_list = MagicMock(return_value=mock_response)

    args = {
        "cloud_provider_in": "AWS,AZURE",
        "cloud_environment_in": "DEVELOPMENT,STAGING",
        "policy_severity_in": "MEDIUM,LOW",
        "category_type_in": "ATTACK,FIRST_MOVE",
        "status_in": "CLOSED,OPEN",
        "sort": "status,DESC"
    }
    result = get_list_of_alerts(client, args, 0)

    assert isinstance(result, List)
    assert result[0].get('id') == "274314608"

    args = {
        "cloud_provider_equal": "AWS",
        "cloud_environment_equal": "STAGING",
        "policy_severity_equal": "MEDIUM",
        "category_type_equal": "FIRST_MOVE",
        "status_equal": "OPEN",
        "sort": "status,ASC"
    }
    result = get_list_of_alerts(client, args, 0)

    assert isinstance(result, List)
    assert result[0].get('id') == "274314608"


def test_get_list_of_alerts_with_invalid_args(client):
    mock_response = [
        {
            "id": "274314608",
            "detectionTime": "2024-02-02T08:02:49.15636Z",
            "policyName": "Data asset transferred to foreign project",
            "assetName": "bpachauli-flowlog",
            "assetLabels": [
                {
                    "label": {
                        "id": 270802756,
                        "name": "Sensitive",
                                "description": "Sensitive information",
                                "color": "34A49A",
                                "prettyName": "Sensitive"
                    },
                    "connectedBy": "SYSTEM"
                }
            ],
            "cloudProvider": "AWS",
            "destinationProjects": {
                "188619942792": "Redlock"
            },
            "cloudEnvironment": "PRODUCTION",
            "policySeverity": "HIGH",
            "policyCategoryType": "ATTACK",
            "status": "UNIMPORTANT",
            "eventActor": "PrismaCloudReadWriteRoleWithDLP",
            "eventUserAgent": "[aws-sdk-java/1.12.565 Linux]",
            "eventActionMedium": "SDK",
            "eventSource": "*.**.**.***",
            "policyFrameWorks": [
                "MITRE-T1074",
                "MITRE-T1537"
            ],
            "eventRawData": ""
        }
    ]
    client.get_alerts_list = MagicMock(return_value=mock_response)

    # List of test cases with invalid args and expected error messages
    test_cases = [
        ({"cloud_provider_in": "AWS,AZURE12"}, 'This "AZURE12" cloudProvider is not supported'),
        ({"cloud_environment_in": "Wrong,AZURE1"}, 'This "Wrong" cloudEnvironment is not supported'),
        ({"policy_severity_in": "AWS32"}, 'This "AWS32" policySeverity is not supported'),
        ({"category_type_in": "AWS,INVALID"}, 'This "AWS" categoryType is not supported'),
        ({"status_in": "IN,OPEN"}, 'This "IN" status is not supported'),
        ({"cloud_provider_equal": "AZURE12"}, 'This "AZURE12" cloudProvider is not supported'),
        ({"cloud_environment_equal": "Wrong"}, 'This "Wrong" cloudEnvironment is not supported'),
        ({"policy_severity_equal": "AWS32"}, 'This "AWS32" policySeverity is not supported'),
        ({"category_type_equal": "AWS"}, 'This "AWS" categoryType is not supported'),
        ({"status_equal": "IN"}, 'This "IN" status is not supported')
    ]

    # Iterate over the test cases
    for args, expected_error in test_cases:
        with pytest.raises(ValueError, match=expected_error):
            get_list_of_alerts(client, args, 0)


def test_get_asset_details_command(client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
    args = {'asset_id': 'asset1'}
    result = get_asset_details(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs['name'] == 'Test Asset'  # type: ignore


def test_update_risk_finding_status_invalid_status(client):
    args = {'findingId': '1', 'status': 'INVALID_STATUS'}

    with pytest.raises(ValueError, match='This "INVALID_STATUS" status is not supported'):
        update_risk_finding_status(client, args)


def test_get_data_types(client):
    result = get_data_types(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.DataTypes'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == [{"No": 1, "Key": "Type1"}, {"No": 2, "Key": "Type2"}, {"No": 3, "Key": "Type3"}]


def test_get_data_types_empty(client):
    client.get_data_types = MagicMock(return_value=[])  # Empty data types
    result = get_data_types(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.DataTypes'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == []


def test_get_data_types_single_type(client):
    client.get_data_types = MagicMock(return_value=["Type1"])  # Single data type
    result = get_data_types(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.DataTypes'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == [{"No": 1, "Key": "Type1"}]


def test_get_labels(client):
    result = get_list_of_labels(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.Label'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == [{"No": 1, "Key": "label1"}, {"No": 2, "Key": "label2"}, {"No": 3, "Key": "label3"}]


def test_get_labels_empty_response(client):
    client.get_labels = MagicMock(return_value=[])  # Empty data types
    result = get_list_of_labels(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.Label'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == []


def test_get_labels_single_label(client):
    client.get_labels = MagicMock(return_value=["Label1"])  # Single data type
    result = get_list_of_labels(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.Label'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == [{"No": 1, "Key": "Label1"}]


sample_data_multiple = [
    {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"},
    {"dataTypeName": "PII"},
    {"dataTypeName": "CREDIT_CARD"},
    {"dataTypeName": "SSN"}
]

sample_data_multiple_strings = [
    "AADHAAR_INDIVIDUAL_IDENTIFICATION",
    "PII",
    "CREDIT_CARD",
    "SSN"
]

sample_data_single = [
    {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"}
]

sample_data_single_string = [
    "AADHAAR_INDIVIDUAL_IDENTIFICATION"
]


def test_get_data_type_findings_command(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_multiple)  # Mocked data types
    args = {}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    assert result == [
        {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"},
        {"dataTypeName": "PII"},
        {"dataTypeName": "CREDIT_CARD"},
        {"dataTypeName": "SSN"}
    ]


def test_get_data_type_findings_command_multiple_strings(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_multiple_strings)  # Mocked data types as strings
    args = {}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    assert result == [
        "AADHAAR_INDIVIDUAL_IDENTIFICATION",
        "PII",
        "CREDIT_CARD",
        "SSN"
    ]


def test_get_data_type_findings_command_single_type(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_single)  # Single data type
    args = {}
    result = get_data_type_findings(client, args, page=0)
    assert isinstance(result, List)
    assert result == [
        {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"}
    ]


def test_get_data_type_findings_command_single_string(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_single_string)  # Single data type as string
    args = {}
    result = get_data_type_findings(client, args, page=0)
    assert isinstance(result, List)
    assert result == [
        "AADHAAR_INDIVIDUAL_IDENTIFICATION"
    ]


def test_get_asset_files_by_id(client):
    # Mock response data
    mock_responses = [
        {
            "files": [
                {"filename": "file1.txt", "size": 1234},
                {"filename": "file2.txt", "size": 5678}
            ],
            "filesCount": 2
        },
        {
            "files": [],
            "filesCount": 0
        }
    ]

    # Mock the client method
    client.get_asset_files = MagicMock(side_effect=[mock_responses[0], mock_responses[1]])

    # Define the arguments for the command
    args = {
        'asset_id': 'asset1',
        'types': ['type1', 'type2'],
        'page': 1,
        'size': 20
    }

    # Call the function
    result = get_asset_files_by_id(client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.AssetFiles'
    assert result.outputs_key_field == 'filename'
    assert result.outputs == {
        'files': [
            {"filename": "file1.txt", "size": 1234},
            {"filename": "file2.txt", "size": 5678}
        ],
        'filesCount': 2
    }


def test_dspm_get_list_of_asset_fields_command(client):
    # Mock response data
    mock_responses = [
        {
            "fields": [
                {"name": "maidenname", "databaseName": "dummy"},
                {"name": "salary", "databaseName": "dummy"}
            ],
            "fieldsCount": 2
        },
        {
            "fields": [],
            "filesCount": 0
        }
    ]

    # Mock the client method
    client.get_list_of_asset_fields = MagicMock(side_effect=[mock_responses[0], mock_responses[1]])

    # Define the arguments for the command
    args = {
        'assetId': 'asset1',
        'page': 1,
        'size': 20
    }

    # Call the function
    result = dspm_get_list_of_asset_fields_command(client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.AssetFields'
    assert result.outputs_key_field == 'name'
    assert result.outputs == {
        'fields': [
            {"name": "maidenname", "databaseName": "dummy"},
            {"name": "salary", "databaseName": "dummy"}
        ],
        'fieldsCount': 2
    }


def test_get_asset_files_by_id_with_invalid_key_name(client):
    # Define the arguments for the command
    args = {
        'invalid_key': 'asset1'
    }
    expected_error = "Asset ID not specified"
    # Call the function
    with pytest.raises(ValueError, match=expected_error):
        get_asset_files_by_id(client, args)


def test_get_list_of_assets_empty_response(client, mocker):
    # Mock response data
    mock_response = {
        "assets": []
    }

    # Mock the client method
    client.get_asset_lists = MagicMock(return_value=mock_response)

    # Define the arguments for the command
    args = {
        'region_in': 'us-east',
        'cloud_provider_in': 'AWS',
        'service_type_equal': 'UNMANAGED_AWS_REDIS',
        'dig_tag_key_contains': 'env',
        'lifecycle_in': 'RUNNING',
        'sort': 'status,DESC',
        'size': 10
    }

    # Call the function
    result = get_list_of_assets(client, args, page=0)

    # Assertions
    assert isinstance(result, List)
    assert result == []


mock_assets_page_1 = [
    {
        "id": "asset1",
        "projectId": "project1",
        "projectName": "Project One",
        "name": "Asset One",
        "cloudProvider": "GCP",
        "cloudEnvironment": "TESTING",
        "serviceType": "UNMANAGED_GCP_MS_SQL",
        "lifecycle": "RUNNING",
        "openRisksCount": 5,
        "openAlertsCount": 3,
        "encrypted": True,
        "openToWorld": False,
        "tags": {"example_tag_key": "example_tag_value"},
        "assetDigTags": [
            {"digTagId": 1, "key": "tag1", "value": "value1"},
            {"digTagId": 2, "key": "tag2", "value": "value2"}
        ]
    }
]

mock_assets_page_2 = [
    {
        "id": "asset2",
        "projectId": "project2",
        "projectName": "Project Two",
        "name": "Asset Two",
        "cloudProvider": "AWS",
        "cloudEnvironment": "PRODUCTION",
        "serviceType": "UNMANAGED_AWS_AEROSPIKE",
        "lifecycle": "DELETED",
        "openRisksCount": 2,
        "openAlertsCount": 1,
        "encrypted": False,
        "openToWorld": True,
        "tags": {"another_tag_key": "another_tag_value"},
        "assetDigTags": [
            {"digTagId": 3, "key": "tag3", "value": "value3"},
            {"digTagId": 4, "key": "tag4", "value": "value4"}
        ]
    }
]


@pytest.mark.parametrize("mock_responses, expected_outputs", [
    (
        [  # Single page response
            {"assets": mock_assets_page_1},
            {"assets": []}  # No more assets
        ],
        [
            {
                'id': 'asset1',
                'projectId': 'project1',
                'projectName': 'Project One',
                'name': 'Asset One',
                'cloudProvider': 'GCP',
                'cloudEnvironment': 'TESTING',
                'serviceType': 'UNMANAGED_GCP_MS_SQL',
                'lifecycle': 'RUNNING',
                'openRisksCount': 5,
                'openAlertsCount': 3,
                'encrypted': True,
                'openToWorld': False,
                'tags': {"example_tag_key": "example_tag_value"},
                'assetDigTags': [
                    {"digTagId": 1, "key": "tag1", "value": "value1"},
                    {"digTagId": 2, "key": "tag2", "value": "value2"}
                ]
            }
        ]
    ),
    (
        [  # Pagination response
            {"assets": mock_assets_page_1},
            {"assets": mock_assets_page_2},
            {"assets": []}  # No more assets
        ],
        [
            {
                'id': 'asset1',
                'projectId': 'project1',
                'projectName': 'Project One',
                'name': 'Asset One',
                'cloudProvider': 'GCP',
                'cloudEnvironment': 'TESTING',
                'serviceType': 'UNMANAGED_GCP_MS_SQL',
                'lifecycle': 'RUNNING',
                'openRisksCount': 5,
                'openAlertsCount': 3,
                'encrypted': True,
                'openToWorld': False,
                'tags': {"example_tag_key": "example_tag_value"},
                'assetDigTags': [
                    {"digTagId": 1, "key": "tag1", "value": "value1"},
                    {"digTagId": 2, "key": "tag2", "value": "value2"}
                ]
            }
        ]
    )
])
def test_get_list_of_assets(mocker, mock_responses, expected_outputs):
    # Mock the client method to return different pages
    client = MagicMock()
    client.get_asset_lists.side_effect = mock_responses

    # Define the arguments for the command
    args = {}

    # Call the function
    result = get_list_of_assets(client, args, page=0)

    # Assertions
    assert isinstance(result, List)
    assert result == expected_outputs


def test_get_asset_details(mocker):
    client = MagicMock()
    client.get_asset_details.return_value = {"asset": {"id": "asset1", "name": "Asset One"}}

    args = {"asset_id": "asset1"}  # Ensure the argument is correct
    result = get_asset_details(client, args)

    assert result.outputs == {"asset": {"id": "asset1", "name": "Asset One"}}  # Access 'outputs' attribute


def test_update_risk_status_with_valid_status(client):
    args = {'risk_finding_id': '1', 'status': 'INVESTIGATING'}

    mock_response = {
        "riskFindingId": '1',
        "oldStatus": 'OPEN',
        "newStatus": 'INVESTIGATING',
    }

    client = MagicMock()
    client.update_risk_status.return_value = mock_response
    result = update_risk_finding_status(client, args)

    assert result.outputs == mock_response


def test_update_alert_status_invalid_status(client):
    args = {'alert_id': '1', 'status': 'INVALID_STATUS'}

    with pytest.raises(ValueError, match='This "INVALID_STATUS" status is not supported'):
        update_dspm_alert_status(client, args)


def test_update_alert_status_valid_status(client):
    args = {'alert_id': '1', 'status': 'INVESTIGATING'}

    mock_response = {
        "alertId": '1',
        "oldStatus": 'OPEN',
        "newStatus": 'INVESTIGATING',
    }

    client = MagicMock()
    client.update_alert_status.return_value = mock_response
    result = update_dspm_alert_status(client, args)

    assert result.outputs == mock_response


def test_get_risk_finding_by_id_with_missing_id(client):
    args = {}

    with pytest.raises(ValueError, match='finding_id argument is required'):
        get_risk_finding_by_id(client, args)


def test_risk_finding_by_id_with_valid_id(client):
    mock_response = {
        "id": "7e9a3891-8970-4c08-961a-03f49e239d68",
        "ruleName": "Sensitive asset without storage versioning",
        "severity": "MEDIUM",
        "asset": {
            "name": "****",
            "assetId": "****",
        },
        "status": "OPEN",
        "projectId": "****",
        "cloudProvider": "AZURE",
        "cloudEnvironment": "DEVELOPMENT",
        "firstDiscovered": "2024-04-25T17:08:11.020304Z",
        "complianceStandards": {}
    }

    client = MagicMock()
    client.get_risk_information.return_value = mock_response
    args = {'finding_id': '7e9a3891-8970-4c08-961a-03f49e239d68'}
    result = get_risk_finding_by_id(client, args)

    assert result.outputs == mock_response


def test_validate_parameter_valid_and_invalid():
    supported_list = ["AWS", "AZURE"]
    param_name = "parameter"

    # with valid param_in and param_equal
    validate_parameter(param_name, "AWS,AZURE", "AWS", supported_list)

    # with invalid param_in
    with pytest.raises(ValueError, match='This "AWS1" parameter is not supported'):
        validate_parameter(param_name, "AWS,AWS1", None, supported_list)

    # with invalid param_equal
    with pytest.raises(ValueError, match='This "AWS1" parameter is not supported'):
        validate_parameter(param_name, None, "AWS1", supported_list)


def test_dspm_get_risk_findings_command(client):
    # Mock response data
    mock_responses = [
        {
            "id": "7e9a3891-8970-4c08-961a-01f49e239d68",
            "ruleName": "Sensitive asset without storage versioning",
            "severity": "MEDIUM",
            "asset": {
                "name": "****",
                "assetId": "****",
            },
            "status": "OPEN",
            "projectId": "****",
            "cloudProvider": "AZURE",
            "cloudEnvironment": "DEVELOPMENT",
            "firstDiscovered": "2024-04-25T17:08:11.020304Z",
            "complianceStandards": {}
        },
        {
            "id": "7e9a3891-8970-4c08-961a-03f49e139d68",
            "ruleName": "Sensitive asset without storage versioning",
            "severity": "MEDIUM",
            "asset": {
                "name": "****",
                "assetId": "****",
            },
            "status": "OPEN",
            "projectId": "****",
            "cloudProvider": "AZURE",
            "cloudEnvironment": "DEVELOPMENT",
            "firstDiscovered": "2024-04-25T17:08:11.020304Z",
            "complianceStandards": {}
        }
    ]
    args = {
        "cloud_provider_equal": "AZURE",
        "affects_equal": "SECURITY",
        "status_equal": "OPEN",
        "service_type_equal": "UNMANAGED_AWS_REDIS",
        "dig_tag_key_contains": "env",
        "lifecycle_in": "RUNNING",
        "sort": "status,desc"
    }

    # Mock the client method
    client.fetch_risk_findings = MagicMock(side_effect=[mock_responses, None])
    result = dspm_list_risk_findings_command(client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "DSPM.RiskFinding"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == len(mock_responses)  # type: ignore

    # with invalid - 'limit' param
    with pytest.raises(ValueError, match="The 'limit' parameter must be an integer."):
        args = {"limit": "123abc"}
        dspm_list_risk_findings_command(client, args)


def test_dspm_get_list_of_assets_command(client):
    # Mock response data
    mock_responses = [
        {
            "projectId": "00000000000",
            "projectName": "00000000000",
            "name": "*********",
            "cloudProvider": "AWS",
            "cloudEnvironment": "TESTING",
            "serviceType": "S3",
            "dataTypeGroups": [],
            "dataTypes": [],
            "lifecycle": "RUNNING",
            "openRisksCount": 0,
            "openAlertsCount": 0,
            "encrypted": True,
            "openToWorld": False,
            "tags": {},
            "assetDigTags": [],
            "id": "arn:aws:s3:::*********"
        },
        {
            "projectId": "00000000000",
            "projectName": "00000000000",
            "name": "*********",
            "cloudProvider": "AWS",
            "cloudEnvironment": "TESTING",
            "serviceType": "S3",
            "dataTypeGroups": [],
            "dataTypes": [],
            "lifecycle": "RUNNING",
            "openRisksCount": 0,
            "openAlertsCount": 0,
            "encrypted": True,
            "openToWorld": False,
            "tags": {},
            "assetDigTags": [],
            "id": "arn:aws:s3:::*********"
        }
    ]
    args = {
        "cloud_provider_equal": "AZURE",
        "affects_equal": "SECURITY",
        "status_equal": "OPEN",
        "service_type_equal": "UNMANAGED_AWS_REDIS",
        "dig_tag_key_contains": "env",
        "lifecycle_in": "RUNNING",
        "sort": "status,desc"
    }

    # Mock the client method
    client.get_asset_lists = MagicMock(side_effect=[mock_responses, None])
    result = dspm_list_assets_command(client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "DSPM.Asset"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == len(mock_responses)  # type: ignore

    # with invalid - 'limit' param
    with pytest.raises(ValueError, match="The 'limit' parameter must be an integer."):
        args = {"limit": "123abc"}
        dspm_list_assets_command(client, args)


def test_dspm_get_data_types_findings_command(client):
    # Mock response data
    mock_responses = [
        {
            "dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION",
            "label": "PII",
            "assets": 1,
            "clouds": [
                "AWS"
            ],
            "regions": [
                "us-east-1"
            ],
            "lastFound": "2024-05-09T03:24:29Z",
            "recordsAtRisk": {}
        },
        {
            "dataTypeName": "CC_EXPIRATION_DATE",
            "label": "PII",
            "assets": 1,
            "clouds": [
                "AWS"
            ],
            "regions": [
                "us-east-1"
            ],
            "lastFound": "2024-05-09T03:24:29Z",
            "recordsAtRisk": {}
        }
    ]
    args = {
        "cloud_provider_equal": "AZURE",
        "affects_equal": "SECURITY",
        "status_equal": "OPEN",
        "service_type_equal": "UNMANAGED_AWS_REDIS",
        "dig_tag_key_contains": "env",
        "lifecycle_in": "RUNNING",
        "sort": "status,desc"
    }

    # Mock the client method
    client.get_data_type_findings = MagicMock(side_effect=[mock_responses, None])
    result = dspm_list_data_types_findings_command(client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "DSPM.DataTypesFinding"
    assert result.outputs_key_field == "dataTypeName"
    assert len(result.outputs) == len(mock_responses)  # type: ignore

    # with invalid - 'limit' param
    with pytest.raises(ValueError, match="The 'limit' parameter must be an integer."):
        args = {"limit": "123abc"}
        dspm_list_data_types_findings_command(client, args)


def test_dspm_get_list_of_alerts_command(client):
    # Mock response data
    mock_responses = [
        {
            "id": "340256006",
            "detectionTime": "2024-08-07T18:55:50.64996Z",
            "policyName": "Asset made public",
            "assetName": "mikeys3",
            "assetLabels": [],
            "cloudProvider": "AWS",
            "destinationProjects": {},
            "cloudEnvironment": "TESTING",
            "policySeverity": "HIGH",
            "policyCategoryType": "ATTACK",
            "status": "OPEN",
            "eventActor": "dummy_email",
            "eventUserAgent": "",
            "eventActionMedium": "CONSOLE",
            "eventSource": "***.**.**.***.***",
            "policyFrameWorks": [
                "MITRE-T1098"
            ],
            "eventRawData": ""
        },
        {
            "id": "340256006",
            "detectionTime": "2024-08-07T18:55:50.64996Z",
            "policyName": "Asset made public",
            "assetName": "mikeys3",
            "assetLabels": [],
            "cloudProvider": "AWS",
            "destinationProjects": {},
            "cloudEnvironment": "TESTING",
            "policySeverity": "HIGH",
            "policyCategoryType": "ATTACK",
            "status": "OPEN",
            "eventActor": "dummy_email",
            "eventUserAgent": "",
            "eventActionMedium": "CONSOLE",
            "eventSource": "***.**.**.***.***",
            "policyFrameWorks": [
                "MITRE-T1098"
            ],
            "eventRawData": ""
        }
    ]

    args = {
        "cloud_provider_equal": "AZURE",
        "policy_name_in": "SECURITY",
        "status_equal": "OPEN",
        "asset_name_in": "assets1,assets2",
        "cloud_environment_in": "TESTING",
        "policy_severity_equals": "HIGH",
        "category_type_equals": "FIRST_MOVE",
        "sort": "status,desc"
    }

    # Mock the client method
    client.get_alerts_list = MagicMock(side_effect=[mock_responses, None])
    result = dspm_list_alerts_command(client, args)

    # Assertions
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "DSPM.Alert"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == len(mock_responses)  # type: ignore

    # with invalid - 'limit' param
    with pytest.raises(ValueError, match="The 'limit' parameter must be an integer."):
        args = {"limit": "123abc"}
        dspm_list_alerts_command(client, args)(client, args)
