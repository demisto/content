import json
import pytest
from unittest.mock import MagicMock, patch
from CommonServerPython import *  # noqa: F401
from DSPM import (
    get_list_of_assets,
    get_asset_files_by_id,
    test_module,
    dspm_get_risk_findings,
    get_asset_details,
    update_risk_finding_status,
    get_data_types,
    get_data_type_findings,
    get_list_of_alerts,
    get_integration_config,
    update_dspm_alert_status,
    get_risk_finding_by_id,
    validate_parameter,
    dspm_get_risk_findings_command,
    dspm_get_list_of_assets_command,
    dspm_get_data_types_findings_command,
    dspm_get_list_of_alerts_command
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
        "ID": "7e9a3891-8970-4c08-961a-03f49e239d68",
        "Rule Name": "Sensitive asset without storage versioning",
        "Severity": "MEDIUM",
        "Asset Name": "****",
        "Asset ID": "****",
        "Status": "OPEN",
        "Project ID": "****",
        "Cloud Provider": "AZURE",
        "Cloud Environment": "DEVELOPMENT",
        "First Discovered": "2024-04-25T17:08:11.020304Z",
        "Compliance Standards": {}
    }
    args = {
        "ruleNameIn": "InvalidRule,AnotherInvalidRule",
        "ruleNameEqual": "NotARealRule",
        "dspmTagKeyIn": "InvalidKey,AnotherInvalidKey",
        "dspmTagKeyEqual": "NotARealKey",
        "dspmTagValueIn": "InvalidValue,AnotherInvalidValue",
        "dspmTagValueEqual": "NotARealValue",
        "projectIdIn": "InvalidProjectID123",
        "projectIdEqual": "NotARealProjectID",
        "cloudProviderIn": "AWS,AZURE",
        "cloudProviderEqual": "AZURE",
        "affectsIn": "SECURITY,COMPLIANCE",
        "affectsEqual": "SECURITY",
        "statusIn": "OPEN",
        "statusEqual": "OPEN",
        "sort": "status,desc"
    }
    result = dspm_get_risk_findings(client, args, page=0)
    finding = result[0]  # type: ignore

    assert isinstance(result, List)
    assert expected_output == finding

    # Check the structure of one finding
    required_keys = [
        'ID', 'Rule Name', 'Severity', 'Asset Name', 'Asset ID',
        'Status', 'Project ID', 'Cloud Provider', 'Cloud Environment',
        'First Discovered', 'Compliance Standards'
    ]
    assert all(key in finding for key in required_keys)


def test_dspm_get_risk_findings_with_valid_args(client):
    expected_output = {
        "ID": "7e9a3891-8970-4c08-961a-03f49e239d68",
        "Rule Name": "Sensitive asset without storage versioning",
        "Severity": "MEDIUM",
        "Asset Name": "****",
        "Asset ID": "****",
        "Status": "OPEN",
        "Project ID": "****",
        "Cloud Provider": "AZURE",
        "Cloud Environment": "DEVELOPMENT",
        "First Discovered": "2024-04-25T17:08:11.020304Z",
        "Compliance Standards": {}
    }
    args = {"cloudProviderIn": "AWS,AZURE", "affectsIn": "SECURITY,COMPLIANCE",
            "statusIn": "OPEN,CLOSED", "sort": "records,asc"}
    result = dspm_get_risk_findings(client, args, page=0)

    assert isinstance(result, List)
    assert result[0] == expected_output

    args = {"cloudProviderEqual": "AWS", "affectsEqual": "SECURITY",
            "statusEqual": "OPEN", "sort": "records,desc"}
    result = dspm_get_risk_findings(client, args, page=0)

    assert isinstance(result, List)
    assert result[0] == expected_output


def test_dspm_get_risk_findings_with_invalid_args(client):

    test_cases = [
        ({"cloudProviderIn": "AWS,AZURE12"}, 'This "AZURE12" cloudProvider is not supported'),
        ({"cloudProviderEqual": "INVALID"}, 'This "INVALID" cloudProvider is not supported'),
        ({"affectsIn": "SECURITY,INVALID"}, 'This "INVALID" affects is not supported'),
        ({"affectsEqual": "WRONG"}, 'This "WRONG" affects is not supported'),
        ({"statusIn": "INVALID,CLOSED"}, 'This "INVALID" status is not supported'),
        ({"statusEqual": "IN"}, 'This "IN" status is not supported'),
        ({"sort": "records,wrongOrder"}, 'This "records,wrongOrder" sorting order is not supported'),
    ]

    # Iterate over the test cases
    for args, expected_error in test_cases:
        with pytest.raises(ValueError, match=expected_error):
            dspm_get_risk_findings(client, args, 0)


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

    args = {"cloudProviderIn": "AWS,AZURE", "serviceTypeIn": "EFS,RDS",
            "lifecycleIn": "RUNNING,STOPPED", "sort": "name,DESC"}
    result = get_list_of_assets(client, args, page=0)

    assert isinstance(result, List)
    assert result[0].get('ID') == "asset2"

    args = {"cloudProviderEqual": "AWS", "serviceTypeEqual": "RDS",
            "lifecycleEqual": "RUNNING", "sort": "name,ASC"}
    result = get_list_of_assets(client, args, page=0)

    assert isinstance(result, List)
    assert result[0].get('ID') == "asset2"


def test_get_list_of_assets_with_invalid_args(client):
    # List of invalid args and their expected error messages
    invalid_test_cases = [
        ({"cloudProviderIn": "INVALID_CLOUD_PROVIDER"}, 'This "INVALID_CLOUD_PROVIDER" cloudProvider is not supported'),
        ({"serviceTypeIn": "INVALID_SERVICE_TYPE"}, 'This "INVALID_SERVICE_TYPE" serviceType is not supported'),
        ({"lifecycleIn": "INVALID_LIFECYCLE"}, 'This "INVALID_LIFECYCLE" lifecycle is not supported'),
        ({"sort": "invalid_sort_order"}, 'This "invalid_sort_order" sorting order is not supported'),
    ]

    # Loop through each invalid test case
    for invalid_args, expected_error in invalid_test_cases:
        with pytest.raises(ValueError, match=expected_error):
            get_list_of_assets(client, invalid_args, page=0)


def test_get_data_type_findings_with_valid_args(client):
    args = {"cloudProviderIn": "AWS,AZURE", "serviceTypeIn": "DYNAMODB,RDS",
            "lifecycleIn": "DELETED,STOPPED", "sort": "records,DESC"}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    assert len(result) == 4

    args = {"cloudProviderEqual": "AWS", "serviceTypeEqual": "DYNAMODB",
            "lifecycleEqual": "DELETED", "sort": "records,ASC"}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    assert len(result) == 4


def test_get_data_type_findings_with_invalid_args(client):
    # List of invalid args and their expected error messages
    invalid_test_cases = [
        ({"cloudProviderIn": "INVALID_CLOUD_PROVIDER"}, 'This "INVALID_CLOUD_PROVIDER" cloudProvider is not supported'),
        ({"serviceTypeIn": "INVALID_SERVICE_TYPE"}, 'This "INVALID_SERVICE_TYPE" serviceType is not supported'),
        ({"lifecycleIn": "INVALID_LIFECYCLE"}, 'This "INVALID_LIFECYCLE" lifecycle is not supported'),
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
        "cloudProviderIn": "AWS,AZURE",
        "cloudEnvironmentIn": "DEVELOPMENT,STAGING",
        "policySeverityIn": "MEDIUM,LOW",
        "categoryTypeIn": "ATTACK,FIRST_MOVE",
        "statusIn": "CLOSED,OPEN",
        "sort": "name,DESC"
    }
    result = get_list_of_alerts(client, args, 0)

    assert isinstance(result, List)
    assert result[0].get('id') == "274314608"

    args = {
        "cloudProviderEqual": "AWS",
        "cloudEnvironmentEqual": "STAGING",
        "policySeverityEqual": "MEDIUM",
        "categoryTypeEqual": "FIRST_MOVE",
        "statusEqual": "OPEN",
        "sort": "name,ASC"
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
        ({"cloudProviderIn": "AWS,AZURE12"}, 'This "AZURE12" cloudProvider is not supported'),
        ({"cloudEnvironmentIn": "Wrong,AZURE1"}, 'This "Wrong" cloudEnvironment is not supported'),
        ({"policySeverityIn": "AWS32"}, 'This "AWS32" policySeverity is not supported'),
        ({"categoryTypeIn": "AWS,INVALID"}, 'This "AWS" categoryType is not supported'),
        ({"statusIn": "IN,OPEN"}, 'This "IN" status is not supported'),
        ({"cloudProviderEqual": "AZURE12"}, 'This "AZURE12" cloudProvider is not supported'),
        ({"cloudEnvironmentEqual": "Wrong"}, 'This "Wrong" cloudEnvironment is not supported'),
        ({"policySeverityEqual": "AWS32"}, 'This "AWS32" policySeverity is not supported'),
        ({"categoryTypeEqual": "AWS"}, 'This "AWS" categoryType is not supported'),
        ({"statusEqual": "IN"}, 'This "IN" status is not supported')
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


def test_get_asset_files_by_id_with_invalid_key_name(client):
    # Define the arguments for the command
    args = {
        'invalid_key': 'asset1'
    }
    expected_error = "Asset ID not specified"
    # Call the function
    with pytest.raises(ValueError, match=expected_error):
        get_asset_files_by_id(client, args)


@patch('DSPM.demisto')
def test_get_integration_config(mock_demisto):
    mock_params = {
        "dspmApiKey": {"password": "mocked_dspm_api_key"},
        "slackMsgLifetime": 4,
        "defaultSlackUser": "mock_user"
    }
    expected_result = {
        "integration_config": {
            "defaultSlackUser": "mock_user",
            "dspmApiKey": "mocked_dspm_api_key",
            "slackMsgLifetime": 4
        }
    }
    mock_demisto.params.return_value = mock_params

    result = get_integration_config()
    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.IntegrationConfig'
    assert result.outputs_key_field == 'config'
    assert result.outputs == expected_result


def test_get_list_of_assets_empty_response(client, mocker):
    # Mock response data
    mock_response = {
        "assets": []
    }

    # Mock the client method
    client.get_asset_lists = MagicMock(return_value=mock_response)

    # Define the arguments for the command
    args = {
        'regionIn': 'us-east',
        'cloudProviderIn': 'AWS',
        'serviceTypeEqual': 'UNMANAGED_AWS_REDIS',
        'digTagKeyContains': 'env',
        'lifecycleIn': 'RUNNING',
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
                'ID': 'asset1',
                'Project ID': 'project1',
                'Project Name': 'Project One',
                'Name': 'Asset One',
                'Cloud Provider': 'GCP',
                'Cloud Environment': 'TESTING',
                'Service Type': 'UNMANAGED_GCP_MS_SQL',
                'Lifecycle': 'RUNNING',
                'Open Risks Count': 5,
                'Open Alerts Count': 3,
                'Encrypted': True,
                'Open To World': False,
                'Tags': {"example_tag_key": "example_tag_value"},
                'Asset Dig Tags': [
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
                'ID': 'asset1',
                'Project ID': 'project1',
                'Project Name': 'Project One',
                'Name': 'Asset One',
                'Cloud Provider': 'GCP',
                'Cloud Environment': 'TESTING',
                'Service Type': 'UNMANAGED_GCP_MS_SQL',
                'Lifecycle': 'RUNNING',
                'Open Risks Count': 5,
                'Open Alerts Count': 3,
                'Encrypted': True,
                'Open To World': False,
                'Tags': {"example_tag_key": "example_tag_value"},
                'Asset Dig Tags': [
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
    args = {'riskFindingId': '1', 'status': 'INVESTIGATING'}

    mock_response = {
        "riskFindingId": '1',
        "oldStatus": 'OPEN',
        "newStatus": 'INVESTIGATING',
    }

    expected_output = {
        "Risk Finding ID": '1',
        "Old Status": 'OPEN',
        "New Status": 'INVESTIGATING',
    }
    client = MagicMock()
    client.update_risk_status.return_value = mock_response
    result = update_risk_finding_status(client, args)

    assert result.outputs == expected_output


def test_update_alert_status_invalid_status(client):
    args = {'alertId': '1', 'status': 'INVALID_STATUS'}

    with pytest.raises(ValueError, match='This "INVALID_STATUS" status is not supported'):
        update_dspm_alert_status(client, args)


def test_update_alert_status_valid_status(client):
    args = {'alertId': '1', 'status': 'INVESTIGATING'}

    mock_response = {
        "alertId": '1',
        "oldStatus": 'OPEN',
        "newStatus": 'INVESTIGATING',
    }

    expected_output = {
        "Alert ID": '1',
        "Old Status": 'OPEN',
        "New Status": 'INVESTIGATING',
    }
    client = MagicMock()
    client.update_alert_status.return_value = mock_response
    result = update_dspm_alert_status(client, args)

    assert result.outputs == expected_output


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
    expected_output = {
        "ID": "7e9a3891-8970-4c08-961a-03f49e239d68",
        "Rule Name": "Sensitive asset without storage versioning",
        "Severity": "MEDIUM",
        "Asset Name": "****",
        "Asset ID": "****",
        "Status": "OPEN",
        "Project ID": "****",
        "Cloud Provider": "AZURE",
        "Cloud Environment": "DEVELOPMENT",
        "First Discovered": "2024-04-25T17:08:11.020304Z",
        "Compliance Standards": {}
    }
    client = MagicMock()
    client.get_risk_information.return_value = mock_response
    args = {'finding_id': '7e9a3891-8970-4c08-961a-03f49e239d68'}
    result = get_risk_finding_by_id(client, args)

    assert result.outputs == expected_output


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
        "cloudProviderEqual": "AZURE",
        "affectsEqual": "SECURITY",
        "statusEqual": "OPEN",
        "serviceTypeEqual": "UNMANAGED_AWS_REDIS",
        "digTagKeyContains": "env",
        "lifecycleIn": "RUNNING",
        "sort": "status,desc"
    }

    # Mock the client method
    client.fetch_risk_findings = MagicMock(side_effect=[mock_responses, None])
    with patch('DSPM.return_results') as mock_return_results:
        dspm_get_risk_findings_command(client, args)
        result = mock_return_results.call_args[0][0]

        # Assertions
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "DSPM.RiskFindings"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == len(mock_responses)  # type: ignore


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
        "cloudProviderEqual": "AZURE",
        "affectsEqual": "SECURITY",
        "statusEqual": "OPEN",
        "serviceTypeEqual": "UNMANAGED_AWS_REDIS",
        "digTagKeyContains": "env",
        "lifecycleIn": "RUNNING",
        "sort": "status,desc"
    }

    # Mock the client method
    client.get_asset_lists = MagicMock(side_effect=[mock_responses, None])
    with patch('DSPM.return_results') as mock_return_results:
        dspm_get_list_of_assets_command(client, args)
        result = mock_return_results.call_args[0][0]

        # Assertions
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "DSPM.Assets"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == len(mock_responses)  # type: ignore


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
        "cloudProviderEqual": "AZURE",
        "affectsEqual": "SECURITY",
        "statusEqual": "OPEN",
        "serviceTypeEqual": "UNMANAGED_AWS_REDIS",
        "digTagKeyContains": "env",
        "lifecycleIn": "RUNNING",
        "sort": "status,desc"
    }

    # Mock the client method
    client.get_data_type_findings = MagicMock(side_effect=[mock_responses, None])
    with patch('DSPM.return_results') as mock_return_results:
        dspm_get_data_types_findings_command(client, args)
        result = mock_return_results.call_args[0][0]

        # Assertions
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "DSPM.DataTypesFindings"
        assert result.outputs_key_field == "Key"
        assert len(result.outputs) == len(mock_responses)  # type: ignore


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
        "cloudProviderEqual": "AZURE",
        "policyNameIn": "SECURITY",
        "statusEqual": "OPEN",
        "assetNameIn": "assets1,assets2",
        "cloudEnvironmentIn": "TESTING",
        "policySeverityEquals": "HIGH",
        "categoryTypeEquals": "FIRST_MOVE",
        "sort": "status,desc"
    }

    # Mock the client method
    client.get_alerts_list = MagicMock(side_effect=[mock_responses, None])
    with patch('DSPM.return_results') as mock_return_results:
        dspm_get_list_of_alerts_command(client, args)
        result = mock_return_results.call_args[0][0]

        # Assertions
        assert isinstance(result, CommandResults)
        assert result.outputs_prefix == "DSPM.Alerts"
        assert result.outputs_key_field == "id"
        assert len(result.outputs) == len(mock_responses)  # type: ignore
