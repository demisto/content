import json
import pytest
from unittest.mock import MagicMock
from CommonServerPython import *  # noqa: F401
from DSPM import (
    get_list_of_assets,
    get_asset_files_by_id,
    test_module,
    get_risk_findings_command,
    get_asset_details_command,
    update_risk_finding_status_command,
    get_data_types_command,
    get_data_type_findings,
    get_slack_msg_lifetime,
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


def test_get_risk_findings_command(client):
    args = {}
    result = get_risk_findings_command(client, args, page=0)

    assert isinstance(result, List)
    # assert 'DSPM.RiskFindings' in result.outputs_prefix
    # assert len(result.outputs) > 0  # type: ignore

    # Check the structure of one finding
    finding = result[0]  # type: ignore
    assert 'ID' in finding
    assert 'Rule Name' in finding
    assert 'Severity' in finding
    assert 'Asset Name' in finding
    assert 'Asset ID' in finding
    assert 'Status' in finding
    assert 'Project ID' in finding
    assert 'Cloud Provider' in finding
    assert 'Cloud Environment' in finding
    assert 'First Discovered' in finding
    assert 'Compliance Standards' in finding


def test_get_risk_findings_command_with_valid_args(client):
    args = {"cloudProviderIn": "AWS,AZURE", "affectsIn": "SECURITY,COMPLIANCE",
            "statusIn": "OPEN,CLOSED", "sort": "records,asc"}
    result = get_risk_findings_command(client, args, page=0)

    assert isinstance(result, List)
    assert len(result) >= 1

    args = {"cloudProviderEqual": "AWS", "affectsEqual": "SECURITY",
            "statusEqual": "OPEN", "sort": "records,desc"}
    result = get_risk_findings_command(client, args, page=0)

    assert isinstance(result, List)
    assert len(result) >= 1

def test_get_slack_msg_lifetime(client):
    sleep_time = 2
    result = get_slack_msg_lifetime(client, sleep_time)
    assert isinstance(result, str)



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


def test_get_asset_details_command(client, mocker):
    mocker.patch.object(client, '_http_request', side_effect=mock_http_request)
    args = {'asset_id': 'asset1'}
    result = get_asset_details_command(client, args)

    assert isinstance(result, CommandResults)
    assert result.outputs['name'] == 'Test Asset'  # type: ignore


def test_update_risk_finding_status_command_invalid_status(client):
    args = {'findingId': '1', 'status': 'INVALID_STATUS'}

    with pytest.raises(ValueError, match='This "INVALID_STATUS" cloud provider does not supported'):
        update_risk_finding_status_command(client, args)


def test_get_data_types_command(client):
    result = get_data_types_command(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.DataTypes'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == [{"No": 1, "Key": "Type1"}, {"No": 2, "Key": "Type2"}, {"No": 3, "Key": "Type3"}]

    expected_human_readable = (
        "### Data Types\n"
        "| No | Key  |\n"
        "|----|------|\n"
        "| 1  | Type1 |\n"
        "| 2  | Type2 |\n"
        "| 3  | Type3 |\n"
    )
    assert result.readable_output == expected_human_readable


def test_get_data_types_command_empty(client):
    client.get_data_types = MagicMock(return_value=[])  # Empty data types
    result = get_data_types_command(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.DataTypes'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == []

    expected_human_readable = (
        "### Data Types\n"
        "| No | Key |\n"
        "|----|-----|\n"
        "**No entries.**\n"
    )
    assert result.readable_output == expected_human_readable


def test_get_data_types_command_single_type(client):
    client.get_data_types = MagicMock(return_value=["Type1"])  # Single data type
    result = get_data_types_command(client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == 'DSPM.DataTypes'
    assert result.outputs_key_field == 'Key'
    assert result.outputs == [{"No": 1, "Key": "Type1"}]

    expected_human_readable = (
        "### Data Types\n"
        "| No | Key  |\n"
        "|----|------|\n"
        "| 1  | Type1 |\n"
    )
    assert result.readable_output == expected_human_readable


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
    # assert result.outputs_prefix == 'DSPM.DataTypesFindings'
    # assert result.outputs_key_field == 'Key'
    assert result == [
        {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"},
        {"dataTypeName": "PII"},
        {"dataTypeName": "CREDIT_CARD"},
        {"dataTypeName": "SSN"}
    ]

    # expected_human_readable = (
    #     "### Data Types\n"
    #     "| No | Key  |\n"
    #     "|----|------|\n"
    #     "| 1  | AADHAAR_INDIVIDUAL_IDENTIFICATION |\n"
    #     "| 2  | PII |\n"
    #     "| 3  | CREDIT_CARD |\n"
    #     "| 4  | SSN |\n"
    # )
    # assert result.readable_output == expected_human_readable


def test_get_data_type_findings_command_multiple_strings(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_multiple_strings)  # Mocked data types as strings
    args = {}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    # assert result.outputs_prefix == 'DSPM.DataTypesFindings'
    # assert result.outputs_key_field == 'Key'
    assert result == [
        "AADHAAR_INDIVIDUAL_IDENTIFICATION",
        "PII",
        "CREDIT_CARD",
        "SSN"
    ]

    # expected_human_readable = (
    #     "### Data Types\n"
    #     "| No | Key  |\n"
    #     "|----|------|\n"
    #     "| 1  | AADHAAR_INDIVIDUAL_IDENTIFICATION |\n"
    #     "| 2  | PII |\n"
    #     "| 3  | CREDIT_CARD |\n"
    #     "| 4  | SSN |\n"
    # )
    # assert result.readable_output == expected_human_readable


def test_get_data_type_findings_command_single_type(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_single)  # Single data type
    args = {}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    # assert result.outputs_prefix == 'DSPM.DataTypesFindings'
    # assert result.outputs_key_field == 'Key'
    assert result == [
        {"dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION"}
    ]

    # expected_human_readable = (
    #     "### Data Types\n"
    #     "| No | Key  |\n"
    #     "|----|------|\n"
    #     "| 1  | AADHAAR_INDIVIDUAL_IDENTIFICATION |\n"
    # )
    # assert result.readable_output == expected_human_readable


def test_get_data_type_findings_command_single_string(client):
    client.get_data_type_findings = MagicMock(return_value=sample_data_single_string)  # Single data type as string
    args = {}
    result = get_data_type_findings(client, args, page=0)

    assert isinstance(result, List)
    # assert result.outputs_prefix == 'DSPM.DataTypesFindings'
    # assert result.outputs_key_field == 'Key'
    assert result == [
        "AADHAAR_INDIVIDUAL_IDENTIFICATION"
    ]

    # expected_human_readable = (
    #     "### Data Types\n"
    #     "| No | Key  |\n"
    #     "|----|------|\n"
    #     "| 1  | AADHAAR_INDIVIDUAL_IDENTIFICATION |\n"
    # )
    # assert result.readable_output == expected_human_readable


def test_get_asset_files_by_id(client, mocker):
    # Mock response data
    mock_response = {
        "files": [
            {"filename": "file1.txt", "size": 1234},
            {"filename": "file2.txt", "size": 5678}
        ],
        "filesCount": 2
    }

    # Mock the client method
    client.get_asset_files = MagicMock(return_value=mock_response)

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


# Test case for get_list_of_assets with empty response
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
    # assert result.outputs_prefix == 'DSPM.Assets'
    # assert result.outputs_key_field == 'id'
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
            },
            # {
            #     'ID': 'asset2',
            #     'Project ID': 'project2',
            #     'Project Name': 'Project Two',
            #     'Name': 'Asset Two',
            #     'Cloud Provider': 'AWS',
            #     'Cloud Environment': 'PRODUCTION',
            #     'Service Type': 'UNMANAGED_AWS_AEROSPIKE',
            #     'Lifecycle': 'DELETED',
            #     'Open Risks Count': 2,
            #     'Open Alerts Count': 1,
            #     'Encrypted': False,
            #     'Open To World': True,
            #     'Tags': {"another_tag_key": "another_tag_value"},
            #     'Asset Dig Tags': [
            #         {"digTagId": 3, "key": "tag3", "value": "value3"},
            #         {"digTagId": 4, "key": "tag4", "value": "value4"}
            #     ]
            # }
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
    # assert result.outputs_prefix == 'DSPM.Assets'
    # assert result.outputs_key_field == 'id'
    assert result == expected_outputs


def test_get_asset_details(mocker):
    client = MagicMock()
    client.get_asset_details.return_value = {"asset": {"id": "asset1", "name": "Asset One"}}

    args = {"asset_id": "asset1"}  # Ensure the argument is correct
    result = get_asset_details_command(client, args)

    assert result.outputs == {"asset": {"id": "asset1", "name": "Asset One"}}  # Access 'outputs' attribute
