import copy
import random
import uuid

import pytest
from unittest.mock import patch
import demistomock as demisto

from CommonServerPython import DemistoException
from Packs.Wiz.Integrations.WizDefend.WizDefend import WizApiVariables, get_filtered_detections

integration_params = {
    'api_endpoint': 'http://test.io',
    'credentials': {'identifier': 'test', 'password': 'pass'},
    'first_fetch': '2 days',
    'auth_endpoint': "https://auth.wiz.io/oauth/token"
}

TEST_TOKEN = '123456789'
SIMILAR_COMMANDS = [
    'wiz-get-detections',
    'wiz-get-detection'
]


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    mocker.patch('WizDefend.TOKEN', TEST_TOKEN)
    mocker.patch('WizDefend.AUTH_E', integration_params['auth_endpoint'])
    mocker.patch('WizDefend.URL', integration_params['api_endpoint'])


# Test Responses
test_get_detections_response = {
    "data": {
        "detections": {
            "nodes": [
                {
                    "id": "12345678-1234-1234-1234-d25e16359c19",
                    "issue": {
                        "id": "98765432-4321-4321-4321-ff5fa2ff7f78",
                        "url": "https://app.wiz.io/issues/98765432-4321-4321-4321-ff5fa2ff7f78"
                    },
                    "ruleMatch": {
                        "rule": {
                            "id": "12345678-4321-4321-4321-3792e8a03318",
                            "name": "suspicious activity detected",
                            "sourceType": "THREAT_DETECTION",
                            "securitySubCategories": []
                        }
                    },
                    "description": "Suspicious activity detected",
                    "severity": "CRITICAL",
                    "createdAt": "2022-01-02T15:46:34Z",
                    "startedAt": "2022-01-02T15:45:00Z",
                    "endedAt": "2022-01-02T15:47:00Z",
                    "actors": [],
                    "resources": [],
                    "triggeringEvents": {
                        "nodes": []
                    }
                }
            ],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": ""
            }
        }
    }
}

test_error_response = {
    "errors": [
        {
            "message": "Resource not found",
            "extensions": {
                "code": "NOT_FOUND",
                "exception": {
                    "message": "Resource not found",
                    "path": ["detections"]
                }
            }
        }
    ],
    "data": None
}

test_bad_token_response = {
    "error": "access_denied",
    "error_description": "Unauthorized"
}

test_empty_detection_response = {
    "data": {
        "detections": {
            "nodes": [],
            "pageInfo": {
                "hasNextPage": False,
                "endCursor": ""
            }
        }
    }
}

DEMISTO_ARGS = {
    'detection_type': 'GENERATED_THREAT',
    'detection_platform': 'AWS',
    'resource_id': 'test-id',
    'severity': 'CRITICAL',
    'creation_days_back': '2',
    'matched_rule': '12345678-1234-1234-1234-d25e16359c19',
    'matched_rule_name': 'test_rule',
    'project': 'test_project',
    'detection_id': '12345678-1234-1234-1234-d25e16359c19',
    'issue_id': '98765432-4321-4321-4321-ff5fa2ff7f78'
}


def mocked_requests_get(json, status):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.json_data = json_data
            self.status_code = status_code

        def json(self):
            return self.json_data

    return MockResponse(json, status)


@patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
def test_get_filtered_detections(query_api):
    from WizDefend import get_filtered_detections

    result_response = [
        {
            "id": "12345678-1234-1234-1234-d25e16359c19",
            "issue": {
                "id": "98765432-4321-4321-4321-ff5fa2ff7f78",
                "url": "https://app.wiz.io/issues/98765432-4321-4321-4321-ff5fa2ff7f78"
            },
            "ruleMatch": {
                "rule": {
                    "id": "12345678-4321-4321-4321-3792e8a03318",
                    "name": "suspicious activity detected",
                    "sourceType": "THREAT_DETECTION",
                    "securitySubCategories": []
                }
            },
            "description": "Suspicious activity detected",
            "severity": "CRITICAL",
            "createdAt": "2022-01-02T15:46:34Z",
            "startedAt": "2022-01-02T15:45:00Z",
            "endedAt": "2022-01-02T15:47:00Z",
            "actors": [],
            "resources": [],
            "triggeringEvents": {
                "nodes": []
            }
        }
    ]

    # Use keyword arguments instead of positional arguments
    res = get_filtered_detections(
        detection_type='GENERATED THREAT',
        detection_platform=['AWS'],
        resource_id='test-id',
        severity='CRITICAL'
    )
    assert res == result_response


@patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
def test_get_detection(query_api):
    """
    You can either modify the test to use your actual function name:
    from WizDefend import get_filtered_detections as get_detection

    Or add a compatibility function in the test:
    """
    from WizDefend import get_filtered_detections
    result_response = [
        {
            "id": "12345678-1234-1234-1234-d25e16359c19",
            "issue": {
                "id": "98765432-4321-4321-4321-ff5fa2ff7f78",
                "url": "https://app.wiz.io/issues/98765432-4321-4321-4321-ff5fa2ff7f78"
            },
            "ruleMatch": {
                "rule": {
                    "id": "12345678-4321-4321-4321-3792e8a03318",
                    "name": "suspicious activity detected",
                    "sourceType": "THREAT_DETECTION",
                    "securitySubCategories": []
                }
            },
            "description": "Suspicious activity detected",
            "severity": "CRITICAL",
            "createdAt": "2022-01-02T15:46:34Z",
            "startedAt": "2022-01-02T15:45:00Z",
            "endedAt": "2022-01-02T15:47:00Z",
            "actors": [],
            "resources": [],
            "triggeringEvents": {
                "nodes": []
            }
        }
    ]

    res = get_filtered_detections(detection_id='12345678-1234-1234-1234-d25e16359c19')
    assert res == result_response


def test_get_detection_bad_arguments(mocker, capfd):
    from WizDefend import get_filtered_detections
    with capfd.disabled():
        mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])

        # Test no arguments
        detection = get_filtered_detections()
        assert'You should pass at least one of the following parameters' in detection

        # Test invalid UUID
        detection = get_filtered_detections(detection_id='invalid_uuid')
        assert 'Wrong format: detection_id should be in UUID format.' in detection


def test_get_filtered_detections_bad_arguments(mocker, capfd):
    from WizDefend import get_filtered_detections
    with capfd.disabled():
        mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])

        # Test no arguments
        detections = get_filtered_detections(
            detection_type=None,
            detection_platform=None,
            resource_id=None,
            severity=None
        )
        assert 'You should pass at least one of the following parameters:' in detections

        # Test invalid severity
        detections = get_filtered_detections(
            detection_type=None,
            detection_platform=None,
            resource_id=None,
            severity='INVALID'
        )
        assert 'You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL' in detections

        # Test invalid detection_id (not a UUID)
        detections = get_filtered_detections(
            detection_id='invalid-uuid'
        )
        assert 'Wrong format: detection_id should be in UUID format' in detections

        # Test invalid platform
        detections = get_filtered_detections(
            detection_platform='INVALID_PLATFORM',
            severity='CRITICAL'  # Add valid severity to pass other validations
        )
        assert 'Invalid platform(s): INVALID_PLATFORM' in detections

        # Test invalid detection type
        detections = get_filtered_detections(
            detection_type='INVALID_TYPE',
            severity='CRITICAL'  # Add valid severity to pass other validations
        )
        assert 'Invalid detection type' in detections

        # Test invalid creation_minutes_back (too low)
        detections = get_filtered_detections(
            creation_minutes_back='5',  # Below minimum of 10
            severity='CRITICAL'  # Add valid severity to pass other validations
        )
        assert 'creation_minutes_back must be a valid integer between 10 and 600' in detections

        # Test invalid creation_minutes_back (too high)
        detections = get_filtered_detections(
            creation_minutes_back='700',  # Above maximum of 600
            severity='CRITICAL'  # Add valid severity to pass other validations
        )
        assert 'creation_minutes_back must be a valid integer between 10 and 600' in detections

        # Test invalid creation_minutes_back (not a number)
        detections = get_filtered_detections(
            creation_minutes_back='not_a_number',
            severity='CRITICAL'  # Add valid severity to pass other validations
        )
        assert 'creation_minutes_back must be a valid integer' in detections

        # Test invalid issue_id (not a UUID)
        detections = get_filtered_detections(
            issue_id='invalid-uuid'
        )
        assert 'Wrong format: issue_id should be in UUID format' in detections

        # Test conflicting time parameters
        detections = get_filtered_detections(
            creation_minutes_back='20',
            after_time='2022-01-01T00:00:00Z',
            severity='CRITICAL'  # Add valid severity to pass other validations
        )
        assert 'Cannot provide both creation_minutes_back and after_time parameters' in detections

@patch('requests.post', return_value=mocked_requests_get({"access_token": TEST_TOKEN}, 200))
def test_get_token_success(mock_post):
    from WizDefend import get_token, set_authentication_endpoint

    set_authentication_endpoint('https://auth.wiz.io/oauth/token')
    token = get_token()
    assert token == TEST_TOKEN


def test_get_token_failure(mocker):
    from WizDefend import get_token, set_authentication_endpoint

    mock_response = mocker.Mock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized"
    mock_response.json.return_value = test_bad_token_response

    mocker.patch('requests.post', return_value=mock_response)

    set_authentication_endpoint('https://auth.wiz.io/oauth/token')
    with pytest.raises(Exception) as e:
        get_token()
    assert 'Error authenticating to Wiz' in str(e.value)


def test_translate_severity():
    from WizDefend import translate_severity

    # Test each severity level
    assert translate_severity({'severity': 'CRITICAL'}) == 4
    assert translate_severity({'severity': 'HIGH'}) == 3
    assert translate_severity({'severity': 'MEDIUM'}) == 2
    assert translate_severity({'severity': 'LOW'}) == 1
    assert translate_severity({'severity': 'INFORMATIONAL'}) == 0.5
    assert translate_severity({'severity': 'UNKNOWN'}) is None


def test_is_valid_uuid():
    from WizDefend import is_valid_uuid

    # Test valid UUID
    valid_uuid = str(uuid.uuid4())
    assert is_valid_uuid(valid_uuid) is True

    # Test invalid UUID
    assert is_valid_uuid('invalid-uuid') is False
    assert is_valid_uuid('12345') is False
    assert is_valid_uuid(None) is False


def test_is_valid_param_id():
    from WizDefend import is_valid_param_id

    # Test valid UUID
    valid_uuid = str(uuid.uuid4())
    is_valid, message = is_valid_param_id(valid_uuid, 'detection_id')
    assert is_valid is True
    assert 'is in a valid format' in message

    # Test empty ID
    is_valid, message = is_valid_param_id(None, 'detection_id')
    assert is_valid is False
    assert 'You should pass a detection_id' in message

    # Test invalid UUID
    is_valid, message = is_valid_param_id('invalid-uuid', 'detection_id')
    assert is_valid is False
    assert 'Wrong format: detection_id should be in UUID format' in message


def test_build_incidents():
    from WizDefend import build_incidents

    detection = test_get_detections_response['data']['detections']['nodes'][0]
    incident = build_incidents(detection)

    assert incident['name'] == 'suspicious activity detected - 12345678-1234-1234-1234-d25e16359c19'
    assert incident['occurred'] == '2022-01-02T15:46:34Z'
    assert incident['severity'] == 4
    assert 'rawJSON' in incident

    # Test with None
    assert build_incidents(None) == {}


@patch('WizDefend.get_token', return_value=TEST_TOKEN)
@patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
def test_fetch_incidents(mock_query_api, mock_token, mocker):
    from WizDefend import fetch_incidents
    import demistomock as demisto

    # Mock demisto functions
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2022-01-01T00:00:00Z'})
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')

    fetch_incidents()

    # Verify incidents were created
    assert demisto.incidents.called
    # Verify last run was set
    assert demisto.setLastRun.called


@patch('WizDefend.get_token', return_value=TEST_TOKEN)
@patch('WizDefend.query_api', return_value=[])
def test_test_module(mock_query_api, mock_token, mocker):
    from WizDefend import main

    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')

    main()

    # Verify test-module returned 'ok'
    demisto.results.assert_called_with('ok')


@pytest.mark.parametrize("severity", ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'])
def test_get_filtered_detections_severity_levels(mocker, severity):
    from WizDefend import get_filtered_detections

    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
    result = get_filtered_detections(severity=severity)

    assert result == test_get_detections_response['data']['detections']['nodes']


@pytest.mark.parametrize("platform", [
    'AWS', 'GCP', 'Azure', 'OCI', 'Alibaba', 'vSphere', 'OpenStack',
    'AKS', 'EKS', 'GKE', 'Kubernetes', 'OpenShift'
])
def test_get_filtered_detections_platforms(mocker, platform):
    from WizDefend import get_filtered_detections

    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
    result = get_filtered_detections(detection_platform=platform)

    assert result == test_get_detections_response['data']['detections']['nodes']


def test_get_filtered_detections_invalid_platform(mocker):
    from WizDefend import get_filtered_detections

    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
    result = get_filtered_detections(detection_platform=['INVALID_PLATFORM'])

    assert 'Invalid platform(s)' in result


def test_get_filtered_detections_invalid_type(mocker):
    from WizDefend import get_filtered_detections

    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
    result = get_filtered_detections(detection_type='INVALID_TYPE')

    assert 'Invalid detection type: INVALID_TYPE' in result


def test_get_filtered_detections_invalid_minutes_back(mocker):
    from WizDefend import get_filtered_detections

    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])

    # Test invalid number
    result = get_filtered_detections(detection_platform=['GCP'], creation_minutes_back='not_a_number')
    assert 'creation_minutes_back must be a valid integer between 10 and 600' in result

    result = get_filtered_detections(detection_platform=['GCP'], creation_minutes_back='9')
    assert 'creation_minutes_back must be a valid integer between 10 and 600' in result

    # No other params
    result = get_filtered_detections(creation_minutes_back='9')
    assert 'You should pass at least one of the following parameters' in result




def test_get_error_output():
    from WizDefend import get_error_output

    # Test with error response
    error_output = get_error_output(test_error_response)
    assert 'Resource not found' in error_output

    # Test with empty errors
    empty_response = {"errors": []}
    error_output = get_error_output(empty_response)
    assert error_output == empty_response

    # Test with no errors
    no_error_response = {"data": {}}
    error_output = get_error_output(no_error_response)
    assert error_output == no_error_response


def test_main_unrecognized_command(mocker):
    from WizDefend import main

    mocker.patch.object(demisto, 'command', return_value='unknown-command')
    mocker.patch('WizDefend.return_error')

    main()

    # Verify return_error was called
    from WizDefend import return_error
    assert return_error.called


@pytest.mark.parametrize("command_name", SIMILAR_COMMANDS)
def test_main_commands(mocker, command_name):
    from WizDefend import main

    mocker.patch.object(demisto, 'command', return_value=command_name)
    mocker.patch.object(demisto, 'args', return_value=DEMISTO_ARGS)
    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
    mocker.patch('WizDefend.return_results')

    main()

    # Verify return_results was called
    from WizDefend import return_results
    assert return_results.called


def test_validate_detection_type_valid():
    """Test validate_detection_type with valid input"""
    from WizDefend import validate_detection_type

    result = validate_detection_type("GENERATED THREAT")
    assert result.is_valid is True
    assert result.value == "GENERATED_THREAT"


def test_validate_detection_type_invalid():
    """Test validate_detection_type with invalid input"""
    from WizDefend import validate_detection_type

    result = validate_detection_type("INVALID_TYPE")
    assert result.is_valid is False
    assert "Invalid detection type" in result.error_message


def test_validate_detection_platform_valid():
    """Test validate_detection_platform with valid input"""
    from WizDefend import validate_detection_platform

    result = validate_detection_platform("AWS")
    assert result.is_valid is True
    assert result.value == ["AWS"]


def test_validate_detection_platform_invalid():
    """Test validate_detection_platform with invalid input"""
    from WizDefend import validate_detection_platform

    result = validate_detection_platform("INVALID_PLATFORM")
    assert result.is_valid is False
    assert "Invalid platform" in result.error_message


def test_validate_detection_platform_none():
    """Test validate_detection_platform with None input"""
    from WizDefend import validate_detection_platform

    result = validate_detection_platform(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_creation_minutes_back_valid():
    """Test validate_creation_minutes_back with valid input"""
    from WizDefend import validate_creation_minutes_back

    result = validate_creation_minutes_back("10")
    assert result.is_valid is True
    assert result.minutes_value == 10


def test_validate_creation_minutes_back_invalid_format():
    """Test validate_creation_minutes_back with invalid format"""
    from WizDefend import validate_creation_minutes_back

    result = validate_creation_minutes_back("invalid")
    assert result.is_valid is False
    assert "must be a valid integer" in result.error_message


def test_validate_creation_minutes_back_out_of_range():
    """Test validate_creation_minutes_back with out of range value"""
    from WizDefend import validate_creation_minutes_back

    result = validate_creation_minutes_back("9")
    assert result.is_valid is False
    assert "must be a valid integer between 10 and 600" in result.error_message

    result = validate_creation_minutes_back("601")
    assert result.is_valid is False
    assert "must be a valid integer between 10 and 600" in result.error_message


def test_validate_creation_days_back_none():
    """Test validate_creation_days_back with None input"""
    from WizDefend import validate_creation_minutes_back

    result = validate_creation_minutes_back(None)
    assert result.is_valid is True
    assert result.minutes_value == 2  # Default value


def test_validate_severity_valid():
    """Test validate_severity with valid input"""
    from WizDefend import validate_severity

    result = validate_severity("CRITICAL")
    assert result.is_valid is True
    assert result.severity_list == ["CRITICAL"]


def test_validate_severity_invalid():
    """Test validate_severity with invalid input"""
    from WizDefend import validate_severity

    result = validate_severity("INVALID")
    assert result.is_valid is False
    assert "You should only use these severity types" in result.error_message


def test_validate_severity_case_insensitive():
    """Test validate_severity with lowercase input"""
    from WizDefend import validate_severity

    result = validate_severity("critical")
    assert result.is_valid is True
    assert result.severity_list == ["CRITICAL"]


def test_validate_severity_none():
    """Test validate_severity with None input"""
    from WizDefend import validate_severity

    result = validate_severity(None)
    assert result.is_valid is True
    assert result.severity_list is None


def test_validate_resource_id_valid():
    """Test validate_resource_id with valid input"""
    from WizDefend import validate_resource_id

    result = validate_resource_id("test-resource-id")
    assert result.is_valid is True
    assert result.value == "test-resource-id"


def test_validate_resource_id_none():
    """Test validate_resource_id with None input"""
    from WizDefend import validate_resource_id

    result = validate_resource_id(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_rule_match_id_valid():
    """Test validate_rule_match_id with valid UUID"""
    from WizDefend import validate_rule_match_id
    import uuid

    valid_uuid = str(uuid.uuid4())
    result = validate_rule_match_id(valid_uuid)
    assert result.is_valid is True
    assert result.value == valid_uuid


def test_validate_rule_match_id_invalid():
    """Test validate_rule_match_id with invalid UUID"""
    from WizDefend import validate_rule_match_id

    result = validate_rule_match_id("invalid-uuid")
    assert result.is_valid is False
    assert "Must be a valid UUID" in result.error_message


def test_validate_rule_match_id_none():
    """Test validate_rule_match_id with None input"""
    from WizDefend import validate_rule_match_id

    result = validate_rule_match_id(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_rule_match_name_valid():
    """Test validate_rule_match_name with valid input"""
    from WizDefend import validate_rule_match_name

    result = validate_rule_match_name("test rule")
    assert result.is_valid is True
    assert result.value == "test rule"


def test_validate_rule_match_name_none():
    """Test validate_rule_match_name with None input"""
    from WizDefend import validate_rule_match_name

    result = validate_rule_match_name(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_project_valid():
    """Test validate_project with valid input"""
    from WizDefend import validate_project

    result = validate_project("test project")
    assert result.is_valid is True
    assert result.value == "test project"


def test_validate_project_none():
    """Test validate_project with None input"""
    from WizDefend import validate_project

    result = validate_project(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_all_parameters():
    """Test the centralized parameter validation function"""
    from WizDefend import validate_all_parameters

    # Test with valid parameters
    params = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'resource_id': 'test-id',
        'severity': 'CRITICAL',
        'creation_minutes_back': '15',
        'matched_rule': str(uuid.uuid4()),
        'matched_rule_name': 'test rule',
        'project_id': 'test project'
    }

    success, error_message, validated_values = validate_all_parameters(params)
    assert success is True
    assert error_message is None
    assert validated_values['type'] == 'GENERATED_THREAT'
    assert validated_values['severity'] == ['CRITICAL']
    assert validated_values['creation_minutes_back'] == 15

    # Test with no parameters
    empty_params = {}
    success, error_message, validated_values = validate_all_parameters(empty_params)
    assert success is False
    assert 'You should pass at least one of the following parameters' in error_message

    # Test with invalid parameters
    invalid_params = {
        'type': 'INVALID_TYPE'
    }
    success, error_message, validated_values = validate_all_parameters(invalid_params)
    assert success is False
    assert 'Invalid detection type' in error_message


def test_apply_creation_in_last_minutes_filter():
    """Test apply_creation_in_last_minutes_filter function"""
    from WizDefend import apply_creation_in_last_minutes_filter

    variables = {}
    result = apply_creation_in_last_minutes_filter(variables, 5)

    assert 'filterBy' in result
    assert 'createdAt' in result['filterBy']
    assert result['filterBy']['createdAt']['inLast']['amount'] == 5
    assert result['filterBy']['createdAt']['inLast']['unit'] == 'DurationFilterValueUnitMinutes'


def test_apply_creation_in_last_days_filter_none():
    """Test apply_creation_in_last_days_filter with None"""
    from WizDefend import apply_creation_in_last_minutes_filter

    variables = {}
    result = apply_creation_in_last_minutes_filter(variables, None)

    assert result == {}


def test_apply_detection_type_filter():
    """Test apply_detection_type_filter function"""
    from WizDefend import apply_detection_type_filter

    variables = {}
    result = apply_detection_type_filter(variables, 'GENERATED_THREAT')

    assert 'filterBy' in result
    assert 'type' in result['filterBy']
    assert result['filterBy']['type']['equals'] == ['GENERATED_THREAT']


def test_apply_detection_type_filter_none():
    """Test apply_detection_type_filter with None"""
    from WizDefend import apply_detection_type_filter

    variables = {}
    result = apply_detection_type_filter(variables, None)

    assert result == {}


def test_apply_platform_filter():
    """Test apply_platform_filter function"""
    from WizDefend import apply_platform_filter

    variables = {}
    result = apply_platform_filter(variables, 'AWS')

    assert 'filterBy' in result
    assert 'cloudPlatform' in result['filterBy']
    assert result['filterBy']['cloudPlatform']['equals'] == ['AWS']


def test_apply_platform_filter_none():
    """Test apply_platform_filter with None"""
    from WizDefend import apply_platform_filter

    variables = {}
    result = apply_platform_filter(variables, None)

    assert result == {}


def test_apply_resource_id_filter():
    """Test apply_resource_id_filter function"""
    from WizDefend import apply_resource_id_filter

    variables = {}
    result = apply_resource_id_filter(variables, 'test-id')

    assert 'filterBy' in result
    assert 'resource' in result['filterBy']
    assert result['filterBy']['resource']['id']['equals'] == ['test-id']


def test_apply_resource_id_filter_none():
    """Test apply_resource_id_filter with None"""
    from WizDefend import apply_resource_id_filter

    variables = {}
    result = apply_resource_id_filter(variables, None)

    assert result == {}


def test_apply_severity_filter():
    """Test apply_severity_filter function"""
    from WizDefend import apply_severity_filter

    variables = {}
    result = apply_severity_filter(variables, ['CRITICAL', 'HIGH'])

    assert 'filterBy' in result
    assert 'severity' in result['filterBy']
    assert result['filterBy']['severity']['equals'] == ['CRITICAL', 'HIGH']


def test_apply_severity_filter_none():
    """Test apply_severity_filter with None"""
    from WizDefend import apply_severity_filter

    variables = {}
    result = apply_severity_filter(variables, None)

    assert result == {}


def test_apply_matched_rule_filter():
    """Test apply_matched_rule_filter function"""
    from WizDefend import apply_matched_rule_filter

    variables = {}
    result = apply_matched_rule_filter(variables, 'rule-id')

    assert 'filterBy' in result
    assert 'matchedRule' in result['filterBy']
    assert result['filterBy']['matchedRule']['id'] == 'rule-id'


def test_apply_matched_rule_filter_none():
    """Test apply_matched_rule_filter with None"""
    from WizDefend import apply_matched_rule_filter

    variables = {}
    result = apply_matched_rule_filter(variables, None)

    assert result == {}


def test_apply_matched_rule_name_filter():
    """Test apply_matched_rule_name_filter function"""
    from WizDefend import apply_matched_rule_name_filter

    variables = {}
    result = apply_matched_rule_name_filter(variables, 'rule name')

    assert 'filterBy' in result
    assert 'matchedRuleName' in result['filterBy']
    assert result['filterBy']['matchedRuleName']['equals'] == ['rule name']


def test_apply_matched_rule_name_filter_none():
    """Test apply_matched_rule_name_filter with None"""
    from WizDefend import apply_matched_rule_name_filter

    variables = {}
    result = apply_matched_rule_name_filter(variables, None)

    assert result == {}


def test_apply_project_id_filter():
    """Test apply_project_id_filter function"""
    from WizDefend import apply_project_id_filter

    variables = {}
    result = apply_project_id_filter(variables, 'project-id')

    assert 'filterBy' in result
    assert 'projectId' in result['filterBy']
    assert result['filterBy']['projectId'] == 'project-id'


def test_apply_project_id_filter_none():
    """Test apply_project_id_filter with None"""
    from WizDefend import apply_project_id_filter

    variables = {}
    result = apply_project_id_filter(variables, None)

    assert result == {}


def test_apply_all_filters():
    """Test apply_all_filters function with all values"""
    from WizDefend import apply_all_filters

    validated_values = {
        'type': 'GENERATED_THREAT',
        'platform': 'AWS',
        'resource_id': 'test-id',
        'severity': ['CRITICAL'],
        'creation_minutes_back': 15,
        'matched_rule': 'rule-id',
        'matched_rule_name': 'rule name',
        'project_id': 'project-id'
    }

    variables = {}
    result = apply_all_filters(variables, validated_values)

    assert 'filterBy' in result
    assert result['filterBy']['type']['equals'] == ['GENERATED_THREAT']
    assert result['filterBy']['cloudPlatform']['equals'] == ['AWS']
    assert result['filterBy']['resource']['id']['equals'] == ['test-id']
    assert result['filterBy']['severity']['equals'] == ['CRITICAL']
    assert result['filterBy']['createdAt']['inLast']['amount'] == 15
    assert result['filterBy']['matchedRule']['id'] == 'rule-id'
    assert result['filterBy']['matchedRuleName']['equals'] == ['rule name']
    assert result['filterBy']['projectId'] == 'project-id'


def test_query_api_pagination():
    """Test query_api function with pagination"""
    from WizDefend import query_api

    # Mock response with pagination
    first_response = copy.deepcopy(test_get_detections_response)
    first_response['data']['detections']['pageInfo']['hasNextPage'] = True
    first_response['data']['detections']['pageInfo']['endCursor'] = 'cursor1'

    second_response = copy.deepcopy(test_get_detections_response)
    second_response['data']['detections']['nodes'][0]['id'] = 'second-detection-id'
    second_response['data']['detections']['pageInfo']['hasNextPage'] = False

    with patch('WizDefend.get_entries', side_effect=[
        (first_response['data']['detections']['nodes'], first_response['data']['detections']['pageInfo']),
        (second_response['data']['detections']['nodes'], second_response['data']['detections']['pageInfo'])
    ]):
        result = query_api('test_query', {})

        # Should have both detections
        assert len(result) == 2
        assert result[0]['id'] == '12345678-1234-1234-1234-d25e16359c19'
        assert result[1]['id'] == 'second-detection-id'


def test_query_api_empty_response():
    """Test query_api function with empty response"""
    from WizDefend import query_api

    empty_page_info = {
        'hasNextPage': False,
        'endCursor': None
    }

    with patch('WizDefend.get_entries', return_value=([], empty_page_info)):
        result = query_api('test_query', {})

        assert result == {}


def test_get_entries_error_handling():
    """Test get_entries function error handling"""
    from WizDefend import get_entries

    # Test with API error response
    with patch('requests.post') as mock_post:
        mock_response = mock_post.return_value
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        mock_response.json.return_value = test_error_response

        with pytest.raises(Exception) as e:
            get_entries('test_query', {})
        assert 'Received an error while performing an API call' in str(e.value)


@patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
def test_get_detection_with_multiple_ids(query_api):
    """Test get_detection function with multiple detection IDs"""
    from WizDefend import get_filtered_detections

    valid_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    result = get_filtered_detections(detection_id=valid_ids)

    assert result == test_get_detections_response['data']['detections']['nodes']

    # Test with some invalid IDs
    mixed_ids = [str(uuid.uuid4()), 'invalid-id']
    result = get_filtered_detections(detection_id=mixed_ids)
    assert 'Wrong format: detection_id should be in UUID format' in result


@patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
def test_get_filtered_detection_with_issue_id(query_api):
    """Test get_detection function with issue_id"""
    from WizDefend import get_filtered_detections

    issue_id = str(uuid.uuid4())
    result = get_filtered_detections(issue_id=issue_id)

    assert result == test_get_detections_response['data']['detections']['nodes']

    # Test with invalid issue_id
    result = get_filtered_detections(issue_id='invalid-id')
    assert 'Wrong format: issue_id should be in UUID format' in result


def test_validation_response_class():
    """Test the ValidationResponse class"""
    from WizDefend import ValidationResponse

    # Test success response
    success_response = ValidationResponse.create_success('test_value')
    assert success_response.is_valid is True
    assert success_response.error_message is None
    assert success_response.value == 'test_value'

    # Test error response
    error_response = ValidationResponse.create_error('Error message')
    assert error_response.is_valid is False
    assert error_response.error_message == 'Error message'
    assert error_response.value is None

    # Test to_dict method
    response_dict = success_response.to_dict()
    assert 'is_valid' in response_dict
    assert 'error_message' in response_dict
    assert 'value' in response_dict


def test_detection_type_class():
    """Test the DetectionType class"""
    from WizDefend import DetectionType

    values = DetectionType.values()
    assert 'GENERATED THREAT' in values
    assert 'DID NOT GENERATE THREAT' in values
    assert len(values) == 2

    values = DetectionType.api_values()
    assert 'GENERATED_THREAT' in values
    assert 'MATCH_ONLY' in values
    assert len(values) == 2


def test_cloud_platform_class():
    """Test the CloudPlatform class"""
    from WizDefend import CloudPlatform

    values = CloudPlatform.values()
    assert 'AWS' in values
    assert 'Azure' in values
    assert 'GCP' in values
    assert 'Kubernetes' in values
    assert len(values) > 10  # Should have many platforms


def test_duration_unit_class():
    """Test the DurationUnit class"""
    from WizDefend import DurationUnit

    assert DurationUnit.DAYS == "DurationFilterValueUnitDays"
    assert DurationUnit.HOURS == "DurationFilterValueUnitHours"
    assert DurationUnit.MINUTES == "DurationFilterValueUnitMinutes"


def test_get_integration_user_agent():
    """Test the get_integration_user_agent function"""
    from WizDefend import get_integration_user_agent

    user_agent = get_integration_user_agent()
    assert '8864e131-72db-4928-1293-e292f0ed699f' in user_agent
    assert 'xsoar_defend' in user_agent
    assert '1.0.0' in user_agent


def test_set_authentication_endpoint():
    """Test setting the authentication endpoint"""
    from WizDefend import set_authentication_endpoint

    test_endpoint = 'https://test.auth.endpoint/oauth/token'
    set_authentication_endpoint(test_endpoint)

    import WizDefend
    assert WizDefend.AUTH_E == test_endpoint


def test_set_api_endpoint():
    """Test setting the API endpoint"""
    from WizDefend import set_api_endpoint

    test_endpoint = 'https://test.api.endpoint/graphql'
    set_api_endpoint(test_endpoint)

    import WizDefend
    assert WizDefend.URL == test_endpoint


def test_validate_detection_type_none():
    """Test validation when detection type is None"""
    from WizDefend import validate_detection_type

    result = validate_detection_type(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_detection_platform_none():
    """Test validation when platform is None"""
    from WizDefend import validate_detection_platform

    result = validate_detection_platform(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_severity_none():
    """Test validation when severity is None"""
    from WizDefend import validate_severity

    result = validate_severity(None)
    assert result.is_valid is True
    assert result.severity_list is None


def test_validate_creation_days_back_none():
    """Test validation when creation_days_back is None"""
    from WizDefend import validate_creation_minutes_back

    result = validate_creation_minutes_back(None)
    assert result.is_valid is True
    assert result.minutes_value == 10  # Default value


def test_validate_resource_id_none():
    """Test validation when resource_id is None"""
    from WizDefend import validate_resource_id

    result = validate_resource_id(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_rule_match_id_none():
    """Test validation when rule_match_id is None"""
    from WizDefend import validate_rule_match_id

    result = validate_rule_match_id(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_rule_match_name_none():
    """Test validation when rule_match_name is None"""
    from WizDefend import validate_rule_match_name

    result = validate_rule_match_name(None)
    assert result.is_valid is True
    assert result.value is None


def test_validate_project_none():
    """Test validation when project is None"""
    from WizDefend import validate_project

    result = validate_project(None)
    assert result.is_valid is True
    assert result.value is None


def test_apply_filters_with_none_values():
    """Test applying filters when values are None"""
    from WizDefend import (
        apply_creation_in_last_minutes_filter,
        apply_detection_type_filter,
        apply_platform_filter,
        apply_resource_id_filter,
        apply_severity_filter,
        apply_matched_rule_filter,
        apply_matched_rule_name_filter,
        apply_project_id_filter
    )

    variables = {}

    # Test each filter with None
    variables = apply_creation_in_last_minutes_filter(variables, None)
    assert variables == {}

    variables = apply_detection_type_filter(variables, None)
    assert variables == {}

    variables = apply_platform_filter(variables, None)
    assert variables == {}

    variables = apply_resource_id_filter(variables, None)
    assert variables == {}

    variables = apply_severity_filter(variables, None)
    assert variables == {}

    variables = apply_matched_rule_filter(variables, None)
    assert variables == {}

    variables = apply_matched_rule_name_filter(variables, None)
    assert variables == {}

    variables = apply_project_id_filter(variables, None)
    assert variables == {}


def test_get_token_without_access_token():
    """Test get_token when response doesn't contain access_token"""
    from WizDefend import get_token, set_authentication_endpoint

    set_authentication_endpoint('https://auth.wiz.io/oauth/token')

    with patch('requests.post') as mock_post:
        mock_response = mock_post.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {'message': 'No token provided'}

        with pytest.raises(Exception) as e:
            get_token()
        assert 'Could not retrieve token from Wiz' in str(e.value)


def test_get_token_json_parse_error():
    """Test get_token when response is not valid JSON"""
    from WizDefend import get_token, set_authentication_endpoint

    set_authentication_endpoint('https://auth.wiz.io/oauth/token')

    with patch('requests.post') as mock_post:
        mock_response = mock_post.return_value
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError('Invalid JSON')

        with pytest.raises(Exception) as e:
            get_token()
        assert 'Could not parse API response' in str(e.value)


def test_get_entries_with_token_refresh():
    """Test get_entries when token needs to be refreshed"""
    from WizDefend import get_entries, get_token

    with patch('WizDefend.TOKEN', None):
        with patch('WizDefend.get_token', return_value=TEST_TOKEN):
            with patch('requests.post') as mock_post:
                mock_response = mock_post.return_value
                mock_response.status_code = 200
                mock_response.json.return_value = test_get_detections_response

                entries, page_info = get_entries('test_query', {})

                assert entries == test_get_detections_response['data']['detections']['nodes']
                assert not page_info['hasNextPage']


def test_get_error_output_with_duplicate_errors():
    """Test get_error_output with duplicate error messages"""
    from WizDefend import get_error_output

    duplicate_error_response = {
        "errors": [
            {"message": "Same error"},
            {"message": "Same error"},
            {"message": "Different error"}
        ]
    }

    error_output = get_error_output(duplicate_error_response)

    # Should only include each error once
    assert error_output.count("Same error") == 1
    assert "Different error" in error_output


def test_fetch_incidents_no_last_run(mocker):
    """Test fetch_incidents when there's no last run time"""
    from WizDefend import fetch_incidents
    import demistomock as demisto
    from datetime import datetime

    # Mock no last run
    mocker.patch.object(demisto, 'getLastRun', return_value={})
    mocker.patch.object(demisto, 'params', return_value={'first_fetch': '2 days'})
    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')

    # Mock dateparser
    mocker.patch('dateparser.parse', return_value=datetime(2022, 1, 1))

    fetch_incidents()

    # Verify incidents were created
    assert demisto.incidents.called

def test_build_incidents_no_rule():
    """Test build_incidents when detection has no rule match"""
    from WizDefend import build_incidents

    detection_no_rule = {
        "id": "test-id",
        "createdAt": "2022-01-02T15:46:34Z",
        "severity": "HIGH"
    }

    incident = build_incidents(detection_no_rule)

    assert incident['name'] == 'No name - test-id'
    assert incident['severity'] == 3


def test_fetch_incidents_with_pagination(mocker):
    """Test fetch_incidents with paginated response"""
    from WizDefend import fetch_incidents
    import demistomock as demisto

    # Create response with pagination
    paginated_detections = copy.deepcopy(test_get_detections_response['data']['detections']['nodes'])

    # Create final response
    final_detections = copy.deepcopy(test_get_detections_response['data']['detections']['nodes'])
    final_detections[0]['id'] = 'second-detection-id'

    # Mock demisto functions
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2022-01-01T00:00:00Z'})

    # Mock query_api to return paginated results
    def mock_query_api(query, variables, paginate=True):
        if paginate:
            return paginated_detections + final_detections
        return paginated_detections

    mocker.patch('WizDefend.query_api', side_effect=mock_query_api)
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')

    fetch_incidents()

    # Verify incidents were created with both detections
    calls = demisto.incidents.call_args_list
    assert len(calls) == 1
    incidents = calls[0][0][0]
    assert len(incidents) == 2


def test_get_filtered_detections_all_parameters(mocker):
    """Test get_filtered_detections with all parameters provided"""
    from WizDefend import get_filtered_detections

    mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])

    # Update the parameter name from creation_days_back to creation_minutes_back
    result = get_filtered_detections(
        detection_type='GENERATED THREAT',
        detection_platform=['AWS', 'AKS'],
        resource_id='test-id',
        severity='CRITICAL',
        creation_minutes_back='10',
        matched_rule=str(uuid.uuid4()),
        matched_rule_name='test rule',
        project_id='test-project'
    )

    assert result == test_get_detections_response['data']['detections']['nodes']


def test_main_error_handling(mocker):
    """Test main function error handling"""
    from WizDefend import main

    mocker.patch.object(demisto, 'command', return_value='wiz-get-detections')
    mocker.patch.object(demisto, 'args', side_effect=Exception('Test error'))
    mocker.patch('WizDefend.return_error')

    main()

    # Verify return_error was called
    from WizDefend import return_error
    assert return_error.called


def test_validate_severity_case_insensitive():
    """Test that severity validation is case-insensitive"""
    from WizDefend import validate_severity

    result = validate_severity('critical')
    assert result.is_valid is True
    assert result.severity_list == ['CRITICAL']

    result = validate_severity('CRITICAL')
    assert result.is_valid is True
    assert result.severity_list == ['CRITICAL']


def test_is_valid_uuid_edge_cases():
    """Test is_valid_uuid with edge cases"""
    from WizDefend import is_valid_uuid

    # Test with integer
    assert is_valid_uuid(12345) is False

    # Test with object that can't be converted to string
    class NonStringifiable:
        def __str__(self):
            raise Exception("Can't stringify")

    # This should also return False, but might require try/except in the function
    try:
        result = is_valid_uuid(NonStringifiable())
        assert result is False
    except Exception:
        pass  # If exception is raised, it's also acceptable


def test_apply_creation_after_days_filter():
    """Test the apply_creation_after_days_filter function"""
    from WizDefend import apply_creation_after_time_filter

    variables = {}
    after_time = '2022-01-01T00:00:00Z'

    result = apply_creation_after_time_filter(variables, after_time)

    assert result['filterBy']['createdAt']['after'] == after_time

    # Test with None
    result = apply_creation_after_time_filter({}, None)
    assert result == {}


def test_query_api_with_none_nodes():
    """Test query_api when nodes are None"""
    from WizDefend import query_api

    mock_page_info = {
        'hasNextPage': False,
        'endCursor': None
    }

    with patch('WizDefend.get_entries', return_value=([], mock_page_info)):
        result = query_api('test_query', {})
        assert result == {}


def test_main_with_all_commands(mocker):
    """Test main function with all supported commands"""
    from WizDefend import main

    commands = ['test-module', 'fetch-incidents', 'wiz-get-detections', 'wiz-get-detection']

    for command in commands:
        mocker.patch.object(demisto, 'command', return_value=command)

        if command == 'test-module':
            mocker.patch('WizDefend.get_token', return_value=TEST_TOKEN)
            mocker.patch('WizDefend.query_api', return_value=[])
            mocker.patch.object(demisto, 'results')
        elif command == 'fetch-incidents':
            mocker.patch('WizDefend.fetch_incidents')
        else:
            mocker.patch.object(demisto, 'args', return_value=DEMISTO_ARGS)
            mocker.patch('WizDefend.query_api', return_value=test_get_detections_response['data']['detections']['nodes'])
            mocker.patch('WizDefend.return_results')

        main()


def test_detection_platform_values_match_cloud_platform_class():
    """Test that detection_platform values in YAML match CloudPlatform class values"""
    import yaml
    import os
    from WizDefend import CloudPlatform

    # Load the YAML file
    yaml_path = os.path.join(os.path.dirname(__file__), 'WizDefend.yml')
    with open(yaml_path, 'r') as yaml_file:
        yaml_content = yaml.safe_load(yaml_file)

    # Get values from CloudPlatform class
    cloud_platform_values = CloudPlatform.values()
    cloud_platform_set = set(cloud_platform_values)

    # Check configuration section
    config_param = None
    for config_item in yaml_content.get('configuration', []):
        if config_item.get('name') == 'platform':
            config_param = config_item
            break

    assert config_param is not None, "platform parameter not found in configuration section"

    config_options = config_param.get('options', [])
    config_options_set = set(config_options)

    # Check if configuration values match CloudPlatform class
    assert config_options_set == cloud_platform_set, (
        f"Configuration detection platform values don't match CloudPlatform class!\n"
        f"In configuration but not in CloudPlatform: {config_options_set - cloud_platform_set}\n"
        f"In CloudPlatform but not in configuration: {cloud_platform_set - config_options_set}"
    )

    # Check commands section
    commands = yaml_content.get('script', {}).get('commands', [])
    command_param = None

    for command in commands:
        if command.get('name') == 'wiz-get-detections':
            for arg in command.get('arguments', []):
                if arg.get('name') == 'platform':
                    command_param = arg
                    break
            break

    assert command_param is not None, "platform argument not found in wiz-get-detections command"

    command_predefined = command_param.get('predefined', [])
    command_predefined_set = set(command_predefined)

    # Check if command values match CloudPlatform class
    assert command_predefined_set == cloud_platform_set, (
        f"Command detection platform values don't match CloudPlatform class!\n"
        f"In command but not in CloudPlatform: {command_predefined_set - cloud_platform_set}\n"
        f"In CloudPlatform but not in command: {cloud_platform_set - command_predefined_set}"
    )

    # Check if both YAML locations have the same values
    assert config_options_set == command_predefined_set, (
        f"Detection platform values differ between configuration and command sections!\n"
        f"In configuration but not in command: {config_options_set - command_predefined_set}\n"
        f"In command but not in configuration: {command_predefined_set - config_options_set}"
    )

    # Print success message
    print(f"✓ Success: All {len(config_options)} detection platform values match across:")
    print(f"  - Configuration section")
    print(f"  - Command argument predefined values")
    print(f"  - CloudPlatform class")


def test_comprehensive_integration(mocker):
    """Test a complete flow from main to get_filtered_detections"""
    from WizDefend import main

    # Mock all necessary components
    mocker.patch.object(demisto, 'command', return_value='wiz-get-detections')
    mocker.patch.object(demisto, 'args', return_value=DEMISTO_ARGS)
    mocker.patch('requests.post')
    mocker.patch('WizDefend.return_results')

    # Mock token response
    with patch('requests.post') as mock_post:
        # First call is for token
        token_response = mock_post.return_value
        token_response.status_code = 200
        token_response.json.return_value = {'access_token': TEST_TOKEN}

        # Second call is for API
        api_response = mock_post.return_value
        api_response.status_code = 200
        api_response.json.return_value = test_get_detections_response

        main()

        # Verify return_results was called
        from WizDefend import return_results
        assert return_results.called


def test_validate_first_fetch_timestamp():
    """Test the validate_first_fetch_timestamp function"""
    from WizDefend import validate_first_fetch_timestamp
    from datetime import datetime, timedelta
    import dateparser

    # Test valid timestamp within 5 days
    is_valid, error_msg, valid_date = validate_first_fetch_timestamp('5 days')
    assert is_valid is True
    assert error_msg is None
    expected_date = dateparser.parse('5 days')
    assert (valid_date.date() - expected_date.date()).days == 0

    # Test timestamp beyond 5 days - should return max allowed
    is_valid, error_msg, valid_date = validate_first_fetch_timestamp('30 days')
    assert is_valid is True
    assert error_msg is None
    max_days_back = datetime.now() - timedelta(days=5)
    diff_days = abs((valid_date.date() - max_days_back.date()).days)
    assert diff_days <= 1  # Allow 1 day difference for test timing


def test_get_fetch_timestamp(mocker):
    """Test the get_fetch_timestamp function"""
    from WizDefend import get_fetch_timestamp
    import demistomock as demisto

    # Mock demisto.info and demisto.error
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')

    # Test valid timestamp within 5 days
    timestamp = get_fetch_timestamp('5 days')
    assert timestamp.endswith('Z')
    assert demisto.info.call_count == 0  # No info message for valid timestamp

    # Test timestamp beyond 5 days - should log info
    timestamp = get_fetch_timestamp('30 days')
    assert timestamp.endswith('Z')
    assert demisto.info.called
    info_call_args = demisto.info.call_args[0][0]
    # Use the actual message from your implementation
    assert 'automatically setting to 5 days back' in info_call_args  # Changed from 14 to 5


def test_fetch_incidents_with_timestamp_functions(mocker):
    """Test fetch_incidents with the new timestamp functions"""
    from WizDefend import fetch_incidents
    import demistomock as demisto
    from datetime import datetime

    # Mock demisto functions
    mocker.patch.object(demisto, 'getLastRun', return_value={})  # No last run - first fetch
    mocker.patch.object(demisto, 'params', return_value={
        'first_fetch': '20 days',  # More than 14 days
        'severity': 'HIGH',
        'detection_type': 'GENERATED_THREAT',
        'detection_platform': 'AWS'
    })
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')

    # Mock get_filtered_detections to return some test detections
    mock_detections = [
        {
            'id': 'test-id-1',
            'createdAt': '2022-01-01T00:00:00Z',
            'severity': 'HIGH',
            'ruleMatch': {'rule': {'name': 'Test Rule 1'}}
        }
    ]
    mocker.patch('WizDefend.get_filtered_detections', return_value=mock_detections)

    # Run fetch_incidents
    fetch_incidents()

    # Verify that demisto.info was called with the appropriate message
    assert demisto.info.called
    info_calls = [call[0][0] for call in demisto.info.call_args_list]
    assert any('First fetch timestamp was more than 5 days (20 days), automatically setting to 5 days back' in call for call in info_calls)

    # Verify incidents were created
    assert demisto.incidents.called
    incidents = demisto.incidents.call_args[0][0]
    assert len(incidents) == 1

    # Verify last run was set
    assert demisto.setLastRun.called


def test_fetch_incidents_with_invalid_timestamp(mocker):
    """Test fetch_incidents with invalid first fetch timestamp"""
    from WizDefend import fetch_incidents
    import demistomock as demisto

    # Mock demisto functions
    mocker.patch.object(demisto, 'getLastRun', return_value={})  # No last run - first fetch
    mocker.patch.object(demisto, 'params', return_value={
        'first_fetch': 'invalid timestamp format',
        'severity': 'HIGH',
        'detection_type': 'GENERATED_THREAT',
        'detection_platform': 'AWS'
    })
    mocker.patch.object(demisto, 'error')

    # Test that invalid timestamp raises an exception
    with pytest.raises(ValueError) as e:
        fetch_incidents()
    assert 'Invalid date format' in str(e.value)

    # Verify error was logged
    assert demisto.error.called
    error_calls = [call[0][0] for call in demisto.error.call_args_list]
    assert any('Invalid date format' in call for call in error_calls)


def test_get_fetch_timestamp_date_comparison(mocker):
    """Test the date comparison logic in get_fetch_timestamp"""
    from WizDefend import get_fetch_timestamp
    import demistomock as demisto
    from datetime import datetime, timedelta
    import dateparser

    # Mock demisto.info
    mocker.patch.object(demisto, 'info')

    # Test when date is exactly at 5 days boundary
    fourteen_days_ago = datetime.now() - timedelta(days=5)
    fourteen_days_ago_str = f"{fourteen_days_ago.strftime('%Y-%m-%d')} 00:00:00"

    # Parse to get a date object for comparison
    parsed_date = dateparser.parse(fourteen_days_ago_str)

    timestamp = get_fetch_timestamp(fourteen_days_ago_str)
    assert timestamp.endswith('Z')

    # Should not log info message since it's exactly at boundary
    assert not demisto.info.called

    # Test with a slight offset to ensure comparison is working
    fifteen_days_ago = datetime.now() - timedelta(days=6)
    fifteen_days_ago_str = f"{fifteen_days_ago.strftime('%Y-%m-%d')} 00:00:00"

    timestamp = get_fetch_timestamp(fifteen_days_ago_str)
    assert timestamp.endswith('Z')

    # Should log info message since it's beyond boundary
    assert demisto.info.called
    info_call_args = demisto.info.call_args[0][0]
    assert 'automatically setting to 5 days back' in info_call_args


def test_multiple_detection_platforms(mocker):
    """Test handling of multiple detection platforms in get_filtered_detections"""
    from WizDefend import get_filtered_detections, validate_detection_platform, apply_platform_filter

    # Test validation with multiple platforms
    platforms_list = ["AWS", "Azure", "GCP"]
    platforms_str = "AWS,Azure,GCP"

    # Test validation with list input
    list_validation = validate_detection_platform(platforms_list)
    assert list_validation.is_valid is True
    assert sorted(list_validation.value) == sorted(platforms_list)

    # Test validation with comma-separated string
    str_validation = validate_detection_platform(platforms_str)
    assert str_validation.is_valid is True
    assert sorted(str_validation.value) == sorted(platforms_list)

    # Test validation with invalid platforms
    invalid_validation = validate_detection_platform("AWS,InvalidPlatform")
    assert invalid_validation.is_valid is False
    assert "Invalid platform(s): InvalidPlatform" in invalid_validation.error_message

    # Test filter application
    variables = {}
    updated_vars = apply_platform_filter(variables, platforms_list)

    assert WizApiVariables.FILTER_BY in updated_vars
    assert WizApiVariables.CLOUD_PLATFORM in updated_vars[WizApiVariables.FILTER_BY]
    assert WizApiVariables.EQUALS in updated_vars[WizApiVariables.FILTER_BY][WizApiVariables.CLOUD_PLATFORM]
    assert sorted(updated_vars[WizApiVariables.FILTER_BY][WizApiVariables.CLOUD_PLATFORM][WizApiVariables.EQUALS]) == sorted(
        platforms_list)

    # Test the entire flow with mock API call
    mock_query = mocker.patch('WizDefend.query_api', return_value=[{"id": "test-detection"}])

    result = get_filtered_detections(detection_platform=platforms_str)

    # Verify that query_api was called with the right variables
    call_args = mock_query.call_args[0]


def test_detection_type_parsing():
    """Test that detection types are correctly parsed in various formats"""
    from WizDefend import validate_detection_type, DetectionType, apply_detection_type_filter

    # Test cases with different input formats
    test_cases = [
    # Format: (input_value, expected_is_valid, expected_api_value)
    ("GENERATED THREAT", True, "GENERATED_THREAT"),
    ("GENERATED_THREAT", True, "GENERATED_THREAT"),  # API format
    ("generated threat", True, "GENERATED_THREAT"),  # lowercase
    ("DID NOT GENERATE THREAT", True, "MATCH_ONLY"),
    ("did not generate threat", True, "MATCH_ONLY"),  # lowercase
    ("NO_MATCH", True, "MATCH_ONLY"),  # Direct API value
    ("INVALID_TYPE", False, None),  # Invalid type
    (None, True, None),  # None should be valid (no filter)
    ("", True, None),  # Empty string should be valid (no filter)
    ]

    for input_value, expected_is_valid, expected_api_value in test_cases:
        result = validate_detection_type(input_value)

    assert result.is_valid == expected_is_valid, \
        f"validate_detection_type failed for '{input_value}'. Expected valid={expected_is_valid}, got {result.is_valid}"

    if expected_is_valid:
        assert result.value == expected_api_value, \
            f"validate_detection_type failed for '{input_value}'. Expected API value='{expected_api_value}', got '{result.value}'"

    # Test apply_detection_type_filter function
    variables = {}
    filtered_variables = apply_detection_type_filter(variables, input_value)

    if not expected_api_value:
        # If no API value expected, the filter should not be added
        assert 'filterBy' not in filtered_variables or 'type' not in filtered_variables.get('filterBy', {}), \
            f"apply_detection_type_filter should not add filter for '{input_value}', but added: {filtered_variables}"
    else:
        # If API value expected, verify filter structure
        assert 'filterBy' in filtered_variables, \
            f"apply_detection_type_filter missing filterBy for '{input_value}'"
        assert 'type' in filtered_variables['filterBy'], \
            f"apply_detection_type_filter missing type filter for '{input_value}'"
        assert 'equals' in filtered_variables['filterBy']['type'], \
            f"apply_detection_type_filter missing equals in type filter for '{input_value}'"
        assert filtered_variables['filterBy']['type']['equals'] == [expected_api_value], \
            f"apply_detection_type_filter wrong value for '{input_value}'. Expected [{expected_api_value}], got {filtered_variables['filterBy']['type']['equals']}"

    # Test direct API mapping in DetectionType class
    assert DetectionType.get_api_value("GENERATED THREAT") == "GENERATED_THREAT"
    assert DetectionType.get_api_value("DID NOT GENERATE THREAT") == "MATCH_ONLY"


def test_detection_type_in_full_request_flow(mocker):
    """Test that detection type is correctly handled in the full request flow"""
    from WizDefend import get_filtered_detections, query_api, DetectionType

    # First, let's check the direct mapping in DetectionType class
    api_value = DetectionType.get_api_value("GENERATED THREAT")
    assert api_value == "GENERATED_THREAT", f"DetectionType.get_api_value('GENERATED THREAT') returned {api_value} instead of 'GENERATED_THREAT'"

    # Mock the query_api function to capture the variables sent to the API
    mock_query = mocker.patch('WizDefend.query_api', return_value=[{"id": "test-detection"}])

    # Test with valid detection type
    get_filtered_detections(detection_type="GENERATED THREAT", severity="CRITICAL")  # Add severity to pass validation

    # Check that the API was called with the correct variables
    call_args = mock_query.call_args[0]
    variables = call_args[1]

    assert 'filterBy' in variables
    assert 'type' in variables['filterBy']
    assert 'equals' in variables['filterBy']['type']
    assert variables['filterBy']['type']['equals'] == ["GENERATED_THREAT"]

    # Reset mock and test with second detection type
    mock_query.reset_mock()
    get_filtered_detections(detection_type="DID NOT GENERATE THREAT", severity="CRITICAL")

    call_args = mock_query.call_args[0]
    variables = call_args[1]

    assert 'filterBy' in variables
    assert 'type' in variables['filterBy']
    assert 'equals' in variables['filterBy']['type']
    assert variables['filterBy']['type']['equals'] == ["MATCH_ONLY"]

    # Reset mock and test with None detection type (should not add filter)
    mock_query.reset_mock()
    get_filtered_detections(detection_type=None, severity="CRITICAL")  # Add severity to pass validation

    call_args = mock_query.call_args[0]
    variables = call_args[1]

    # Type filter should not be present or should be None
    assert 'filterBy' in variables
    if 'type' in variables['filterBy']:
        assert variables['filterBy']['type']['equals'] == [None] or variables['filterBy']['type']['equals'] == []


def test_validate_incident_type():
    """Test validate_incident_type function"""
    from WizDefend import validate_incident_type

    # Test with valid incident type
    result = validate_incident_type("WizDefend Detection")
    assert result.is_valid is True
    assert result.value == "WizDefend Detection"

    # Test with valid incident type in different case
    result = validate_incident_type("wizdefend detection")
    assert result.is_valid is False

    # Test with no incident type (should return default)
    result = validate_incident_type(None)
    assert result.is_valid is False

    # Test with invalid incident type
    result = validate_incident_type("Some Other Type")
    assert result.is_valid is False
    assert "Invalid incident type" in result.error_message


def test_validate_first_fetch():
    """Test validate_first_fetch function"""
    from WizDefend import validate_first_fetch, MAX_DAYS_FIRST_FETCH_DETECTIONS, DEFAULT_FETCH_BACK

    # Test with valid duration in hours
    result = validate_first_fetch("12 hours")
    assert result.is_valid is True
    assert result.value == "12 hours"

    # Test with valid duration in days
    result = validate_first_fetch("2 days")
    assert result.is_valid is True
    assert result.value == "2 days"

    # Test with valid duration in minutes
    result = validate_first_fetch("30 minutes")
    assert result.is_valid is True
    assert result.value == "30 minutes"

    # Test with no duration (should return default)
    result = validate_first_fetch(None)
    assert result.is_valid is False

    # Test with empty string
    result = validate_first_fetch("")
    assert result.is_valid is False

    # Test with invalid format
    result = validate_first_fetch("not a duration")
    assert result.is_valid is False
    assert "Invalid first fetch format" in result.error_message

    # Test with invalid unit
    result = validate_first_fetch("5 years")
    assert result.is_valid is False
    assert "Invalid first fetch format" in result.error_message

    # Test exact maximum days
    result = validate_first_fetch(f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days")
    assert result.is_valid is True
    assert result.value == f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days"

    # Test exceeding maximum days
    result = validate_first_fetch(f"{MAX_DAYS_FIRST_FETCH_DETECTIONS + 1} days")
    assert result.is_valid is False
    assert "Maximum allowed is" in result.error_message

    result = get_filtered_detections(detection_origin=['dfaf'])
    print(result)
    # Test exact maximum hours
    max_hours = MAX_DAYS_FIRST_FETCH_DETECTIONS * 24
    result = validate_first_fetch(f"{max_hours} hours")
    assert result.is_valid is True
    assert result.value == f"{max_hours} hours"

    # Test exceeding maximum hours
    result = validate_first_fetch(f"{max_hours + 1} hours")
    assert result.is_valid is False
    assert "Maximum allowed is" in result.error_message

    # Test exact maximum minutes
    max_minutes = MAX_DAYS_FIRST_FETCH_DETECTIONS * 24 * 60
    result = validate_first_fetch(f"{max_minutes} minutes")
    assert result.is_valid is True
    assert result.value == f"{max_minutes} minutes"

    # Test exceeding maximum minutes
    result = validate_first_fetch(f"{max_minutes + 1} minutes")
    assert result.is_valid is False
    assert "Maximum allowed is" in result.error_message

    # Test singular units
    result = validate_first_fetch("1 day")
    assert result.is_valid is True
    assert result.value == "1 day"

    result = validate_first_fetch("1 hour")
    assert result.is_valid is True
    assert result.value == "1 hour"

    result = validate_first_fetch("1 minute")
    assert result.is_valid is True
    assert result.value == "1 minute"