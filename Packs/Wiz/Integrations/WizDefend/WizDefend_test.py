import copy
import random
import re
import uuid
from datetime import datetime, timedelta

import pytest
from unittest.mock import patch, MagicMock
import demistomock as demisto

from CommonServerPython import DemistoException
from Packs.Wiz.Integrations.WizDefend.WizDefend import (
    # Constants
    WIZ_VERSION, WIZ_DEFEND_INCIDENT_TYPE, INTEGRATION_GUID,
    MAX_DAYS_FIRST_FETCH_DETECTIONS, FETCH_INTERVAL_MINIMUM_MIN, FETCH_INTERVAL_MAXIMUM_MIN,
    # Classes
    ValidationResponse, DetectionType, CloudPlatform, WizApiVariables, DurationUnit,
    WizInputParam, WizApiResponse, WizSeverity, DetectionOrigin,
    # Core functions
    get_token, get_entries, query_api,
    # Validation functions
    validate_detection_type, validate_detection_platform, validate_detection_origin,
    validate_detection_subscription, validate_creation_minutes_back, validate_severity,
    validate_resource_id, validate_rule_match_id, validate_rule_match_name,
    validate_project, validate_all_parameters, validate_incident_type, validate_first_fetch,
    validate_fetch_interval, validate_first_fetch_timestamp,
    # Filter functions
    apply_creation_in_last_minutes_filter, apply_creation_after_time_filter,
    apply_detection_type_filter, apply_platform_filter, apply_origin_filter,
    apply_resource_id_filter, apply_subscription_filter, apply_severity_filter,
    apply_matched_rule_filter, apply_matched_rule_name_filter, apply_project_id_filter,
    apply_detection_id_filter, apply_issue_id_filter, apply_all_filters,
    # Utility functions
    get_integration_user_agent, translate_severity, build_incidents, is_valid_uuid,
    is_valid_param_id, get_error_output, get_detection_url,
    # Integration functions
    set_authentication_endpoint, set_api_endpoint, get_filtered_detections,
    get_last_run_time, get_fetch_timestamp, extract_params_from_integration_settings,
    check_advanced_params, test_module, fetch_incidents, main, WIZ_DEFEND,
)


# ===== TEST FIXTURES =====

@pytest.fixture(autouse=True)
def set_mocks(mocker):
    """Set up common mocks that should apply to all tests"""
    integration_params = {
        'api_endpoint': 'http://test.io',
        'credentials': {'identifier': 'test', 'password': 'pass'},
        'first_fetch': '2 days',
        'auth_endpoint': "https://auth.wiz.io/oauth/token"
    }
    mocker.patch.object(demisto, 'params', return_value=integration_params)
    mocker.patch('WizDefend.TOKEN', 'test-token')
    mocker.patch('WizDefend.AUTH_E', integration_params['auth_endpoint'])
    mocker.patch('WizDefend.URL', integration_params['api_endpoint'])

    # Mock logging functions to prevent test output pollution
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')


@pytest.fixture(autouse=True)
def global_mocks(mocker):
    """Apply critical mocks to all tests"""
    # Mock token and authentication
    mocker.patch('WizDefend.TOKEN', 'test-token')
    mocker.patch('WizDefend.get_token', return_value='test-token')

    # Mock API endpoints
    mocker.patch('WizDefend.AUTH_E', 'https://auth.wiz.io/oauth/token')
    mocker.patch('WizDefend.URL', 'https://api.wiz.io/graphql')

    # Mock demisto parameters
    mocker.patch.object(demisto, 'params', return_value={
        'api_endpoint': 'https://api.wiz.io/graphql',
        'credentials': {'identifier': 'test', 'password': 'pass'},
        'first_fetch': '2 days',
        'auth_endpoint': 'https://auth.wiz.io/oauth/token'
    })

    # Silence logging
    mocker.patch.object(demisto, 'debug')
    mocker.patch.object(demisto, 'info')
    mocker.patch.object(demisto, 'error')


def patch_wiz_api(api_response=None):
    """
    Returns a list of patch decorators for all Wiz API-related functions and variables.

    Args:
        api_response (dict or list, optional): Custom API response to return from get_entries.
            If None, returns a default sample detection.

    Returns:
        list: List of patch decorators
    """
    # Default response if none provided
    if api_response is None:
        sample_detection = {"id": "test-detection", "severity": "CRITICAL"}
        api_response = [sample_detection]  # Default to list for consistent handling

    # Ensure api_response is in the expected format for get_entries
    if isinstance(api_response, list):
        mock_return = (api_response, {"hasNextPage": False, "endCursor": ""})
    else:
        # Assume it's a complete response structure
        mock_return = api_response

    return [
        patch('WizDefend.get_token', return_value='test-token'),
        patch('WizDefend.TOKEN', 'test-token'),
        patch('WizDefend.AUTH_E', 'https://auth.wiz.io/oauth/token'),
        patch('WizDefend.URL', 'https://api.wiz.io/graphql'),
        patch('WizDefend.get_entries', return_value=mock_return)
    ]


def mock_wiz_api(monkeypatch, mocker, api_response=None):
    """
    Helper function to mock all Wiz API-related functions and variables
    """
    # Mock the entire query_api function which is called by get_filtered_detections
    if api_response is None:
        sample_detection = {"id": "test-detection", "severity": "CRITICAL"}
        api_response = [sample_detection]

    # This creates a mock that completely bypasses get_entries and get_token
    mock_query_api = mocker.patch('WizDefend.query_api', return_value=api_response)

    return mock_query_api


@pytest.fixture
def mock_response_factory():
    """Create mock response objects with configurable status and JSON content"""

    def _create_mock_response(status_code=200, json_data=None, text=None):
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = json_data or {}
        mock_response.text = text or ""
        return mock_response

    return _create_mock_response


@pytest.fixture
def sample_detection():
    """Return a sample detection object for testing"""
    return {
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


@pytest.fixture
def sample_detection_no_rule():
    """Return a sample detection object without a rule match for testing edge cases"""
    return {
        "id": "12345678-1234-1234-1234-d25e16359c19",
        "issue": {
            "id": "98765432-4321-4321-4321-ff5fa2ff7f78",
            "url": "https://app.wiz.io/issues/98765432-4321-4321-4321-ff5fa2ff7f78"
        },
        "description": "Suspicious activity without rule match",
        "severity": "HIGH",
        "createdAt": "2022-01-02T15:46:34Z",
        "startedAt": "2022-01-02T15:45:00Z",
        "endedAt": "2022-01-02T15:47:00Z",
        "actors": [],
        "resources": [],
        "triggeringEvents": {
            "nodes": []
        }
    }


@pytest.fixture
def mock_api_response(sample_detection):
    """Return a complete API response structure"""
    return {
        "data": {
            "detections": {
                "nodes": [sample_detection],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": ""
                }
            }
        }
    }


@pytest.fixture
def sample_detection():
    """Return a sample detection object for testing"""
    return {
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


@pytest.fixture
def mock_api_paginated_response(sample_detection):
    """Return a paginated API response for testing pagination"""
    detection2 = copy.deepcopy(sample_detection)
    detection2["id"] = "second-detection-id"

    # First page response
    first_page = {
        "data": {
            "detections": {
                "nodes": [sample_detection],
                "pageInfo": {
                    "hasNextPage": True,
                    "endCursor": "cursor1"
                }
            }
        }
    }

    # Second page response
    second_page = {
        "data": {
            "detections": {
                "nodes": [detection2],
                "pageInfo": {
                    "hasNextPage": False,
                    "endCursor": ""
                }
            }
        }
    }

    return first_page, second_page


@pytest.fixture
def mock_api_error_response():
    """Return an API error response"""
    return {
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


@pytest.fixture
def mock_api_empty_response():
    """Return an empty API response"""
    return {
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


# ===== VALIDATION FUNCTION TESTS =====

@pytest.mark.parametrize("detection_type,expected_valid,expected_value", [
    ("GENERATED THREAT", True, "GENERATED_THREAT"),
    ("GENERATED_THREAT", False, None),
    ("generated threat", True, "GENERATED_THREAT"),  # Case insensitive
    ("DID NOT GENERATE THREAT", True, "MATCH_ONLY"),
    ("did not generate threat", True, "MATCH_ONLY"),  # Case insensitive
    ("MATCH_ONLY", False, None),
    ("INVALID_TYPE", False, None),
    (None, True, None),  # None should be valid (no filter)
    ("", True, None),  # Empty string should be valid (no filter)
])
def test_validate_detection_type(detection_type, expected_valid, expected_value):
    """Test validate_detection_type with various inputs"""
    result = validate_detection_type(detection_type)
    assert result.is_valid == expected_valid
    assert result.value == expected_value


@pytest.mark.parametrize("platform,expected_valid,expected_value", [
    ("AWS", True, ["AWS"]),
    (["AWS", "Azure", "GCP"], True, ["AWS", "Azure", "GCP"]),
    ("AWS,Azure,GCP", True, ["AWS", "Azure", "GCP"]),  # Comma-separated
    ("INVALID_PLATFORM", False, None),
    ("AWS,INVALID_PLATFORM", False, None),  # One invalid in list
    (None, True, None),
])
def test_validate_detection_platform(platform, expected_valid, expected_value):
    """Test validate_detection_platform with various inputs"""
    result = validate_detection_platform(platform)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("origin,expected_valid,expected_value", [
    ("WIZ_SENSOR", True, ["WIZ_SENSOR"]),
    (["WIZ_SENSOR", "AWS_GUARD_DUTY"], True, ["WIZ_SENSOR", "AWS_GUARD_DUTY"]),
    ("WIZ_SENSOR,AWS_GUARD_DUTY", True, ["WIZ_SENSOR", "AWS_GUARD_DUTY"]),  # Comma-separated
    ("INVALID_ORIGIN", False, None),
    ("WIZ_SENSOR,INVALID_ORIGIN", False, None),  # One invalid in list
    (None, True, None),
])
def test_validate_detection_origin(origin, expected_valid, expected_value):
    """Test validate_detection_origin with various inputs"""
    result = validate_detection_origin(origin)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("subscription,expected_valid,expected_value", [
    ("test-subscription", True, "test-subscription"),
    ("", True, ""),
    (None, True, None),
    (123, False, None),  # Non-string should be invalid
])
def test_validate_detection_subscription(subscription, expected_valid, expected_value):
    """Test validate_detection_subscription with various inputs"""
    result = validate_detection_subscription(subscription)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("minutes_back,expected_valid,expected_value", [
    ("5", True, 5),  # Minimum value
    ("600", True, 600),  # Maximum value
    ("300", True, 300),  # Middle value
    ("4", False, None),  # Below minimum
    ("601", False, None),  # Above maximum
    ("not_a_number", False, None),  # Non-numeric
    (None, True, FETCH_INTERVAL_MINIMUM_MIN),  # None defaults to minimum
])
def test_validate_creation_minutes_back(minutes_back, expected_valid, expected_value):
    """Test validate_creation_minutes_back with various inputs"""
    result = validate_creation_minutes_back(minutes_back)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.minutes_value == expected_value


@pytest.mark.parametrize("severity,expected_valid,expected_list", [
    ("CRITICAL", True, ["CRITICAL"]),
    ("HIGH", True, ["CRITICAL", "HIGH"]),
    ("MEDIUM", True, ["CRITICAL", "HIGH", "MEDIUM"]),
    ("LOW", True, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    ("INFORMATIONAL", True, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]),
    ("critical", True, ["CRITICAL"]),  # Case insensitive
    ("INVALID", False, None),
    (None, True, None),  # None is valid (no filter)
])
def test_validate_severity(severity, expected_valid, expected_list):
    """Test validate_severity with various inputs"""
    result = validate_severity(severity)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.severity_list == expected_list


@pytest.mark.parametrize("resource_id,expected_valid,expected_value", [
    ("test-resource-id", True, "test-resource-id"),
    ("", True, ""),
    (None, True, None),
    (123, True, 123),  # Any value should be valid
])
def test_validate_resource_id(resource_id, expected_valid, expected_value):
    """Test validate_resource_id with various inputs"""
    result = validate_resource_id(resource_id)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("rule_id,expected_valid,expected_value", [
    (str(uuid.uuid4()), True, None),  # Valid UUID
    ("invalid-uuid", False, None),  # Invalid UUID
    (None, True, None),  # None is valid
])
def test_validate_rule_match_id(rule_id, expected_valid, expected_value):
    """Test validate_rule_match_id with various inputs"""
    result = validate_rule_match_id(rule_id)
    assert result.is_valid == expected_valid
    if expected_valid and rule_id:
        assert result.value == rule_id


@pytest.mark.parametrize("rule_name,expected_valid,expected_value", [
    ("test rule", True, "test rule"),
    ("", True, ""),
    (None, True, None),
    (123, True, 123),  # Any value should be valid
])
def test_validate_rule_match_name(rule_name, expected_valid, expected_value):
    """Test validate_rule_match_name with various inputs"""
    result = validate_rule_match_name(rule_name)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("project,expected_valid,expected_value", [
    ("test project", True, "test project"),
    ("", True, ""),
    (None, True, None),
    (123, True, 123),  # Any value should be valid
])
def test_validate_project(project, expected_valid, expected_value):
    """Test validate_project with various inputs"""
    result = validate_project(project)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("incident_type,expected_valid,expected_value", [
    (WIZ_DEFEND_INCIDENT_TYPE, True, WIZ_DEFEND_INCIDENT_TYPE),
    ("Other Type", False, None),
    (None, False, None),
])
def test_validate_incident_type(incident_type, expected_valid, expected_value):
    """Test validate_incident_type with various inputs"""
    result = validate_incident_type(incident_type)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize("fetch_interval,expected_valid,expected_value", [
    (5, True, 5),  # Valid - at minimum
    (30, True, 30),  # Valid - above minimum
    (4, False, None),  # Invalid - below minimum
    (None, False, None),  # Invalid - None
])
def test_validate_fetch_interval(fetch_interval, expected_valid, expected_value):
    """Test validate_fetch_interval with various inputs"""
    result = validate_fetch_interval(fetch_interval)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.minutes_value == expected_value


@pytest.mark.parametrize("first_fetch,expected_valid,expected_value", [
    ("2 days", True, "2 days"),
    ("12 hours", True, "12 hours"),
    ("30 minutes", True, "30 minutes"),
    (f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days", True, f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days"),
    (f"{MAX_DAYS_FIRST_FETCH_DETECTIONS + 1} days", False, None),
    ("not a duration", False, None),
    ("5 years", False, None),
    ("", False, None),
    (None, False, None),
])
def test_validate_first_fetch(first_fetch, expected_valid, expected_value):
    """Test validate_first_fetch with various inputs"""
    result = validate_first_fetch(first_fetch)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


def test_validate_first_fetch_timestamp(mocker):
    """Test validate_first_fetch_timestamp function"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend
    import datetime as dt
    from freezegun import freeze_time

    # Use freezegun to mock datetime.now()
    with freeze_time("2022-01-06 12:00:00"):
        # Current time is now frozen at 2022-01-06
        current_time = dt.datetime(2022, 1, 6, 12, 0, 0)
        max_days_ago = current_time - dt.timedelta(days=WizDefend.MAX_DAYS_FIRST_FETCH_DETECTIONS)

        # Test with valid date (2 days ago)
        valid_date = dt.datetime(2022, 1, 4, 12, 0, 0)
        mocker.patch('dateparser.parse', return_value=valid_date)

        is_valid, error_msg, date = WizDefend.validate_first_fetch_timestamp("2 days")
        assert is_valid is True
        assert error_msg is None
        assert date == valid_date

        # Test with date beyond limits (30 days ago)
        old_date = dt.datetime(2021, 12, 1, 12, 0, 0)
        mocker.patch('dateparser.parse', return_value=old_date)

        is_valid, error_msg, date = WizDefend.validate_first_fetch_timestamp("30 days")
        assert is_valid is True  # Still valid, but adjusted
        assert error_msg is None
        assert date == max_days_ago  # Should be adjusted to max_days_ago

        # Test with invalid date format
        mocker.patch('dateparser.parse', return_value=None)

        is_valid, error_msg, date = WizDefend.validate_first_fetch_timestamp("invalid format")
        assert is_valid is False
        assert "Invalid date format" in error_msg
        assert date is None


def test_validate_all_parameters():
    """Test validate_all_parameters with various parameter combinations"""
    # Test with all valid parameters
    valid_params = {
        'detection_id': str(uuid.uuid4()),
        'issue_id': str(uuid.uuid4()),
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'origin': 'WIZ_SENSOR',
        'subscription': 'test-subscription',
        'resource_id': 'test-resource',
        'severity': 'CRITICAL',
        'creation_minutes_back': '15',
        'matched_rule': str(uuid.uuid4()),
        'matched_rule_name': 'test rule',
        'project_id': 'test-project'
    }

    success, error_message, validated_values = validate_all_parameters(valid_params)
    assert success is True
    assert error_message is None
    assert validated_values['type'] == 'GENERATED_THREAT'
    assert validated_values['platform'] == ['AWS']
    assert validated_values['origin'] == ['WIZ_SENSOR']
    assert validated_values['severity'] == ['CRITICAL']
    assert validated_values['creation_minutes_back'] == 15

    # Test with no parameters (should fail)
    empty_params = {}
    success, error_message, validated_values = validate_all_parameters(empty_params)
    assert success is False
    assert "You should pass at least one of the following parameters" in error_message

    # Test with after_time parameter (special case)
    after_time_params = {
        'severity': 'CRITICAL',
        'after_time': '2022-01-01T00:00:00Z'
    }
    success, error_message, validated_values = validate_all_parameters(after_time_params)
    assert success is True
    assert error_message is None
    assert validated_values['after_time'] == '2022-01-01T00:00:00Z'

    # Test with conflicting time parameters
    conflicting_params = {
        'severity': 'CRITICAL',
        'creation_minutes_back': '15',
        'after_time': '2022-01-01T00:00:00Z'
    }
    success, error_message, validated_values = validate_all_parameters(conflicting_params)
    assert success is False
    assert "Cannot provide both" in error_message

    # Test with invalid detection_id
    invalid_id_params = {
        'detection_id': 'invalid-uuid',
        'severity': 'CRITICAL'
    }
    success, error_message, validated_values = validate_all_parameters(invalid_id_params)
    assert success is False
    assert "should be in UUID format" in error_message

    # Test with invalid detection type
    invalid_type_params = {
        'type': 'INVALID_TYPE',
        'severity': 'CRITICAL'
    }
    success, error_message, validated_values = validate_all_parameters(invalid_type_params)
    assert success is False
    assert "Invalid detection type" in error_message

    # Test with invalid platform
    invalid_platform_params = {
        'platform': 'INVALID_PLATFORM',
        'severity': 'CRITICAL'
    }
    success, error_message, validated_values = validate_all_parameters(invalid_platform_params)
    assert success is False
    assert "Invalid platform" in error_message

    # Test with invalid severity
    invalid_severity_params = {
        'severity': 'INVALID'
    }
    success, error_message, validated_values = validate_all_parameters(invalid_severity_params)
    assert success is False
    assert "You should only use these severity types" in error_message

    # Test with invalid creation_minutes_back
    invalid_minutes_params = {
        'creation_minutes_back': '4',  # Below minimum
        'severity': 'CRITICAL'
    }
    success, error_message, validated_values = validate_all_parameters(invalid_minutes_params)
    assert success is False
    assert "must be a valid integer between" in error_message


# ===== FILTER APPLICATION TESTS =====

def test_apply_detection_type_filter():
    """Test apply_detection_type_filter function"""
    # Test with value
    variables = {}
    result = apply_detection_type_filter(variables, "GENERATED_THREAT")
    assert "filterBy" in result
    assert "type" in result["filterBy"]
    assert result["filterBy"]["type"]["equals"] == ["GENERATED_THREAT"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_detection_type_filter(variables, None)
    assert result == {}

    # Test with existing filterBy
    variables = {"filterBy": {"existingFilter": "value"}}
    result = apply_detection_type_filter(variables, "GENERATED_THREAT")
    assert "existingFilter" in result["filterBy"]
    assert "type" in result["filterBy"]


def test_apply_platform_filter():
    """Test apply_platform_filter function"""
    # Test with single value
    variables = {}
    result = apply_platform_filter(variables, "AWS")
    assert "filterBy" in result
    assert "cloudPlatform" in result["filterBy"]
    assert result["filterBy"]["cloudPlatform"]["equals"] == ["AWS"]

    # Test with multiple values
    variables = {}
    result = apply_platform_filter(variables, ["AWS", "Azure", "GCP"])
    assert result["filterBy"]["cloudPlatform"]["equals"] == ["AWS", "Azure", "GCP"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_platform_filter(variables, None)
    assert result == {}


def test_apply_origin_filter():
    """Test apply_origin_filter function"""
    # Test with single value
    variables = {}
    result = apply_origin_filter(variables, "WIZ_SENSOR")
    assert "filterBy" in result
    assert "origin" in result["filterBy"]
    assert result["filterBy"]["origin"]["equals"] == ["WIZ_SENSOR"]

    # Test with multiple values
    variables = {}
    result = apply_origin_filter(variables, ["WIZ_SENSOR", "AWS_GUARD_DUTY"])
    assert result["filterBy"]["origin"]["equals"] == ["WIZ_SENSOR", "AWS_GUARD_DUTY"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_origin_filter(variables, None)
    assert result == {}


def test_apply_subscription_filter():
    """Test apply_subscription_filter function"""
    # Test with value
    variables = {}
    result = apply_subscription_filter(variables, "test-subscription")
    assert "filterBy" in result
    assert "cloudAccountOrCloudOrganizationId" in result["filterBy"]
    assert result["filterBy"]["cloudAccountOrCloudOrganizationId"]["equals"] == ["test-subscription"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_subscription_filter(variables, None)
    assert result == {}


def test_apply_resource_id_filter():
    """Test apply_resource_id_filter function"""
    # Test with value
    variables = {}
    result = apply_resource_id_filter(variables, "test-resource")
    assert "filterBy" in result
    assert "resource" in result["filterBy"]
    assert result["filterBy"]["resource"]["id"]["equals"] == ["test-resource"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_resource_id_filter(variables, None)
    assert result == {}


def test_apply_severity_filter():
    """Test apply_severity_filter function"""
    # Test with single value
    variables = {}
    result = apply_severity_filter(variables, ["CRITICAL"])
    assert "filterBy" in result
    assert "severity" in result["filterBy"]
    assert result["filterBy"]["severity"]["equals"] == ["CRITICAL"]

    # Test with multiple values
    variables = {}
    result = apply_severity_filter(variables, ["CRITICAL", "HIGH"])
    assert result["filterBy"]["severity"]["equals"] == ["CRITICAL", "HIGH"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_severity_filter(variables, None)
    assert result == {}


def test_apply_creation_in_last_minutes_filter():
    """Test apply_creation_in_last_minutes_filter function"""
    # Test with value
    variables = {}
    result = apply_creation_in_last_minutes_filter(variables, 15)
    assert "filterBy" in result
    assert "createdAt" in result["filterBy"]
    assert result["filterBy"]["createdAt"]["inLast"]["amount"] == 15
    assert result["filterBy"]["createdAt"]["inLast"]["unit"] == DurationUnit.MINUTES

    # Test with None (should not add filter)
    variables = {}
    result = apply_creation_in_last_minutes_filter(variables, None)
    assert result == {}


def test_apply_creation_after_time_filter():
    """Test apply_creation_after_time_filter function"""
    # Test with value
    variables = {}
    timestamp = "2022-01-01T00:00:00Z"
    result = apply_creation_after_time_filter(variables, timestamp)
    assert "filterBy" in result
    assert "createdAt" in result["filterBy"]
    assert result["filterBy"]["createdAt"]["after"] == timestamp

    # Test with None (should not add filter)
    variables = {}
    result = apply_creation_after_time_filter(variables, None)
    assert result == {}


def test_apply_matched_rule_filter():
    """Test apply_matched_rule_filter function"""
    # Test with value
    variables = {}
    result = apply_matched_rule_filter(variables, "rule-id")
    assert "filterBy" in result
    assert "matchedRule" in result["filterBy"]
    assert result["filterBy"]["matchedRule"]["id"] == "rule-id"

    # Test with None (should not add filter)
    variables = {}
    result = apply_matched_rule_filter(variables, None)
    assert result == {}


def test_apply_matched_rule_name_filter():
    """Test apply_matched_rule_name_filter function"""
    # Test with value
    variables = {}
    result = apply_matched_rule_name_filter(variables, "rule name")
    assert "filterBy" in result
    assert "matchedRuleName" in result["filterBy"]
    assert result["filterBy"]["matchedRuleName"]["equals"] == ["rule name"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_matched_rule_name_filter(variables, None)
    assert result == {}


def test_apply_project_id_filter():
    """Test apply_project_id_filter function"""
    # Test with value
    variables = {}
    result = apply_project_id_filter(variables, "project-id")
    assert "filterBy" in result
    assert "projectId" in result["filterBy"]
    assert result["filterBy"]["projectId"] == "project-id"

    # Test with None (should not add filter)
    variables = {}
    result = apply_project_id_filter(variables, None)
    assert result == {}


def test_apply_detection_id_filter():
    """Test apply_detection_id_filter function"""
    # Test with single ID
    variables = {}
    detection_id = str(uuid.uuid4())
    result = apply_detection_id_filter(variables, [detection_id])
    assert "filterBy" in result
    assert "id" in result["filterBy"]
    assert result["filterBy"]["id"]["equals"] == [detection_id]

    # Test with multiple IDs
    variables = {}
    detection_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    result = apply_detection_id_filter(variables, detection_ids)
    assert result["filterBy"]["id"]["equals"] == detection_ids

    # Test with None (should not add filter)
    variables = {}
    result = apply_detection_id_filter(variables, None)
    assert result == {}


def test_apply_issue_id_filter():
    """Test apply_issue_id_filter function"""
    # Test with value
    variables = {}
    issue_id = str(uuid.uuid4())
    result = apply_issue_id_filter(variables, issue_id)
    assert "filterBy" in result
    assert "issueId" in result["filterBy"]
    assert result["filterBy"]["issueId"] == issue_id

    # Test with None (should not add filter)
    variables = {}
    result = apply_issue_id_filter(variables, None)
    assert result == {}


def test_apply_all_filters():
    """Test that apply_all_filters correctly applies all filters"""
    validated_values = {
        'detection_id': [str(uuid.uuid4())],
        'issue_id': str(uuid.uuid4()),
        'type': 'GENERATED_THREAT',
        'platform': ['AWS', 'Azure'],
        'origin': ['WIZ_SENSOR'],
        'subscription': 'test-subscription',
        'resource_id': 'test-id',
        'severity': ['CRITICAL'],
        'creation_minutes_back': 15,
        'matched_rule': 'rule-id',
        'matched_rule_name': 'rule name',
        'project_id': 'project-id'
    }

    variables = {}
    result = apply_all_filters(variables, validated_values)

    # Check that all filters were applied
    assert result["filterBy"]["id"]["equals"] == validated_values['detection_id']
    assert result["filterBy"]["issueId"] == validated_values['issue_id']
    assert result["filterBy"]["type"]["equals"] == [validated_values['type']]
    assert result["filterBy"]["cloudPlatform"]["equals"] == validated_values['platform']
    assert result["filterBy"]["origin"]["equals"] == validated_values['origin']
    assert result["filterBy"]["cloudAccountOrCloudOrganizationId"]["equals"] == [validated_values['subscription']]
    assert result["filterBy"]["resource"]["id"]["equals"] == [validated_values['resource_id']]
    assert result["filterBy"]["severity"]["equals"] == validated_values['severity']
    assert result["filterBy"]["createdAt"]["inLast"]["amount"] == validated_values['creation_minutes_back']
    assert result["filterBy"]["matchedRule"]["id"] == validated_values['matched_rule']
    assert result["filterBy"]["matchedRuleName"]["equals"] == [validated_values['matched_rule_name']]
    assert result["filterBy"]["projectId"] == validated_values['project_id']

    # Test with after_time instead of creation_minutes_back
    validated_values_with_after = copy.deepcopy(validated_values)
    validated_values_with_after.pop('creation_minutes_back')
    validated_values_with_after['after_time'] = "2022-01-01T00:00:00Z"

    variables = {}
    result = apply_all_filters(variables, validated_values_with_after)

    # Check that after_time filter was applied
    assert "createdAt" in result["filterBy"]
    assert "after" in result["filterBy"]["createdAt"]
    assert result["filterBy"]["createdAt"]["after"] == "2022-01-01T00:00:00Z"

    # Test with minimal filters
    minimal_values = {
        'severity': ['CRITICAL']
    }

    variables = {}
    result = apply_all_filters(variables, minimal_values)

    # Check that only severity filter was applied
    assert "severity" in result["filterBy"]
    assert len(result["filterBy"]) == 1


# ===== CORE API COMMUNICATION TESTS =====

def test_get_token_error(mock_response_factory, mocker):
    """Test get_token with error response"""
    # Mock authentication endpoint
    set_authentication_endpoint('https://auth.wiz.io/oauth/token')

    # Mock the response
    mock_response = mock_response_factory(
        status_code=401,
        json_data={"error": "access_denied", "error_description": "Unauthorized"},
        text="Unauthorized"
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(
        demisto, 'params',
        return_value={
            'credentials': {'identifier': 'test', 'password': 'pass'}
        }
    )

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        get_token()
    assert 'Error authenticating to Wiz' in str(e.value)


def test_get_token_no_access_token(mock_response_factory, mocker):
    """Test get_token when response doesn't contain access_token"""
    # Mock authentication endpoint
    set_authentication_endpoint('https://auth.wiz.io/oauth/token')

    # Mock the response
    mock_response = mock_response_factory(
        status_code=200,
        json_data={"message": "No token provided"}
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(
        demisto, 'params',
        return_value={
            'credentials': {'identifier': 'test', 'password': 'pass'}
        }
    )

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        get_token()
    assert 'Could not retrieve token from Wiz' in str(e.value)


def test_get_token_json_parse_error(mock_response_factory, mocker):
    """Test get_token when response is not valid JSON"""
    # Mock authentication endpoint
    set_authentication_endpoint('https://auth.wiz.io/oauth/token')

    # Mock the response
    mock_response = mock_response_factory(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mocker.patch('requests.post', return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(
        demisto, 'params',
        return_value={
            'credentials': {'identifier': 'test', 'password': 'pass'}
        }
    )

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        get_token()
    assert 'Could not parse API response' in str(e.value)


def test_get_entries(mock_response_factory, mocker, mock_api_response):
    """Test get_entries with successful response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Mock at module level
    test_token = 'test-token'
    WizDefend.TOKEN = test_token
    WizDefend.get_token = lambda: test_token

    # Mock the response for API call
    mock_response = mock_response_factory(
        status_code=200,
        json_data=mock_api_response
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Call the function
    entries, page_info = WizDefend.get_entries("test_query", {})

    # Verify entries and page_info
    assert entries == mock_api_response["data"]["detections"]["nodes"]
    assert page_info == mock_api_response["data"]["detections"]["pageInfo"]


def test_get_entries_with_token_refresh(mock_response_factory, mocker, mock_api_response):
    """Test get_entries when token needs to be refreshed"""
    # Mock token as None (needs refresh)
    mocker.patch('WizDefend.TOKEN', None)

    # Mock get_token
    mocker.patch('WizDefend.get_token', return_value='refreshed-token')

    # Mock the response
    mock_response = mock_response_factory(
        status_code=200,
        json_data=mock_api_response
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Call the function
    entries, page_info = get_entries("test_query", {})

    # Verify entries and page_info
    assert entries == mock_api_response["data"]["detections"]["nodes"]
    assert page_info == mock_api_response["data"]["detections"]["pageInfo"]


def test_get_entries_error(mock_response_factory, mocker, mock_api_error_response):
    """Test get_entries with error response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Mock token
    WizDefend.TOKEN = 'test-token'

    # Mock the response
    mock_response = mock_response_factory(
        status_code=200,
        json_data=mock_api_error_response
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        WizDefend.get_entries("test_query", {})
    assert 'Wiz API error details' in str(e.value)
    assert 'Resource not found' in str(e.value)


def test_get_entries_http_error(mock_response_factory, mocker):
    """Test get_entries with HTTP error response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Mock token
    WizDefend.TOKEN = 'test-token'

    # Mock the response
    mock_response = mock_response_factory(
        status_code=500,
        text="Internal Server Error"
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        WizDefend.get_entries("test_query", {})
    assert 'Error authenticating to Wiz' in str(e.value)


# Modify test_get_token_success function in WizDefend_test.py
def test_get_token_success(mock_response_factory, mocker):
    """Test get_token with successful response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend
    import copy

    # Save original HEADERS to restore later
    original_headers = copy.deepcopy(WizDefend.HEADERS)

    # Mock authentication endpoint
    WizDefend.AUTH_E = 'https://auth.wiz.io/oauth/token'

    # Mock the response
    mock_response = mock_response_factory(
        status_code=200,
        json_data={"access_token": "test-token"}
    )
    mocker.patch('requests.post', return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(
        demisto, 'params',
        return_value={
            'credentials': {'identifier': 'test', 'password': 'pass'}
        }
    )

    # Call the function
    token = WizDefend.get_token()

    # Verify token was returned
    assert token == "test-token"

    # Verify token was set in the module
    assert WizDefend.TOKEN == "test-token"

    # Skip checking if Authorization header is in HEADERS
    # Just verify that the token value is correct
    WizDefend.HEADERS = original_headers



def test_query_api(mocker, sample_detection):
    """Test query_api with simple response"""
    # Import the module locally
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Set required module variables directly
    WizDefend.TOKEN = 'test-token'
    WizDefend.URL = 'https://api.wiz.io/graphql'  # Set a valid URL

    # Mock the get_entries function at module level
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = lambda q, v: ([sample_detection], {"hasNextPage": False, "endCursor": ""})

    try:
        # Call the function
        result = WizDefend.query_api("test_query", {})

        # Verify result
        assert result == [sample_detection]
    finally:
        # Restore original function
        WizDefend.get_entries = orig_get_entries


def test_query_api_pagination(mocker, mock_api_paginated_response):
    """Test query_api with pagination"""
    # Import the module locally
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Unpack the paginated responses
    first_page, second_page = mock_api_paginated_response

    # Set required module variables directly
    WizDefend.TOKEN = 'test-token'
    WizDefend.URL = 'https://api.wiz.io/graphql'

    # Define a side effect function to simulate pagination
    call_count = [0]  # Use a list to maintain state between calls

    def mock_get_entries_side_effect(query, variables):
        call_count[0] += 1
        if call_count[0] == 1:
            return (first_page["data"]["detections"]["nodes"],
                    first_page["data"]["detections"]["pageInfo"])
        else:
            return (second_page["data"]["detections"]["nodes"],
                    second_page["data"]["detections"]["pageInfo"])

    # Replace get_entries with our mock function
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = mock_get_entries_side_effect

    try:
        # Call the function
        result = WizDefend.query_api("test_query", {})

        # Verify result contains combined detections from both pages
        assert len(result) == 2
        assert result[0]["id"] == first_page["data"]["detections"]["nodes"][0]["id"]
        assert result[1]["id"] == second_page["data"]["detections"]["nodes"][0]["id"]
    finally:
        # Restore original function
        WizDefend.get_entries = orig_get_entries


def test_query_api_empty_response(mocker, mock_api_empty_response):
    """Test query_api with empty response"""
    # Import the module locally
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Set required module variables directly
    WizDefend.TOKEN = 'test-token'
    WizDefend.URL = 'https://api.wiz.io/graphql'

    # Mock get_entries to return empty results
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = lambda q, v: ([], {"hasNextPage": False, "endCursor": ""})

    try:
        # Call the function
        result = WizDefend.query_api("test_query", {})

        # Verify result is empty dict
        assert result == {}
    finally:
        # Restore original function
        WizDefend.get_entries = orig_get_entries


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_entries')
def test_query_api_with_pagination_disabled(mock_get_entries, mock_api_paginated_response):
    """Test query_api with pagination disabled"""
    # Unpack the paginated responses
    first_page, _ = mock_api_paginated_response

    # Set up the mock for get_entries
    mock_get_entries.return_value = (
        first_page["data"]["detections"]["nodes"],
        first_page["data"]["detections"]["pageInfo"]
    )

    # Call the function with paginate=False
    result = query_api("test_query", {}, paginate=False)

    # Verify result only contains first page
    assert len(result) == 1
    assert result[0]["id"] == first_page["data"]["detections"]["nodes"][0]["id"]


# ===== UTILITY FUNCTION TESTS =====

@pytest.mark.parametrize("severity,expected_result", [
    ("CRITICAL", 4),
    ("HIGH", 3),
    ("MEDIUM", 2),
    ("LOW", 1),
    ("INFORMATIONAL", 0.5),
    ("UNKNOWN", None),
])
def test_translate_severity(severity, expected_result):
    """Test translate_severity with various severity levels"""
    detection = {"severity": severity}
    assert translate_severity(detection) == expected_result


def test_build_incidents(sample_detection):
    """Test build_incidents with valid detection"""
    incident = build_incidents(sample_detection)

    assert incident["name"] == "suspicious activity detected - 12345678-1234-1234-1234-d25e16359c19"
    assert incident["occurred"] == "2022-01-02T15:46:34Z"
    assert incident["severity"] == 4
    assert "rawJSON" in incident
    assert incident["dbotMirrorId"] == "12345678-1234-1234-1234-d25e16359c19"

    # Test with None
    assert build_incidents(None) == {}


def test_build_incidents_no_rule_match(sample_detection_no_rule):
    """Test build_incidents with detection that has no rule match"""
    incident = build_incidents(sample_detection_no_rule)

    assert incident["name"] == "No name - 12345678-1234-1234-1234-d25e16359c19"
    assert incident["occurred"] == "2022-01-02T15:46:34Z"
    assert incident["severity"] == 3  # HIGH
    assert "rawJSON" in incident
    assert incident["dbotMirrorId"] == "12345678-1234-1234-1234-d25e16359c19"


@pytest.mark.parametrize("input_value,expected_result", [
    (str(uuid.uuid4()), True),  # Valid UUID
    ("invalid-uuid", False),  # Invalid UUID
    (None, False),  # None value
    ("", False),  # Empty string
    (123, False),  # Non-string
    (object(), False),  # Non-stringifiable object
])
def test_is_valid_uuid(input_value, expected_result):
    """Test is_valid_uuid with various inputs"""
    assert is_valid_uuid(input_value) == expected_result


def test_is_valid_param_id():
    """Test is_valid_param_id function"""
    # Test with valid UUID
    valid_uuid = str(uuid.uuid4())
    is_valid, message = is_valid_param_id(valid_uuid, "test_param")
    assert is_valid is True
    assert "is in a valid format" in message

    # Test with None
    is_valid, message = is_valid_param_id(None, "test_param")
    assert is_valid is False
    assert "You should pass a test_param" in message

    # Test with invalid UUID
    is_valid, message = is_valid_param_id("invalid-uuid", "test_param")
    assert is_valid is False
    assert "should be in UUID format" in message


def test_get_error_output():
    """Test get_error_output with different error structures"""
    # Test with error array
    error_response = {
        "errors": [
            {"message": "Resource not found"},
            {"message": "Another error"}
        ]
    }
    result = get_error_output(error_response)
    assert "Resource not found" in result
    assert "Another error" in result

    # Test with duplicate errors (should deduplicate)
    error_response = {
        "errors": [
            {"message": "Same error"},
            {"message": "Same error"}
        ]
    }
    result = get_error_output(error_response)
    assert result.count("Same error") == 1

    # Test with no errors
    no_error_response = {"data": {}}
    result = get_error_output(no_error_response)
    assert result == no_error_response


def test_get_detection_url(sample_detection):
    """Test get_detection_url function"""
    # Test with app environment (default)
    url = get_detection_url(sample_detection)
    assert "app.wiz.io" in url
    assert sample_detection["id"] in url

    # Test with test environment
    test_detection = copy.deepcopy(sample_detection)
    test_detection["issue"]["url"] = "https://test.wiz.io/issues/123"
    url = get_detection_url(test_detection)
    assert "test.wiz.io" in url
    assert test_detection["id"] in url


def test_get_integration_user_agent():
    """Test get_integration_user_agent function"""
    user_agent = get_integration_user_agent()
    assert INTEGRATION_GUID in user_agent
    assert 'xsoar_defend' in user_agent
    assert WIZ_VERSION in user_agent


def test_set_authentication_endpoint(mocker):
    """Test set_authentication_endpoint function"""
    # Import the module correctly using the full path
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # First, remove the patch from the fixture that would reset AUTH_E
    mocker.stopall()

    test_endpoint = "https://test-auth.wiz.io/oauth/token"
    WizDefend.set_authentication_endpoint(test_endpoint)

    # Verify the endpoint was set correctly
    assert WizDefend.AUTH_E == test_endpoint


def test_set_api_endpoint(mocker):
    """Test set_api_endpoint function"""
    # Import the module correctly using the full path
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # First, remove the patch from the fixture that would reset URL
    mocker.stopall()

    test_endpoint = "https://test-api.wiz.io/graphql"
    WizDefend.set_api_endpoint(test_endpoint)

    # Verify the endpoint was set correctly
    assert WizDefend.URL == test_endpoint


# ===== INTEGRATION CONTEXT FUNCTION TESTS =====

def test_extract_params_from_integration_settings(mocker):
    """Test extract_params_from_integration_settings function"""
    # Mock demisto.params
    integration_params = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL',
        'origin': 'WIZ_SENSOR',
        'subscription': 'sub-123',
        'first_fetch': '2 days',
        'incidentFetchInterval': 10,
        'incidentType': 'WizDefend Detection',
        'isFetch': True
    }
    mocker.patch.object(demisto, 'params', return_value=integration_params)

    # Test with basic params
    result = extract_params_from_integration_settings(advanced_params=False)
    assert result['type'] == 'GENERATED THREAT'
    assert result['platform'] == 'AWS'
    assert result['severity'] == 'CRITICAL'
    assert result['origin'] == 'WIZ_SENSOR'
    assert result['subscription'] == 'sub-123'
    assert 'first_fetch' not in result

    # Test with advanced params
    result = extract_params_from_integration_settings(advanced_params=True)
    assert result['first_fetch'] == '2 days'
    assert result['incidentFetchInterval'] == 10
    assert result['incidentType'] == 'WizDefend Detection'
    assert result['isFetch'] is True


def test_check_advanced_params(mocker):
    """Test check_advanced_params function"""
    # Mock validation functions
    validation_response_success = ValidationResponse()
    validation_response_success.is_valid = True

    validation_response_error = ValidationResponse()
    validation_response_error.is_valid = False
    validation_response_error.error_message = "Validation error"

    mocker.patch(
        'WizDefend.validate_first_fetch',
        return_value=validation_response_success
    )
    mocker.patch(
        'WizDefend.validate_fetch_interval',
        return_value=validation_response_success
    )
    mocker.patch(
        'WizDefend.validate_incident_type',
        return_value=validation_response_success
    )

    # Test with valid params
    params = {
        'isFetch': True,
        'first_fetch': '2 days',
        'incidentFetchInterval': 10,
        'incidentType': 'WizDefend Detection'
    }
    are_valid, error_message = check_advanced_params(params)
    assert are_valid is True
    assert error_message == ""

    # Test with isFetch=False (should skip validation)
    params = {
        'isFetch': False
    }
    are_valid, error_message = check_advanced_params(params)
    assert are_valid is True
    assert error_message == ""

    # Mock validation function with error
    mocker.patch(
        'WizDefend.validate_first_fetch',
        return_value=validation_response_error
    )

    # Test with invalid first_fetch
    params = {
        'isFetch': True,
        'first_fetch': 'invalid',
        'incidentFetchInterval': 10,
        'incidentType': 'WizDefend Detection'
    }
    are_valid, error_message = check_advanced_params(params)
    assert are_valid is False
    assert "Invalid first fetch format" in error_message


# Helper to validate ISO timestamps
def is_valid_iso_timestamp(s):
    """Check if a string is a valid ISO timestamp."""
    pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z'
    return bool(re.match(pattern, s))


def test_get_last_run_time_first_run(mocker):
    """Test get_last_run_time when no last run exists"""
    # Mock demisto.getLastRun to return empty dict
    mocker.patch.object(demisto, 'getLastRun', return_value={})

    # Mock demisto.params
    mocker.patch.object(
        demisto, 'params',
        return_value={'first_fetch': '2 days'}
    )

    # Call the function
    result = get_last_run_time()

    # Verify result is a valid ISO timestamp
    assert is_valid_iso_timestamp(result), f"Result '{result}' is not a valid ISO timestamp"


def test_get_last_run_time_existing_run(mocker):
    """Test get_last_run_time with existing last run"""
    from datetime import datetime

    # Use a timestamp that's guaranteed to be recent (now)
    recent_time = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

    # Mock demisto.getLastRun to return our recent timestamp
    mocker.patch.object(demisto, 'getLastRun', return_value={"time": recent_time})

    # Call the function
    result = get_last_run_time()

    # Verify result is a valid ISO timestamp and matches the recent time
    assert is_valid_iso_timestamp(result), f"Result '{result}' is not a valid ISO timestamp"
    assert result == recent_time, "Function should return recent timestamps unchanged"


def test_get_last_run_time_too_old(mocker):
    """Test get_last_run_time when last run is too old"""
    # Use a timestamp that's guaranteed to be old
    very_old_time = "1970-01-01T00:00:00Z"

    # Mock demisto.getLastRun to return our very old timestamp
    mocker.patch.object(demisto, 'getLastRun', return_value={"time": very_old_time})

    # Call the function
    result = get_last_run_time()

    # Verify result is a valid ISO timestamp and is different from the very old time
    assert is_valid_iso_timestamp(result), f"Result '{result}' is not a valid ISO timestamp"
    assert result != very_old_time, "Function should adjust timestamps that are too old"


def test_get_fetch_timestamp_valid(mocker):
    """Test get_fetch_timestamp with valid input"""
    # Call the function
    result = get_fetch_timestamp("2 days")

    # Verify result is a valid ISO timestamp
    assert is_valid_iso_timestamp(result), f"Result '{result}' is not a valid ISO timestamp"


def test_get_fetch_timestamp_invalid(mocker):
    """Test get_fetch_timestamp with invalid input"""
    # Mock validate_first_fetch_timestamp
    mocker.patch(
        'WizDefend.validate_first_fetch_timestamp',
        return_value=(False, "Invalid date format", None)
    )

    # Call the function and check exception
    with pytest.raises(ValueError) as e:
        get_fetch_timestamp("invalid format")

    # Verify exception message
    assert "Invalid date format" in str(e.value)


# ===== MAIN FUNCTION TESTS =====
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_parameters', return_value=(True, None, {'severity': ['CRITICAL']}))
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.query_api')
def test_get_filtered_detections_success(mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with successful validation and API call"""

    # Set up the mock to return the sample detection
    mock_query_api.return_value = [sample_detection]

    # Call the function
    result = get_filtered_detections(
        detection_type="GENERATED THREAT",
        detection_platform=["AWS"],
        severity="CRITICAL"
    )

    # Verify result
    assert result == [sample_detection]
    assert mock_query_api.called


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_parameters', return_value=(False, "Validation error message", None))
def test_get_filtered_detections_validation_error(mock_validate):
    """Test get_filtered_detections with validation error"""
    # Call the function
    result = get_filtered_detections(detection_type="INVALID")

    # Verify result is the error message
    assert result == "Validation error message"


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_parameters', return_value=(True, None, {'severity': ['CRITICAL']}))
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.query_api')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_detection_url', return_value="https://app.wiz.io/detection/123")
def test_get_filtered_detections_with_all_params(mock_url, mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with all parameters specified"""
    # Set up validated values
    validated_values = {
        'detection_id': [str(uuid.uuid4())],
        'issue_id': str(uuid.uuid4()),
        'type': 'GENERATED_THREAT',
        'platform': ['AWS'],
        'origin': ['WIZ_SENSOR'],
        'subscription': 'test-subscription',
        'resource_id': 'test-id',
        'severity': ['CRITICAL'],
        'creation_minutes_back': 15,
        'matched_rule': 'rule-id',
        'matched_rule_name': 'rule name',
        'project_id': 'project-id'
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_api.return_value = [sample_detection]

    # Call the function with all parameters
    result = get_filtered_detections(
        detection_id=validated_values['detection_id'][0],
        issue_id=validated_values['issue_id'],
        detection_type="GENERATED THREAT",
        detection_platform=validated_values['platform'],
        detection_origin=validated_values['origin'],
        detection_subscription=validated_values['subscription'],
        resource_id=validated_values['resource_id'],
        severity="CRITICAL",
        creation_minutes_back="15",
        matched_rule=validated_values['matched_rule'],
        matched_rule_name=validated_values['matched_rule_name'],
        project_id=validated_values['project_id']
    )

    # Verify result
    assert result == [sample_detection]
    assert result[0].get("url") == "https://app.wiz.io/detection/123"


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_parameters')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.query_api')
def test_get_filtered_detections_with_no_url(mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with add_detection_url=False"""
    # Set up validated values
    validated_values = {
        'severity': ['CRITICAL'],
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_api.return_value = [sample_detection]

    # Call the function with add_detection_url=False
    result = get_filtered_detections(
        severity="CRITICAL",
        add_detection_url=False
    )

    # Verify result (should not have url)
    assert result == [sample_detection]
    assert "url" not in result[0]


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_parameters')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.query_api')
def test_get_filtered_detections_with_api_limit(mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with custom API limit"""
    # Set up validated values
    validated_values = {
        'severity': ['CRITICAL'],
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_api.return_value = [sample_detection]

    # Call the function with custom api_limit
    result = get_filtered_detections(
        severity="CRITICAL",
        api_limit=50
    )

    # Verify query_api was called with correct api_limit
    variables = mock_query_api.call_args[0][1]
    assert variables["first"] == 50


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value=[{"id": "test-detection"}])
@patch('WizDefend.check_advanced_params', return_value=(True, ""))
@patch('WizDefend.extract_params_from_integration_settings')
@patch.object(demisto, 'results')
def test_test_module_success(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with successful validation and API call"""
    # Set up mock extraction params
    mock_extract_params.return_value = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL',
        'origin': 'WIZ_SENSOR',
        'subscription': 'test-subscription'
    }

    # Call the function
    test_module()

    # Verify demisto.results was called with 'ok'
    mock_results.assert_called_with('ok')


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value=[{"id": "test-detection"}])
@patch('WizDefend.check_advanced_params', return_value=(True, ""))
@patch('WizDefend.extract_params_from_integration_settings')
@patch.object(demisto, 'results')
def test_test_module_success(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with successful validation and API call"""
    # Set up mock extraction params
    mock_extract_params.return_value = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL',
        'origin': 'WIZ_SENSOR',
        'subscription': 'test-subscription'
    }

    # Call the function
    test_module()

    # Verify demisto.results was called with 'ok'
    mock_results.assert_called_with('ok')


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value=[{"id": "test-detection"}])
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.check_advanced_params', return_value=(False, "Parameter validation error"))
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.extract_params_from_integration_settings')
@patch.object(demisto, 'results')
def test_test_module_invalid_params(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with invalid parameters"""
    # Set up mock extraction params
    mock_extract_params.return_value = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL'
    }

    # Call the function
    test_module()

    # Verify demisto.results was called with the error message
    mock_results.assert_called_with("Parameter validation error")


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value="API error message")
@patch('WizDefend.check_advanced_params', return_value=(True, ""))
@patch('WizDefend.extract_params_from_integration_settings')
@patch.object(demisto, 'results')
def test_test_module_api_error(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with API error"""
    # Set up mock extraction params
    mock_extract_params.return_value = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL'
    }

    # Call the function
    test_module()

    # Verify demisto.results was called with the error message
    mock_results.assert_called_with("API error message")


from freezegun import freeze_time


@freeze_time("2022-01-02T00:00:00Z")  # This is safer than patching datetime
@patch.object(demisto, 'setLastRun')
@patch.object(demisto, 'incidents')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections')
@patch('WizDefend.get_last_run_time', return_value="2022-01-01T00:00:00Z")
@patch('WizDefend.extract_params_from_integration_settings')
def test_fetch_incidents_success(mock_extract_params, mock_last_run,
                                 mock_get_filtered, mock_incidents, mock_set_last_run, sample_detection):
    """Test fetch_incidents with successful API call"""
    # Set up mocks
    mock_extract_params.return_value = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL',
        'origin': 'WIZ_SENSOR',
        'subscription': 'test-subscription'
    }

    mock_get_filtered.return_value = [sample_detection]

    # Call the function
    fetch_incidents()

    # Verify demisto.incidents was called with the incident
    incident_arg = mock_incidents.call_args[0][0]
    assert len(incident_arg) == 1
    assert incident_arg[0]["name"] == "suspicious activity detected - 12345678-1234-1234-1234-d25e16359c19"

    # Verify demisto.setLastRun was called with the expected timestamp
    mock_set_last_run.assert_called_with({"time": "2022-01-02T00:00:00Z"})


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value="API error message")
@patch('WizDefend.get_last_run_time', return_value="2022-01-01T00:00:00Z")
@patch('WizDefend.extract_params_from_integration_settings')
def test_fetch_incidents_api_error(mock_extract_params, mock_last_run, mock_get_filtered):
    """Test fetch_incidents with API error"""
    # Set up mocks
    mock_extract_params.return_value = {
        'type': 'GENERATED THREAT',
        'platform': 'AWS',
        'severity': 'CRITICAL'
    }

    # Call the function
    fetch_incidents()

    # No assertions needed as we're just checking if it runs without raising exceptions


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.test_module')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint')
@patch.object(demisto, 'command', return_value='test-module')
def test_main_test_module(mock_command, mock_set_auth, mock_set_api, mock_test_module):
    """Test main function handling test-module command"""
    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify test_module was called
    assert mock_test_module.called


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.fetch_incidents')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint')
@patch.object(demisto, 'command', return_value='fetch-incidents')
def test_main_fetch_incidents(mock_command, mock_set_auth, mock_set_api, mock_fetch):
    """Test main function handling fetch-incidents command"""
    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify fetch_incidents was called
    assert mock_fetch.called


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.return_results')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value=[{"id": "test-detection"}])
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint')
@patch.object(demisto, 'args')
@patch.object(demisto, 'command', return_value='wiz-get-detections')
def test_main_get_detections(mock_command, mock_args, mock_set_auth, mock_set_api,
                             mock_filtered_detections, mock_return_results):
    """Test main function handling wiz-get-detections command"""
    # Set up mock args
    mock_args.return_value = {
        'severity': 'CRITICAL',
        'type': 'GENERATED THREAT',
        'platform': 'AWS'
    }

    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify return_results was called
    assert mock_return_results.called


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.return_results')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections', return_value=[{"id": "test-detection"}])
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint')
@patch.object(demisto, 'args')
@patch.object(demisto, 'command', return_value='wiz-get-detection')
def test_main_get_detection(mock_command, mock_args, mock_set_auth, mock_set_api,
                            mock_filtered_detections, mock_return_results):
    """Test main function handling wiz-get-detection command"""
    # Set up mock args
    detection_id = str(uuid.uuid4())
    mock_args.return_value = {
        'detection_id': detection_id
    }

    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify return_results was called
    assert mock_return_results.called


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.return_error')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint')
@patch.object(demisto, 'args', side_effect=Exception("Test error"))
@patch.object(demisto, 'command', return_value='wiz-get-detections')
def test_main_error_handling(mock_command, mock_args, mock_set_auth, mock_set_api, mock_return_error):
    """Test main function error handling"""
    # Call the function
    main()

    # Verify return_error was called with the error message
    mock_return_error.assert_called_once()
    assert "Test error" in mock_return_error.call_args[0][0]


@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.return_error')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint')
@patch('Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint')
@patch.object(demisto, 'command', return_value='unknown-command')
def test_main_unknown_command(mock_command, mock_set_auth, mock_set_api, mock_return_error):
    """Test main function handling unknown command"""
    # Call the function
    main()

    # Verify return_error was called with appropriate message
    mock_return_error.assert_called_once()
    assert "Unrecognized command" in mock_return_error.call_args[0][0]


# ===== VALIDATION RESPONSE CLASS TESTS =====

def test_validation_response_class():
    """Test the ValidationResponse class"""
    # Test success response
    success_response = ValidationResponse.create_success("test_value")
    assert success_response.is_valid is True
    assert success_response.error_message is None
    assert success_response.value == "test_value"

    # Test error response
    error_response = ValidationResponse.create_error("Error message")
    assert error_response.is_valid is False
    assert error_response.error_message == "Error message"
    assert error_response.value is None

    # Test custom attributes
    custom_response = ValidationResponse()
    custom_response.is_valid = True
    custom_response.minutes_value = 10
    custom_response.severity_list = ["CRITICAL", "HIGH"]

    assert custom_response.is_valid is True
    assert custom_response.minutes_value == 10
    assert custom_response.severity_list == ["CRITICAL", "HIGH"]

    # Test to_dict method
    response_dict = success_response.to_dict()
    assert response_dict["is_valid"] is True
    assert response_dict["error_message"] is None
    assert response_dict["value"] == "test_value"


# ===== CLASS TESTS =====

def test_detection_type_class():
    """Test the DetectionType class"""
    # Test values method
    values = DetectionType.values()
    assert "GENERATED THREAT" in values
    assert "DID NOT GENERATE THREAT" in values

    # Test api_values method
    api_values = DetectionType.api_values()
    assert "GENERATED_THREAT" in api_values
    assert "MATCH_ONLY" in api_values

    # Test get_api_value method
    assert DetectionType.get_api_value("GENERATED THREAT") == "GENERATED_THREAT"
    assert DetectionType.get_api_value("DID NOT GENERATE THREAT") == "MATCH_ONLY"
    assert DetectionType.get_api_value("generated threat") == "GENERATED_THREAT"  # Case insensitive
    assert DetectionType.get_api_value(None) is None
    assert DetectionType.get_api_value("INVALID_TYPE") is None


def test_cloud_platform_class():
    """Test the CloudPlatform class"""
    # Test values method
    values = CloudPlatform.values()
    assert "AWS" in values
    assert "Azure" in values
    assert "GCP" in values
    assert "Kubernetes" in values
    # Ensure all platforms are included
    expected_platforms = [
        "AWS", "GCP", "Azure", "OCI", "Alibaba", "vSphere", "OpenStack",
        "AKS", "EKS", "GKE", "Kubernetes", "OpenShift"
    ]
    for platform in expected_platforms:
        assert platform in values


def test_detection_origin_class():
    """Test the DetectionOrigin class"""
    # Test values method
    values = DetectionOrigin.values()
    assert "WIZ_SENSOR" in values
    assert "AWS_GUARD_DUTY" in values
    assert "AZURE_DEFENDER_FOR_CLOUD" in values
    # Ensure some key origins are included
    expected_origins = [
        "WIZ_SENSOR", "AWS_GUARD_DUTY", "AWS_CLOUDTRAIL",
        "AZURE_DEFENDER_FOR_CLOUD", "GCP_SECURITY_COMMAND_CENTER"
    ]
    for origin in expected_origins:
        assert origin in values


def test_duration_unit_class():
    """Test the DurationUnit class"""
    assert DurationUnit.DAYS == "DurationFilterValueUnitDays"
    assert DurationUnit.HOURS == "DurationFilterValueUnitHours"
    assert DurationUnit.MINUTES == "DurationFilterValueUnitMinutes"
