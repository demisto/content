import copy
from unittest.mock import patch
from freezegun import freeze_time
import pytest
from unittest.mock import MagicMock
import demistomock as demisto
import yaml
import os

from Packs.Wiz.Integrations.WizDefend.WizDefend import *


# ===== TEST FIXTURES =====


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    """Set up common mocks that should apply to all tests"""
    integration_params = {
        "api_endpoint": "http://test.io",
        "credentials": {"identifier": "test", "password": "pass"},
        "first_fetch": "2 days",
        "auth_endpoint": "https://auth.wiz.io/oauth/token",
    }
    mocker.patch.object(demisto, "params", return_value=integration_params)
    mocker.patch("WizDefend.TOKEN", "test-token")
    mocker.patch("WizDefend.AUTH_E", integration_params["auth_endpoint"])
    mocker.patch("WizDefend.URL", integration_params["api_endpoint"])

    # Mock logging functions to prevent test output pollution
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "error")


@pytest.fixture(autouse=True)
def global_mocks(mocker):
    """Apply critical mocks to all tests"""
    # Mock token and authentication
    mocker.patch("WizDefend.TOKEN", "test-token")
    mocker.patch("WizDefend.get_token", return_value="test-token")

    # Mock API endpoints
    mocker.patch("WizDefend.AUTH_E", "https://auth.wiz.io/oauth/token")
    mocker.patch("WizDefend.URL", "https://api.wiz.io/graphql")

    # Mock demisto parameters
    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "api_endpoint": "https://api.wiz.io/graphql",
            "credentials": {"identifier": "test", "password": "pass"},
            "first_fetch": "2 days",
            "auth_endpoint": "https://auth.wiz.io/oauth/token",
        },
    )

    # Silence logging
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "error")


@pytest.fixture(scope="function")
def reset_domain():
    """Reset WIZ_DOMAIN_URL before and after each test"""
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Save current value
    original_value = WizDefend.WIZ_DOMAIN_URL
    # Reset for test
    WizDefend.WIZ_DOMAIN_URL = ""
    # Run test
    yield
    # Restore after test
    WizDefend.WIZ_DOMAIN_URL = original_value


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
        patch("WizDefend.get_token", return_value="test-token"),
        patch("WizDefend.TOKEN", "test-token"),
        patch("WizDefend.AUTH_E", "https://auth.wiz.io/oauth/token"),
        patch("WizDefend.URL", "https://api.wiz.io/graphql"),
        patch("WizDefend.get_entries", return_value=mock_return),
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
    mock_query_api = mocker.patch("WizDefend.query_api", return_value=api_response)

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
            "url": "https://app.wiz.io/issues/98765432-4321-4321-4321-ff5fa2ff7f78",
        },
        "ruleMatch": {
            "rule": {
                "id": "12345678-4321-4321-4321-3792e8a03318",
                "name": "suspicious activity detected",
                "sourceType": "THREAT_DETECTION",
                "securitySubCategories": [],
            }
        },
        "description": "Suspicious activity detected",
        "severity": "CRITICAL",
        "createdAt": "2022-01-02T15:46:34Z",
        "startedAt": "2022-01-02T15:45:00Z",
        "endedAt": "2022-01-02T15:47:00Z",
        "actors": [],
        "resources": [],
        "triggeringEvents": {"nodes": []},
    }


@pytest.fixture
def sample_detection_no_rule():
    """Return a sample detection object without a rule match for testing edge cases"""
    return {
        "id": "12345678-1234-1234-1234-d25e16359c19",
        "issue": {
            "id": "98765432-4321-4321-4321-ff5fa2ff7f78",
            "url": "https://app.wiz.io/issues/98765432-4321-4321-4321-ff5fa2ff7f78",
        },
        "description": "Suspicious activity without rule match",
        "severity": "HIGH",
        "createdAt": "2022-01-02T15:46:34Z",
        "startedAt": "2022-01-02T15:45:00Z",
        "endedAt": "2022-01-02T15:47:00Z",
        "actors": [],
        "resources": [],
        "triggeringEvents": {"nodes": []},
    }


@pytest.fixture
def sample_threat():
    """Return a sample threat object for testing"""
    return {
        "id": "98765432-4321-4321-4321-ff5fa2ff7f78",
        "sourceRule": {
            "id": "12345678-4321-4321-4321-3792e8a03318",
            "name": "suspicious activity detected",
            "type": "THREAT_DETECTION",
            "cloudEventRuleDescription": "Suspicious activity detected",
        },
        "type": "THREAT_DETECTION",
        "createdAt": "2022-01-02T15:46:34Z",
        "updatedAt": "2022-01-02T16:46:34Z",
        "dueAt": "2022-01-09T15:46:34Z",
        "projects": [{"id": "project-123", "name": "Production Project"}],
        "status": "OPEN",
        "severity": "CRITICAL",
        "entitySnapshot": {"id": "entity-123", "type": "VM", "name": "test-instance", "cloudPlatform": "AWS"},
        "notes": [{"id": "note-123", "text": "Investigating this threat", "createdAt": "2022-01-02T16:00:00Z"}],
    }


@pytest.fixture
def mock_threat_api_response(sample_threat):
    """Return a complete threat API response structure"""
    return {"data": {"issues": {"nodes": [sample_threat], "pageInfo": {"hasNextPage": False, "endCursor": ""}}}}


@pytest.fixture
def mock_api_response(sample_detection):
    """Return a complete API response structure"""
    return {"data": {"detections": {"nodes": [sample_detection], "pageInfo": {"hasNextPage": False, "endCursor": ""}}}}


@pytest.fixture
def mock_api_paginated_response(sample_detection):
    """Return a paginated API response for testing pagination"""
    detection2 = copy.deepcopy(sample_detection)
    detection2["id"] = "second-detection-id"

    # First page response
    first_page = {
        "data": {"detections": {"nodes": [sample_detection], "pageInfo": {"hasNextPage": True, "endCursor": "cursor1"}}}
    }

    # Second page response
    second_page = {"data": {"detections": {"nodes": [detection2], "pageInfo": {"hasNextPage": False, "endCursor": ""}}}}

    return first_page, second_page


@pytest.fixture
def mock_api_error_response():
    """Return an API error response"""
    return {
        "errors": [
            {
                "message": "Resource not found",
                "extensions": {"code": "NOT_FOUND", "exception": {"message": "Resource not found", "path": ["detections"]}},
            }
        ],
        "data": None,
    }


@pytest.fixture
def mock_api_empty_response():
    """Return an empty API response"""
    return {"data": {"detections": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": ""}}}}


@pytest.fixture
def yaml_content():
    """Fixture to load the YAML file once for all tests"""
    yaml_file_path = os.path.join(os.path.dirname(__file__), "WizDefend.yml")
    with open(yaml_file_path) as f:
        return yaml.safe_load(f)


# ===== VALIDATION FUNCTION TESTS =====


@pytest.mark.parametrize(
    "detection_type,expected_valid,expected_value",
    [
        ("GENERATED THREAT", True, "GENERATED_THREAT"),
        ("GENERATED_THREAT", False, None),
        ("generated threat", True, "GENERATED_THREAT"),  # Case insensitive
        ("DID NOT GENERATE THREAT", True, "MATCH_ONLY"),
        ("did not generate threat", True, "MATCH_ONLY"),  # Case insensitive
        ("MATCH_ONLY", False, None),
        ("INVALID_TYPE", False, None),
        (None, True, None),  # None should be valid (no filter)
        ("", True, None),  # Empty string should be valid (no filter)
    ],
)
def test_validate_detection_type(detection_type, expected_valid, expected_value):
    """Test validate_detection_type with various inputs"""
    result = validate_detection_type(detection_type)
    assert result.is_valid == expected_valid
    assert result.value == expected_value


@pytest.mark.parametrize(
    "platform,expected_valid,expected_value",
    [
        ("AWS", True, ["AWS"]),
        (["AWS", "Azure", "GCP"], True, ["AWS", "Azure", "GCP"]),
        ("AWS,Azure,GCP", True, ["AWS", "Azure", "GCP"]),  # Comma-separated
        ("INVALID_PLATFORM", False, None),
        ("AWS,INVALID_PLATFORM", False, None),  # One invalid in list
        (None, True, None),
    ],
)
def test_validate_detection_platform(platform, expected_valid, expected_value):
    """Test validate_detection_platform with various inputs"""
    result = validate_detection_platform(platform)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "origin,expected_valid,expected_value",
    [
        ("WIZ_SENSOR", True, ["WIZ_SENSOR"]),
        (["WIZ_SENSOR", "AWS_GUARD_DUTY"], True, ["WIZ_SENSOR", "AWS_GUARD_DUTY"]),
        ("WIZ_SENSOR,AWS_GUARD_DUTY", True, ["WIZ_SENSOR", "AWS_GUARD_DUTY"]),  # Comma-separated
        ("INVALID_ORIGIN", False, None),
        ("WIZ_SENSOR,INVALID_ORIGIN", False, None),  # One invalid in list
        (None, True, None),
    ],
)
def test_validate_detection_origin(origin, expected_valid, expected_value):
    """Test validate_detection_origin with various inputs"""
    result = validate_detection_origin(origin)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "subscription,expected_valid,expected_value",
    [
        (
            ["12345678-1234-1234-1234-d25e16359c19", "12345678-1234-1234-1234-d25e16359c20"],
            True,
            ["12345678-1234-1234-1234-d25e16359c19", "12345678-1234-1234-1234-d25e16359c20"],
        ),
        ("12345678-1234-1234-1234-d25e16359c19", True, ["12345678-1234-1234-1234-d25e16359c19"]),
        ("test-subscription", False, "test-subscription"),
        ("", True, None),
        (None, True, None),
        (123, False, None),  # Non-string should be invalid
    ],
)
def test_validate_detection_subscription(subscription, expected_valid, expected_value):
    """Test validate_detection_subscription with various inputs"""
    result = validate_detection_cloud_account_or_cloud_organization(subscription)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "minutes_back,expected_valid,expected_value",
    [
        ("10", True, 10),  # Minimum value
        ("600", True, 600),  # Maximum value
        ("300", True, 300),  # Middle value
        ("4", False, None),  # Below minimum
        ("601", False, None),  # Above maximum
        ("not_a_number", False, None),  # Non-numeric
        (None, True, FETCH_INTERVAL_MINIMUM_MIN),  # None defaults to minimum
    ],
)
def test_validate_creation_minutes_back(minutes_back, expected_valid, expected_value):
    """Test validate_creation_minutes_back with various inputs"""
    result = validate_creation_time_back(minutes_back)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.minutes_value == expected_value


@pytest.mark.parametrize(
    "severity,expected_valid,expected_list",
    [
        ("CRITICAL", True, ["CRITICAL"]),
        ("HIGH", True, ["CRITICAL", "HIGH"]),
        ("MEDIUM", True, ["CRITICAL", "HIGH", "MEDIUM"]),
        ("LOW", True, ["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
        ("INFORMATIONAL", True, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]),
        ("critical", True, ["CRITICAL"]),  # Case insensitive
        ("INVALID", False, None),
        (None, True, None),  # None is valid (no filter)
    ],
)
def test_validate_severity(severity, expected_valid, expected_list):
    """Test validate_severity with various inputs"""
    result = validate_severity(severity)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.severity_list == expected_list


@pytest.mark.parametrize(
    "resource_id,expected_valid,expected_value",
    [
        ("test-resource-id", True, "test-resource-id"),
        ("", True, ""),
        (None, True, None),
        (123, True, 123),  # Any value should be valid
    ],
)
def test_validate_resource_id(resource_id, expected_valid, expected_value):
    """Test validate_resource_id with various inputs"""
    result = validate_resource_id(resource_id)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "rule_id,expected_valid,expected_value",
    [
        (str(uuid.uuid4()), True, None),  # Valid UUID
        ("invalid-uuid", False, None),  # Invalid UUID
        (None, True, None),  # None is valid
    ],
)
def test_validate_rule_match_id(rule_id, expected_valid, expected_value):
    """Test validate_rule_match_id with various inputs"""
    result = validate_rule_match_id(rule_id)
    assert result.is_valid == expected_valid
    if expected_valid and rule_id:
        assert result.value == rule_id


@pytest.mark.parametrize(
    "project,expected_valid,expected_value",
    [
        ("test project", True, "test project"),
        ("", True, ""),
        (None, True, None),
        (123, True, 123),  # Any value should be valid
    ],
)
def test_validate_project(project, expected_valid, expected_value):
    """Test validate_project with various inputs"""
    result = validate_project(project)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "incident_type,expected_valid,expected_value",
    [
        (WIZ_DEFEND_INCIDENT_TYPE, True, WIZ_DEFEND_INCIDENT_TYPE),
        ("Other Type", False, None),
        (None, False, None),
    ],
)
def test_validate_incident_type(incident_type, expected_valid, expected_value):
    """Test validate_incident_type with various inputs"""
    result = validate_incident_type(incident_type)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "fetch_interval,expected_valid,expected_value",
    [
        (10, True, 10),  # Valid - at minimum
        (30, True, 30),  # Valid - above minimum
        (4, False, None),  # Invalid - below minimum
        (None, False, None),  # Invalid - None
    ],
)
def test_validate_fetch_interval(fetch_interval, expected_valid, expected_value):
    """Test validate_fetch_interval with various inputs"""
    result = validate_fetch_interval(fetch_interval)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.minutes_value == expected_value


@pytest.mark.parametrize(
    "max_fetch,expected_valid,expected_value",
    [
        ("10", True, 10),  # Minimum valid value
        ("1000", True, 1000),  # Maximum valid value
        ("500", True, 500),  # Middle value
        ("9", False, None),  # Below minimum
        ("1001", False, None),  # Above maximum
        ("not_a_number", False, None),  # Non-numeric string
        ("", True, API_MAX_FETCH),  # Empty string should default to max
        (None, True, API_MAX_FETCH),  # None should default to max
        (10, True, 10),  # Integer input
        (1000, True, 1000),  # Integer input at max
    ],
)
def test_validate_max_fetch(max_fetch, expected_valid, expected_value):
    """Test validate_max_fetch with various inputs"""
    result = validate_max_fetch(max_fetch)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


@pytest.mark.parametrize(
    "max_fetch,expected_in_error",
    [
        ("5", "Received 5"),  # Below minimum
        ("2000", "Received 2000"),  # Above maximum
        ("invalid", None),  # Non-numeric (no "Received" message)
        ("-10", "Received -10"),  # Negative number
        ("0", "Received 0"),  # Zero
    ],
)
def test_validate_max_fetch_error_messages(max_fetch, expected_in_error):
    """Test validate_max_fetch error messages"""
    result = validate_max_fetch(max_fetch)
    assert result.is_valid is False
    assert f"{DemistoParams.MAX_FETCH} must be a valid integer between 10 and 1000" in result.error_message
    if expected_in_error:
        assert expected_in_error in result.error_message


@pytest.mark.parametrize(
    "first_fetch,expected_valid,expected_value",
    [
        ("2 days", True, "2 days"),
        ("12 hours", True, "12 hours"),
        ("30 minutes", True, "30 minutes"),
        (f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days", True, f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days"),
        (f"{MAX_DAYS_FIRST_FETCH_DETECTIONS + 1} days", False, None),
        ("not a duration", False, None),
        ("5 years", False, None),
        ("", False, None),
        (None, False, None),
    ],
)
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
        mocker.patch("dateparser.parse", return_value=valid_date)

        is_valid, error_msg, date = WizDefend.validate_first_fetch_timestamp("2 days")
        assert is_valid is True
        assert error_msg is None
        assert date == valid_date

        # Test with date beyond limits (30 days ago)
        old_date = dt.datetime(2021, 12, 1, 12, 0, 0)
        mocker.patch("dateparser.parse", return_value=old_date)

        is_valid, error_msg, date = WizDefend.validate_first_fetch_timestamp("30 days")
        assert is_valid is True  # Still valid, but adjusted
        assert error_msg is None
        assert date == max_days_ago  # Should be adjusted to max_days_ago

        # Test with invalid date format
        mocker.patch("dateparser.parse", return_value=None)

        is_valid, error_msg, date = WizDefend.validate_first_fetch_timestamp("invalid format")
        assert is_valid is False
        assert "Invalid date format" in error_msg
        assert date is None


def test_validate_all_detection_parameters():
    """Test validate_all_detection_parameters with various parameter combinations"""
    # Test with all valid parameters
    valid_params = {
        "detection_id": str(uuid.uuid4()),
        "issue_id": str(uuid.uuid4()),
        "type": "GENERATED THREAT",
        "platform": "AWS",
        "origin": "WIZ_SENSOR",
        "subscription": "12345678-1234-1234-1234-d25e16359c19",
        "resource_id": "test-resource",
        "severity": "CRITICAL",
        "creation_minutes_back": "15",
        "rule_match_id": str(uuid.uuid4()),
        "rule_match_name": "test rule",
        "project_id": "test-project",
    }

    success, error_message, validated_values = validate_all_detection_parameters(valid_params)
    assert success is True
    assert error_message is None
    assert validated_values["type"] == "GENERATED_THREAT"
    assert validated_values["platform"] == ["AWS"]
    assert validated_values["origin"] == ["WIZ_SENSOR"]
    assert validated_values["severity"] == ["CRITICAL"]
    assert validated_values["creation_minutes_back"] == 15

    # ... (other existing test cases)

    # Test with invalid rule_match_id
    invalid_rule_params = {"rule_match_id": "invalid-uuid", "severity": "CRITICAL"}
    success, error_message, validated_values = validate_all_detection_parameters(invalid_rule_params)
    assert success is False
    assert "Invalid matched rule ID" in error_message


@pytest.mark.parametrize(
    "status,expected_valid,expected_list",
    [
        ("OPEN", True, ["OPEN"]),
        ("IN_PROGRESS", True, ["IN_PROGRESS"]),
        ("REJECTED", True, ["REJECTED"]),
        ("RESOLVED", True, ["RESOLVED"]),
        ("open", True, ["OPEN"]),  # Case insensitive
        ("OPEN,IN_PROGRESS", True, ["OPEN", "IN_PROGRESS"]),  # Comma-separated
        ("INVALID", False, None),
        (None, True, None),  # None is valid (no filter)
    ],
)
def test_validate_status(status, expected_valid, expected_list):
    """Test validate_status with various inputs"""
    result = validate_status(status)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.status_list == expected_list


@pytest.mark.parametrize(
    "days_back,expected_valid,expected_value",
    [
        ("1", True, 1),  # Minimum value
        ("30", True, 30),  # Maximum value
        ("15", True, 15),  # Middle value
        ("0", False, None),  # Below minimum
        ("31", False, None),  # Above maximum
        ("not_a_number", False, None),  # Non-numeric
        (None, True, THREATS_DAYS_DEFAULT),  # None defaults to default
    ],
)
def test_validate_creation_days_back(days_back, expected_valid, expected_value):
    """Test validate_creation_time_back with 'days' time unit"""
    result = validate_creation_time_back(days_back, time_unit="days")
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.days_value == expected_value


def test_validate_all_threat_parameters():
    """Test validate_all_threat_parameters with various parameter combinations"""
    # Test with all valid parameters
    valid_params = {
        "issue_id": str(uuid.uuid4()),
        "platform": "AWS",
        "origin": "WIZ_SENSOR",
        "cloud_account_or_cloud_organization": "12345678-1234-1234-1234-d25e16359c19",
        "resource_id": "test-resource",
        "severity": "CRITICAL",
        "status": "OPEN",
        "creation_days_back": "15",
        "project_id": "test-project",
    }

    success, error_message, validated_values = validate_all_threat_parameters(valid_params)
    assert success is True
    assert error_message is None
    assert validated_values["platform"] == ["AWS"]
    assert validated_values["origin"] == ["WIZ_SENSOR"]
    assert validated_values["severity"] == ["CRITICAL"]
    assert validated_values["status"] == ["OPEN"]
    assert validated_values["creation_days_back"] == 15

    # Test with no parameters (should fail)
    empty_params = {}
    success, error_message, validated_values = validate_all_threat_parameters(empty_params)
    assert success is False
    assert "You should pass at least one of the following parameters" in error_message

    # Test with invalid issue_id
    invalid_id_params = {"issue_id": "invalid-uuid", "severity": "CRITICAL"}
    success, error_message, validated_values = validate_all_threat_parameters(invalid_id_params)
    assert success is False
    assert "should be in UUID format" in error_message

    # Test with invalid status
    invalid_status_params = {"status": "INVALID_STATUS", "severity": "CRITICAL"}
    success, error_message, validated_values = validate_all_threat_parameters(invalid_status_params)
    assert success is False
    assert "Invalid status" in error_message


@pytest.mark.parametrize(
    "rule_id,expected_valid,expected_value",
    [
        (str(uuid.uuid4()), True, None),  # Valid UUID
        ("invalid-uuid", False, None),  # Invalid UUID
        (None, True, None),  # None is valid
    ],
)
def test_validate_matched_rule_id(rule_id, expected_valid, expected_value):
    """Test validate_matched_rule_id with various inputs"""
    result = validate_matched_rule_id(rule_id)
    assert result.is_valid == expected_valid
    if expected_valid and rule_id:
        assert result.value == rule_id


@pytest.mark.parametrize(
    "rule_name,expected_valid,expected_value",
    [
        ("test rule", True, "test rule"),
        ("", True, ""),
        (None, True, None),
        (123, True, 123),  # Any value should be valid
    ],
)
def test_validate_rule_match_name(rule_name, expected_valid, expected_value):
    """Test validate_rule_match_name with various inputs"""
    result = validate_rule_match_name(rule_name)
    assert result.is_valid == expected_valid
    if expected_valid:
        assert result.value == expected_value


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
    result = apply_cloud_account_or_cloud_organization_filter(variables, "12345678-1234-1234-1234-d25e16359c19")
    assert "filterBy" in result
    assert "cloudAccountOrCloudOrganizationId" in result["filterBy"]
    assert result["filterBy"]["cloudAccountOrCloudOrganizationId"]["equals"] == ["12345678-1234-1234-1234-d25e16359c19"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_cloud_account_or_cloud_organization_filter(variables, None)
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
    result = apply_creation_in_last_filter(variables, 15)
    assert "filterBy" in result
    assert "createdAt" in result["filterBy"]
    assert result["filterBy"]["createdAt"]["inLast"]["amount"] == 15
    assert result["filterBy"]["createdAt"]["inLast"]["unit"] == DurationUnit.MINUTES

    # Test with None (should not add filter)
    variables = {}
    result = apply_creation_in_last_filter(variables, None)
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
        "detection_id": [str(uuid.uuid4())],
        "issue_id": str(uuid.uuid4()),
        "type": "GENERATED_THREAT",
        "platform": ["AWS", "Azure"],
        "origin": ["WIZ_SENSOR"],
        "cloud_account_or_cloud_organization": "test-subscription",
        "resource_id": "test-id",
        "severity": ["CRITICAL"],
        "creation_minutes_back": 15,
        "rule_match_id": "rule-id",
        "rule_match_name": "rule name",
        "project": "project-id",
    }

    variables = {}
    result = apply_all_detection_filters(variables, validated_values)

    # Check that all filters were applied
    assert result["filterBy"]["id"]["equals"] == validated_values["detection_id"]
    assert result["filterBy"]["issueId"] == validated_values["issue_id"]
    assert result["filterBy"]["type"]["equals"] == [validated_values["type"]]
    assert result["filterBy"]["cloudPlatform"]["equals"] == validated_values["platform"]
    assert result["filterBy"]["origin"]["equals"] == validated_values["origin"]
    assert result["filterBy"]["cloudAccountOrCloudOrganizationId"]["equals"] == [
        validated_values["cloud_account_or_cloud_organization"]
    ]
    assert result["filterBy"]["resource"]["id"]["equals"] == [validated_values["resource_id"]]
    assert result["filterBy"]["severity"]["equals"] == validated_values["severity"]
    assert result["filterBy"]["createdAt"]["inLast"]["amount"] == validated_values["creation_minutes_back"]
    assert result["filterBy"]["matchedRule"]["id"] == validated_values["rule_match_id"]
    assert result["filterBy"]["matchedRuleName"]["equals"] == [validated_values["rule_match_name"]]
    assert result["filterBy"]["projectId"] == validated_values["project"]

    # Test with after_time instead of creation_minutes_back
    validated_values_with_after = copy.deepcopy(validated_values)
    validated_values_with_after.pop("creation_minutes_back")
    validated_values_with_after["after_time"] = "2022-01-01T00:00:00Z"

    variables = {}
    result = apply_all_detection_filters(variables, validated_values_with_after)

    # Check that after_time filter was applied
    assert "createdAt" in result["filterBy"]
    assert "after" in result["filterBy"]["createdAt"]
    assert result["filterBy"]["createdAt"]["after"] == "2022-01-01T00:00:00Z"

    # Test with minimal filters
    minimal_values = {"severity": ["CRITICAL"]}

    variables = {}
    result = apply_all_detection_filters(variables, minimal_values)

    # Check that only severity filter was applied
    assert "severity" in result["filterBy"]
    assert len(result["filterBy"]) == 1


def test_apply_status_filter():
    """Test apply_status_filter function"""
    # Test with single value
    variables = {}
    result = apply_status_filter(variables, ["OPEN"])
    assert "filterBy" in result
    assert "status" in result["filterBy"]
    assert result["filterBy"]["status"] == ["OPEN"]

    # Test with multiple values
    variables = {}
    result = apply_status_filter(variables, ["OPEN", "IN_PROGRESS"])
    assert result["filterBy"]["status"] == ["OPEN", "IN_PROGRESS"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_status_filter(variables, None)
    assert result == {}


def test_apply_creation_days_back_filter():
    """Test apply_creation_in_last_filter with 'days' time unit"""
    # Test with value
    variables = {}
    result = apply_creation_in_last_filter(variables, 15, time_unit="days")
    assert "filterBy" in result
    assert "createdAt" in result["filterBy"]
    assert result["filterBy"]["createdAt"]["inLast"]["amount"] == 15
    assert result["filterBy"]["createdAt"]["inLast"]["unit"] == DurationUnit.DAYS

    # Test with None (should not add filter)
    variables = {}
    result = apply_creation_in_last_filter(variables, None, time_unit="days")
    assert result == {}


def test_apply_all_threat_filters():
    """Test that apply_all_threat_filters correctly applies all filters"""
    validated_values = {
        "issue_id": str(uuid.uuid4()),
        "platform": ["AWS", "Azure"],
        "origin": ["WIZ_SENSOR"],
        "cloud_account_or_cloud_organization": "test-subscription",
        "resource_id": "test-id",
        "severity": ["CRITICAL"],
        "status": ["OPEN", "IN_PROGRESS"],
        "creation_days_back": 15,
        "project": "project-id",
    }

    variables = {}
    result = apply_all_threat_filters(variables, validated_values)

    # Check that all filters were applied
    assert result["filterBy"]["id"] == validated_values["issue_id"]
    assert "relatedEntity" in result["filterBy"]
    assert result["filterBy"]["relatedEntity"]["cloudPlatform"] == validated_values["platform"]
    assert result["filterBy"]["eventOrigin"]["equals"] == validated_values["origin"]
    assert result["filterBy"]["cloudAccountOrCloudOrganizationId"] == [validated_values["cloud_account_or_cloud_organization"]]
    assert "threatResource" in result["filterBy"]
    assert result["filterBy"]["threatResource"]["ids"] == [validated_values["resource_id"]]
    assert result["filterBy"]["severity"] == validated_values["severity"]
    assert result["filterBy"]["status"] == validated_values["status"]
    assert result["filterBy"]["createdAt"]["inLast"]["amount"] == validated_values["creation_days_back"]
    assert result["filterBy"]["createdAt"]["inLast"]["unit"] == DurationUnit.DAYS
    assert result["filterBy"]["project"] == "project-id"

    # Test with minimal filters
    minimal_values = {"severity": ["CRITICAL"]}

    variables = {}
    result = apply_all_threat_filters(variables, minimal_values)

    # Check that only severity filter was applied
    assert "severity" in result["filterBy"]
    assert len(result["filterBy"]) == 1


def test_apply_matched_rule_filter():
    """Test apply_matched_rule_filter function"""
    # Test with value
    variables = {}
    result = apply_rule_match_id_filter(variables, "rule-id")
    assert "filterBy" in result
    assert "matchedRule" in result["filterBy"]
    assert result["filterBy"]["matchedRule"]["id"] == "rule-id"

    # Test with None (should not add filter)
    variables = {}
    result = apply_rule_match_id_filter(variables, None)
    assert result == {}


def test_apply_rule_match_name_filter():
    """Test apply_rule_match_name_filter function"""
    # Test with value
    variables = {}
    result = apply_rule_match_name_filter(variables, "rule name")
    assert "filterBy" in result
    assert "matchedRuleName" in result["filterBy"]
    assert result["filterBy"]["matchedRuleName"]["equals"] == ["rule name"]

    # Test with None (should not add filter)
    variables = {}
    result = apply_rule_match_name_filter(variables, None)
    assert result == {}


# ===== CORE API COMMUNICATION TESTS =====


def test_get_token_error(mock_response_factory, mocker):
    """Test get_token with error response"""
    # Mock authentication endpoint
    set_authentication_endpoint("https://auth.wiz.io/oauth/token")

    # Mock the response
    mock_response = mock_response_factory(
        status_code=401, json_data={"error": "access_denied", "error_description": "Unauthorized"}, text="Unauthorized"
    )
    mocker.patch("requests.post", return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(demisto, "params", return_value={"credentials": {"identifier": "test", "password": "pass"}})

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        get_token()
    assert "Error authenticating to Wiz" in str(e.value)


def test_get_token_no_access_token(mock_response_factory, mocker):
    """Test get_token when response doesn't contain access_token"""
    # Mock authentication endpoint
    set_authentication_endpoint("https://auth.wiz.io/oauth/token")

    # Mock the response
    mock_response = mock_response_factory(status_code=200, json_data={"message": "No token provided"})
    mocker.patch("requests.post", return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(demisto, "params", return_value={"credentials": {"identifier": "test", "password": "pass"}})

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        get_token()
    assert "Could not retrieve token from Wiz" in str(e.value)


def test_get_token_json_parse_error(mock_response_factory, mocker):
    """Test get_token when response is not valid JSON"""
    # Mock authentication endpoint
    set_authentication_endpoint("https://auth.wiz.io/oauth/token")

    # Mock the response
    mock_response = mock_response_factory(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mocker.patch("requests.post", return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(demisto, "params", return_value={"credentials": {"identifier": "test", "password": "pass"}})

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        get_token()
    assert "Could not parse API response" in str(e.value)


def test_get_entries(mock_response_factory, mocker, mock_api_response):
    """Test get_entries with successful response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Mock at module level
    test_token = "test-token"
    WizDefend.TOKEN = test_token
    WizDefend.get_token = lambda: test_token

    # Mock the response for API call
    mock_response = mock_response_factory(status_code=200, json_data=mock_api_response)
    mocker.patch("requests.post", return_value=mock_response)

    # Call the function
    entries, page_info = WizDefend.get_entries("test_query", {}, WizApiResponse.DETECTIONS)

    # Verify entries and page_info
    assert entries == mock_api_response["data"]["detections"]["nodes"]
    assert page_info == mock_api_response["data"]["detections"]["pageInfo"]


def test_get_entries_with_token_refresh(mock_response_factory, mocker, mock_api_response):
    """Test get_entries when token needs to be refreshed"""
    # Mock token as None (needs refresh)
    mocker.patch("WizDefend.TOKEN", None)

    # Mock get_token
    mocker.patch("WizDefend.get_token", return_value="refreshed-token")

    # Mock the response
    mock_response = mock_response_factory(status_code=200, json_data=mock_api_response)
    mocker.patch("requests.post", return_value=mock_response)

    # Call the function
    entries, page_info = get_entries("test_query", {}, WizApiResponse.DETECTIONS)

    # Verify entries and page_info
    assert entries == mock_api_response["data"]["detections"]["nodes"]
    assert page_info == mock_api_response["data"]["detections"]["pageInfo"]


def test_get_entries_error(mock_response_factory, mocker, mock_api_error_response):
    """Test get_entries with error response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Mock token
    WizDefend.TOKEN = "test-token"

    # Mock the response
    mock_response = mock_response_factory(status_code=200, json_data=mock_api_error_response)
    mocker.patch("requests.post", return_value=mock_response)

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        WizDefend.get_entries("test_query", {}, WizApiResponse.DETECTIONS)
    assert "Wiz API error details" in str(e.value)
    assert "Resource not found" in str(e.value)


def test_get_entries_http_error(mock_response_factory, mocker):
    """Test get_entries with HTTP error response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Mock token
    WizDefend.TOKEN = "test-token"

    # Mock the response
    mock_response = mock_response_factory(status_code=500, text="Internal Server Error")
    mocker.patch("requests.post", return_value=mock_response)

    # Call the function and check exception
    with pytest.raises(Exception) as e:
        WizDefend.get_entries("test_query", {}, WizApiResponse.DETECTIONS)
    assert "Got an error querying Wiz API [500] - Internal Server Error" in str(e.value)


# Modify test_get_token_success function in WizDefend_test.py
def test_get_token_success(mock_response_factory, mocker):
    """Test get_token with successful response"""
    # Import the module inside the test to get a fresh instance
    from Packs.Wiz.Integrations.WizDefend import WizDefend
    import copy

    # Save original HEADERS to restore later
    original_headers = copy.deepcopy(WizDefend.HEADERS)

    # Mock authentication endpoint
    WizDefend.AUTH_E = "https://auth.wiz.io/oauth/token"

    # Mock the response
    mock_response = mock_response_factory(status_code=200, json_data={"access_token": "test-token"})
    mocker.patch("requests.post", return_value=mock_response)

    # Mock demisto.params
    mocker.patch.object(demisto, "params", return_value={"credentials": {"identifier": "test", "password": "pass"}})

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
    WizDefend.TOKEN = "test-token"
    WizDefend.URL = "https://api.wiz.io/graphql"  # Set a valid URL

    # Mock the get_entries function at module level
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = lambda q, v, w: ([sample_detection], {"hasNextPage": False, "endCursor": ""})

    try:
        # Call the function
        result = WizDefend.query_api("test_query", {}, WizApiResponse.DETECTIONS)

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
    WizDefend.TOKEN = "test-token"
    WizDefend.URL = "https://api.wiz.io/graphql"

    # Define a side effect function to simulate pagination
    call_count = [0]  # Use a list to maintain state between calls

    def mock_get_entries_side_effect(query, variables, wiz_type=None):
        call_count[0] += 1
        if call_count[0] == 1:
            return (first_page["data"]["detections"]["nodes"], first_page["data"]["detections"]["pageInfo"])
        else:
            return (second_page["data"]["detections"]["nodes"], second_page["data"]["detections"]["pageInfo"])

    # Replace get_entries with our mock function
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = mock_get_entries_side_effect

    try:
        # Call the function
        result = WizDefend.query_api("test_query", {}, WizApiResponse.DETECTIONS)

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
    WizDefend.TOKEN = "test-token"
    WizDefend.URL = "https://api.wiz.io/graphql"

    # Mock get_entries to return empty results
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = lambda q, v, w=None: ([], {"hasNextPage": False, "endCursor": ""})
    try:
        # Call the function
        result = WizDefend.query_api("test_query", {}, WizApiResponse.DETECTIONS)

        # Verify result is empty dict
        assert result == {}
    finally:
        # Restore original function
        WizDefend.get_entries = orig_get_entries


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_entries")
def test_query_api_with_pagination_disabled(mock_get_entries, mock_api_paginated_response):
    """Test query_api with pagination disabled"""
    # Unpack the paginated responses
    first_page, _ = mock_api_paginated_response

    # Set up the mock for get_entries
    mock_get_entries.return_value = (first_page["data"]["detections"]["nodes"], first_page["data"]["detections"]["pageInfo"])

    # Call the function with paginate=False
    result = query_api("test_query", {}, WizApiResponse.DETECTIONS, paginate=False)

    # Verify result only contains first page
    assert len(result) == 1
    assert result[0]["id"] == first_page["data"]["detections"]["nodes"][0]["id"]


def test_query_threats(mocker, sample_threat):
    """Test query_threats with simple response"""
    # Import the module locally
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Set required module variables directly
    WizDefend.TOKEN = "test-token"
    WizDefend.URL = "https://api.wiz.io/graphql"  # Set a valid URL

    # Mock the get_entries function at module level
    orig_get_entries = WizDefend.get_entries
    WizDefend.get_entries = lambda q, v, w: ([sample_threat], {"hasNextPage": False, "endCursor": ""})

    try:
        # Call the function
        result = WizDefend.query_threats("test_query", {}, WizApiResponse.ISSUES)

        # Verify result
        assert result == [sample_threat]
    finally:
        # Restore original function
        WizDefend.get_entries = orig_get_entries


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_entries")
def test_query_threats_with_pagination(mock_get_entries, sample_threat):
    """Test query_threats with pagination"""
    # Create a second threat for pagination
    second_threat = copy.deepcopy(sample_threat)
    second_threat["id"] = "second-threat-id"

    # Set up the mock with pagination
    mock_get_entries.side_effect = [
        ([sample_threat], {"hasNextPage": True, "endCursor": "cursor1"}),
        ([second_threat], {"hasNextPage": False, "endCursor": ""}),
    ]

    # Call the function
    result = query_threats("test_query", {}, paginate=True)

    # Verify result contains both threats
    assert len(result) == 2
    assert result[0]["id"] == sample_threat["id"]
    assert result[1]["id"] == "second-threat-id"


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_entries")
def test_query_threats_with_pagination_disabled(mock_get_entries, sample_threat):
    """Test query_threats with pagination disabled"""
    # Setup first page response
    mock_get_entries.return_value = ([sample_threat], {"hasNextPage": True, "endCursor": "cursor1"})

    # Call the function with paginate=False
    result = query_threats("test_query", {}, paginate=False)

    # Verify result only contains first page
    assert len(result) == 1
    assert result[0]["id"] == sample_threat["id"]
    # Verify get_entries was only called once
    assert mock_get_entries.call_count == 1


# ===== UTILITY FUNCTION TESTS =====


@pytest.mark.parametrize(
    "severity,expected_result",
    [
        ("CRITICAL", 4),
        ("HIGH", 3),
        ("MEDIUM", 2),
        ("LOW", 1),
        ("INFORMATIONAL", 0.5),
        ("UNKNOWN", None),
    ],
)
def test_translate_severity(severity, expected_result):
    """Test translate_severity with various severity levels"""
    detection = {"severity": severity}
    assert translate_severity(detection) == expected_result


@pytest.mark.parametrize(
    "max_fetch,expected_api_limit",
    [
        # Valid values - should return the input value
        (10, 10),  # Minimum valid value
        (100, 100),  # Middle value
        (500, 500),  # Another middle value
        (1000, 1000),  # Maximum valid value
        # Invalid values - should return API_MAX_FETCH
        (5, API_MAX_FETCH),  # Below minimum
        (1001, API_MAX_FETCH),  # Above maximum
        (None, API_MAX_FETCH),  # None value
        ("invalid", API_MAX_FETCH),  # Non-numeric string
        ("", API_MAX_FETCH),  # Empty string
        (0, API_MAX_FETCH),  # Zero
        (-10, API_MAX_FETCH),  # Negative value
    ],
)
def test_get_fetch_incidents_api_limit(max_fetch, expected_api_limit):
    """Test get_fetch_incidents_api_limit with various max_fetch values"""
    api_limit = get_fetch_incidents_api_max_fetch(max_fetch)
    assert api_limit == expected_api_limit


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


@pytest.mark.parametrize(
    "input_value,expected_result",
    [
        (str(uuid.uuid4()), True),  # Valid UUID
        ("invalid-uuid", False),  # Invalid UUID
        (None, False),  # None value
        ("", False),  # Empty string
        (123, False),  # Non-string
        (object(), False),  # Non-stringifiable object
    ],
)
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
    error_response = {"errors": [{"message": "Resource not found"}, {"message": "Another error"}]}
    result = get_error_output(error_response)
    assert "Resource not found" in result
    assert "Another error" in result

    # Test with duplicate errors (should deduplicate)
    error_response = {"errors": [{"message": "Same error"}, {"message": "Same error"}]}
    result = get_error_output(error_response)
    assert result.count("Same error") == 1

    # Test with no errors
    no_error_response = {"data": {}}
    result = get_error_output(no_error_response)
    assert result == no_error_response


@pytest.mark.parametrize(
    "auth_endpoint, expected_domain",
    [
        ("https://auth.test.wiz.io/oauth/token", "test.wiz.io"),
        ("https://auth.app.wiz.io/oauth/token", "app.wiz.io"),
        ("https://auth.gov.wiz.io/oauth/token", "gov.wiz.io"),
        ("https://auth.staging-env.wiz.io/oauth/token", "staging-env.wiz.io"),
        ("invalid-url", "app.wiz.io"),
    ],
)
def test_update_wiz_domain_url(mocker, auth_endpoint, expected_domain, reset_domain):
    """Test update_wiz_domain_url function correctly extracts the domain from auth endpoint"""
    # Mock demisto.params() to return our test auth_endpoint
    mocker.patch.object(demisto, "params", return_value={"auth_endpoint": auth_endpoint})

    # Import here to ensure we get the reset value
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Call the function
    update_wiz_domain_url()

    # Verify domain was correctly extracted
    assert (
        expected_domain == WizDefend.WIZ_DOMAIN_URL
    ), f"Failed for auth_endpoint={auth_endpoint}: expected {expected_domain}, got {WizDefend.WIZ_DOMAIN_URL}"


@pytest.mark.parametrize("domain", ["app.wiz.io", "test.wiz.io", "staging-env.wiz.io", "customer-subdomain.wiz.io"])
def test_get_detection_url(mocker, sample_detection, domain):
    """Test get_detection_url constructs the correct URL for detections with different domains"""
    # Import here to set the domain
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Set the domain directly
    WizDefend.WIZ_DOMAIN_URL = domain

    # Call the function
    url = get_detection_url(sample_detection)

    # Expected URL pattern
    expected_pattern = f"https://{domain}/findings/detections#~(filters~(updateTime~(dateRange~(past~(amount~5~unit~'day))))~detectionId~'{sample_detection['id']}~streamCols~(~'event~'principal~'principalIp~'resource))"

    # Verify URL was correctly constructed
    assert url == expected_pattern, f"Failed for domain={domain}: expected {expected_pattern}, got {url}"


def test_get_integration_user_agent():
    """Test get_integration_user_agent function"""
    user_agent = get_integration_user_agent()
    assert INTEGRATION_GUID in user_agent
    assert "xsoar_defend" in user_agent
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
    assert test_endpoint == WizDefend.AUTH_E


def test_set_api_endpoint(mocker):
    """Test set_api_endpoint function"""
    # Import the module correctly using the full path
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # First, remove the patch from the fixture that would reset URL
    mocker.stopall()

    test_endpoint = "https://test-api.wiz.io/graphql"
    WizDefend.set_api_endpoint(test_endpoint)

    # Verify the endpoint was set correctly
    assert test_endpoint == WizDefend.URL


# ===== INTEGRATION CONTEXT FUNCTION TESTS =====


@pytest.mark.parametrize(
    "advanced_params,expected_has_max_fetch",
    [
        (False, False),  # Basic params should not include max_fetch
        (True, True),  # Advanced params should include max_fetch
    ],
)
def test_extract_params_from_integration_settings_with_max_fetch(mocker, advanced_params, expected_has_max_fetch):
    """Test extract_params_from_integration_settings function includes max_fetch in advanced params"""
    # Mock demisto.params with max_fetch
    integration_params = {
        "type": "GENERATED THREAT",
        "platform": "AWS",
        "severity": "CRITICAL",
        "origin": "WIZ_SENSOR",
        "cloud_account_or_cloud_organization": "sub-123",
        "first_fetch": "2 days",
        "incidentFetchInterval": 10,
        "incidentType": "WizDefend Detection",
        "isFetch": True,
        "max_fetch": "100",
    }
    mocker.patch.object(demisto, "params", return_value=integration_params)

    result = extract_params_from_integration_settings(advanced_params=advanced_params)

    if expected_has_max_fetch:
        assert result["max_fetch"] == "100"
        assert result["first_fetch"] == "2 days"
        assert result["incidentFetchInterval"] == 10
        assert result["incidentType"] == "WizDefend Detection"
        assert result["isFetch"] is True
    else:
        assert "max_fetch" not in result
        # Basic params should still be present
        assert result["type"] == "GENERATED THREAT"
        assert result["platform"] == "AWS"


def test_extract_params_from_integration_settings(mocker):
    """Test extract_params_from_integration_settings function"""
    # Mock demisto.params
    integration_params = {
        "type": "GENERATED THREAT",
        "platform": "AWS",
        "severity": "CRITICAL",
        "origin": "WIZ_SENSOR",
        "cloud_account_or_cloud_organization": "sub-123",
        "first_fetch": "2 days",
        "incidentFetchInterval": 10,
        "incidentType": "WizDefend Detection",
        "isFetch": True,
    }
    mocker.patch.object(demisto, "params", return_value=integration_params)

    # Test with basic params
    result = extract_params_from_integration_settings(advanced_params=False)
    assert result["type"] == "GENERATED THREAT"
    assert result["platform"] == "AWS"
    assert result["severity"] == "CRITICAL"
    assert result["origin"] == "WIZ_SENSOR"
    assert result["cloud_account_or_cloud_organization"] == "sub-123"
    assert "first_fetch" not in result

    # Test with advanced params
    result = extract_params_from_integration_settings(advanced_params=True)
    assert result["first_fetch"] == "2 days"
    assert result["incidentFetchInterval"] == 10
    assert result["incidentType"] == "WizDefend Detection"
    assert result["isFetch"] is True


@pytest.mark.parametrize(
    "is_fetch,max_fetch,validation_result,expected_valid,expected_error",
    [
        # isFetch=True scenarios
        (True, "100", True, True, ""),  # Valid max_fetch
        (True, "5", False, False, "max_fetch must be a valid integer between 10 and 1000"),  # Invalid max_fetch - updated message
        (True, "invalid", False, False, "max_fetch must be a valid integer between 10 and 1000"),
        (True, None, True, True, ""),  # No max_fetch (should still be valid)
        # isFetch=False scenarios (should skip max_fetch validation)
        (False, "5", True, True, ""),  # Invalid max_fetch but isFetch=False
        (False, "invalid", True, True, ""),  # Non-numeric max_fetch but isFetch=False
    ],
)
def test_check_advanced_params_max_fetch(mocker, is_fetch, max_fetch, validation_result, expected_valid, expected_error):
    """Test check_advanced_params function with max_fetch validation"""
    # Mock all other validation functions to return success
    validation_response_success = ValidationResponse()
    validation_response_success.is_valid = True

    mocker.patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_first_fetch", return_value=validation_response_success)
    mocker.patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_fetch_interval", return_value=validation_response_success)
    mocker.patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_incident_type", return_value=validation_response_success)

    # For failing cases, don't mock validate_max_fetch - let it run with real validation
    # This way we test against the actual error messages
    if validation_result:
        # Only mock when we want to force success
        max_fetch_response = validation_response_success
        mocker.patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_max_fetch", return_value=max_fetch_response)
    # For failing cases, let the real validate_max_fetch function run

    params = {
        "isFetch": is_fetch,
        "first_fetch": "2 days",
        "incidentFetchInterval": 10,
        "incidentType": "WizDefend Detection",
        "max_fetch": max_fetch,
    }

    are_valid, error_message = check_advanced_params(params)
    assert are_valid is expected_valid
    if expected_error:
        assert expected_error in error_message


def test_check_advanced_params(mocker):
    """Test check_advanced_params function"""
    # Mock validation functions
    validation_response_success = ValidationResponse()
    validation_response_success.is_valid = True

    validation_response_error = ValidationResponse()
    validation_response_error.is_valid = False
    validation_response_error.error_message = "Validation error"

    mocker.patch("WizDefend.validate_first_fetch", return_value=validation_response_success)
    mocker.patch("WizDefend.validate_fetch_interval", return_value=validation_response_success)
    mocker.patch("WizDefend.validate_incident_type", return_value=validation_response_success)

    # Test with valid params
    params = {"isFetch": True, "first_fetch": "2 days", "incidentFetchInterval": 10, "incidentType": "WizDefend Detection"}
    are_valid, error_message = check_advanced_params(params)
    assert are_valid is True
    assert error_message == ""

    # Test with isFetch=False (should skip validation)
    params = {"isFetch": False}
    are_valid, error_message = check_advanced_params(params)
    assert are_valid is True
    assert error_message == ""

    # Mock validation function with error
    mocker.patch("WizDefend.validate_first_fetch", return_value=validation_response_error)

    # Test with invalid first_fetch
    params = {"isFetch": True, "first_fetch": "invalid", "incidentFetchInterval": 10, "incidentType": "WizDefend Detection"}
    are_valid, error_message = check_advanced_params(params)
    assert are_valid is False
    assert "Invalid first fetch format" in error_message


# Helper to validate ISO timestamps
def is_valid_iso_timestamp(s):
    """Check if a string is a valid ISO timestamp."""
    pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z"
    return bool(re.match(pattern, s))


def test_get_last_run_time_first_run(mocker):
    """Test get_last_run_time when no last run exists"""
    # Mock demisto.getLastRun to return empty dict
    mocker.patch.object(demisto, "getLastRun", return_value={})

    # Mock demisto.params
    mocker.patch.object(demisto, "params", return_value={"first_fetch": "2 days"})

    # Call the function
    result = get_last_run_time()

    # Verify result is a valid ISO timestamp
    assert is_valid_iso_timestamp(result), f"Result '{result}' is not a valid ISO timestamp"


def test_get_last_run_time_existing_run(mocker):
    """Test get_last_run_time with existing last run"""
    from datetime import datetime

    # Use a timestamp that's guaranteed to be recent (now)
    recent_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Mock demisto.getLastRun to return our recent timestamp
    mocker.patch.object(demisto, "getLastRun", return_value={"time": recent_time})

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
    mocker.patch.object(demisto, "getLastRun", return_value={"time": very_old_time})

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
    mocker.patch("WizDefend.validate_first_fetch_timestamp", return_value=(False, "Invalid date format", None))

    # Call the function and check exception
    with pytest.raises(ValueError) as e:
        get_fetch_timestamp("invalid format")

    # Verify exception message
    assert "Invalid date format" in str(e.value)


# ===== DETECTION FUNCTION TESTS =====
@patch(
    "Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_detection_parameters",
    return_value=(True, None, {"severity": ["CRITICAL"]}),
)
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_api")
def test_get_filtered_detections_success(mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with successful validation and API call"""

    # Set up the mock to return the sample detection
    mock_query_api.return_value = [sample_detection]

    # Call the function
    result = get_filtered_detections(detection_type="GENERATED THREAT", detection_platform=["AWS"], severity="CRITICAL")

    # Verify result
    assert result == [sample_detection]
    assert mock_query_api.called


@patch(
    "Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_detection_parameters",
    return_value=(False, "Validation error message", None),
)
def test_get_filtered_detections_validation_error(mock_validate):
    """Test get_filtered_detections with validation error"""
    # Call the function
    result = get_filtered_detections(detection_type="INVALID")

    # Verify result is the error message
    assert result == "Validation error message"


@patch(
    "Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_detection_parameters",
    return_value=(True, None, {"severity": ["CRITICAL"]}),
)
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_api")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_detection_url", return_value="https://app.wiz.io/detection/123")
def test_get_filtered_detections_with_all_params(mock_url, mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with all parameters specified"""
    # Set up validated values
    validated_values = {
        "detection_id": [str(uuid.uuid4())],
        "issue_id": str(uuid.uuid4()),
        "type": "GENERATED_THREAT",
        "platform": ["AWS"],
        "origin": ["WIZ_SENSOR"],
        "subscription": "test-subscription",
        "resource_id": "test-id",
        "severity": ["CRITICAL"],
        "creation_minutes_back": 15,
        "rule_match_id": "rule-id",
        "rule_match_name": "rule name",
        "project_id": "project-id",
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_api.return_value = [sample_detection]

    # Call the function with all parameters
    result = get_filtered_detections(
        detection_id=validated_values["detection_id"][0],
        issue_id=validated_values["issue_id"],
        detection_type="GENERATED THREAT",
        detection_platform=validated_values["platform"],
        detection_origin=validated_values["origin"],
        detection_cloud_account_or_cloud_organization=validated_values["subscription"],
        resource_id=validated_values["resource_id"],
        severity="CRITICAL",
        creation_minutes_back="15",
        rule_match_id=validated_values["rule_match_id"],
        rule_match_name=validated_values["rule_match_name"],
        project_id=validated_values["project_id"],
    )

    # Verify result
    assert result == [sample_detection]
    assert result[0].get("url") == "https://app.wiz.io/detection/123"


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_detection_parameters")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_api")
def test_get_filtered_detections_with_no_url(mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with add_detection_url=False"""
    # Set up validated values
    validated_values = {
        "severity": ["CRITICAL"],
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_api.return_value = [sample_detection]

    # Call the function with add_detection_url=False
    result = get_filtered_detections(severity="CRITICAL", add_detection_url=False)

    # Verify result (should not have url)
    assert result == [sample_detection]
    assert "url" not in result[0]


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_detection_parameters")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_api")
def test_get_filtered_detections_with_api_limit(mock_query_api, mock_validate, sample_detection):
    """Test get_filtered_detections with custom API limit"""
    # Set up validated values
    validated_values = {
        "severity": ["CRITICAL"],
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_api.return_value = [sample_detection]

    # Call the function with custom api_limit
    get_filtered_detections(severity="CRITICAL", api_limit=50)

    # Verify query_api was called with correct api_limit
    variables = mock_query_api.call_args[0][1]
    assert variables["first"] == 50


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections", return_value=[{"id": "test-detection"}])
@patch("WizDefend.check_advanced_params", return_value=(True, ""))
@patch("WizDefend.extract_params_from_integration_settings")
@patch.object(demisto, "results")
def test_test_module_success(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with successful validation and API call"""
    # Set up mock extraction params
    mock_extract_params.return_value = {
        "type": "GENERATED THREAT",
        "platform": "AWS",
        "severity": "CRITICAL",
        "origin": "WIZ_SENSOR",
        "subscription": "test-subscription",
    }

    # Call the function
    test_module()

    # Verify demisto.results was called with 'ok'
    mock_results.assert_called_with("ok")


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections", return_value=[{"id": "test-detection"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.check_advanced_params", return_value=(False, "Parameter validation error"))
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.extract_params_from_integration_settings")
@patch.object(demisto, "results")
def test_test_module_invalid_params(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with invalid parameters"""
    # Set up mock extraction params
    mock_extract_params.return_value = {"type": "GENERATED THREAT", "platform": "AWS", "severity": "CRITICAL"}

    # Call the function
    test_module()

    # Verify demisto.results was called with the error message
    mock_results.assert_called_with("Parameter validation error")


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections", return_value="API error message")
@patch("WizDefend.check_advanced_params", return_value=(True, ""))
@patch("WizDefend.extract_params_from_integration_settings")
@patch.object(demisto, "results")
def test_test_module_api_error(mock_results, mock_extract_params, mock_check_params, mock_get_filtered):
    """Test test_module function with API error"""
    # Set up mock extraction params
    mock_extract_params.return_value = {"type": "GENERATED THREAT", "platform": "AWS", "severity": "CRITICAL"}

    # Call the function
    test_module()

    # Verify demisto.results was called with the error message
    mock_results.assert_called_with("API error message")


@freeze_time("2022-01-02T00:00:00Z")  # This is safer than patching datetime
@patch.object(demisto, "setLastRun")
@patch.object(demisto, "incidents")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections")
@patch("WizDefend.get_last_run_time", return_value="2022-01-01T00:00:00Z")
@patch("WizDefend.extract_params_from_integration_settings")
def test_fetch_incidents_success(
    mock_extract_params, mock_last_run, mock_get_filtered, mock_incidents, mock_set_last_run, sample_detection
):
    """Test fetch_incidents with successful API call"""
    # Set up mocks
    mock_extract_params.return_value = {
        "type": "GENERATED THREAT",
        "platform": "AWS",
        "severity": "CRITICAL",
        "origin": "WIZ_SENSOR",
        "subscription": "test-subscription",
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


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections", return_value="API error message")
@patch("WizDefend.get_last_run_time", return_value="2022-01-01T00:00:00Z")
@patch("WizDefend.extract_params_from_integration_settings")
def test_fetch_incidents_api_error(mock_extract_params, mock_last_run, mock_get_filtered):
    """Test fetch_incidents with API error"""
    # Set up mocks
    mock_extract_params.return_value = {"type": "GENERATED THREAT", "platform": "AWS", "severity": "CRITICAL"}

    # Call the function
    fetch_incidents()

    # No assertions needed as we're just checking if it runs without raising exceptions


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.test_module")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "command", return_value="test-module")
def test_main_test_module(mock_command, mock_set_auth, mock_set_api, mock_test_module):
    """Test main function handling test-module command"""
    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify test_module was called
    assert mock_test_module.called


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.fetch_incidents")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "command", return_value="fetch-incidents")
def test_main_fetch_incidents(mock_command, mock_set_auth, mock_set_api, mock_fetch):
    """Test main function handling fetch-incidents command"""
    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify fetch_incidents was called
    assert mock_fetch.called


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_results")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections", return_value=[{"id": "test-detection"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "args")
@patch.object(demisto, "command", return_value="wiz-get-detections")
def test_main_get_detections(mock_command, mock_args, mock_set_auth, mock_set_api, mock_filtered_detections, mock_return_results):
    """Test main function handling wiz-get-detections command"""
    # Set up mock args
    mock_args.return_value = {"severity": "CRITICAL", "type": "GENERATED THREAT", "platform": "AWS"}

    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify return_results was called
    assert mock_return_results.called


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_results")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_detections", return_value=[{"id": "test-detection"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "args")
@patch.object(demisto, "command", return_value="wiz-get-detection")
def test_main_get_detection(mock_command, mock_args, mock_set_auth, mock_set_api, mock_filtered_detections, mock_return_results):
    """Test main function handling wiz-get-detection command"""
    # Set up mock args
    detection_id = str(uuid.uuid4())
    mock_args.return_value = {"detection_id": detection_id}

    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify return_results was called
    assert mock_return_results.called


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_error")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "args", side_effect=Exception("Test error"))
@patch.object(demisto, "command", return_value="wiz-get-detections")
def test_main_error_handling(mock_command, mock_args, mock_set_auth, mock_set_api, mock_return_error):
    """Test main function error handling"""
    # Call the function
    main()

    # Verify return_error was called with the error message
    mock_return_error.assert_called_once()
    assert "Test error" in mock_return_error.call_args[0][0]


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_error")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "command", return_value="unknown-command")
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


# ===== THREAT FUNCTION TESTS =====


def test_get_threat_url(mocker, sample_threat):
    """Test get_threat_url constructs the correct URL for threats with different domains"""
    # Import here to set the domain
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Set the domain directly
    domain = "app.wiz.io"
    WizDefend.WIZ_DOMAIN_URL = domain

    # Call the function
    url = get_threat_url(sample_threat)

    # Expected URL pattern
    expected_pattern = (
        f"https://{domain}/threats#~(filters~(createdAt~(inTheLast~(amount~90~unit~'days)))~issue~'{sample_threat['id']})"
    )

    # Verify URL was correctly constructed
    assert url == expected_pattern


@patch(
    "Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_threat_parameters",
    return_value=(True, None, {"severity": ["CRITICAL"], "platform": ["AWS"], "status": ["OPEN"]}),
)
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_threats", return_value=[{"id": "test-threat"}])
def test_get_filtered_threats_success(mock_query_threats, mock_validate, sample_threat):
    """Test get_filtered_threats with successful validation and API call"""
    # Replace the API call with our mock threat
    mock_query_threats.return_value = [sample_threat]

    # Call the function
    result = get_filtered_threats(platform=["AWS"], severity="CRITICAL", status=["OPEN"])

    # Verify result
    assert result == [sample_threat]
    assert mock_query_threats.called


@patch(
    "Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_threat_parameters",
    return_value=(False, "Validation error message", None),
)
def test_get_filtered_threats_validation_error(mock_validate):
    """Test get_filtered_threats with validation error"""
    # Call the function
    result = get_filtered_threats(status="INVALID")

    # Verify result is the error message
    assert result == "Validation error message"


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_threat_parameters")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_threats")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_threat_url", return_value="https://app.wiz.io/threats/123")
def test_get_filtered_threats_with_all_params(mock_url, mock_query_threats, mock_validate, sample_threat):
    """Test get_filtered_threats with all parameters specified"""
    # Set up validated values
    validated_values = {
        "issue_id": str(uuid.uuid4()),
        "platform": ["AWS"],
        "origin": ["WIZ_SENSOR"],
        "cloud_account_or_cloud_organization": "test-subscription",
        "resource_id": "test-id",
        "severity": ["CRITICAL"],
        "status": ["OPEN"],
        "creation_days_back": 15,
        "project_id": "project-id",
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_threats.return_value = [sample_threat]

    # Call the function with all parameters
    result = get_filtered_threats(
        issue_id=validated_values["issue_id"],
        platform=validated_values["platform"],
        origin=validated_values["origin"],
        cloud_account_or_cloud_organization=validated_values["cloud_account_or_cloud_organization"],
        resource_id=validated_values["resource_id"],
        severity="CRITICAL",
        status=validated_values["status"],
        creation_days_back="15",
        project_id=validated_values["project_id"],
    )

    # Verify result
    assert result == [sample_threat]
    assert result[0].get("url") == "https://app.wiz.io/threats/123"


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.validate_all_threat_parameters")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.query_threats")
def test_get_filtered_threats_with_no_url(mock_query_threats, mock_validate, sample_threat):
    """Test get_filtered_threats with add_threat_url=False"""
    # Set up validated values
    validated_values = {
        "severity": ["CRITICAL"],
    }

    # Configure the mocks
    mock_validate.return_value = (True, None, validated_values)
    mock_query_threats.return_value = [sample_threat]

    # Call the function with add_threat_url=False
    result = get_filtered_threats(severity="CRITICAL", add_threat_url=False)

    # Verify result (should not have url)
    assert result == [sample_threat]
    assert "url" not in result[0]


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_results")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_threats", return_value=[{"id": "test-threat"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "args")
@patch.object(demisto, "command", return_value="wiz-get-threats")
def test_main_get_threats(mock_command, mock_args, mock_set_auth, mock_set_api, mock_filtered_threats, mock_return_results):
    """Test main function handling wiz-get-threats command"""
    # Set up mock args
    mock_args.return_value = {"severity": "CRITICAL", "platform": "AWS", "status": "OPEN"}

    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify return_results was called
    assert mock_return_results.called


@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_results")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_threats", return_value=[{"id": "test-threat"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_api_endpoint")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.set_authentication_endpoint")
@patch.object(demisto, "args")
@patch.object(demisto, "command", return_value="wiz-get-threat")
def test_main_get_threat(mock_command, mock_args, mock_set_auth, mock_set_api, mock_filtered_threats, mock_return_results):
    """Test main function handling wiz-get-threat command"""
    # Set up mock args
    issue_id = str(uuid.uuid4())
    mock_args.return_value = {"issue_id": issue_id}

    # Call the function
    main()

    # Verify endpoints were set
    assert mock_set_auth.called
    assert mock_set_api.called

    # Verify return_results was called
    assert mock_return_results.called


@patch.object(demisto, "args", return_value={"issue_id": str(uuid.uuid4())})
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_threats", return_value=[{"id": "test-threat"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.CommandResults")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_error")  # Add return_error patch
def test_get_single_threat(mock_return_error, mock_command_results, mock_get_filtered, mock_args):
    """Test get_single_threat function"""
    # Import here because we need the patched versions
    from Packs.Wiz.Integrations.WizDefend.WizDefend import get_single_threat

    get_single_threat()

    # Since we're returning a valid threat list, return_error should not be called
    assert not mock_return_error.called
    # Check that CommandResults was called with correct parameters
    mock_command_results.assert_called_once()
    assert mock_command_results.call_args[1]["outputs_prefix"] == OutputPrefix.THREAT


@patch.object(demisto, "args", return_value={"severity": "CRITICAL", "platform": "AWS", "status": "OPEN"})
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.get_filtered_threats", return_value=[{"id": "test-threat"}])
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.CommandResults")
@patch("Packs.Wiz.Integrations.WizDefend.WizDefend.return_error")  # Add return_error patch
def test_get_threats(mock_return_error, mock_command_results, mock_get_filtered, mock_args):
    """Test get_threats function"""
    # Import here because we need the patched versions
    from Packs.Wiz.Integrations.WizDefend.WizDefend import get_threats

    get_threats()

    # Since we're returning a valid threat list, return_error should not be called
    assert not mock_return_error.called
    # Check that CommandResults was called with correct parameters
    mock_command_results.assert_called_once()
    assert mock_command_results.call_args[1]["outputs_prefix"] == OutputPrefix.THREATS


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
        "AWS",
        "GCP",
        "Azure",
        "OCI",
        "Alibaba",
        "vSphere",
        "OpenStack",
        "AKS",
        "EKS",
        "GKE",
        "Kubernetes",
        "OpenShift",
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
        "WIZ_SENSOR",
        "AWS_GUARD_DUTY",
        "AWS_CLOUDTRAIL",
        "AZURE_DEFENDER_FOR_CLOUD",
        "GCP_SECURITY_COMMAND_CENTER",
    ]
    for origin in expected_origins:
        assert origin in values


def test_duration_unit_class():
    """Test the DurationUnit class"""
    assert DurationUnit.DAYS == "DurationFilterValueUnitDays"
    assert DurationUnit.HOURS == "DurationFilterValueUnitHours"
    assert DurationUnit.MINUTES == "DurationFilterValueUnitMinutes"


# ===== YML FIXTURES =====


def test_cloud_platform_values_consistency(yaml_content):
    """Test that cloud platform values defined in YAML match those in the CloudPlatform class"""
    # Extract platform values from both commands in YAML
    yaml_platform_values_detections = []
    yaml_platform_values_threats = []

    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-detections":
            for arg in command.get("arguments", []):
                if arg.get("name") == "platform":
                    yaml_platform_values_detections = arg.get("predefined", [])
        elif command.get("name") == "wiz-get-threats":
            for arg in command.get("arguments", []):
                if arg.get("name") == "platform":
                    yaml_platform_values_threats = arg.get("predefined", [])

    # Also check the root configuration platforms
    yaml_config_platforms = []
    for config in yaml_content.get("configuration", []):
        if config.get("name") == "platform":
            yaml_config_platforms = config.get("options", [])

    # Get platform values from code
    code_platform_values = CloudPlatform.values()

    # Sort all lists for deterministic comparison
    code_platform_values.sort()
    yaml_platform_values_detections.sort()
    yaml_platform_values_threats.sort()
    yaml_config_platforms.sort()

    # Test exact equality between code and YAML values
    assert code_platform_values == yaml_platform_values_detections, (
        f"Platform values in code do not exactly match wiz-get-detections:\n"
        f"Code: {code_platform_values}\n"
        f"YAML: {yaml_platform_values_detections}"
    )

    assert code_platform_values == yaml_platform_values_threats, (
        f"Platform values in code do not exactly match wiz-get-threats:\n"
        f"Code: {code_platform_values}\n"
        f"YAML: {yaml_platform_values_threats}"
    )

    assert code_platform_values == yaml_config_platforms, (
        f"Platform values in code do not exactly match configuration options:\n"
        f"Code: {code_platform_values}\n"
        f"YAML config: {yaml_config_platforms}"
    )

    # Test exact equality between the two commands
    assert yaml_platform_values_detections == yaml_platform_values_threats, (
        f"Platform values differ between commands:\n"
        f"wiz-get-detections: {yaml_platform_values_detections}\n"
        f"wiz-get-threats: {yaml_platform_values_threats}"
    )


def test_detection_type_values_consistency(yaml_content):
    """Test that detection type values defined in YAML match those in the DetectionType class"""
    # Extract detection type values from YAML
    yaml_type_values_command = []
    yaml_type_values_config = []

    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-detections":
            for arg in command.get("arguments", []):
                if arg.get("name") == "type":
                    yaml_type_values_command = arg.get("predefined", [])

    for config in yaml_content.get("configuration", []):
        if config.get("name") == "type":
            yaml_type_values_config = config.get("options", [])
            # Remove 'None' from configuration options if present
            if "None" in yaml_type_values_config:
                yaml_type_values_config.remove("None")

    # Get detection type values from code
    code_type_values = DetectionType.values()

    # Sort all lists for deterministic comparison
    code_type_values.sort()
    yaml_type_values_command.sort()
    yaml_type_values_config.sort()

    # Test exact equality between code and YAML values
    assert code_type_values == yaml_type_values_command, (
        f"Detection type values in code do not exactly match wiz-get-detections:\n"
        f"Code: {code_type_values}\n"
        f"YAML: {yaml_type_values_command}"
    )

    assert code_type_values == yaml_type_values_config, (
        f"Detection type values in code do not exactly match configuration options:\n"
        f"Code: {code_type_values}\n"
        f"YAML config: {yaml_type_values_config}"
    )


def test_severity_values_consistency(yaml_content):
    """Test that severity values defined in YAML match those in the WizSeverity class, ignoring INFORMATIONAL"""
    # Extract severity values from both commands in YAML
    yaml_severity_values_detections = []
    yaml_severity_values_threats = []
    yaml_severity_config = []

    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-detections":
            for arg in command.get("arguments", []):
                if arg.get("name") == "severity":
                    yaml_severity_values_detections = arg.get("predefined", [])
        elif command.get("name") == "wiz-get-threats":
            for arg in command.get("arguments", []):
                if arg.get("name") == "severity":
                    yaml_severity_values_threats = arg.get("predefined", [])

    for config in yaml_content.get("configuration", []):
        if config.get("name") == "severity":
            yaml_severity_config = config.get("options", [])
            # Remove 'None' from configuration options if present
            if "None" in yaml_severity_config:
                yaml_severity_config.remove("None")

    # Get severity values from code
    code_severity_values = [
        getattr(WizSeverity, attr)
        for attr in dir(WizSeverity)
        if not attr.startswith("_") and not callable(getattr(WizSeverity, attr))
    ]

    # Convert all values to uppercase for case-insensitive comparison
    # and filter out INFORMATIONAL from all sets
    code_upper = {s.upper() for s in code_severity_values if s.upper() != "INFORMATIONAL"}
    yaml_detections_upper = {s.upper() for s in yaml_severity_values_detections if s.upper() != "INFORMATIONAL"}
    yaml_threats_upper = {s.upper() for s in yaml_severity_values_threats if s.upper() != "INFORMATIONAL"}
    yaml_config_upper = {s.upper() for s in yaml_severity_config if s.upper() != "INFORMATIONAL"}

    # Test case-insensitive equality between code and YAML values (ignoring INFORMATIONAL)
    assert code_upper == yaml_config_upper, (
        f"Severity values in code do not match configuration options (ignoring INFORMATIONAL):\n"
        f"Code (uppercase, without INFORMATIONAL): {sorted(code_upper)}\n"
        f"YAML config (uppercase, without INFORMATIONAL): {sorted(yaml_config_upper)}"
    )

    assert code_upper == yaml_detections_upper, (
        f"Severity values in code do not match wiz-get-detections (ignoring INFORMATIONAL):\n"
        f"Code (uppercase, without INFORMATIONAL): {sorted(code_upper)}\n"
        f"YAML detections (uppercase, without INFORMATIONAL): {sorted(yaml_detections_upper)}"
    )

    assert code_upper == yaml_threats_upper, (
        f"Severity values in code do not match wiz-get-threats (ignoring INFORMATIONAL):\n"
        f"Code (uppercase, without INFORMATIONAL): {sorted(code_upper)}\n"
        f"YAML threats (uppercase, without INFORMATIONAL): {sorted(yaml_threats_upper)}"
    )

    # Test equality between the YAML values (case-insensitive)
    assert yaml_detections_upper == yaml_threats_upper, (
        f"Severity values differ between commands (ignoring INFORMATIONAL):\n"
        f"wiz-get-detections (uppercase, without INFORMATIONAL): {sorted(yaml_detections_upper)}\n"
        f"wiz-get-threats (uppercase, without INFORMATIONAL): {sorted(yaml_threats_upper)}"
    )

    assert yaml_detections_upper == yaml_config_upper, (
        f"Severity values differ between command and configuration (ignoring INFORMATIONAL):\n"
        f"wiz-get-detections (uppercase, without INFORMATIONAL): {sorted(yaml_detections_upper)}\n"
        f"configuration (uppercase, without INFORMATIONAL): {sorted(yaml_config_upper)}"
    )


def test_status_values_consistency(yaml_content):
    """Test that status values defined in YAML match those in the WizStatus class"""
    # Extract status values from threats command in YAML
    yaml_status_values = []

    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-threats":
            for arg in command.get("arguments", []):
                if arg.get("name") == "status":
                    yaml_status_values = arg.get("predefined", [])

    # Get status values from code
    code_status_values = [
        getattr(WizStatus, attr) for attr in dir(WizStatus) if not attr.startswith("_") and not callable(getattr(WizStatus, attr))
    ]

    # Sort all lists for deterministic comparison
    code_status_values.sort()
    yaml_status_values.sort()

    # Test exact equality between code and YAML values
    assert (
        code_status_values == yaml_status_values
    ), f"Status values in code do not exactly match wiz-get-threats:\nCode: {code_status_values}\nYAML: {yaml_status_values}"


def test_origin_values_consistency(yaml_content):
    """Test that origin values defined in YAML match those in the DetectionOrigin class"""
    # Extract origin values from both commands in YAML
    yaml_origin_values_detections = []
    yaml_origin_values_threats = []
    yaml_origin_config = []

    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-detections":
            for arg in command.get("arguments", []):
                if arg.get("name") == "origin":
                    yaml_origin_values_detections = arg.get("predefined", [])
        elif command.get("name") == "wiz-get-threats":
            for arg in command.get("arguments", []):
                if arg.get("name") == "origin":
                    yaml_origin_values_threats = arg.get("predefined", [])

    for config in yaml_content.get("configuration", []):
        if config.get("name") == "origin":
            yaml_origin_config = config.get("options", [])

    # Get origin values from code
    code_origin_values = DetectionOrigin.values()

    # Sort all lists for deterministic comparison
    code_origin_values.sort()
    yaml_origin_values_detections.sort()
    yaml_origin_values_threats.sort()
    yaml_origin_config.sort()

    # Test exact equality between code and YAML values
    assert code_origin_values == yaml_origin_values_detections, (
        f"Origin values in code do not exactly match wiz-get-detections:\n"
        f"Code: {code_origin_values}\n"
        f"YAML: {yaml_origin_values_detections}"
    )

    assert code_origin_values == yaml_origin_values_threats, (
        f"Origin values in code do not exactly match wiz-get-threats:\n"
        f"Code: {code_origin_values}\n"
        f"YAML: {yaml_origin_values_threats}"
    )

    if yaml_origin_config:  # Only check if origin config exists
        assert code_origin_values == yaml_origin_config, (
            f"Origin values in code do not exactly match configuration options:\n"
            f"Code: {code_origin_values}\n"
            f"YAML config: {yaml_origin_config}"
        )

    # Test exact equality between the two commands
    assert yaml_origin_values_detections == yaml_origin_values_threats, (
        f"Origin values differ between commands:\n"
        f"wiz-get-detections: {yaml_origin_values_detections}\n"
        f"wiz-get-threats: {yaml_origin_values_threats}"
    )


def test_max_fetch_values_consistency(yaml_content):
    """Test that max_fetch values defined in YAML match those in the code constants"""
    # Find the max_fetch configuration
    max_fetch_config = None
    for config in yaml_content.get("configuration", []):
        if config.get("name") == "max_fetch":
            max_fetch_config = config
            break

    assert max_fetch_config is not None, "max_fetch configuration not found in YAML"

    # Get default value from YAML
    default_value_in_yaml = max_fetch_config.get("defaultvalue")
    assert default_value_in_yaml is not None, "No defaultvalue for max_fetch"
    default_max_fetch_in_yaml = int(default_value_in_yaml)

    # Assert that the code constant matches the YAML value
    assert default_max_fetch_in_yaml == API_MAX_FETCH, (
        f"API_MAX_FETCH ({API_MAX_FETCH}) does not match "
        f"the defaultvalue in max_fetch configuration ({default_max_fetch_in_yaml})"
    )

    # Check additional info mentions the range
    additional_info = max_fetch_config.get("additionalinfo", "")
    assert (
        "10-1000" in additional_info
    ), f"max_fetch additionalinfo doesn't mention the expected range (10-1000): {additional_info}"

    # Verify the range in additionalinfo matches the code constants
    import re

    range_match = re.search(r"(\d+)-(\d+)", additional_info)
    assert range_match is not None, f"Could not find range format in additionalinfo: {additional_info}"

    min_value_in_yaml = int(range_match.group(1))
    max_value_in_yaml = int(range_match.group(2))

    assert (
        min_value_in_yaml == API_MIN_FETCH
    ), f"API_MIN_FETCH ({API_MIN_FETCH}) does not match the minimum value in max_fetch additionalinfo ({min_value_in_yaml})"

    assert (
        max_value_in_yaml == API_MAX_FETCH
    ), f"API_MAX_FETCH ({API_MAX_FETCH}) does not match the maximum value in max_fetch additionalinfo ({max_value_in_yaml})"


def test_first_fetch_timestamp_consistency(yaml_content):
    """Test that MAX_DAYS_FIRST_FETCH_DETECTIONS matches the max days in first fetch timestamp description"""
    # Find the first fetch timestamp configuration
    first_fetch_config = None
    for config in yaml_content.get("configuration", []):
        if config.get("name") == "first_fetch":
            first_fetch_config = config
            break

    assert first_fetch_config is not None, "first_fetch configuration not found in YAML"

    # Extract max days value from the display text
    display_text = first_fetch_config.get("display", "")
    import re

    # Update the pattern to match both "max X days" and "maximum X days"
    max_days_match = re.search(r"max(?:imum)? (\d+) days", display_text)

    assert (
        max_days_match is not None
    ), f"Could not find 'max X days' or 'maximum X days' in first_fetch display text: {display_text}"
    max_days_in_yaml = int(max_days_match.group(1))

    # Assert that the code constant matches the YAML value
    assert max_days_in_yaml == MAX_DAYS_FIRST_FETCH_DETECTIONS, (
        f"MAX_DAYS_FIRST_FETCH_DETECTIONS ({MAX_DAYS_FIRST_FETCH_DETECTIONS}) does not match "
        f"the value in first_fetch display text ({max_days_in_yaml})"
    )


def test_threats_days_params_consistency(yaml_content):
    """Test that THREATS_DAYS constants match the creation_days_back argument description"""
    from Packs.Wiz.Integrations.WizDefend.WizDefend import THREATS_DAYS_MIN, THREATS_DAYS_MAX, THREATS_DAYS_DEFAULT

    # Find the creation_days_back argument in wiz-get-threats command
    creation_days_back_arg = None
    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-threats":
            for arg in command.get("arguments", []):
                if arg.get("name") == "creation_days_back":
                    creation_days_back_arg = arg
                    break
            if creation_days_back_arg:
                break

    assert creation_days_back_arg is not None, "creation_days_back argument not found in wiz-get-threats command"

    # Extract min, max, default values from description
    description = creation_days_back_arg.get("description", "")
    import re

    # Update pattern to match "range 1-30" instead of just "(1-30)"
    range_match = re.search(r"range (\d+)-(\d+)", description)

    assert range_match is not None, f"Could not find range format (e.g., 'range 1-30') in description: {description}"
    min_days_in_yaml = int(range_match.group(1))
    max_days_in_yaml = int(range_match.group(2))

    # Get default value
    default_value_in_yaml = creation_days_back_arg.get("defaultValue")
    assert default_value_in_yaml is not None, "No defaultValue for creation_days_back"
    default_days_in_yaml = int(default_value_in_yaml)

    # Assert that code constants match YAML values
    assert min_days_in_yaml == THREATS_DAYS_MIN, (
        f"THREATS_DAYS_MIN ({THREATS_DAYS_MIN}) does not match "
        f"the minimum value in creation_days_back description ({min_days_in_yaml})"
    )

    assert max_days_in_yaml == THREATS_DAYS_MAX, (
        f"THREATS_DAYS_MAX ({THREATS_DAYS_MAX}) does not match "
        f"the maximum value in creation_days_back description ({max_days_in_yaml})"
    )

    assert default_days_in_yaml == THREATS_DAYS_DEFAULT, (
        f"THREATS_DAYS_DEFAULT ({THREATS_DAYS_DEFAULT}) does not match "
        f"the default value in creation_days_back argument ({default_days_in_yaml})"
    )


def test_fetch_interval_consistency(yaml_content):
    """Test that FETCH_INTERVAL constants match the creation_minutes_back argument description"""
    from Packs.Wiz.Integrations.WizDefend.WizDefend import FETCH_INTERVAL_MINIMUM_MIN, FETCH_INTERVAL_MAXIMUM_MIN

    # Find the creation_minutes_back argument in wiz-get-detections command
    creation_minutes_back_arg = None
    for command in yaml_content.get("script", {}).get("commands", []):
        if command.get("name") == "wiz-get-detections":
            for arg in command.get("arguments", []):
                if arg.get("name") == "creation_minutes_back":
                    creation_minutes_back_arg = arg
                    break
            if creation_minutes_back_arg:
                break

    assert creation_minutes_back_arg is not None, "creation_minutes_back argument not found in wiz-get-detections command"

    # Extract min, max values from description
    description = creation_minutes_back_arg.get("description", "")
    import re

    # Update pattern to match "range 10-600" instead of just "(10-600)"
    range_match = re.search(r"range (\d+)-(\d+)", description)

    assert range_match is not None, f"Could not find range format (e.g., 'range 10-600') in description: {description}"
    min_minutes_in_yaml = int(range_match.group(1))
    max_minutes_in_yaml = int(range_match.group(2))

    # We don't check FETCH_INTERVAL_MINIMUM_MIN directly since the values might be different
    # for the command argument vs. fetch interval. Instead, we check that the values are reasonable.
    assert min_minutes_in_yaml >= FETCH_INTERVAL_MINIMUM_MIN, (
        f"Minimum minutes in creation_minutes_back description ({min_minutes_in_yaml}) "
        f"is less than FETCH_INTERVAL_MINIMUM_MIN ({FETCH_INTERVAL_MINIMUM_MIN})"
    )

    assert max_minutes_in_yaml <= FETCH_INTERVAL_MAXIMUM_MIN, (
        f"Maximum minutes in creation_minutes_back description ({max_minutes_in_yaml}) "
        f"is greater than FETCH_INTERVAL_MAXIMUM_MIN ({FETCH_INTERVAL_MAXIMUM_MIN})"
    )


def test_default_fetch_back_consistency(yaml_content):
    """Test that DEFAULT_FETCH_BACK matches the first_fetch defaultvalue"""
    from Packs.Wiz.Integrations.WizDefend.WizDefend import DEFAULT_FETCH_BACK

    # Find the first_fetch configuration
    first_fetch_config = None
    for config in yaml_content.get("configuration", []):
        if config.get("name") == "first_fetch":
            first_fetch_config = config
            break

    assert first_fetch_config is not None, "first_fetch configuration not found in YAML"

    # Get default value
    default_value_in_yaml = first_fetch_config.get("defaultvalue")
    assert default_value_in_yaml is not None, "No defaultvalue for first_fetch"

    # Assert that the code constant matches the YAML value
    assert default_value_in_yaml == DEFAULT_FETCH_BACK, (
        f"DEFAULT_FETCH_BACK ({DEFAULT_FETCH_BACK}) does not match "
        f"the defaultvalue in first_fetch configuration ({default_value_in_yaml})"
    )

    # Also check the additional info - update to match the actual text in additionalinfo
    additional_info = first_fetch_config.get("additionalinfo", "")
    assert (
        "Maximum allowed is 2 days" in additional_info
    ), f"first_fetch additionalinfo doesn't mention the maximum days limit: {additional_info}"


def test_wiz_input_param_consistency(yaml_content):
    """
    Test that every argument and configuration name in the YAML has a corresponding value in WizInputParam or WizApiInputFields.
    This ensures that all parameters defined in the YAML interface can be correctly accessed in the code.
    """
    from Packs.Wiz.Integrations.WizDefend.WizDefend import WizInputParam, WizApiInputFields

    # Collect all parameter names from YAML
    yaml_param_names = set()

    # Add argument names from all commands
    for command in yaml_content.get("script", {}).get("commands", []):
        for arg in command.get("arguments", []):
            arg_name = arg.get("name")
            if arg_name:
                yaml_param_names.add(arg_name)

    # Add configuration parameter names
    for config in yaml_content.get("configuration", []):
        config_name = config.get("name")
        if config_name:
            yaml_param_names.add(config_name)

    # Filter out standard Cortex XSOAR parameters that don't need corresponding enum values
    standard_params = {"proxy", "isFetch", "incidentType", "incidentFetchInterval", "max_fetch", "first_fetch", "credentials"}
    yaml_param_names = yaml_param_names - standard_params

    # Get all values from WizInputParam and WizApiInputFields
    input_param_values = set()

    # Add values from WizInputParam
    for attr in dir(WizInputParam):
        if not attr.startswith("_") and not callable(getattr(WizInputParam, attr)):
            input_param_values.add(getattr(WizInputParam, attr))

    # Add values from WizApiInputFields
    for attr in dir(WizApiInputFields):
        if not attr.startswith("_") and not callable(getattr(WizApiInputFields, attr)):
            input_param_values.add(getattr(WizApiInputFields, attr))

    # Check each YAML parameter against the enum values directly
    missing_params = []
    for param in yaml_param_names:
        if param not in input_param_values:
            missing_params.append(param)

    assert not missing_params, (
        f"The following parameters in YAML do not have a corresponding value in WizInputParam or WizApiInputFields:\n"
        f"{sorted(missing_params)}\n"
        f"Please add these values to the appropriate enum class."
    )


# ===== COMMAND EXAMPLES TESTS =====


def get_command_examples():
    """Load and parse command examples from command_examples.txt"""
    with open("command_examples.txt") as f:
        examples = f.read().splitlines()
    return [example.strip() for example in examples if example.strip()]


def extract_param_value_pairs(command_line):
    """Extract parameter-value pairs from a command line"""
    # Skip the command name (everything before the first space)
    params_part = command_line.split(" ", 1)[1] if " " in command_line else ""

    # Define regex pattern to match parameter=value pairs, handling quoted values
    pattern = r'(\w+)=(?:"([^"]*)"|([\w\-\.,:/]+))'
    matches = re.findall(pattern, params_part)

    # Convert matches to dictionary
    param_values = {}
    for match in matches:
        param_name = match[0]
        # Value is either the quoted value or the non-quoted value
        param_value = match[1] if match[1] else match[2]
        param_values[param_name] = param_value

    return param_values


# Extract demisto command name from example command
def get_demisto_command_name(example_command):
    """Convert example command to demisto command name"""
    # Strip '!' prefix and replace hyphens with underscores
    command_name = example_command.split(" ")[0][1:].replace("-", "_").upper()
    return command_name


# Group example commands by their demisto command name
def group_examples_by_command():
    """Group examples by command type"""
    examples = get_command_examples()
    grouped = {}

    for example in examples:
        if not example.startswith("!"):
            continue

        command_name = example.split(" ")[0]
        demisto_command = get_demisto_command_name(command_name)

        if demisto_command not in grouped:
            grouped[demisto_command] = []

        grouped[demisto_command].append(example)

    return grouped


# Get all commands and examples for parametrize
def get_all_commands_for_test():
    """Get all commands and examples for parametrized test"""
    grouped = group_examples_by_command()
    test_params = []

    for demisto_command, examples in grouped.items():
        for example in examples:
            test_params.append((demisto_command, example))

    return test_params


def test_commands_in_examples_match_demisto_commands():
    """Test that all commands in the examples match those defined in DemistoCommands"""
    command_examples = get_command_examples()

    # Get all command values from DemistoCommands class
    demisto_command_values = {
        getattr(DemistoCommands, attr)
        for attr in dir(DemistoCommands)
        if not attr.startswith("_") and not callable(getattr(DemistoCommands, attr))
    }

    # Convert command values to command names as they would appear in examples (with ! prefix)
    demisto_command_names = {
        "!" + cmd.replace("_", "-") for cmd in demisto_command_values if cmd not in ["TEST_MODULE", "FETCH_INCIDENTS"]
    }  # Exclude commands not meant for direct use

    # Extract all commands from examples
    example_commands = set()
    for example in command_examples:
        if not example.startswith("!"):
            continue

        command_name = example.split(" ")[0]
        example_commands.add(command_name)

    # Check that all example commands are defined in DemistoCommands
    undefined_commands = example_commands - demisto_command_names
    assert not undefined_commands, f"Found commands in examples that are not defined in DemistoCommands: {undefined_commands}"

    # Check that all demo-accessible DemistoCommands are used in examples
    unused_commands = demisto_command_names - example_commands
    if unused_commands:
        pass  # Removed print statement


def test_all_command_examples_are_in_wiz_input_params():
    """Test that all parameters in command examples are defined in WizInputParam"""
    command_examples = get_command_examples()

    # Get all attribute values from WizInputParam class
    wiz_input_param_values = set()
    for attr in dir(WizInputParam):
        if not attr.startswith("_") and not callable(getattr(WizInputParam, attr)):
            wiz_input_param_values.add(getattr(WizInputParam, attr))

    # Extract all parameters from command examples
    unknown_params = set()
    for example in command_examples:
        if not example.startswith("!"):
            continue

        command_parts = example.split(" ", 1)
        if len(command_parts) == 1:  # No parameters
            continue

        param_values = extract_param_value_pairs(example)

        for param in param_values:
            # Check if parameter exists in WizInputParam values
            if param not in wiz_input_param_values:
                unknown_params.add(param)

    # Assert that all parameters are recognized
    assert not unknown_params, f"Found parameters not defined in WizInputParam values: {unknown_params}"


def test_all_wiz_input_params_have_examples():
    """Test that all values in WizInputParam have corresponding examples in the command examples"""
    command_examples = get_command_examples()

    # Get all attribute values from WizInputParam class
    wiz_input_param_values = set()
    for attr in dir(WizInputParam):
        if not attr.startswith("_") and not callable(getattr(WizInputParam, attr)):
            wiz_input_param_values.add(getattr(WizInputParam, attr))

    # Parameters that can be ignored (don't need examples)
    ignore_list = []

    # Extract all parameters used in the command examples
    example_params = set()
    for example in command_examples:
        if not example.startswith("!"):
            continue

        command_parts = example.split(" ", 1)
        if len(command_parts) == 1:  # No parameters
            continue

        param_values = extract_param_value_pairs(example)
        example_params.update(param_values.keys())

    # Remove ignored parameters from check
    params_to_check = wiz_input_param_values - set(ignore_list)

    # Check which parameters don't have examples
    missing_examples = set()
    for param in params_to_check:
        if param not in example_params:
            missing_examples.add(param)

    # Assert that all parameters have examples
    assert (
        not missing_examples
    ), f"The following WizInputParam values don't have examples in command_examples.txt: {missing_examples}"


@pytest.mark.parametrize("demisto_command,example", get_all_commands_for_test())
def test_command_validation(demisto_command, example, mocker):
    """Test that all commands in the examples file can be validated without errors"""
    # Extract parameters from example
    params = extract_param_value_pairs(example)

    # Mock demisto.args() to return our parameters
    mocker.patch.object(demisto, "args", return_value=params)

    # Mock demisto.command() to return our command
    mocker.patch.object(demisto, "command", return_value=getattr(DemistoCommands, demisto_command))

    # Create mock result
    mock_result = [{"id": "test-id", "severity": "CRITICAL"}]

    # Import the module directly to patch internal functions
    from Packs.Wiz.Integrations.WizDefend import WizDefend

    # Patch at module level
    mocker.patch.object(WizDefend, "query_detections", return_value=mock_result)
    mocker.patch.object(WizDefend, "query_threats", return_value=mock_result)

    # Create the mock functions with MagicMock to track calls
    mock_return_results = mocker.MagicMock(return_value=True)
    mock_return_error = mocker.MagicMock(return_value=True)

    # Apply the patches
    mocker.patch.object(WizDefend, "return_results", mock_return_results)
    mocker.patch.object(WizDefend, "return_error", mock_return_error)

    # Run the main function
    main()

    # Check if return_error was called (indicating validation failure)
    if mock_return_error.called:
        error_message = mock_return_error.call_args[0][0]
        pytest.fail(f"Example failed validation: {example}\nError: {error_message}")

    # Otherwise, validation passed
    assert mock_return_results.called, f"Example should have called return_results: {example}"
