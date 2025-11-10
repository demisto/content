"""Test File for GoogleSecOps Integration."""

import json
from unittest import mock

import demistomock as demisto
import pytest
from GoogleSecOps import (
    MESSAGES,
    VALID_CONTENT_TYPE,
    VALID_DETECTIONS_ALERT_STATE,
    VALID_DETECTIONS_LIST_BASIS,
)

PROXY_MOCK = {"proxy": "0.0.0.0"}

PARAMS = {
    "malicious_categories": "APT-Activity",
    "suspicious_categories": "Observed serving executables",
    "override_severity_malicious": ["high"],
    "override_severity_suspicious": ["medium"],
    "override_confidence_score_malicious_threshold": "80",
    "override_confidence_score_suspicious_threshold": "40",
    "integrationReliability": "B - Usually reliable",
}

DUMMY_DICT = '{"key":"value"}'
DUMMY_RULE_TEXT = "meta events condition"
RETURN_ERROR_MOCK_PATH = "GoogleSecOps.return_error"
COMMON_RESP = {
    "PERM_DENIED_RESP": '{ "error": { "code": 403, "message": "Permission denied" \
                     , "status": "PERMISSION_DENIED", "details": [ {  } ] } } ',
    "PERM_DENIED_MSG": "Status code: 403\nError: Permission denied",
    "INVALID_PAGE_SIZE": "Page size must be a non-zero and positive numeric value",
    "ERROR_RESPONSE": '{"error": {}}',
}

DUMMY_RULE_TEXT = "meta events condition"


@pytest.fixture
def client():
    """Fixture for the http client."""
    mocked_client = mock.Mock()
    mocked_client.project_location = "us"
    mocked_client.project_instance_id = "dummy_instance_id"
    return mocked_client


def return_error(error):
    """Mock for CommonServerPython's return_error."""
    raise ValueError(error)


def test_function_success(client):
    """When success response come then test_function command should pass."""
    from GoogleSecOps import test_function

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return json.loads("{}")

    client.http_client.request.return_value = MockResponse

    with mock.patch("GoogleSecOps.demisto.results") as mock_demisto_result:
        test_function(client, PROXY_MOCK)
    mock_demisto_result.assert_called_with("ok")


def test_function_failure_status_code_400(client, mocker):
    """When unsuccessful response come then test_function command should raise ValueError with appropriate message."""
    from GoogleSecOps import test_function

    dummy_response = (
        '{"error": { "code": 400, "message": "Request contains an invalid argument.", "status": "INVALID_ARGUMENT" } }'
    )

    class MockResponse:
        status_code = 400
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        test_function(client, PROXY_MOCK)
    assert str(error.value) == "Status code: 400\nError: Request contains an invalid argument."


def test_function_failure_status_code_403(client, mocker):
    """When entered JSON is correct but client has not given any access, should return permission denied."""
    from GoogleSecOps import test_function

    dummy_response = '{"error": { "code": 403, "message": "Permission denied" } }'

    class MockResponse:
        status_code = 403
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)
    with pytest.raises(ValueError) as error:
        test_function(client, PROXY_MOCK)
    assert str(error.value) == COMMON_RESP["PERM_DENIED_MSG"]


def test_validate_parameter_success(mocker):
    """When valid input is added on Integration Configuration then it should pass."""
    mocker.patch.object(demisto, "params", return_value=PARAMS)
    from GoogleSecOps import validate_configuration_parameters

    param = {
        "credentials": {"password": DUMMY_DICT},
        "max_fetch": "20",
        "region": "us",
        "secops_project_instance_id": "dummy_instance_id",
    }
    validate_configuration_parameters(param)


def test_validate_parameter_failure_wrong_json():
    """When wrong JSON format of User Service account JSON input is added it should return validation error."""
    from GoogleSecOps import validate_configuration_parameters

    wrong_credentials = {"credentials": {"password": '{"key","value"}'}, "secops_project_instance_id": "dummy_instance_id"}

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(wrong_credentials)
    assert str(error.value) == "User's Service Account JSON has invalid format"


@pytest.mark.parametrize(
    "params, error_message",
    [
        ({}, "Please Provide the Google SecOps Project Instance ID."),
        ({"secops_project_instance_id": "dummy", "region": "other"}, "Please Provide the valid region."),
        (
            {"secops_project_instance_id": "dummy", "credentials": {"password": "invalid-json"}},
            "User's Service Account JSON has invalid format",
        ),
        (
            {"secops_project_instance_id": "dummy", "credentials": {"password": "{}"}, "max_fetch": 0},
            "Incidents fetch limit should be in the range from 1 to 10000.",
        ),
        (
            {"secops_project_instance_id": "dummy", "credentials": {"password": "{}"}, "max_fetch": 10001},
            "Incidents fetch limit should be in the range from 1 to 10000.",
        ),
        (
            {
                "secops_project_instance_id": "dummy",
                "credentials": {"password": "{}"},
                "override_confidence_score_malicious_threshold": "abc",
            },
            "Confidence Score Threshold must be a number",
        ),
        (
            {
                "secops_project_instance_id": "dummy",
                "credentials": {"password": "{}"},
                "override_confidence_score_suspicious_threshold": "xyz",
            },
            "Confidence Score Threshold must be a number",
        ),
        (
            {"secops_project_instance_id": "dummy", "credentials": {"password": "{}"}, "max_fetch": "abc"},
            'Invalid number: "Incidents fetch limit"="abc"',
        ),
        (
            {"secops_project_instance_id": "dummy", "credentials": {"password": "{}"}, "first_fetch": "invalid date"},
            'Invalid date: "First fetch time"="invalid date"',
        ),
    ],
)
def test_validate_configuration_parameters_invalid_params(params, error_message):
    """Test validate_configuration_parameters with invalid parameters."""
    from GoogleSecOps import validate_configuration_parameters

    with pytest.raises(ValueError) as error:
        validate_configuration_parameters(params)
    assert str(error.value) == error_message


def test_main_success(mocker, client):
    """When command execute successfully then main should pass."""
    import GoogleSecOps

    param = {
        "credentials": {"password": DUMMY_DICT},
        "configured_malicious_categories": "Spyware Reporting Server, Target of a DDoS, Known Spam Source",
        "secops_project_instance_id": "dummy_project_instance_id",
    }

    dummy_response = "{}"

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    mocker.patch.object(demisto, "params", return_value=param)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(GoogleSecOps, "test_function", return_value=("", {}, {}))
    mocker.patch("GoogleSecOps.Client", return_value=client)
    GoogleSecOps.main()
    assert GoogleSecOps.test_function.called


def test_fetch_incidents_when_no_events_are_returned_and_end_time_not_current_time(client, mocker):
    """Test fetch_incidents updates last_run when no events and end_time != current_time."""
    from GoogleSecOps import datetime, fetch_incidents

    with open("test_data/fetch_incidents_empty_response.json") as f:
        responses = json.loads(f.read())

    params = {"first_fetch": "2025-07-20T00:00:00Z", "max_fetch": 2}
    # Simulate last_run with a previous start_time and end_time
    last_run = {"ioc_domain_matches": {"start_time": "2025-07-20T00:00:00Z", "end_time": "2025-07-22T00:00:00Z", "index": 2}}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    # Patch datetime.now() to a value different from end_time
    class FakeDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2025, 7, 23, 0, 0, 0)

    mocker.patch("GoogleSecOps.datetime", FakeDatetime)

    # Both API calls return no events
    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    client.http_client.request.return_value = MockResponse(responses["api_call"])

    incidents, updated_last_run = fetch_incidents(client, params)
    # Should update start_time to end_time and index to 1
    ioc_last_run = updated_last_run["ioc_domain_matches"]
    assert incidents == []
    assert ioc_last_run["start_time"] == "2025-07-22T00:00:00Z"
    assert ioc_last_run["index"] == 1
    assert "end_time" not in ioc_last_run


def test_fetch_incidents_when_no_events_are_returned_and_end_time_is_current_time(client, mocker):
    """Test fetch_incidents does NOT update last_run when no events and end_time == current_time."""
    from GoogleSecOps import datetime, fetch_incidents

    with open("test_data/fetch_incidents_empty_response.json") as f:
        responses = json.loads(f.read())

    params = {"first_fetch": "2025-07-20T00:00:00Z", "max_fetch": 2}
    last_run = {"ioc_domain_matches": {"start_time": "2025-07-20T00:00:00Z", "end_time": "2025-07-22T00:00:00Z", "index": 2}}
    # Simulate last_run with a previous start_time and end_time
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    # Patch datetime.now() to exactly match end_time
    class FakeDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2025, 7, 22, 0, 0, 0)

    mocker.patch("GoogleSecOps.datetime", FakeDatetime)

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    client.http_client.request.return_value = MockResponse(responses["api_call"])

    incidents, updated_last_run = fetch_incidents(client, params)
    # Should NOT update last_run, it should be same as input last_run
    assert incidents == []
    assert updated_last_run == last_run


def test_fetch_incidents_when_events_are_returned(client, mocker):
    """Test fetch_incidents returns incidents and updates last_run when events are returned."""
    from GoogleSecOps import fetch_incidents

    with open("test_data/fetch_incidents_response.json") as f:
        responses = json.loads(f.read())
    with open("test_data/incidents_ioc_domain.json") as f:
        expected_incidents = json.loads(f.read())
    params = {"first_fetch": "3 days", "max_fetch": 2, "time_window": 60}
    mocker.patch.object(demisto, "getLastRun", return_value={})

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    client.http_client.request.side_effect = [
        MockResponse(responses["adjusting_time_interval"]),  # First call - For setting the start and end time
        MockResponse(responses["api_call"]),  # Second call - Actual api call with updated start and end time
    ]

    incidents, last_run = fetch_incidents(client, params)

    assert incidents == expected_incidents
    assert last_run["ioc_domain_matches"]["previous_artifact_values"] == ["0.0.0.0 - 3rd Party", "0.0.0.1 - 3rd Party"]
    assert last_run["ioc_domain_matches"]["index"] == 2


def test_fetch_incidents_when_duplicates_are_present(client, mocker):
    """Test fetch_incidents skips duplicate artifacts and only returns new incidents."""
    from GoogleSecOps import fetch_incidents

    with open("test_data/fetch_incidents_response.json") as f:
        responses = json.loads(f.read())
    with open("test_data/incidents_ioc_domain.json") as f:
        expected_incidents = json.loads(f.read())

    params = {"first_fetch": "3 days", "max_fetch": 2}
    last_run = {"ioc_domain_matches": {"previous_artifact_values": ["0.0.0.1 - 3rd Party"], "index": 2}}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    client.http_client.request.return_value = MockResponse(responses["api_call"])

    incidents, updated_last_run = fetch_incidents(client, params)
    assert incidents == [expected_incidents[0]]
    assert updated_last_run["ioc_domain_matches"]["previous_artifact_values"] == ["0.0.0.1 - 3rd Party", "0.0.0.0 - 3rd Party"]
    assert updated_last_run["ioc_domain_matches"]["index"] == 3


def test_fetch_incidents_when_max_page_size_is_reached(client, mocker):
    """Test fetch_incidents does not increment index if max page size is reached."""
    from GoogleSecOps import fetch_incidents

    with open("test_data/fetch_incidents_response.json") as f:
        responses = json.loads(f.read())
    with open("test_data/incidents_ioc_domain.json") as f:
        expected_incidents = json.loads(f.read())

    params = {"first_fetch": "3 days", "max_fetch": 1, "time_window": 60}
    last_run = {"ioc_domain_matches": {"previous_artifact_values": ["4.3.2.1 - 3rd Party"], "index": 2}}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    client.http_client.request.return_value = MockResponse(responses["api_call"])

    incidents, updated_last_run = fetch_incidents(client, params)

    assert incidents == [expected_incidents[0]]
    assert updated_last_run["ioc_domain_matches"]["previous_artifact_values"] == ["4.3.2.1 - 3rd Party", "0.0.0.0 - 3rd Party"]
    assert updated_last_run["ioc_domain_matches"]["index"] == 2


def test_fetch_incidents_when_new_incidents_not_available(client, mocker):
    """Test fetch_incidents reset the start time when moreDataAvailable is false and not incidents."""
    from GoogleSecOps import fetch_incidents

    with open("test_data/fetch_incidents_response.json") as f:
        responses = json.loads(f.read())

    params = {"first_fetch": "3 days", "max_fetch": 2, "time_window": 60}
    last_run = {"ioc_domain_matches": {"previous_artifact_values": ["0.0.0.0 - 3rd Party", "0.0.0.1 - 3rd Party"], "index": 2}}
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    client.http_client.request.return_value = MockResponse(responses["api_call"])

    incidents, updated_last_run = fetch_incidents(client, params)

    assert incidents == []
    assert updated_last_run["ioc_domain_matches"]["previous_artifact_values"] == ["0.0.0.0 - 3rd Party", "0.0.0.1 - 3rd Party"]
    assert updated_last_run["ioc_domain_matches"]["index"] == 1
    assert "end_time" not in updated_last_run["ioc_domain_matches"]


def test_fetch_incidents_exits_when_time_diff_exceeds_4_minutes(client, mocker):
    """
    Test that fetch_incidents exits the while loop early if the difference between now and current_time is more than 4 minutes.
    """
    from GoogleSecOps import datetime, fetch_incidents, timedelta

    with open("test_data/fetch_incidents_response.json") as f:
        responses = json.loads(f.read())

    params = {"first_fetch": "2025-07-20T00:00:00Z", "max_fetch": 2}
    mocker.patch.object(demisto, "getLastRun", return_value={})

    # Patch datetime.now()
    mock_now = mocker.patch("GoogleSecOps.datetime")

    t1 = datetime(2024, 1, 1, 10, 0, 0)
    t2 = t1 + timedelta(minutes=10)  # > 4 minutes

    mock_now.now.side_effect = [t1, t2]

    mocker.patch("GoogleSecOps.get_informal_time", return_value="10 minutes ago")

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            data = json.loads(self.text)
            data.update({"moreDataAvailable": True})
            return data

    client.http_client.request.side_effect = [
        MockResponse(responses["adjusting_time_interval"]),  # First call - For setting the start and end time
        MockResponse(responses["api_call"]),  # Second call - Actual api call with updated start and end time
    ]

    incidents, updated_last_run = fetch_incidents(client, params)
    assert len(incidents) == 2
    assert updated_last_run["ioc_domain_matches"]["index"] == 1


def test_list_rules_command(client):
    """When valid response comes in gcb-list-rules command it should respond with result."""
    from GoogleSecOps import gcb_list_rules_command

    args = {"page_size": "2", "page_token": "foobar_page_token"}

    with open("test_data/list_rules_response.json") as f:
        dummy_response = f.read()

    with open("test_data/list_rules_ec.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/list_rules_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_rules_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr

    # Test command when no rules found
    class MockResponseEmpty:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, _ = gcb_list_rules_command(client, args)
    assert ec == {}
    assert hr == "### No Rules Found"


def test_gcb_create_rule_command_with_valid_response(client):
    """Test gcb_create_rule command when valid response is returned."""
    from GoogleSecOps import gcb_create_rule_command

    with open("test_data/create_rule_response.json") as f:
        response = f.read()

    with open("test_data/create_rule_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/create_rule_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    args = {
        "rule_text": """rule demoRuleCreatedFromAPI {
        meta:
        author = \"testuser\"
        description = \"single event rule that should generate detections\"

        events:
        $e.metadata.event_type = \"NETWORK_DNS\"

        condition:
        $e
    }"""
    }

    hr, ec, _ = gcb_create_rule_command(client, args=args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_create_rule_command_with_invalid_arguments(client):
    """Test gcb_create_rule command when invalid argument provided."""
    from GoogleSecOps import gcb_create_rule_command

    args = {
        "rule_text": """rule demoRuleCreatedFromAPI {
            meta:
            author = \"testuser\"
            description = \"single event rule that should generate detections\"

            condition:
            $e
        }"""
    }

    with pytest.raises(ValueError) as err:
        gcb_create_rule_command(client, args)

    assert str(err.value) == MESSAGES["INVALID_RULE_TEXT"]


def test_gcb_create_rule_command_when_400_error_code_returned(client):
    """Test gcb_create_rule command when 400 error code is returned."""
    from GoogleSecOps import gcb_create_rule_command

    args = {"rule_text": DUMMY_RULE_TEXT}

    with open("test_data/create_rule_400_response.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as err:
        gcb_create_rule_command(client, args)

    assert (
        str(err.value) == "Status code: 400\nError: compiling rule: parsing: error with "
        'token: "="\nexpected identifier for meta assignment key\nline: 1 \ncolumn: 32-33 '
    )


def test_get_rules():
    """Internal method used in gcb-list-rules command."""
    from GoogleSecOps import gcb_list_rules

    with pytest.raises(ValueError) as e:
        gcb_list_rules(client, args={"page_size": "dummy"})

    assert str(e.value) == COMMON_RESP["INVALID_PAGE_SIZE"]

    with pytest.raises(ValueError) as e:
        gcb_list_rules(client, args={"page_size": "100000"})

    assert str(e.value) == "Page size should be in the range from 1 to 1000."

    with pytest.raises(ValueError) as e:
        gcb_list_rules(client, args={"page_size": "-5"})

    assert str(e.value) == COMMON_RESP["INVALID_PAGE_SIZE"]

    with pytest.raises(ValueError) as e:
        gcb_list_rules(client, args={"page_size": "0"})

    assert str(e.value) == COMMON_RESP["INVALID_PAGE_SIZE"]


def test_gcb_get_rule_command_when_empty_args_given(client):
    """Test gcb_get_rule_command when Rule ID is a string with space."""
    from GoogleSecOps import gcb_get_rule_command

    with pytest.raises(ValueError) as e:
        gcb_get_rule_command(client, args={"id": ""})
    assert str(e.value) == "Missing argument id."


def test_gcb_get_rule_output_when_valid_args_provided(client):
    """Test gcb_get_rule_command when valid args are provided and gives valid output."""
    from GoogleSecOps import gcb_get_rule_command

    args = {"id": "dummy_rule_id"}

    with open("test_data/gcb_get_rule_response.json") as f:
        dummy_response = f.read()

    with open("test_data/gcb_get_rule_ec.json") as f:
        dummy_ec = json.loads(f.read())

    with open("test_data/gcb_get_rule_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_get_rule_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr


def test_gcb_get_rule_command_when_rule_id_provided_does_not_exist(client):
    """Test gcb_get_rule_command when rule id provided does not exist."""
    from GoogleSecOps import gcb_get_rule_command

    with open("test_data/gcb_get_rule_invalid_id_400.json") as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_get_rule_command(client, args={"id": "1234"})
    assert str(e.value) == "Status code: 400\nError: invalid rule_id"


def test_gcb_delete_rule_command_with_valid_response(client):
    """Test gcb_delete_rule command when valid response is returned."""
    from GoogleSecOps import gcb_delete_rule_command

    with open("test_data/delete_rule_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/delete_rule_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    args = {"rule_id": "test_rule_id"}
    hr, ec, _ = gcb_delete_rule_command(client, args=args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_delete_rule_command_when_empty_rule_id_provided(client):
    """Test gcb_delete_rule command when empty rule id provided."""
    from GoogleSecOps import gcb_delete_rule_command

    args = {"rule_id": ""}

    with pytest.raises(ValueError) as err:
        gcb_delete_rule_command(client, args)

    assert str(err.value) == MESSAGES["REQUIRED_ARGUMENT"].format("rule_id")


def test_gcb_delete_rule_command_when_400_error_code_returned(client):
    """Test gcb_delete_rule command when 400 error code is returned."""
    from GoogleSecOps import gcb_delete_rule_command

    args = {"rule_id": "1234"}

    with open("test_data/delete_rule_400_response.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as err:
        gcb_delete_rule_command(client, args)

    assert str(err.value) == "Status code: 400\nError: rule with ID 1234 could not be found"


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"rule_id": "dummy", "rule_text": ""}, "Missing argument rule_text."),
        ({"rule_id": "", "rule_text": "dummy"}, "Missing argument rule_id."),
    ],
)
def test_gcb_create_rule_version_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_create_rule_version_command when empty arguments provided."""
    from GoogleSecOps import gcb_create_rule_version_command

    with pytest.raises(ValueError) as e:
        gcb_create_rule_version_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_create_rule_version_command_when_invalid_rule_text_provided(client):
    """Test gcb_create_rule_version_command when rule text provided is not valid."""
    from GoogleSecOps import gcb_create_rule_version_command

    args = {"rule_id": "dummy", "rule_text": "1234"}
    with pytest.raises(ValueError) as e:
        gcb_create_rule_version_command(client, args)
    assert str(e.value) == 'Invalid rule text provided. Section "meta", "events" or "condition" is missing.'


def test_gcb_create_rule_version_command_when_provided_rule_id_is_not_valid(client):
    """Test gcb_create_rule_version_command when rule id provided does not exist."""
    from GoogleSecOps import gcb_create_rule_version_command

    with open("test_data/gcb_create_rule_version_command_invalid_id_400.json") as f:
        raw_response = f.read()
    args = {"rule_id": "dummy", "rule_text": DUMMY_RULE_TEXT}

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_create_rule_version_command(client, args)
    assert str(e.value) == "Status code: 400\nError: invalid rule_id"


def test_gcb_create_rule_version_command_when_valid_args_provided(client):
    """Test gcb_create_rule_version_command for correct output when valid arguments are given."""
    from GoogleSecOps import gcb_create_rule_version_command

    with open("test_data/gcb_create_rule_version_command_response.json") as f:
        expected_response = f.read()
    with open("test_data/gcb_create_rule_version_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_create_rule_version_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = expected_response

        def json():
            return json.loads(expected_response)

    client.http_client.request.return_value = MockResponse
    args = {"rule_id": "dummy rule", "rule_text": DUMMY_RULE_TEXT}
    hr, ec, _ = gcb_create_rule_version_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"rule_id": "dummy", "alerting_status": ""}, "Missing argument alerting_status."),
        ({"rule_id": "", "alerting_status": "dummy"}, "Missing argument rule_id."),
    ],
)
def test_gcb_change_rule_alerting_status_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_change_rule_alerting_status_command when empty arguments are provided."""
    from GoogleSecOps import gcb_change_rule_alerting_status_command

    with pytest.raises(ValueError) as e:
        gcb_change_rule_alerting_status_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_change_rule_alerting_status_command_when_invalid_alerting_status_provided(client):
    """Test gcb_change_rule_alerting_status_command when invalid argument value for alerting_status is provided."""
    from GoogleSecOps import gcb_change_rule_alerting_status_command

    args = {"rule_id": "dummy", "alerting_status": "status"}
    with pytest.raises(ValueError) as e:
        gcb_change_rule_alerting_status_command(client, args)
    assert str(e.value) == "alerting_status can have one of these values only enable, disable."


def test_gcb_change_rule_alerting_status_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_change_rule_alerting_status_command when rule id provided does not exist."""
    from GoogleSecOps import gcb_change_rule_alerting_status_command

    with open("test_data/gcb_change_rule_alerting_status_command_invalid_id_404.json") as f:
        raw_response = f.read()
    args = {"rule_id": "dummy", "alerting_status": "enable"}

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_change_rule_alerting_status_command(client, args)
    assert str(e.value) == "Status code: 400\nError: rule with ID dummy could not be found"


def test_gcb_change_rule_alerting_status_command_when_valid_args_provided(client):
    """Test gcb_change_rule_alerting_status_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_change_rule_alerting_status_command

    with open("test_data/gcb_change_rule_alerting_status_response.json") as f:
        raw_resp = json.loads(f.read())

    with open("test_data/gcb_change_rule_alerting_status_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/gcb_change_rule_alerting_status_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = raw_resp

        def json():
            return {}

    args = {"rule_id": "dummy_rule_id", "alerting_status": "enable"}
    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_change_rule_alerting_status_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


arg_error = [
    ({"page_size": "-20"}, COMMON_RESP["INVALID_PAGE_SIZE"]),
    ({"page_size": "20000"}, "Page size should be in the range from 1 to 1000."),
    ({"retrohunts_for_all_versions": "dummy"}, "Argument does not contain a valid boolean-like value"),
    ({"retrohunts_for_all_versions": "True", "id": "abc@xyz"}, "Invalid value in argument 'id'. Expected rule_id."),
]


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"rule_id": "dummy", "live_rule_status": ""}, "Missing argument live_rule_status."),
        ({"rule_id": "", "live_rule_status": "dummy"}, "Missing argument rule_id."),
    ],
)
def test_gcb_change_live_rule_status_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_change_live_rule_status_command when empty arguments are provided."""
    from GoogleSecOps import gcb_change_live_rule_status_command

    with pytest.raises(ValueError) as e:
        gcb_change_live_rule_status_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_change_live_rule_status_command_when_invalid_live_rule_status_provided(client):
    """Test gcb_change_live_rule_status_command when invalid argument value for live_rule_status is provided."""
    from GoogleSecOps import gcb_change_live_rule_status_command

    args = {"rule_id": "dummy", "live_rule_status": "status"}
    with pytest.raises(ValueError) as e:
        gcb_change_live_rule_status_command(client, args)
    assert str(e.value) == "live_rule_status can have one of these values only enable, disable."


def test_gcb_change_live_rule_status_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_change_live_rule_status_command when rule id provided does not exist."""
    from GoogleSecOps import gcb_change_live_rule_status_command

    with open("test_data/gcb_change_live_rule_status_command_invalid_id_400.json") as f:
        raw_response = f.read()
    args = {"rule_id": "dummy", "live_rule_status": "enable"}

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_change_live_rule_status_command(client, args)

    assert str(e.value) == "Status code: 400\nError: invalid rule_id"


def test_gcb_change_live_rule_status_command_when_valid_args_provided(client):
    """Test gcb_change_live_rule_status_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_change_live_rule_status_command

    with open("test_data/gcb_change_live_rule_status_command_response.json") as f:
        raw_response = json.loads(f.read())

    with open("test_data/gcb_change_live_rule_status_command_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/gcb_change_live_rule_status_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = raw_response

        def json():
            return {}

    args = {"rule_id": "ru_abcd", "live_rule_status": "enable"}
    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_change_live_rule_status_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_verify_rule_command_with_valid_response(client):
    """Test gcb_verify_rule command when valid response is returned."""
    from GoogleSecOps import gcb_verify_rule_command

    with open("test_data/gcb_verify_rule_response.json") as f:
        response = f.read()

    with open("test_data/gcb_verify_rule_ec.json") as f:
        expected_ec = json.loads(f.read())

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    args = {
        "rule_text": """rule singleEventRule2 {
        meta:
        author = \"testuser\"
        description = \"single event rule that should generate detections\"

        events:
        $e.metadata.event_type = \"NETWORK_DNS\"

        condition:
        $e
    }"""
    }

    hr, ec, json_data = gcb_verify_rule_command(client, args=args)

    assert json.loads(response) == json_data
    assert ec == expected_ec
    assert hr == "### Identified no known errors"


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {
                "rule_text": """rule demoRuleCreatedFromAPI { meta: author = \"testuser\" description = \"single
      event rule that should generate detections\" condition:$e }"""
            },
            MESSAGES["INVALID_RULE_TEXT"],
        ),
        ({"rule_text": ""}, MESSAGES["REQUIRED_ARGUMENT"].format("rule_text")),
    ],
)
def test_gcb_verify_rule_command_with_invalid_arguments(client, args, error_msg, capfd):
    """Test gcb_verify_rule command when invalid argument provided."""
    from GoogleSecOps import gcb_verify_rule_command

    with pytest.raises(ValueError) as err, capfd.disabled():
        gcb_verify_rule_command(client, args)

    assert str(err.value) == error_msg


def test_gcb_verify_rule_command_when_rule_text_invalid_yaral_format(client):
    """Test gcb_create_rule command when rule text has invalid YARA-L format."""
    from GoogleSecOps import gcb_verify_rule_command

    args = {"rule_text": DUMMY_RULE_TEXT}

    with open("test_data/gcb_verify_rule_invalid_format_response.json") as f:
        response = f.read()

    with open("test_data/gcb_verify_rule_invalid_format_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/gcb_verify_rule_invalid_format_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_verify_rule_command(client, args=args)

    assert json.loads(response) == json_data
    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize("args,error_msg", arg_error)
def test_gcb_list_retrohunts_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_list_retrohunts_command when invalid arguments are provided."""
    from GoogleSecOps import gcb_list_retrohunts_command

    with pytest.raises(ValueError) as e:
        gcb_list_retrohunts_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_list_retrohunts_command_when_empty_response_is_obtained(client):
    """Test gcb_list_retrohunts_command when empty response is obtained for a rule."""
    from GoogleSecOps import gcb_list_retrohunts_command

    args = {"id": "dummy_rule_id@dummy_revision_id"}

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_retrohunts_command(client, args)
    assert hr == "## RetroHunt Details\nNo Records Found."
    assert ec == {}


def test_gcb_list_retrohunts_command_when_retrohunts_for_all_versions_is_set_true(client):
    """Test gcb_list_retrohunts_command when retrohunts_for_all_versions is true and rule_id is provided."""
    from GoogleSecOps import gcb_list_retrohunts_command

    with open("test_data/gcb_list_retrohunts_all_versions_true.json") as f:
        response_false = f.read()
    with open("test_data/gcb_list_retrohunts_all_versions_true_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_list_retrohunts_all_versions_true_hr.md") as f:
        expected_hr = f.read()
    args = {"id": "dummy", "retrohunts_for_all_versions": "true"}

    class MockResponse:
        status_code = 200
        text = response_false

        def json():
            return json.loads(response_false)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_retrohunts_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test__gcb_list_retrohunts_command_when_retrohunts_for_all_versions_is_set_false(client):
    """Test gcb_list_retrohunts_command when retrohunts_for_all_versions is false and version_id is provided."""
    from GoogleSecOps import gcb_list_retrohunts_command

    with open("test_data/gcb_list_retrohunts_all_versions_false.json") as f:
        response_false = f.read()
    with open("test_data/gcb_list_retrohunts_all_versions_false_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_list_retrohunts_all_versions_false_hr.md") as f:
        expected_hr = f.read()
    args = {"id": "dummy_rule_id@dummy_revision_id", "retrohunts_for_all_versions": "false"}

    class MockResponse:
        status_code = 200
        text = response_false

        def json():
            return json.loads(response_false)

    client.http_client.request.return_value = MockResponse

    hr, ec, json_data = gcb_list_retrohunts_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec
    assert json_data == json.loads(response_false)


def test_gcb_list_retrohunts_command_when_no_arg_supplied_success(client):
    """Test gcb_list_retrohunts_command when no argumnets are provided."""
    from GoogleSecOps import gcb_list_retrohunts_command

    with open("test_data/gcb_list_retrohunts_no_arg.json") as f:
        response = f.read()
    with open("test_data/gcb_list_retrohunts_no_arg_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_list_retrohunts_no_arg_hr.md") as f:
        expected_hr = f.read()
    args = {}

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_list_retrohunts_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_list_retrohunts_command_when_provided_rule_id_is_not_valid(client):
    """Test gcb_list_retrohunts_command when rule id provided is not valid."""
    from GoogleSecOps import gcb_list_retrohunts_command

    with open("test_data/gcb_list_retrohunts_command_invalid_id_400.json") as f:
        raw_response = f.read()
    args = {
        "rule_id": "dummy",
    }

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_list_retrohunts_command(client, args)
    assert str(e.value) == "Status code: 400\nError: invalid rule_id"


def test_gcb_list_retrohunts_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_list_retrohunts_command when rule id provided does not exist."""
    from GoogleSecOps import gcb_list_retrohunts_command

    with open("test_data/gcb_list_retrohunts_command_id_does_not_exist_404.json") as f:
        raw_response = f.read()
    args = {
        "rule_id": "ru_dummy_rule_id",
    }

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_list_retrohunts_command(client, args)
    assert str(e.value) == "Status code: 404\nError: rule with ID ru_dummy_rule_id could not be found"


@pytest.mark.parametrize(
    "args, err_msg",
    [({"id": ""}, "Missing argument id."), ({"id": "test", "retrohunt_id": ""}, "Missing argument retrohunt_id.")],
)
def test_gcb_get_retrohunt_command_when_empty_args_provided(client, args, err_msg):
    """Test gcb_get_retrohunt command when empty args provided."""
    from GoogleSecOps import gcb_get_retrohunt_command

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args=args)

    assert str(e.value) == err_msg


def test_gcb_get_retrohunt_command_when_valid_args_provided(client):
    """Test gcb_get_retrohunt_command when valid args are provided and gives valid output."""
    from GoogleSecOps import gcb_get_retrohunt_command

    args = {"id": "dummy_rule_or_version_id", "retrohunt_id": "dummy_retrohunt_id"}

    with open("test_data/gcb_get_retrohunt_command_response.json") as f:
        dummy_response = f.read()

    with open("test_data/gcb_get_retrohunt_command_ec.json") as f:
        dummy_ec = json.loads(f.read())

    with open("test_data/gcb_get_retrohunt_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_get_retrohunt_command(client, args)

    assert ec == dummy_ec
    assert hr == dummy_hr


def test_gcb_get_retrohunt_command_when_rule_id_provided_is_invalid(client):
    """Test gcb_get_retrohunt_command when rule id provided is invalid."""
    from GoogleSecOps import gcb_get_retrohunt_command

    with open("test_data/gcb_get_retrohunt_command_invalid_id_400.json") as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args={"id": "dummy_rule_or_version_id", "retrohunt_id": "dummy_retrohunt_id"})
    assert str(e.value) == "Status code: 400\nError: invalid name"


def test_gcb_get_retrohunt_command_when_retrohunt_id_provided_is_invalid(client):
    """Test gcb_get_retrohunt_command when retrohunt id provided is invalid."""
    from GoogleSecOps import gcb_get_retrohunt_command

    with open("test_data/gcb_get_retrohunt_command_invalid_retrohunt_id_400.json") as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args={"id": "dummy_rule_or_version_id", "retrohunt_id": "dummy_retrohunt_id"})
    assert (
        str(e.value)
        == "Status code: 400\nError: generic::invalid_argument: provided retrohunt ID dummy_retrohunt_id is not valid"
    )


def test_gcb_get_retrohunt_command_when_retrohunt_id_provided_does_not_exists(client):
    """Test gcb_get_retrohunt_command when retrohunt id provided does not exists."""
    from GoogleSecOps import gcb_get_retrohunt_command

    with open("test_data/gcb_get_retrohunt_command_invalid_retrohunt_id_404.json") as f:
        raw_response = f.read()

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    with pytest.raises(ValueError) as e:
        gcb_get_retrohunt_command(client, args={"id": "dummy_rule_or_version_id", "retrohunt_id": "dummy_retrohunt_id"})
    assert str(e.value) == "Status code: 404\nError: retrohunt not found with ID dummy_retrohunt_id"


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {"rule_id": "dummy_rule_or_version_id", "start_time": "dummy", "end_time": "today"},
            'Invalid date: "start_time"="dummy"',
        ),
        (
            {"rule_id": "dummy_rule_or_version_id", "start_time": "1 day", "end_time": "dummy"},
            'Invalid date: "end_time"="dummy"',
        ),
        ({"rule_id": "", "start_time": "1 day", "end_time": "today"}, "Missing argument rule_id."),
    ],
)
def test_gcb_start_retrohunt_when_invalid_arguments_provided(client, args, error_msg):
    """Test gcb_start_retrohunt_command when invalid arguments are provided."""
    from GoogleSecOps import gcb_start_retrohunt_command

    with pytest.raises(ValueError) as e:
        gcb_start_retrohunt_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_start_retrohunt_command_when_invalid_rule_id_provided(client):
    """Test gcb_start_retrohunt_command when rule id provided is invalid."""
    from GoogleSecOps import gcb_start_retrohunt_command

    with open("test_data/gcb_start_retrohunt_command_invalid_id_400.json") as f:
        raw_response = f.read()
    args = {"rule_id": "dummy_rule_or_version_id", "start_time": "1 day", "end_time": "today"}

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_start_retrohunt_command(client, args)

    assert str(e.value) == "Status code: 400\nError: invalid rule_id"


def test_gcb_start_retrohunt_command_when_provided_rule_id_does_not_exist(client):
    """Test gcb_start_retrohunt_command when rule id provided does not exist."""
    from GoogleSecOps import gcb_start_retrohunt_command

    with open("test_data/gcb_start_retrohunt_command_id_does_not_exist_404.json") as f:
        raw_response = f.read()
    args = {"rule_id": "dummy_rule_or_version_id", "start_time": "1 day", "end_time": "today"}

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_start_retrohunt_command(client, args)

    assert str(e.value) == "Status code: 404\nError: rule with ID dummy_rule_or_version_id could not be found"


def test_gcb_start_retrohunt_command_when_valid_args_provided(client):
    """Test gcb_start_retrohunt_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_start_retrohunt_command

    with open("test_data/gcb_start_retrohunt_command_ec.json") as f:
        expected_ec = json.loads(f.read())

    with open("test_data/gcb_start_retrohunt_command_hr.md") as f:
        expected_hr = f.read()

    with open("test_data/gcb_start_retrohunt_command_response.json") as f:
        responses = json.loads(f.read())

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = 200
            self.text = json.dumps(response_data)

        def json(self):
            return json.loads(self.text)

    # Mock the first response (start retrohunt)
    client.http_client.request.side_effect = [
        MockResponse(responses["start_retrohunt"]),  # First call - start retrohunt
        MockResponse(responses["get_retrohunt"]),  # Second call - get retrohunt
    ]

    args = {"rule_id": "dummy_rule_or_version_id", "start_time": "1 day", "end_time": "today"}
    hr, ec, _ = gcb_start_retrohunt_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"id": "", "retrohunt_id": "dummy_retrohunt_id"}, "Missing argument id."),
        ({"id": "dummy_rule_or_version_id", "retrohunt_id": ""}, "Missing argument retrohunt_id."),
    ],
)
def test_gcb_cancel_retrohunt_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_cancel_retrohunt_command when arguments provided are empty."""
    from GoogleSecOps import gcb_cancel_retrohunt_command

    with pytest.raises(ValueError) as e:
        gcb_cancel_retrohunt_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_cancel_retrohunt_command_when_valid_args_are_provided(client):
    """Test gcb_cancel_retrohunt_command for valid output when valid args are provided."""
    from GoogleSecOps import gcb_cancel_retrohunt_command

    with open("test_data/gcb_cancel_retrohunt_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_cancel_retrohunt_hr.md") as f:
        expected_hr = f.read()
    args = {"id": "dummy_rule_or_version_id", "retrohunt_id": "dummy_retrohunt_id"}

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_cancel_retrohunt_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_cancel_retrohunt_command_when_provided_retrohunt_id_is_not_in_running_state(client):
    """Test gcb_list_retrohunts_command when retrohunt provided is already DONE or CANCELLED."""
    from GoogleSecOps import gcb_cancel_retrohunt_command

    with open("test_data/gcb_cancel_retrohunt_id_does_not_exist_400.json") as f:
        raw_response = f.read()
    args = {"id": "dummy_rule_or_version_id", "retrohunt_id": "dummy_retrohunt_id"}

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_cancel_retrohunt_command(client, args)

    assert str(e.value) == "Status code: 400\nError: cannot transition retrohunt status from CANCELLED to CANCELLED"


def test_gcb_list_events_command_with_response(client):
    """Test gcb_list_events_command for non-empty response."""
    from GoogleSecOps import gcb_list_events_command

    with open("test_data/gcb_list_events_response.json") as f:
        response = f.read()

    with open("test_data/gcb_list_events_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_list_events_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    args = {"asset_identifier_type": "hostname", "asset_identifier": "host1"}
    hr, ec, _ = gcb_list_events_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_list_events_command_empty_response(client):
    """Test gcb_list_events_command for empty response."""
    from GoogleSecOps import gcb_list_events_command

    class MockResponseEmpty:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    args = {"asset_identifier_type": "hostname", "asset_identifier": "host1"}
    hr, ec, _ = gcb_list_events_command(client, args)
    assert ec == {}
    assert hr == "### No Events Found"


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"asset_identifier_type": "", "asset_identifier": "host1"}, "Missing argument asset_identifier_type."),
        ({"asset_identifier_type": "hostname", "asset_identifier": ""}, "Missing argument asset_identifier."),
        (
            {"asset_identifier_type": "hostname", "asset_identifier": "host1", "page_size": "not_a_number"},
            "Page size must be a non-zero and positive numeric value",
        ),
    ],
)
def test_gcb_list_events_command_validation(client, args, error_msg):
    """Test validation for required arguments and invalid values in gcb_list_events_command."""
    from GoogleSecOps import gcb_list_events_command

    with pytest.raises(ValueError) as e:
        gcb_list_events_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "input_value,expected",
    [
        ("Last 1 day", "1 day"),
        ("Last 7 days", "7 days"),
        ("Last 15 days", "15 days"),
        ("Last 30 days", "30 days"),
    ],
)
def test_validate_preset_time_range_valid(input_value, expected):
    from GoogleSecOps import validate_preset_time_range

    assert validate_preset_time_range(input_value) == expected


@pytest.mark.parametrize(
    "input_value,error_msg",
    [
        ("1 day", MESSAGES["INVALID_DAY_ARGUMENT"]),
        ("Last 2 days", MESSAGES["INVALID_DAY_ARGUMENT"]),
        ("Last day", MESSAGES["INVALID_DAY_ARGUMENT"]),
        ("Last 1 week", MESSAGES["INVALID_DAY_ARGUMENT"]),
        ("", MESSAGES["INVALID_DAY_ARGUMENT"]),
    ],
)
def test_validate_preset_time_range_invalid(input_value, error_msg):
    from GoogleSecOps import validate_preset_time_range

    with pytest.raises(ValueError) as e:
        validate_preset_time_range(input_value)
    assert str(e.value) == error_msg


def test_gcb_get_event_command_valid_response(client):
    """Test gcb_get_event_command for valid output when valid arguments and non-empty response are provided."""
    from GoogleSecOps import gcb_get_event_command

    with open("test_data/gcb_get_event_response.json") as f:
        dummy_response = f.read()

    with open("test_data/gcb_get_event_ec.json") as f:
        dummy_ec = json.load(f)

    with open("test_data/gcb_get_event_hr.md") as f:
        dummy_hr = f.read()

    class MockResponse:
        status_code = 200
        text = dummy_response

        def json():
            return json.loads(dummy_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_get_event_command(client, {"event_id": "dummy_id"})

    assert ec == dummy_ec
    assert hr == dummy_hr


def test_gcb_get_event_command_empty_response(client):
    """Test gcb_get_event_command for correct output when API returns an empty response."""
    from GoogleSecOps import gcb_get_event_command

    class MockResponseEmpty:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, _ = gcb_get_event_command(client, {"event_id": "dummy_id"})

    assert ec == {"GoogleChronicleBackstory.Events(val.id == obj.id)": []}
    assert hr == ""


def test_gcb_get_event_command_invalid_args(client, capfd):
    """Test gcb_get_event_command when invalid arguments are provided."""
    from GoogleSecOps import gcb_get_event_command

    with pytest.raises(ValueError) as e, capfd.disabled():
        gcb_get_event_command(client, {"event_id": ""})
    assert str(e.value) == MESSAGES["REQUIRED_ARGUMENT"].format("event_id")


def test_gcb_list_detections_command_success(client):
    """Test gcb_list_detections_command for success response."""
    from GoogleSecOps import gcb_list_detections_command

    args = {
        "id": "dummy_rule_id",
        "start_time": "2025-07-10T00:00:00Z",
        "end_time": "2 days ago",
    }

    with open("test_data/gcb_list_detections_response.json") as f:
        response = f.read()

    with open("test_data/gcb_list_detections_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_list_detections_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_detections_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_list_detections_command_empty_response(client):
    """Test gcb_list_detections_command for empty response."""
    from GoogleSecOps import gcb_list_detections_command

    args = {
        "id": "dummy_rule_id",
        "start_time": "2025-07-10T00:00:00Z",
        "end_time": "2 days ago",
    }

    # Test command when no detections found
    class MockResponseEmpty:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, _ = gcb_list_detections_command(client, args)
    assert ec == {}
    assert hr == "### No Detections Found"


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"id": "ru_dummy_rule_id", "page_size": "dummy"}, COMMON_RESP["INVALID_PAGE_SIZE"]),
        (
            {"id": "ru_dummy_rule_id", "page_size": "100000"},
            "Page size should be in the range from 1 to 1000.",
        ),
        (
            {"rule_id": "ru_dummy_rule_id", "detection_start_time": "645.08"},
            'Invalid date: "detection_start_time"="645.08"',
        ),
        (
            {"rule_id": "ru_dummy_rule_id", "detection_start_time": "-325.21"},
            'Invalid date: "detection_start_time"="-325.21"',
        ),
        (
            {"rule_id": "ru_dummy_rule_id", "detection_end_time": "645.08"},
            'Invalid date: "detection_end_time"="645.08"',
        ),
        (
            {"rule_id": "ru_dummy_rule_id", "detection_end_time": "-325.21"},
            'Invalid date: "detection_end_time"="-325.21"',
        ),
        ({"rule_id": "ru_dummy_rule_id", "start_time": "645.08"}, 'Invalid date: "start_time"="645.08"'),
        ({"rule_id": "ru_dummy_rule_id", "start_time": "-325.21"}, 'Invalid date: "start_time"="-325.21"'),
        ({"rule_id": "ru_dummy_rule_id", "end_time": "645.08"}, 'Invalid date: "end_time"="645.08"'),
        ({"rule_id": "ru_dummy_rule_id", "end_time": "-325.21"}, 'Invalid date: "end_time"="-325.21"'),
        ({"detection_for_all_versions": True}, 'If "detection_for_all_versions" is true, rule id is required.'),
        (
            {"list_basis": "CREATED_TIME"},
            'To sort detections by "list_basis", either "start_time" or "end_time" argument is required.',
        ),
        (
            {"alert_state": "non_valid_state"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("alert_state", ", ".join(VALID_DETECTIONS_ALERT_STATE)),
        ),
        (
            {"list_basis": "non_valid_list_basis"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("list_basis", ", ".join(VALID_DETECTIONS_LIST_BASIS)),
        ),
    ],
)
def test_gcb_list_detections_command_for_invalid_args(client, args, error_msg):
    """Test gcb_list_detections_command for invalid args."""
    from GoogleSecOps import gcb_list_detections_command

    with pytest.raises(ValueError) as e:
        gcb_list_detections_command(client, args)

    assert str(e.value) == error_msg


def test_list_curatedrule_detections_command(client):
    """Test case for gcb_list_curatedrule_detections_command for successful response."""
    from GoogleSecOps import gcb_list_curatedrule_detections_command

    with open("test_data/gcb_list_curated_rule_detections_raw.json") as f:
        raw_response = f.read()
    with open("test_data/gcb_list_curated_rule_detections_hr.md") as f:
        expected_hr = f.read()
    with open("test_data/gcb_list_curated_rule_detections_ec.json") as f:
        expected_ec = json.load(f)

    class MockResponse:
        status_code = 200
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_curatedrule_detections_command(client, args={"id": "ur_dummy_curatedrule_id"})

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_list_curatedrule_detections_command_with_empty_response(client):
    """Test case for gcb_list_curatedrule_detections_command for empty response."""
    from GoogleSecOps import gcb_list_curatedrule_detections_command

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return json.loads("{}")

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_curatedrule_detections_command(client, args={"id": "ur_dummy_curatedrule_id"})

    assert hr == "### No Curated Detections Found"
    assert ec == {}


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"page_size": "invalid"}, COMMON_RESP["INVALID_PAGE_SIZE"]),
        ({"page_size": "1001"}, "Page size should be in the range from 1 to 1000."),
        ({"id": ""}, "A Curated Rule ID is required to retrieve the detections."),
        (
            {"id": "ur_dummy_curatedrule_id", "alert_state": "non_valid_state"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("alert_state", ", ".join(VALID_DETECTIONS_ALERT_STATE)),
        ),
        (
            {"id": "ur_dummy_curatedrule_id", "list_basis": "non_valid_list_basis"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("list_basis", ", ".join(VALID_DETECTIONS_LIST_BASIS)),
        ),
    ],
)
def test_gcb_list_curatedrule_detections_command_with_invalid_args(client, args, error_msg):
    """Test case for gcb_list_curatedrule_detections_command for invalid arguments."""
    from GoogleSecOps import gcb_list_curatedrule_detections_command

    with pytest.raises(ValueError) as error:
        gcb_list_curatedrule_detections_command(client, args)
    assert str(error.value) == error_msg


def test_gcb_list_curated_rules_command_success(client):
    """Test gcb_list_curated_rules_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_list_curated_rules_command

    with open("test_data/gcb_list_curated_rules_response.json") as f:
        raw_response = f.read()

    with open("test_data/gcb_list_curated_rules_ec.json") as f:
        expected_ec = json.load(f)
    with open("test_data/gcb_list_curated_rules_hr.md") as f:
        expected_hr = f.read()

    args = {"page_size": "1"}

    class MockResponse:
        status_code = 200
        text = raw_response

        def json(self):
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse()

    hr, ec, _ = gcb_list_curated_rules_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"page_size": "-1"}, MESSAGES["INVALID_PAGE_SIZE"].format("1000")),
        ({"page_size": "0"}, MESSAGES["INVALID_PAGE_SIZE"].format("1000")),
        ({"page_size": "1001"}, MESSAGES["INVALID_PAGE_SIZE"].format("1000")),
    ],
)
def test_gcb_list_curated_rules_command_invalid_args(client, args, error_msg):
    """Test gcb_list_curated_rules_command when invalid args are provided."""
    from GoogleSecOps import gcb_list_curated_rules_command

    with pytest.raises(ValueError) as e:
        gcb_list_curated_rules_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"rule_text": DUMMY_RULE_TEXT, "start_time": "dummy"}, 'Invalid date: "start_time"="dummy"'),
        (
            {"rule_text": DUMMY_RULE_TEXT, "start_time": "1 day ago", "end_time": "dummy"},
            'Invalid date: "end_time"="dummy"',
        ),
        (
            {"rule_text": DUMMY_RULE_TEXT, "start_time": "1 day ago", "end_time": "1 day ago", "max_results": 0},
            "Max Results should be in the range 1 to 10000.",
        ),
        (
            {"rule_text": DUMMY_RULE_TEXT, "start_time": "1 day ago", "end_time": "1 day ago", "max_results": "asd"},
            '"asd" is not a valid number',
        ),
        (
            {"rule_text": "meta events", "start_time": "1 day ago", "end_time": "1 day ago", "max_results": "3"},
            'Invalid rule text provided. Section "meta", "events" or "condition" is missing.',
        ),
    ],
)
def test_gcb_test_rule_stream_command_invalid_args(client, args, error_msg):
    """Test gcb_test_rule_stream_command when invalid args are provided."""
    from GoogleSecOps import gcb_test_rule_stream_command

    with pytest.raises(ValueError) as e:
        gcb_test_rule_stream_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_test_rule_stream_command_valid_args(client):
    """Test gcb_test_rule_stream_command for valid response when valid args are provided."""
    from GoogleSecOps import gcb_test_rule_stream_command

    with open("test_data/gcb_test_rule_stream_command_valid_rule_text.txt") as f:
        valid_rule_text = f.read()

    args = {
        "rule_text": valid_rule_text,
        "start_time": "2 day ago",
        "end_time": "1 day ago",
        "max_results": "2",
    }
    with open("test_data/gcb_test_rule_stream_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_test_rule_stream_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_test_rule_stream_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_test_rule_stream_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_test_rule_stream_command_invalid_rule_text_provided(client):
    """Test gcb_test_rule_stream_command when invalid rule text is provided."""
    from GoogleSecOps import gcb_test_rule_stream_command

    with open("test_data/gcb_test_rule_stream_command_invalid_rule_text.txt") as f:
        invalid_rule_text = f.read()
    args = {
        "rule_text": invalid_rule_text,
        "start_time": "2 day ago",
        "end_time": "1 day ago",
        "max_results": "2",
    }
    with open("test_data/gcb_test_rule_stream_command_400.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_test_rule_stream_command(client, args)
    assert str(e.value) == 'Status code: 400\nError: parsing: error with token: "}"\nunexpected token\nline: 1 \ncolumn: 168-169'


def test_gcb_udm_search_command(client):
    """Test gcb_udm_search_command for non-empty and empty response."""
    from GoogleSecOps import gcb_udm_search_command

    with open("test_data/gcb_udm_search_response.json") as f:
        response = f.read()

    with open("test_data/gcb_udm_search_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_udm_search_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_udm_search_command(client, {"query": 'ip!="8.8.8.8"'})

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_udm_search_command_empty_response(client):
    """Test gcb_udm_search_command for empty response."""
    from GoogleSecOps import gcb_udm_search_command

    # Test command when no events found
    class MockResponseEmpty:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponseEmpty

    hr, ec, _ = gcb_udm_search_command(client, {"query": 'ip!="8.8.8.8"'})
    assert ec == {}
    assert hr == "### No events were found for the specified UDM search query."


def test_gcb_udm_search_command_for_invalid_returned_date(capfd, client):
    """Test gcb_udm_search_command for invalid returned date from response."""
    from GoogleSecOps import gcb_udm_search_command

    with open("test_data/gcb_udm_search_response_invalid_date.json") as f:
        response = f.read()

    with open("test_data/gcb_udm_search_ec_invalid_date.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_udm_search_hr_invalid_date.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    with capfd.disabled():
        hr, ec, _ = gcb_udm_search_command(client, {"query": 'ip!="8.8.8.8"'})

    assert ec == expected_ec
    assert hr == expected_hr


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({}, MESSAGES["QUERY_REQUIRED"]),
        (
            {"query": 'ip!="8.8.8.8"', "start_time": "3 days", "end_time": "0 days", "limit": "invalid_limit"},
            MESSAGES["INVALID_LIMIT_TYPE"],
        ),
        ({"query": 'ip!="8.8.8.8"', "limit": "0"}, MESSAGES["INVALID_LIMIT_TYPE"]),
        ({"query": 'ip!="8.8.8.8"', "limit": "-1"}, MESSAGES["INVALID_LIMIT_TYPE"]),
        ({"query": 'ip!="8.8.8.8"', "limit": "1001"}, MESSAGES["INVALID_LIMIT_RANGE"].format(1000)),
    ],
)
def test_gcb_udm_search_command_for_invalid_args(args, error_msg):
    """Test gcb_udm_search_command for failing arguments."""
    from GoogleSecOps import gcb_udm_search_command

    with pytest.raises(ValueError) as e:
        gcb_udm_search_command(client, args)

    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"name": "", "view": "FULL"}, "Missing argument name."),
        ({"name": "dummy", "view": "dummy"}, "view can have one of these values only FULL, BASIC."),
    ],
)
def test_gcb_get_reference_list_command_when_invalid_args_are_provided(client, args, error_msg):
    """Test gcb_get_reference_list_command when arguments provided are invalid."""
    from GoogleSecOps import gcb_get_reference_list_command

    with pytest.raises(ValueError) as e:
        gcb_get_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_get_reference_list_command_when_provided_list_name_does_not_exist(client):
    """Test gcb_get_reference_list_command when list name provided does not exists."""
    from GoogleSecOps import gcb_get_reference_list_command

    with open("test_data/gcb_get_reference_lists_command_list_name_not_found_404.json") as f:
        raw_response = f.read()
    args = {
        "name": "dummy",
    }

    class MockResponse:
        status_code = 404
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_get_reference_list_command(client, args)
    assert str(e.value) == "Status code: 404\nError: getting reference list: list with name dummy not found"


def test_gcb_get_reference_list_command_when_valid_arguments_provided(client):
    """Test gcb_get_reference_list_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_get_reference_list_command

    with open("test_data/gcb_reference_list_valid_args.json") as f:
        response = f.read()
    with open("test_data/gcb_reference_list_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_reference_list_hr.md") as f:
        expected_hr = f.read()
    args = {"name": "dummy", "view": "FULL"}

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_get_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


arg_error = [
    ({"name": "", "description": "dummy", "lines": "l1,l2"}, "Missing argument name."),
    ({"name": "dummy_name", "description": "", "lines": "l1,l2"}, "Missing argument description."),
    ({"name": "dummy_name", "description": "dummy", "lines": ""}, "Missing argument lines."),
    ({"name": "dummy_name", "description": "dummy", "lines": "[]"}, "Missing argument lines."),
    ({"name": "dummy_name", "description": "dummy", "lines": ", ,"}, "Missing argument lines."),
    (
        {"name": "dummy_name", "description": "dummy", "lines": "l1,l2", "content_type": "type"},
        MESSAGES["VALIDATE_SINGLE_SELECT"].format("content_type", ", ".join(VALID_CONTENT_TYPE)),
    ),
    ({"name": "dummy_name", "description": "dummy", "entry_id": ""}, "Missing argument entry_id."),
    (
        {"name": "dummy_name", "description": "dummy", "lines": "L1,L2", "entry_id": "12"},
        "Both 'lines' and 'entry_id' cannot be provided together.",
    ),
    (
        {
            "name": "dummy_name",
            "description": "dummy",
        },
        "Either 'lines' or 'entry_id' must be provided.",
    ),
    ({"name": "dummy_name", "entry_id": "123"}, "Missing argument description."),
]


@pytest.mark.parametrize("args,error_msg", arg_error)
def test_gcb_create_reference_list_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_create_reference_list comamnd when empty arguments are provided."""
    from GoogleSecOps import gcb_create_reference_list_command

    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_create_reference_list_command_when_file_does_not_exists(client, mocker):
    """Test gcb_create_reference_list command when file does not exist."""
    from GoogleSecOps import gcb_create_reference_list_command

    args = {"name": "dummy", "description": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' does not exist."
    mocker.patch.object(demisto, "getFilePath", side_effect=ValueError("Invalid entry_id."))
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_create_reference_list_command_when_file_is_empty(client, mocker):
    """Test gcb_create_reference_list command when file is empty."""
    from GoogleSecOps import gcb_create_reference_list_command

    args = {"name": "dummy", "description": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' is empty."
    entry_mock = {
        "id": "123",
        "path": "test_data/gcb_reference_list_command_empty_text.txt",
        "name": "gcb_reference_list_command_empty_text.txt",
    }
    mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy", "lines": "L1,L2,L3", "description": "dummy_description"}),
        ({"name": "dummy", "entry_id": "1234", "description": "dummy_description"}),
    ],
)
def test_gcb_create_reference_list_command_when_valid_args_provided(client, mocker, args):
    """Test gcb_create_reference_list command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_create_reference_list_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "1234",
            "path": "test_data/gcb_create_reference_list_command_text.txt",
            "name": "gcb_create_reference_list_command_text.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with open("test_data/gcb_create_reference_list_response.json") as f:
        response = f.read()
    with open("test_data/gcb_create_reference_list_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_create_reference_list_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_create_reference_list_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy_name", "description": "dummy_description", "lines": "L1:L2:L3", "delimiter": ":"}),
        {
            "name": "dummy_name",
            "description": "dummy_description",
            "entry_id": "1234",
            "use_delimiter_for_file": True,
            "delimiter": ",",
        },
    ],
)
def test_gcb_create_reference_list_command_when_delimiter_provided(client, mocker, args):
    """Test gcb_create_reference_list command for valid output when delimiter is provided."""
    from GoogleSecOps import gcb_create_reference_list_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "1234",
            "path": "test_data/gcb_create_reference_list_command_text_with_delimiter.txt",
            "name": "gcb_create_reference_list_command_text_with_delimiter.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with open("test_data/gcb_create_reference_list_response.json") as f:
        response = f.read()
    with open("test_data/gcb_create_reference_list_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_create_reference_list_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_create_reference_list_command(client, args)
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_create_reference_list_command_when_list_already_exists(client):
    """Test gcb_create_reference_list command when a list with same name already exists."""
    from GoogleSecOps import gcb_create_reference_list_command

    args = {"name": "dummy_name", "description": "dummy_description", "lines": "dummy"}
    with open("test_data/gcb_create_reference_list_409.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 409
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert str(e.value) == "Status code: 409\nError: creating reference list: list with name dummy already exists"


def test_gcb_create_reference_list_command_when_invalid_lines_content_provided(client):
    """Test gcb_create_reference_list command when invalid lines content is provided accordingly to the content_type."""
    from GoogleSecOps import gcb_create_reference_list_command

    args = {"name": "dummy_name", "description": "dummy_description", "lines": "dummy_lines", "content_type": "CIDR"}
    with open("test_data/gcb_create_reference_list_invalid_lines_content_400.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_create_reference_list_command(client, args)
    assert (
        str(e.value)
        == "Status code: 400\nError: creating reference list: validating parsed content: invalid cidr pattern dummy_lines"
    )


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"name": "dummy", "lines": ""}, "Missing argument lines."),
        ({"name": "dummy_name", "lines": "[]"}, "Missing argument lines."),
        ({"name": "dummy_name", "lines": ", ,"}, "Missing argument lines."),
        ({"name": "", "lines": "dummy"}, "Missing argument name."),
        (
            {"name": "x", "lines": "y", "content_type": "type"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("content_type", ", ".join(VALID_CONTENT_TYPE)),
        ),
        ({"name": "dummy_name", "entry_id": ""}, "Missing argument entry_id."),
        (
            {"name": "dummy_name", "lines": "L1,L2", "entry_id": "12"},
            "Both 'lines' and 'entry_id' cannot be provided together.",
        ),
        ({"name": "dummy_name"}, "Either 'lines' or 'entry_id' must be provided."),
    ],
)
def test_gcb_update_reference_list_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_update_reference_list command when provided args are empty."""
    from GoogleSecOps import gcb_update_reference_list_command

    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_update_reference_list_command_when_file_does_not_exists(client, mocker):
    """Test gcb_update_reference_list command when file does not exist."""
    from GoogleSecOps import gcb_update_reference_list_command

    args = {"name": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' does not exist."
    mocker.patch.object(demisto, "getFilePath", side_effect=ValueError("Invalid entry_id."))
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_update_reference_list_command_when_file_is_empty(client, mocker):
    """Test gcb_update_reference_list command when file is empty."""
    from GoogleSecOps import gcb_update_reference_list_command

    args = {"name": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' is empty."
    entry_mock = {
        "id": "123",
        "path": "test_data/gcb_reference_list_command_empty_text.txt",
        "name": "gcb_reference_list_command_empty_text.txt",
    }
    mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy", "lines": "L1;L2;L3", "delimiter": ";", "description": "dummy_description"}),
        (
            {
                "name": "dummy",
                "entry_id": "123",
                "use_delimiter_for_file": True,
                "delimiter": ";",
                "description": "dummy_description",
            }
        ),
    ],
)
def test_gcb_update_reference_list_command_when_valid_args_provided(client, mocker, args):
    """Test gcb_update_reference_list command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_update_reference_list_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "123",
            "path": "test_data/gcb_update_reference_list_command_text.txt",
            "name": "gcb_update_reference_list_command_text.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with open("test_data/gcb_update_reference_list_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_update_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_update_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_update_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy", "lines": "L1;L2;L3", "delimiter": ";", "description": "dummy_description"}),
        (
            {
                "name": "dummy",
                "entry_id": "123",
                "use_delimiter_for_file": True,
                "delimiter": ";",
                "description": "dummy_description",
            }
        ),
    ],
)
def test_gcb_update_reference_list_command_when_valid_args_provided_without_content_type(client, mocker, args):
    """Test gcb_update_reference_list command for valid output when valid arguments without content_type are provided."""
    from GoogleSecOps import gcb_update_reference_list_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "123",
            "path": "test_data/gcb_update_reference_list_command_text.txt",
            "name": "gcb_update_reference_list_command_text.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with open("test_data/gcb_update_reference_list_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_update_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_update_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse1:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    class MockResponse2:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    # The first call is to get the reference list and the second call is to update the reference list
    client.http_client.request.side_effect = [MockResponse1(), MockResponse2()]
    MockResponse1.json = lambda _: json.loads(response)
    MockResponse2.json = lambda _: json.loads(response)
    hr, ec, _ = gcb_update_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_update_reference_list_command_when_name_prided_does_not_exists(client):
    """Test gcb_update_reference_list command when name provided does not exist."""
    from GoogleSecOps import gcb_update_reference_list_command

    args = {"name": "dummy", "lines": "L1,L2,L3", "description": "dummy_description"}
    with open("test_data/gcb_update_reference_list_command_response_404.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 404
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert str(e.value) == "Status code: 404\nError: getting old reference list version: list with name dummy not found"


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy_name", "lines": "dummy_lines", "description": "dummy_description", "content_type": "Regex"}),
        ({"name": "dummy_name", "entry_id": "123", "description": "dummy_description", "content_type": "Regex"}),
    ],
)
def test_gcb_update_reference_list_command_when_invalid_lines_content_provided(client, mocker, args):
    """Test gcb_update_reference_list command when invalid lines content is provided accordingly to the content_type."""
    from GoogleSecOps import gcb_update_reference_list_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "123",
            "path": "test_data/gcb_update_reference_list_command_text.txt",
            "name": "gcb_update_reference_list_command_text.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)

    with open("test_data/gcb_update_reference_list_invalid_lines_content_400.json") as f:
        response = f.read()

    class MockResponse:
        status_code = 400
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_update_reference_list_command(client, args)
    assert (
        str(e.value)
        == "Status code: 400\nError: updating reference list: validating parsed content: invalid cidr pattern dummy_lines"
    )


arg_error = [
    ({"page_size": "-20"}, "Page size must be a non-zero and positive numeric value"),
    ({"page_size": "20000"}, "Page size should be in the range from 1 to 1000."),
    ({"page_size": "10", "view": "dummy"}, "view can have one of these values only FULL, BASIC."),
]


@pytest.mark.parametrize("args,error_msg", arg_error)
def test_gcb_list_reference_list_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb-list-reference-list-command when invalid arguments are provided."""
    from GoogleSecOps import gcb_list_reference_list_command

    with pytest.raises(ValueError) as e:
        gcb_list_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_list_reference_list_command_when_invalid_page_token_provided(client):
    """Test gcb-list-reference-list-command when invalid page-token is provided."""
    from GoogleSecOps import gcb_list_reference_list_command

    with open("test_data/gcb_list_reference_lists_command_invalid_token_400.json") as f:
        raw_response = f.read()
    args = {"page_size": "3", "page_token": "abcd"}

    class MockResponse:
        status_code = 400
        text = raw_response

        def json():
            return json.loads(raw_response)

    client.http_client.request.return_value = MockResponse
    with pytest.raises(ValueError) as e:
        gcb_list_reference_list_command(client, args)
    assert str(e.value) == "Status code: 400\nError: Request contains an invalid argument."


def test_gcb_list_reference_list_command_when_valid_args_provided(client):
    """Test gcb-list-reference-list-command when valid arguments are provided."""
    from GoogleSecOps import gcb_list_reference_list_command

    with open("test_data/gcb_list_reference_list_valid_args.json") as f:
        response = f.read()
    with open("test_data/gcb_list_reference_list_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_list_reference_list_hr.md") as f:
        expected_hr = f.read()
    args = {"page_size": "3", "view": "FULL"}

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_list_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"lines": ""}, "Missing argument lines."),
        ({"lines": "[]"}, "Missing argument lines."),
        ({"lines": ",,"}, "Missing argument lines."),
        (
            {"lines": "L1", "content_type": "type"},
            MESSAGES["VALIDATE_SINGLE_SELECT"].format("content_type", ", ".join(VALID_CONTENT_TYPE)),
        ),
    ],
)
def test_gcb_verify_reference_list_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_verify_reference_list command when provided args are invalid."""
    from GoogleSecOps import gcb_verify_reference_list_command

    with pytest.raises(ValueError) as e:
        gcb_verify_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_verify_reference_list_command_when_valid_args_provided(client):
    """Test gcb_verify_reference_list command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_verify_reference_list_command

    args = {"lines": "L1;0.0.0.1/1;L3", "content_type": "CIDR", "delimiter": ";"}
    with open("test_data/gcb_verify_reference_list_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_verify_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_verify_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_verify_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_verify_reference_list_command_when_lines_content_are_valid(client):
    """Test gcb_verify_reference_list command for valid output when valid lines_content are provided."""
    from GoogleSecOps import gcb_verify_reference_list_command

    args = {"lines": "L1;0.0.0.1/1;L3", "content_type": "PLAIN_TEXT", "delimiter": ";"}
    response = {"success": True}
    with open("test_data/gcb_verify_reference_list_command_all_valid_lines_ec.json") as f:
        expected_ec = json.loads(f.read())

    expected_hr = "### All provided lines meet validation criteria"

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return response

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_verify_reference_list_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_verify_value_in_reference_list_command_success(client):
    """Test gcb_verify_value_in_reference_list_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_verify_value_in_reference_list_command

    with open("test_data/gcb_verify_value_in_reference_list_command_response.json") as f:
        response = json.loads(f.read())
    with open("test_data/gcb_verify_value_in_reference_list_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_verify_value_in_reference_list_command_hr.md") as f:
        expected_hr = f.read()

    args = {
        "reference_list_names": "list1,list2,list3, ",
        "values": "value1,Value2,value4,value1,[-\\{\\}\\^],0.0.0.1/0",
        "add_not_found_reference_lists": "true",
        "case_insensitive_search": "true",
    }
    with mock.patch("GoogleSecOps.gcb_get_reference_list") as mock_gcb_get_reference_list:
        mock_gcb_get_reference_list.side_effect = [
            ({"entries": [{"value": "value1"}, {"value": "value2"}, {"value": "0.0.0.1/0"}]}),
            ({"entries": [{"value": "value3"}, {"value": "[-\\{\\}\\^]"}]}),
            Exception("Error: Status code: 404\n Error: generic::not_found: list with name xyz not found"),
        ]
        with mock.patch("GoogleSecOps.return_warning") as mock_return:
            hr, ec, data = gcb_verify_value_in_reference_list_command(client, args)
            assert mock_return.call_args[0][0] == "The following Reference lists were not found: list3"
        assert data == response
        assert ec == expected_ec
        assert hr == expected_hr


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"reference_list_names": " , , ", "values": "value1"}, MESSAGES["REQUIRED_ARGUMENT"].format("reference_list_names")),
        ({"reference_list_names": "list1", "values": "   ,   ,  "}, MESSAGES["REQUIRED_ARGUMENT"].format("values")),
    ],
)
def test_gcb_verify_value_in_reference_list_command_invalid_args(client, capfd, args, error_msg):
    """Test gcb_verify_value_in_reference_list_command when invalid arguments are provided."""
    from GoogleSecOps import gcb_verify_value_in_reference_list_command

    with pytest.raises(ValueError) as e, capfd.disabled():
        gcb_verify_value_in_reference_list_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_verify_value_in_reference_list_command_system_exit(capfd, client):
    """Test gcb_verify_value_in_reference_list_command when all reference lists are not found."""
    from GoogleSecOps import gcb_verify_value_in_reference_list_command

    args = {"reference_list_names": "list1,list2,list3", "values": "value1,Value2,value4", "case_insensitive_search": "true"}
    with mock.patch("GoogleSecOps.gcb_get_reference_list") as mock_gcb_get_reference_list:
        mock_gcb_get_reference_list.side_effect = [
            Exception("Error: Status code: 404\n Error: getting reference list: list with name list1 not found"),
            Exception("Error: Status code: 404\n Error: getting reference list: list with name list2 not found"),
            Exception("Error: Status code: 404\n Error: getting reference list: list with name list3 not found"),
        ]

        with capfd.disabled(), pytest.raises(SystemExit) as err:
            gcb_verify_value_in_reference_list_command(client, args)

        assert err.value.code == 0


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"name": "dummy", "lines": ""}, "Missing argument lines."),
        ({"name": "dummy_name", "lines": "[]"}, "Missing argument lines."),
        ({"name": "dummy_name", "lines": ", ,"}, "Missing argument lines."),
        ({"name": "", "lines": "dummy"}, "Missing argument name."),
        ({"name": "", "entry_id": "dummy"}, "Missing argument name."),
        ({"name": "dummy_name", "entry_id": ""}, "Missing argument entry_id."),
        (
            {"name": "dummy_name", "lines": "L1,L2", "entry_id": "12"},
            "Both 'lines' and 'entry_id' cannot be provided together.",
        ),
        ({"name": "dummy_name"}, "Either 'lines' or 'entry_id' must be provided."),
    ],
)
def test_gcb_reference_list_append_content_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_reference_list_append_content command when provided args are empty."""
    from GoogleSecOps import gcb_reference_list_append_content

    with pytest.raises(ValueError) as e:
        gcb_reference_list_append_content(client, args)
    assert str(e.value) == error_msg


def test_gcb_reference_list_append_content_command_when_file_does_not_exists(client, mocker):
    """Test gcb_reference_list_append_content command when file does not exist."""
    from GoogleSecOps import gcb_reference_list_append_content

    args = {"name": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' does not exist."
    mocker.patch.object(demisto, "getFilePath", side_effect=ValueError("Invalid entry_id."))
    with pytest.raises(ValueError) as e:
        gcb_reference_list_append_content(client, args)
    assert str(e.value) == error_msg


def test_gcb_reference_list_append_content_command_when_file_is_empty(client, mocker):
    """Test gcb_reference_list_append_content command when file is empty."""
    from GoogleSecOps import gcb_reference_list_append_content

    args = {"name": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' is empty."
    entry_mock = {
        "id": "123",
        "path": "test_data/gcb_reference_list_command_empty_text.txt",
        "name": "gcb_reference_list_command_empty_text.txt",
    }
    mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with pytest.raises(ValueError) as e:
        gcb_reference_list_append_content(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy", "lines": "L4;L5;L6", "delimiter": ";", "append_unique": True}),
        ({"name": "dummy", "entry_id": "123", "use_delimiter_for_file": True, "append_unique": True, "delimiter": ";"}),
    ],
)
def test_gcb_reference_list_append_content_command_when_valid_args_provided(client, mocker, args):
    """Test gcb_reference_list_append_content command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_reference_list_append_content

    if args.get("entry_id"):
        entry_mock = {
            "id": "123",
            "path": "test_data/gcb_reference_list_command_text.txt",
            "name": "gcb_reference_list_command_text.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with open("test_data/gcb_reference_list_append_content_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_reference_list_append_content_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_reference_list_append_content_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, json_data = gcb_reference_list_append_content(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"name": "dummy", "lines": ""}, "Missing argument lines."),
        ({"name": "dummy_name", "lines": "[]"}, "Missing argument lines."),
        ({"name": "dummy_name", "lines": ", ,"}, "Missing argument lines."),
        ({"name": "", "lines": "dummy"}, "Missing argument name."),
        ({"name": "", "entry_id": "dummy"}, "Missing argument name."),
        ({"name": "dummy_name", "entry_id": ""}, "Missing argument entry_id."),
        (
            {"name": "dummy_name", "lines": "L1,L2", "entry_id": "12"},
            "Both 'lines' and 'entry_id' cannot be provided together.",
        ),
        ({"name": "dummy_name"}, "Either 'lines' or 'entry_id' must be provided."),
    ],
)
def test_gcb_reference_list_remove_content_command_when_empty_args_provided(client, args, error_msg):
    """Test gcb_reference_list_remove_content command when provided args are empty."""
    from GoogleSecOps import gcb_reference_list_remove_content

    with pytest.raises(ValueError) as e:
        gcb_reference_list_remove_content(client, args)
    assert str(e.value) == error_msg


def test_gcb_reference_list_remove_content_command_when_file_does_not_exists(client, mocker):
    """Test gcb_reference_list_remove_content command when file does not exist."""
    from GoogleSecOps import gcb_reference_list_remove_content

    args = {"name": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' does not exist."
    mocker.patch.object(demisto, "getFilePath", side_effect=ValueError("Invalid entry_id."))
    with pytest.raises(ValueError) as e:
        gcb_reference_list_remove_content(client, args)
    assert str(e.value) == error_msg


def test_gcb_reference_list_remove_content_command_when_file_is_empty(client, mocker):
    """Test gcb_reference_list_remove_content command when file is empty."""
    from GoogleSecOps import gcb_reference_list_remove_content

    args = {"name": "dummy", "entry_id": "123"}
    error_msg = "The file with entry_id '123' is empty."
    entry_mock = {
        "id": "123",
        "path": "test_data/gcb_reference_list_command_empty_text.txt",
        "name": "gcb_reference_list_command_empty_text.txt",
    }
    mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with pytest.raises(ValueError) as e:
        gcb_reference_list_remove_content(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args",
    [
        ({"name": "dummy", "lines": "L4;L5;L6", "delimiter": ";"}),
        ({"name": "dummy", "entry_id": "456", "use_delimiter_for_file": True, "delimiter": ";"}),
    ],
)
def test_gcb_reference_list_remove_content_command_when_valid_args_provided(client, mocker, args):
    """Test gcb_reference_list_remove_content command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_reference_list_remove_content

    if args.get("entry_id"):
        entry_mock = {
            "id": "456",
            "path": "test_data/gcb_reference_list_command_text.txt",
            "name": "gcb_reference_list_command_text.txt",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)
    with open("test_data/gcb_reference_list_remove_content_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_reference_list_remove_content_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_reference_list_remove_content_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_reference_list_remove_content(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_list_ioc_success(client, mocker):
    """When valid response comes in gcb-list-iocs command it should respond with result."""
    from GoogleSecOps import gcb_list_iocs_command

    with open("test_data/gcb_list_iocs_response.json") as f:
        response = f.read()

    with open("test_data/gcb_list_iocs_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_list_iocs_hr.md") as f:
        expected_hr = f.read()

    mocker.patch("GoogleSecOps.get_informal_time", return_value="2 months ago")

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_iocs_command(client, {})

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_list_ioc_success_empty_response(client):
    """When valid response comes in gcb-list-iocs command it should respond with result."""
    from GoogleSecOps import gcb_list_iocs_command

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_list_iocs_command(client, {})

    assert hr == "### No domain matches found"
    assert ec == {}


def test_gcb_ioc_details_command_success(client):
    """When command execute successfully then it should prepare valid hr, ec."""
    from GoogleSecOps import gcb_ioc_details_command

    with open("test_data/gcb_ioc_details_response.json") as f:
        response = f.read()

    with open("test_data/gcb_ioc_details_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_ioc_details_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, response = gcb_ioc_details_command(client, {"artifact_value": "0.0.0.1"})

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_ioc_details_command_empty_response(client):
    """When there is an empty response the command should response empty ec and valid text in hr."""
    from GoogleSecOps import gcb_ioc_details_command

    expected_hr = "### For artifact: {}\n".format("0.0.0.1")
    expected_hr += MESSAGES["NO_RECORDS"]

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = gcb_ioc_details_command(client, {"artifact_value": "0.0.0.1"})

    assert hr == expected_hr
    assert ec == {}


def test_ip_command_success(mocker, client):
    """When command execute successfully then it should prepare valid hr, ec."""
    from GoogleSecOps import ip_command

    with open("test_data/gcb_ioc_details_response.json") as f:
        response = f.read()

    with open("test_data/ip_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/ip_command_hr.md") as f:
        expected_hr = f.read()

    mocker.patch.object(demisto, "params", return_value=PARAMS)

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, __cached__ = ip_command(client, "0.0.0.1")

    assert ec == expected_ec
    assert hr == expected_hr


def test_ip_command_when_empty_response(client, mocker):
    """Test ip_command for empty response."""
    from GoogleSecOps import ip_command

    with open("test_data/ip_command_empty_response_ec.json") as f:
        expected_ec = json.load(f)

    expected_hr = "### IP: {} found with Reputation: Unknown\n".format("0.0.0.1")
    expected_hr += MESSAGES["NO_RECORDS"]

    mocker.patch.object(demisto, "params", return_value=PARAMS)

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = ip_command(client, "0.0.0.1")

    assert hr == expected_hr
    assert ec == expected_ec


def test_ip_command_invalid_ip_address(client):
    """When user add invalid IP Address then it should raise ValueError with valid response."""
    from GoogleSecOps import ip_command

    expected_message = "Invalid IP - string"

    with pytest.raises(ValueError) as error:
        ip_command(client, "string")

    assert str(error.value) == expected_message


def test_domain_command_success(mocker, client):
    """When command execute successfully then it should prepare valid hr, ec."""
    from GoogleSecOps import domain_command

    with open("test_data/gcb_ioc_details_response.json") as f:
        response = f.read()

    with open("test_data/domain_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/domain_command_hr.md") as f:
        expected_hr = f.read()

    mocker.patch.object(demisto, "params", return_value=PARAMS)

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = domain_command(client, "test.com")

    assert ec == expected_ec
    assert hr == expected_hr


def test_domain_command_empty_response(client):
    """Test domain_command for empty response."""
    from GoogleSecOps import domain_command

    with open("test_data/domain_command_empty_response_ec.json") as f:
        expected_ec = json.load(f)

    expected_hr = "### Domain: {} found with Reputation: Unknown\n".format("test.com")
    expected_hr += MESSAGES["NO_RECORDS"]

    class MockResponse:
        status_code = 200
        text = "{}"

        def json():
            return {}

    client.http_client.request.return_value = MockResponse

    hr, ec, _ = domain_command(client, "test.com")

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_list_data_tables_command_when_valid_args_provided(client):
    """Test gcb_list_data_tables_command when valid arguments are provided."""
    from GoogleSecOps import gcb_list_data_tables_command

    with open("test_data/gcb_list_data_tables_valid_args.json") as f:
        response = f.read()
    with open("test_data/gcb_list_data_tables_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_list_data_tables_hr.md") as f:
        expected_hr = f.read()
    args = {"page_size": "2"}

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_list_data_tables_command(client, args)

    assert ec == expected_ec
    assert hr == expected_hr


def test_gcb_list_data_tables_command_when_empty_response_is_obtained(client):
    """Test gcb_list_data_tables_command when empty response is obtained."""
    from GoogleSecOps import gcb_list_data_tables_command

    response = {"dataTables": []}

    expected_hr = "### No Data Tables Found"
    expected_ec = {}

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return response

    client.http_client.request.return_value = MockResponse
    hr, ec, _ = gcb_list_data_tables_command(client, {"page_size": "100"})

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"page_size": "0"}, "Page size must be a non-zero and positive numeric value"),
        ({"page_size": "-1"}, "Page size must be a non-zero and positive numeric value"),
        ({"page_size": "not_a_number"}, "Page size must be a non-zero and positive numeric value"),
    ],
)
def test_gcb_list_data_tables_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_list_data_tables_command when invalid arguments are provided."""
    from GoogleSecOps import gcb_list_data_tables_command

    with pytest.raises(ValueError) as e:
        gcb_list_data_tables_command(client, args)

    assert str(e.value) == error_msg


def test_gcb_create_data_table_command_success(client):
    """Test gcb_create_data_table_command when valid response comes back."""
    from GoogleSecOps import gcb_create_data_table_command

    # Load test data from files
    with open("test_data/gcb_create_data_table_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_create_data_table_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_create_data_table_command_hr.md") as f:
        expected_hr = f.read()

    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    args = {
        "name": "test_table",
        "description": "Table for testing",
        "columns": """{"column_1": "String", "column_2": "REGEX", "column_3": "CIDR", "column_4": "entity.ip.address"}""",
    }

    hr, ec, _ = gcb_create_data_table_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args, error_message",
    [
        ({"description": "Test Table", "columns": "{}"}, MESSAGES["REQUIRED_ARGUMENT"].format("name")),
        ({"name": "test_table", "description": "Test Table"}, MESSAGES["REQUIRED_ARGUMENT"].format("columns")),
        (
            {"name": "test_table", "description": "Test Table", "columns": "invalid-json"},
            "Invalid format for columns argument. Please provide a valid JSON format.",
        ),
        ({"name": "test_table", "description": "Test Table", "columns": "{}"}, MESSAGES["REQUIRED_ARGUMENT"].format("columns")),
    ],
)
def test_gcb_create_data_table_command_invalid_args(client, mocker, args, error_message):
    """Test gcb_create_data_table_command with invalid arguments."""
    from GoogleSecOps import gcb_create_data_table_command

    # Mock return_error function to raise ValueError
    mocker.patch(RETURN_ERROR_MOCK_PATH, new=return_error)

    # Test with invalid arguments
    with pytest.raises(ValueError) as e:
        gcb_create_data_table_command(client, args)

    assert str(e.value) == error_message


def test_gcb_get_data_table_command_basic_view(client):
    """Test gcb_get_data_table_command with basic view parameter."""
    from GoogleSecOps import gcb_get_data_table_command

    # Load the test data from file
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_get_data_table_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_get_data_table_command_hr.md") as f:
        expected_hr = f.read()

    # Create the mock response
    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    # Call the function with 'basic' view
    hr, ec, _ = gcb_get_data_table_command(client, {"name": "test_table", "view": "basic"})

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_get_data_table_command_full_view(client):
    """Test gcb_get_data_table_command with full view parameter."""
    from GoogleSecOps import gcb_get_data_table_command

    # Load the test data from files
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_get_data_table_command_full_view_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_get_data_table_command_full_view_hr.md") as f:
        expected_hr = f.read()

    with open("test_data/gcb_get_data_table_command_rows_response.json") as f:
        rows_response = f.read()

    # Mock responses for both API calls
    class MockDataTableResponse:
        status_code = 200
        text = response

        def json(self):
            return json.loads(response)

    class MockRowsResponse:
        status_code = 200
        text = rows_response

        def json(self):
            return json.loads(rows_response)

    # Set up the mock to return different responses for different API calls
    client.http_client.request.side_effect = [MockDataTableResponse(), MockRowsResponse()]

    # Call the function with 'full' view
    hr, ec, _ = gcb_get_data_table_command(client, {"name": "test_table", "view": "FULL"})

    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_get_data_table_command_empty_response(client):
    """Test gcb_get_data_table_command when API returns empty table rows response."""
    from GoogleSecOps import gcb_get_data_table_command

    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_get_data_table_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_get_data_table_command_hr.md") as f:
        expected_hr = f.read()

    # Mock responses for both API calls
    class MockDataTableResponse:
        status_code = 200
        text = response

        def json(self):
            return json.loads(response)

    class MockRowsResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {}

    # Set up the mock to return different responses for different API calls
    client.http_client.request.side_effect = [MockDataTableResponse(), MockRowsResponse()]

    # Call the function with 'full' view
    hr, ec, response = gcb_get_data_table_command(client, {"name": "test_table", "view": "FULL"})

    # Verify the output contains the data table info but no rows data
    expected_hr += "### No Rows Data Found"
    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({"name": "test_table", "view": "FULL", "max_rows_to_return": "0"}, "max_rows_to_return should be greater than 0."),
        ({}, "Missing argument name."),
    ],
)
def test_gcb_get_data_table_command_invalid_args(client, mocker, args, expected_error_message):
    """Test gcb_get_data_table_command input validation with various invalid arguments."""
    from GoogleSecOps import gcb_get_data_table_command

    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = json.loads(f.read())

    mocker.patch("GoogleSecOps.gcb_get_data_table", return_value=(response, {}))
    with pytest.raises(ValueError) as error:
        gcb_get_data_table_command(client, args)
    assert expected_error_message in str(error.value)


def test_gcb_verify_value_in_data_table_command_success(client):
    """Test gcb_verify_value_in_data_table_command success scenario when value is found in specified column."""
    from GoogleSecOps import gcb_verify_value_in_data_table_command

    # Load the test data from files
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_get_data_table_command_rows_response.json") as f:
        rows_response = f.read()

    with open("test_data/gcb_verify_value_in_data_table_success_raw_response.json") as f:
        expected_raw_response = json.load(f)

    with open("test_data/gcb_verify_value_in_data_table_success_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_verify_value_in_data_table_success_hr.md") as f:
        expected_hr = f.read()

    # Mock responses for the API calls
    class MockDataTableResponse:
        status_code = 200
        text = response

        def json(self):
            return json.loads(response)

    class MockRowsResponse:
        status_code = 200
        text = rows_response

        def json(self):
            return json.loads(rows_response)

    # Set up the mock to return different responses for different API calls
    client.http_client.request.side_effect = [MockDataTableResponse(), MockRowsResponse()]

    # Call the function with specific column and value to search
    args = {
        "name": "test_data_table",
        "values": "1,20,^[a-zA-Z]+$,3",
        "case_insensitive_search": "true",
        "add_not_found_columns": "true",
    }
    hr, ec, response = gcb_verify_value_in_data_table_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec
    assert response == expected_raw_response


def test_gcb_verify_value_in_data_table_command_when_rows_data_is_empty(client):
    """Test gcb_verify_value_in_data_table_command when rows data is empty."""
    from GoogleSecOps import gcb_verify_value_in_data_table_command

    # Load the test data from files
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = f.read()

    # Mock responses for the API calls
    class MockDataTableResponse:
        status_code = 200
        text = response

        def json(self):
            return json.loads(response)

    class MockRowsResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {}

    # Set up the mock to return different responses for different API calls
    client.http_client.request.side_effect = [MockDataTableResponse(), MockRowsResponse()]

    # Call the function with specific column and value to search
    args = {
        "name": "test_data_table",
        "values": "1,20,^[a-zA-Z]+$,3",
        "case_insensitive_search": "true",
        "add_not_found_columns": "true",
    }
    hr, ec, response = gcb_verify_value_in_data_table_command(client, args)

    assert hr == "### No Rows data found in the test_data_table data table"
    assert ec == {}
    assert response == {}


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, "Missing argument name."),
        ({"name": "test_table"}, "Missing argument values."),
        ({"name": "test_table", "values": ", , , , "}, "Missing argument values."),
    ],
)
def test_gcb_verify_value_in_data_table_command_invalid_args(client, args, expected_error_message):
    """Test gcb_verify_value_in_data_table_command input validation with various invalid arguments."""
    from GoogleSecOps import gcb_verify_value_in_data_table_command

    with pytest.raises(ValueError) as error:
        gcb_verify_value_in_data_table_command(client, args)
    assert expected_error_message in str(error.value)


def test_gcb_verify_value_in_data_table_command_system_exit(capfd, client):
    """Test gcb_verify_value_in_data_table_command when all reference lists are not found."""
    from GoogleSecOps import gcb_verify_value_in_data_table_command

    with open("test_data/gcb_get_data_table_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_get_data_table_command_rows_response.json") as f:
        rows_response = f.read()

    # Mock responses for the API calls
    class MockDataTableResponse:
        status_code = 200
        text = response

        def json(self):
            return json.loads(response)

    class MockRowsResponse:
        status_code = 200
        text = rows_response

        def json(self):
            return json.loads(rows_response)

    client.http_client.request.side_effect = [MockDataTableResponse(), MockRowsResponse()]
    args = {
        "name": "test_table",
        "columns": "notfound",
        "values": "value1,Value2,value4",
        "case_insensitive_search": "true",
    }

    with capfd.disabled(), pytest.raises(SystemExit) as err:
        gcb_verify_value_in_data_table_command(client, args)

    assert err.value.code == 0


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"name": ""}, "Missing argument name."),
        ({"name": "test_table"}, "Either 'rows' or 'entry_id' must be provided."),
        ({"name": "test_table", "rows": "row1", "entry_id": "123"}, "Both 'rows' and 'entry_id' cannot be provided together."),
        ({"name": "test_table", "rows": ""}, "Missing argument rows."),
        ({"name": "test_table", "entry_id": ""}, "Missing argument entry_id."),
        (
            {"name": "test_table", "rows": "{'name','value'}"},
            "Invalid format for rows argument. Please provide a valid JSON format.",
        ),
    ],
)
def test_gcb_data_table_add_row_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_data_table_add_row_command when provided with invalid arguments."""
    from GoogleSecOps import gcb_data_table_add_row_command

    with pytest.raises(ValueError) as e:
        gcb_data_table_add_row_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_data_table_add_row_command_when_entry_id_file_not_exists(client, mocker):
    """Test gcb_data_table_add_row_command when file with given entry_id does not exist."""
    from GoogleSecOps import gcb_data_table_add_row_command

    args = {"name": "test_table", "entry_id": "123"}
    error_msg = "The file with entry_id '123' does not exist."
    mocker.patch.object(demisto, "getFilePath", side_effect=Exception("Invalid entry_id"))

    with pytest.raises(ValueError) as e:
        gcb_data_table_add_row_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_data_table_add_row_command_when_entry_id_file_is_empty(client, mocker):
    """Test gcb_data_table_add_row_command when file with given entry_id is empty."""
    from GoogleSecOps import gcb_data_table_add_row_command

    args = {"name": "test_table", "entry_id": "123"}
    error_msg = "The file with entry_id '123' is empty."
    entry_mock = {
        "id": "123",
        "path": "test_data/gcb_reference_list_command_empty_text.txt",
        "name": "gcb_reference_list_command_empty_text.txt",
    }
    mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)

    with pytest.raises(ValueError) as e:
        gcb_data_table_add_row_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args",
    [
        (
            {
                "name": "test_table",
                "rows": '[{"column_1": "value1", "column_2": "value2"},{"column_1": "value3", "column_2": "value4"}]',
            }
        ),
        ({"name": "test_table", "entry_id": "123"}),
    ],
)
def test_gcb_data_table_add_row_command_when_valid_args_provided(client, mocker, args):
    """Test gcb_data_table_add_row_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_data_table_add_row_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "123",
            "path": "test_data/gcb_data_table_add_row_command.csv",
            "name": "gcb_data_table_add_row_command.csv",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)

    # Mock data table structure response
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        data_table_response = json.loads(f.read())
    mocker.patch("GoogleSecOps.gcb_get_data_table", return_value=(data_table_response, None))

    # Load expected test responses
    with open("test_data/gcb_data_table_add_row_command_response.json") as f:
        response = f.read()
    with open("test_data/gcb_data_table_add_row_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_data_table_add_row_command_hr.md") as f:
        expected_hr = f.read()

    # Mock HTTP response
    class MockResponse:
        status_code = 200
        text = response

        def json():
            return json.loads(response)

    client.http_client.request.return_value = MockResponse

    # Execute function and validate results
    hr, ec, _ = gcb_data_table_add_row_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {
                "name": "test_table",
                "rows": '{"column_1": "value1", "invalid_column": "value2"}',
            },
            "Invalid value provided in the 'rows' parameter. Column 'invalid_column' not found in the data table.",
        ),
        (
            {
                "name": "test_table",
                "rows": '{"column_1": "value1"}',
            },
            "Invalid value provided in the 'rows' parameter. Please check if the all column names are provided.",
        ),
    ],
)
def test_gcb_data_table_add_row_command_with_invalid_rows(client, mocker, args, error_msg):
    """Test gcb_data_table_add_row_command when invalid rows data is provided."""
    from GoogleSecOps import gcb_data_table_add_row_command

    # Mock data table structure response
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        data_table_response = json.loads(f.read())
    mocker.patch("GoogleSecOps.gcb_get_data_table", return_value=(data_table_response, None))

    with pytest.raises(ValueError) as e:
        gcb_data_table_add_row_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args",
    [
        (
            {
                "name": "test_table",
                "rows": '[{"column_1": "1", "column_2": "[]/+*a"}]',
            }
        ),
        ({"name": "test_table", "entry_id": "123"}),
    ],
)
def test_gcb_data_table_remove_row_command_when_valid_args_provided(client, mocker, args):
    """Test gcb_data_table_remove_row_command for valid output when valid arguments are provided."""
    from GoogleSecOps import gcb_data_table_remove_row_command

    if args.get("entry_id"):
        entry_mock = {
            "id": "123",
            "path": "test_data/gcb_data_table_remove_row_command.csv",
            "name": "gcb_data_table_remove_row_command.csv",
        }
        mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)

    # Mock data table structure response
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        data_table_response = json.loads(f.read())
    mocker.patch("GoogleSecOps.gcb_get_data_table", return_value=(data_table_response, None))

    # Mock data table rows response
    with open("test_data/gcb_get_data_table_command_rows_response.json") as f:
        rows_response = json.loads(f.read())
    mocker.patch("GoogleSecOps.gcb_get_data_table_rows", return_value=rows_response)

    # Load expected test responses
    with open("test_data/gcb_data_table_remove_row_command_ec.json") as f:
        expected_ec = json.loads(f.read())
    with open("test_data/gcb_data_table_remove_row_command_hr.md") as f:
        expected_hr = f.read()

    # Mock HTTP response for delete operation
    class MockResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {}

    client.http_client.request.return_value = MockResponse()

    # Execute function and validate results
    hr, ec, _ = gcb_data_table_remove_row_command(client, args)

    assert hr == expected_hr
    assert ec == expected_ec


@pytest.mark.parametrize(
    "args,error_msg",
    [
        ({"name": ""}, "Missing argument name."),
        ({"name": "test_table"}, "Either 'rows' or 'entry_id' must be provided."),
        ({"name": "test_table", "rows": "row1", "entry_id": "123"}, "Both 'rows' and 'entry_id' cannot be provided together."),
        ({"name": "test_table", "rows": ""}, "Missing argument rows."),
        ({"name": "test_table", "entry_id": ""}, "Missing argument entry_id."),
        (
            {"name": "test_table", "rows": "{'name','value'}"},
            "Invalid format for rows argument. Please provide a valid JSON format.",
        ),
    ],
)
def test_gcb_data_table_remove_row_command_when_invalid_args_provided(client, args, error_msg):
    """Test gcb_data_table_remove_row_command when provided with invalid arguments."""
    from GoogleSecOps import gcb_data_table_remove_row_command

    with pytest.raises(ValueError) as e:
        gcb_data_table_remove_row_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_data_table_remove_row_command_when_entry_id_file_not_exists(client, mocker):
    """Test gcb_data_table_remove_row_command when file with given entry_id does not exist."""
    from GoogleSecOps import gcb_data_table_remove_row_command

    args = {"name": "test_table", "entry_id": "123"}
    error_msg = "The file with entry_id '123' does not exist."
    mocker.patch.object(demisto, "getFilePath", side_effect=Exception("Invalid entry_id"))

    with pytest.raises(ValueError) as e:
        gcb_data_table_remove_row_command(client, args)
    assert str(e.value) == error_msg


def test_gcb_data_table_remove_row_command_when_entry_id_file_is_empty(client, mocker):
    """Test gcb_data_table_remove_row_command when file with given entry_id is empty."""
    from GoogleSecOps import gcb_data_table_remove_row_command

    args = {"name": "test_table", "entry_id": "123"}
    error_msg = "The file with entry_id '123' is empty."
    entry_mock = {
        "id": "123",
        "path": "test_data/gcb_reference_list_command_empty_text.txt",
        "name": "gcb_reference_list_command_empty_text.txt",
    }
    mocker.patch.object(demisto, "getFilePath", return_value=entry_mock)

    with pytest.raises(ValueError) as e:
        gcb_data_table_remove_row_command(client, args)
    assert str(e.value) == error_msg


@pytest.mark.parametrize(
    "args,error_msg",
    [
        (
            {
                "name": "test_table",
                "rows": '[{"column_1": "value1", "invalid_column": "value2"}]',
            },
            "Invalid value provided in the 'rows' parameter. Column 'invalid_column' not found in the data table.",
        ),
    ],
)
def test_gcb_data_table_remove_row_command_with_invalid_rows(client, mocker, args, error_msg):
    """Test gcb_data_table_remove_row_command when invalid rows data is provided."""
    from GoogleSecOps import gcb_data_table_remove_row_command

    # Mock data table structure response
    with open("test_data/gcb_get_data_table_command_response.json") as f:
        data_table_response = json.loads(f.read())
    mocker.patch("GoogleSecOps.gcb_get_data_table", return_value=(data_table_response, None))

    with pytest.raises(ValueError) as e:
        gcb_data_table_remove_row_command(client, args)

    assert str(e.value) == error_msg


def test_gcb_get_detection_command_success(client):
    """Test gcb_get_detection_command with a successful response."""
    from GoogleSecOps import gcb_get_detection_command

    # Load the test data from files
    with open("test_data/gcb_get_detection_command_response.json") as f:
        response = f.read()

    with open("test_data/gcb_get_detection_command_ec.json") as f:
        expected_ec = json.load(f)

    with open("test_data/gcb_get_detection_command_hr.md") as f:
        expected_hr = f.read()

    # Mock the gcb_get_detection function to return our test data
    class MockResponse:
        status_code = 200
        text = response

        def json(self):
            return json.loads(response)

    client.http_client.request.return_value = MockResponse()

    hr, ec, _ = gcb_get_detection_command(client, {"rule_id": "ru_dummy_rule_id", "detection_id": "de_dummy_detection_id"})

    # Verify the output
    assert hr == expected_hr
    assert ec == expected_ec


def test_gcb_get_detection_command_empty_response(client):
    """Test gcb_get_detection_command when API returns an empty response."""
    from GoogleSecOps import gcb_get_detection_command

    # Mock the gcb_get_detection function to return empty response
    class MockResponse:
        status_code = 200
        text = "{}"

        def json(self):
            return {}

    client.http_client.request.return_value = MockResponse()

    hr, ec, _ = gcb_get_detection_command(client, {"rule_id": "ru_dummy_rule_id", "detection_id": "de_dummy_detection_id"})

    # Verify the output for empty response
    assert hr == "### No Detection Details Found"
    assert ec == {}


@pytest.mark.parametrize(
    "args, expected_error_message",
    [
        ({}, MESSAGES["REQUIRED_ARGUMENT"].format("rule_id")),
        ({"rule_id": "ru_dummy_rule_id"}, MESSAGES["REQUIRED_ARGUMENT"].format("detection_id")),
    ],
)
def test_gcb_get_detection_command_invalid_args(client, args, expected_error_message):
    """Test gcb_get_detection_command with invalid arguments."""
    from GoogleSecOps import gcb_get_detection_command

    with pytest.raises(ValueError) as error:
        gcb_get_detection_command(client, args)

    assert expected_error_message == str(error.value)
