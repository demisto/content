import json
import os
from email.utils import format_datetime
from http import HTTPStatus

import dateparser
import demistomock as demisto
import pytest
from CommonServerPython import *
from ForcepointEventCollector import Client, fetch_events, get_events_command


@pytest.fixture(autouse=True)
def mock_client():
    return Client(
        base_url="https://test.com",
        verify=False,
        proxy=False,
        username="user_name",
        password="password",
        utc_now=dateparser.parse("2020-01-01T00:00:00Z"),
    )


@pytest.fixture(autouse=True)
def mock_token_requests(requests_mock):
    token_response = {
        "access_token": "mock_access_token",
        "access_token_expires_in": 1800,
        "refresh_token": "mock_refresh_token",
        "refresh_token_expires_in": 3600
    }
    requests_mock.post(
        "https://test.com/dlp/rest/v1/auth/refresh-token",
        json=token_response,
        headers={"Date": format_datetime(datetime.now(timezone.utc))},
        status_code=HTTPStatus.OK,
    )


@pytest.fixture
def context_patch(monkeypatch):
    """Fixture to mock integration context access."""
    context = {}
    monkeypatch.setattr("ForcepointEventCollector.get_integration_context", lambda: context.copy())
    monkeypatch.setattr("ForcepointEventCollector.set_integration_context", context.update)
    return context


@pytest.fixture
def decorated_dummy():
    from ForcepointEventCollector import validate_authentication

    @validate_authentication
    def dummy_command(_):
        return "API_CALL_OK"

    return dummy_command


def test_get_events_command(requests_mock, mocker, mock_client: Client):
    """Tests get-events command function.

    Checks the output of the command function with the expected output.
    """
    client = mock_client
    since_time = "2022-12-26T00:00:00Z"
    mock_response = {
        "incidents": [generate_mocked_event(1, since_time), generate_mocked_event(1, since_time)],
        "total_count": 2,
        "total_returned": 2,
    }
    args = {"since_time": since_time, "limit": 2}
    # mocker.patch.object(Client, "get_access_token", return_value={"access_token": "access_token"})
    requests_mock.post("https://test.com/dlp/rest/v1/incidents", json=mock_response)
    result, events = get_events_command(client, args)

    assert len(events) == mock_response.get("total_count")
    assert events == mock_response.get("incidents")


def generate_mocked_event(event_id, event_time):
    return {
        "_collector_source": "API",
        "action": "AUTHORIZED",
        "analyzed_by": "Policy Engine test.corp.service.com",
        "channel": "EMAIL",
        "destination": "John.Doe@test.com",
        "details": "SOS",
        "detected_by": "Forcepoint Email Security on test.corp.service.com",
        "event_id": "14070409734372476071",
        "event_time": event_time,
        "file_name": "MIME Data.txt - 337.8 KB; MIME Data.txt - 59.47 KB",
        "id": event_id,
        "ignored_incidents": False,
        "incident_time": event_time,
        "maximum_matches": 1,
        "partition_index": 20210213,
        "policies": "TTL",
        "released_incident": False,
        "severity": "LOW",
        "source": {
            "business_unit": "Excluded Resources",
            "department": "Quality Excellence",
            "email_address": "John.Doe@test.com",
            "login_name": "FooBar",
            "manager": "John Doe",
        },
        "status": "New",
        "transaction_size": 423151,
        "violation_triggers": 1,
    }


@pytest.mark.parametrize(
    "scenario, utc_now, max_fetch, last_fetch_time, api_limit, last_events_ids, incidents_per_time,"
    "returned_events_ids, forward_last_events_ids, forward_last_fetch, backward_done, backward_last_events_ids,"
    "backward_last_fetch, backward_to_time",
    [
        (
            "get all events between the timespan",  # scenario
            "01/01/2020 00:01:00",  # utc now
            10,  # max_fetch.
            "01/01/2020 00:00:00",  # last_fetch_time
            10,  # max API returned limit.
            [],  # last_events_ids
            {  # incidents_per_time
                ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): {
                    1: "01/01/2020 00:00:01",
                    2: "01/01/2020 00:00:02",
                    3: "01/01/2020 00:00:03",
                    4: "01/01/2020 00:00:04",
                    5: "01/01/2020 00:00:05",
                    6: "01/01/2020 00:00:06",
                    7: "01/01/2020 00:00:07",
                    8: "01/01/2020 00:00:08",
                    9: "01/01/2020 00:00:09",
                    10: "01/01/2020 00:00:10",
                },
            },
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # returned_events_ids
            [10],  # forward_last_events_ids
            "01/01/2020 00:00:10",  # forward_last_fetch
            False,  # backward_done
            [],  # backward_last_events_ids
            "01/01/2020 00:00:00",  # backward_last_fetch
            "01/01/2020 00:01:00",  # backward_to_time
        ),
        (
            "all events were already fetched, force move to next second",  # scenario
            "01/01/2020 00:01:00",  # utc now
            10,  # max_fetch.
            "01/01/2020 00:00:00",  # last_fetch_time
            10,  # max API returned limit.
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],  # last_events_ids
            {  # incidents_per_time
                ("01/01/2020 00:00:00", "01/01/2020 00:01:00"): {
                    1: "01/01/2020 00:00:00",
                    2: "01/01/2020 00:00:00",
                    3: "01/01/2020 00:00:00",
                    4: "01/01/2020 00:00:00",
                    5: "01/01/2020 00:00:00",
                    6: "01/01/2020 00:00:00",
                    7: "01/01/2020 00:00:00",
                    8: "01/01/2020 00:00:00",
                    9: "01/01/2020 00:00:00",
                    10: "01/01/2020 00:00:00",
                },
            },
            [],  # returned_events_ids
            [],  # forward_last_events_ids
            "01/01/2020 00:00:01",  # forward_last_fetch
            False,  # backward_done
            [],  # backward_last_events_ids
            "01/01/2020 00:00:00",  # backward_last_fetch
            "01/01/2020 00:01:00",  # backward_to_time
        ),
        (
            "testing starting from a timestamp where we already have existing events in the last fetch (dedup)",  # scenario
            "01/01/2020 00:01:00",  # utc now
            10,  # max_fetch.
            "01/01/2020 00:00:09",  # last_fetch_time
            10,  # max API returned limit.
            [9, 10],  # last_events_ids
            {  # incidents_per_time
                ("01/01/2020 00:00:09", "01/01/2020 00:01:00"): {
                    9: "01/01/2020 00:00:09",
                    10: "01/01/2020 00:00:10",
                    11: "01/01/2020 00:00:11",
                },
            },
            [11],  # returned_events_ids
            [11],  # forward_last_events_ids
            "01/01/2020 00:00:11",  # forward_last_fetch
            False,  # backward_done
            [],  # backward_last_events_ids
            "01/01/2020 00:00:00",  # backward_last_fetch
            "01/01/2020 00:01:00",  # backward_to_time
        ),
    ],
)
def test_fetch_events(
    mocker,
    scenario,
    utc_now,
    max_fetch,
    last_fetch_time,
    api_limit,
    last_events_ids,
    incidents_per_time,
    returned_events_ids,
    forward_last_events_ids,
    forward_last_fetch,
    backward_done,
    backward_last_events_ids,
    backward_last_fetch,
    backward_to_time,
):

    def mock_get_incidents(from_date, to_date):
        from_date_str = from_date
        to_date_str = to_date
        incidents = [
            generate_mocked_event(event_id, event_time)
            for event_id, event_time in incidents_per_time.get((from_date_str, to_date_str)).items()
        ]
        return {
            "incidents": incidents[:api_limit],
            "total_count": len(incidents),
            "total_returned": min(len(incidents), api_limit),
        }

    mocked_client = mocker.Mock()
    mocked_client.list_incidents.side_effect = mock_get_incidents
    mocked_client.api_limit = api_limit
    mocked_client.utc_now = dateparser.parse(utc_now)

    mocked_send_events_to_xsiam = mocker.patch("ForcepointEventCollector.send_events_to_xsiam")
    mocked_demisto_set_last_run = mocker.patch.object(demisto, "setLastRun")

    last_run = {
        "forward": {
            "last_fetch": last_fetch_time,
            "last_events_ids": last_events_ids,
        }
    }

    mocker.patch.object(demisto, "getLastRun", return_value=last_run)

    fetch_events(
        client=mocked_client,
        max_fetch=max_fetch,
    )

    assert mocked_send_events_to_xsiam.called, f"{scenario} - send event to xsiam wasn't called"
    assert [
        event["id"] for event in mocked_send_events_to_xsiam.call_args.args[0]
    ] == returned_events_ids, f"{scenario} - event ids don't match"
    assert mocked_demisto_set_last_run.called, f"{scenario} - set last run wasn't called"
    assert mocked_demisto_set_last_run.call_args.args[0] == {
        "forward": {"last_events_ids": forward_last_events_ids, "last_fetch": forward_last_fetch}
    }, f"{scenario} - set last run doesn't match expected value"


def load_mock_response(file_name: str) -> dict:
    """
    Load mock file that simulates an API response.

    Args:
        file_name (str): Name of the mock response JSON file to return.

    Returns:
        dict: Parsed JSON content from the mock file.
    """
    file_path = os.path.join("test_data", file_name)
    with open(file_path, mode="r", encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


def test_list_policy_command(requests_mock, mock_client: Client):
    """
    Scenario: List enabled policies with a limit of 50.
    Given:
     - User provides a type and limit in the command arguments.
    When:
     - The `forcepoint_dlp_list_policy` command is called.
    Then:
     - Ensure that the correct number of policies are returned.
     - Ensure outputs prefix and key field are correct.
     - Ensure the response matches the mocked data.
    """
    from ForcepointEventCollector import list_policy_command

    json_response = load_mock_response("list_policies.json")

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names?type=DLP",
        json=json_response,
        status_code=HTTPStatus.OK,
    )
    result = list_policy_command(
        mock_client,
        {
            "type": "DLP",
            "limit": "50",
        },
    )

    assert result.outputs_prefix == "ForcepointDlp.Policy"
    assert result.outputs_key_field == "name"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 2
    for i, output in enumerate(result.outputs, start=1):
        assert output["name"] == f"Policy{i}"


def test_error_list_policy_command(requests_mock, mock_client):
    """
    Test case to validate handling of HTTP 420 status code and ensure correct error message.
    """
    from ForcepointEventCollector import (NO_CONTENT_CODE, NO_CONTENT_MESSAGE,
                                          list_policy_command)

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names?type=DLP",
        status_code=NO_CONTENT_CODE,
    )

    with pytest.raises(DemistoException) as error_info:
        list_policy_command(
            mock_client,
            {
                "type": "DLP",
                "limit": "50",
            },
        )

    assert NO_CONTENT_MESSAGE == str(error_info.value)


def test_list_policy_rule_command(requests_mock, mock_client: Client):
    """
    Scenario: List the rules and classifiers for a specified policy.
    Given:
     - A valid policy name.
    When:
     - The `forcepoint-dlp-list-policy-rule` command is executed.
    Then:
     - Ensure that the response is correctly parsed and outputs are generated.
    """
    from ForcepointEventCollector import list_policy_rule_command

    json_response = load_mock_response("list_policy_rules.json")
    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules",
        json=json_response,
        status_code=HTTPStatus.OK,
    )

    result = list_policy_rule_command(
        mock_client,
        {
            "policy_name": "hard4",
        },
    )[0]
    assert result.outputs_prefix == "ForcepointDlp.Policy"
    assert result.outputs_key_field == "policy_name"
    assert isinstance(result.outputs, dict)
    assert result.outputs["policy_name"] == "hard4"
    assert len(result.outputs["Rule"]) == 2
    assert result.outputs["Rule"][0]["rule_name"] == "rule1"
    assert result.outputs["Rule"][1]["rule_name"] == "rule2"
    assert result.outputs["Rule"][0]["Classifier"][0]["classifier_name"] == "test"


def test_error_list_policy_rule_command(requests_mock, mock_client):
    """
    Test case to validate handling of HTTP 420 status code and ensure correct error message.
    """
    from ForcepointEventCollector import (NO_CONTENT_CODE, NO_CONTENT_MESSAGE,
                                          list_policy_rule_command)

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules",
        status_code=NO_CONTENT_CODE,
    )

    with pytest.raises(DemistoException) as error_info:
        list_policy_rule_command(
            mock_client,
            {
                "policy_name": "hard4",
            },
        )

    assert NO_CONTENT_MESSAGE == str(error_info.value)


def test_list_exception_rule_command(requests_mock, mock_client: Client):
    """
    Scenario: List all exception rules associated with policies.
    Given:
     - A valid policy type.
    When:
     - The `forcepoint-dlp-list-exception-rule` command is executed.
    Then:
     - Ensure that the response is correctly parsed and outputs are generated.
    """
    from ForcepointEventCollector import list_exception_rule_command

    json_response = load_mock_response("list_exception_rules.json")
    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules/exceptions/all",
        json=json_response,
        status_code=HTTPStatus.OK,
    )

    result = list_exception_rule_command(
        mock_client,
        {
            "policy_type": "DLP",
            "all_results": "false",
            "limit": "50",
        },
    )
    assert result.outputs_prefix == "ForcepointDlp.PolicyException"
    assert result.outputs_key_field == "policy_name"
    assert isinstance(result.outputs, list)
    assert len(result.outputs) == 1
    assert result.outputs[0]["policy_name"] == "test_policy"
    assert result.outputs[0]["rule_name"] == "test_rule"
    assert result.outputs[0]["exception_rule_names"][0] == "test_exception"


def test_get_exception_rule_command(requests_mock, mock_client: Client):
    """
    Scenario: List all exception rules associated with policies.
    Given:
     - A valid policy type.
    When:
     - The `forcepoint-dlp-list-exception-rule` command is executed.
    Then:
     - Ensure that the response is correctly parsed and outputs are generated.
    """
    from ForcepointEventCollector import list_exception_rule_command

    json_response = load_mock_response("get_exception_rule.json")
    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules/exceptions?type=DLP&policyName=test&ruleName=test",
        json=json_response,
        status_code=HTTPStatus.OK,
    )

    result = list_exception_rule_command(
        mock_client,
        {
            "policy_name": "test",
            "rule_name": "test",
        },
    )

    assert result.outputs_prefix == "ForcepointDlp.PolicyException"
    assert result.outputs_key_field == "policy_name"
    assert isinstance(result.outputs, dict)
    assert len(result.outputs["RuleException"]) == 1
    assert result.outputs["parent_policy_name"] == "test_policy"
    assert result.outputs["parent_rule_name"] == "test_rule"


def test_create_rule_command_success(requests_mock, mock_client: Client):
    """
    Scenario: Successfully create a new rule in a DLP policy.
    Given:
     - A valid policy name and rule details are provided in the arguments.
    When:
     - The `create_rule_command` is executed.
    Then:
     - Ensure the rule is successfully created with a 201 status.
     - Ensure the correct readable output is returned.
    """
    from ForcepointEventCollector import create_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names",
        json=load_mock_response("list_policies.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules?policyName=TestPolicy",
        json=load_mock_response("list_policy_rules.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.post(
        url=f"{mock_client._base_url}/policy/rules",
        status_code=HTTPStatus.CREATED,
    )

    args = {
        "dlp_version": "10.2.0",
        "policy_name": "TestPolicy",
        "policy_enabled": "true",
        "predefined_policy": "false",
        "rule_name": "TestRule",
        "rule_enabled": "true",
        "rule_parts_count_type": "CROSS_COUNT",
        "rule_condition_relation_type": "AND",
        "classifier_name": "TestClassifier",
        "classifier_predefined": "false",
        "classifier_position": 1,
        "classifier_threshold_type": "CHECK_GREATER_THAN",
        "classifier_threshold_value_from": 1,
        "classifier_threshold_value_to": 5,
        "classifier_threshold_calculate_type": "UNIQUE",
        "policy_description": "Test policy description",
        "policy_level": 2,
        "policy_data_type": "NETWORKING",
    }

    result = create_rule_command(mock_client, args)

    assert (
        result.readable_output == "Rule `TestRule` was successfully created in policy 'TestPolicy'."
    )


def test_create_rule_command_failure_rule_exists(requests_mock, mock_client: Client):
    """
    Scenario: Attempt to create a rule that already exists in a DLP policy.
    Given:
     - A valid policy name and rule details are provided in the arguments.
    When:
     - The `create_rule_command` is executed for a rule that already exists.
    Then:
     - Ensure a DemistoException is raised with the correct message.
    """
    from ForcepointEventCollector import create_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names",
        json=load_mock_response("list_policies.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules?policyName=Policy1",
        json=load_mock_response("list_policy_rules.json"),
        status_code=HTTPStatus.OK,
    )

    args = {
        "dlp_version": "10.2.0",
        "policy_name": "Policy1",
        "policy_enabled": "true",
        "predefined_policy": "false",
        "rule_name": "rule1",
        "rule_enabled": "true",
        "rule_parts_count_type": "CROSS_COUNT",
        "rule_condition_relation_type": "AND",
        "classifier_name": "TestClassifier",
        "classifier_predefined": "false",
        "classifier_position": 1,
        "classifier_threshold_type": "CHECK_GREATER_THAN",
        "classifier_threshold_value_from": 1,
        "classifier_threshold_value_to": 5,
        "classifier_threshold_calculate_type": "UNIQUE",
        "policy_description": "Test policy description",
        "policy_level": 2,
        "policy_data_type": "NETWORKING",
    }

    with pytest.raises(DemistoException) as exc_info:
        create_rule_command(mock_client, args)

    assert str(exc_info.value) == "The rule is already exist. Use the update command."


def test_update_rule_command_success(requests_mock, mock_client: Client):
    """
    Scenario: Successfully update an existing rule in a DLP policy.
    Given:
     - A valid policy name and rule details are provided in the arguments.
    When:
     - The `update_rule_command` is executed.
    Then:
     - Ensure the rule is successfully updated with a 200 status.
     - Ensure the correct readable output is returned.
    """
    from ForcepointEventCollector import update_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names",
        json=load_mock_response("list_policies.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules?policyName=Policy1",
        json=load_mock_response("list_policy_rules.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.post(
        url=f"{mock_client._base_url}/policy/rules",
        status_code=HTTPStatus.CREATED,
    )

    args = {
        "dlp_version": "10.2.0",
        "policy_name": "Policy1",
        "policy_enabled": "true",
        "predefined_policy": "false",
        "rule_name": "rule1",
        "rule_enabled": "true",
        "rule_parts_count_type": "CROSS_COUNT",
        "rule_condition_relation_type": "AND",
        "classifier_name": "TestClassifier",
        "classifier_predefined": "false",
        "classifier_position": 2,
        "classifier_threshold_type": "CHECK_GREATER_THAN",
        "classifier_threshold_value_from": 1,
        "classifier_threshold_value_to": 5,
        "classifier_threshold_calculate_type": "UNIQUE",
        "policy_description": "Updated policy description",
        "policy_level": 2,
        "policy_data_type": "NETWORKING",
    }

    result = update_rule_command(mock_client, args)

    assert result.readable_output == "Rule `rule1` was successfully updated in policy 'Policy1'."


def test_update_rule_command_failure_rule_not_found(requests_mock, mock_client: Client):
    """
    Scenario: Attempt to update a rule that does not exist in a DLP policy.
    Given:
     - A valid policy name and rule details are provided in the arguments.
    When:
     - The `update_rule_command` is executed for a rule that does not exist.
    Then:
     - Ensure a DemistoException is raised with the correct message.
    """
    from ForcepointEventCollector import update_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names",
        json=load_mock_response("list_policies.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules?policyName=Policy1",
        json={"rules": []},  # No rules exist in the policy
        status_code=HTTPStatus.OK,
    )

    args = {
        "dlp_version": "10.2.0",
        "policy_name": "Policy1",
        "policy_enabled": "true",
        "predefined_policy": "false",
        "rule_name": "NonExistentRule",
        "rule_enabled": "true",
        "rule_parts_count_type": "CROSS_COUNT",
        "rule_condition_relation_type": "AND",
        "classifier_name": "TestClassifier",
        "classifier_predefined": "false",
        "classifier_position": 1,
        "classifier_threshold_type": "CHECK_GREATER_THAN",
        "classifier_threshold_value_from": 1,
        "classifier_threshold_value_to": 5,
        "classifier_threshold_calculate_type": "UNIQUE",
        "policy_description": "Updated policy description",
        "policy_level": 2,
        "policy_data_type": "NETWORKING",
    }

    with pytest.raises(DemistoException) as exc_info:
        update_rule_command(mock_client, args)

    assert str(exc_info.value) == "The rule does not exist. Use the create command."


def test_update_rule_command_failure_policy_not_found(requests_mock, mock_client: Client):
    """
    Scenario: Attempt to update a rule in a non-existent policy.
    Given:
     - A policy name that does not exist.
    When:
     - The `update_rule_command` is executed.
    Then:
     - Ensure a DemistoException is raised with the correct message.
    """
    from ForcepointEventCollector import update_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names",
        json={"enabled_policies": ["AnotherPolicy"]},  # "TestPolicy" does not exist
        status_code=HTTPStatus.OK,
    )

    args = {
        "dlp_version": "10.2.0",
        "policy_name": "TestPolicy",  # Non-existent policy
        "policy_enabled": "true",
        "predefined_policy": "false",
        "rule_name": "rule1",
        "rule_enabled": "true",
        "rule_parts_count_type": "CROSS_COUNT",
        "rule_condition_relation_type": "AND",
        "classifier_name": "TestClassifier",
        "classifier_predefined": "false",
        "classifier_position": 1,
        "classifier_threshold_type": "CHECK_GREATER_THAN",
        "classifier_threshold_value_from": 1,
        "classifier_threshold_value_to": 5,
        "classifier_threshold_calculate_type": "UNIQUE",
        "policy_description": "Updated policy description",
        "policy_level": 2,
        "policy_data_type": "NETWORKING",
    }

    with pytest.raises(DemistoException) as exc_info:
        update_rule_command(mock_client, args)

    assert str(exc_info.value) == "The policy does not exist. Use the create command."


def test_update_rule_severity_action_command_success(requests_mock, mock_client: Client):
    """
    Scenario: Successfully update the severity actions of a rule in a DLP policy.
    Given:
     - A valid policy name, rule name, and severity action details are provided in the arguments.
    When:
     - The `update_rule_severity_action_command` is executed.
    Then:
     - Ensure the rule's severity actions are successfully updated.
     - Ensure the correct readable output is returned.
    """
    from ForcepointEventCollector import update_rule_severity_action_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules/severity-action?policyName=Policy1",
        json=load_mock_response("get_severity_action_rules.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.post(
        url=f"{mock_client._base_url}/policy/rules/severity-action",
        status_code=HTTPStatus.CREATED,
    )

    args = {
        "policy_name": "Policy1",
        "rule_name": "rule1",
        "rule_type": "EVERY_MATCHED_CONDITION",
        "rule_max_matches": "GREATEST_NUMBER",
        "risk_adaptive_protection_enabled": "false",
        "severity_classifier_selected": "true",
        "severity_classifier_number_of_matches": 3,
        "severity_classifier_severity_type": "MEDIUM",
        "severity_classifier_action_plan": "Audit Only",
    }

    result = update_rule_severity_action_command(mock_client, args)

    assert result.readable_output == (
        "Severity actions for Rule `rule1` in policy 'Policy1' was successfully updated."
    )


def test_update_rule_source_destination_command_success(requests_mock, mock_client: Client):
    """
    Scenario: Successfully update the source and destination settings of a rule in a DLP policy.
    Given:
     - A valid policy name, rule name, and source/destination details are provided in the arguments.
    When:
     - The `update_rule_source_destination_command` is executed.
    Then:
     - Ensure the rule's source and destination settings are successfully updated.
     - Ensure the correct readable output is returned.
    """
    from ForcepointEventCollector import update_rule_source_destination_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules/source-destination?policyName=Policy1",
        json=load_mock_response("get_source_destination_rules.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.post(
        url=f"{mock_client._base_url}/policy/rules/source-destination",
        status_code=HTTPStatus.CREATED,
    )

    args = {
        "policy_name": "Policy1",
        "rule_name": "rule1",
        "rule_source_endpoint_channel_machine_type": "ALL_MACHINES",
        "rule_source_endpoint_connection_type": "ANYWARE",
        "rule_destination_email_monitor_directions": ["OUTGOING"],
        "channel_type": "HTTP",
        "channel_enabled": "true",
        "resource_name": "Excluded Resources",
        "resource_type": "BUSINESS_UNIT",
        "resource_include": "false",
    }

    result = update_rule_source_destination_command(mock_client, args)

    assert result.readable_output == (
        "Source and destination for Rule `rule1` in policy 'Policy1' was successfully updated."
    )


def test_create_exception_rule_command_success(requests_mock, mock_client: Client):
    """
    Scenario: Successfully create a new exception rule for a specified parent rule and policy type.
    Given:
     - A valid parent policy name, rule name, and exception rule details are provided.
    When:
     - The `create_exception_rule_command` is executed.
    Then:
     - Ensure the exception rule is successfully created.
     - Ensure the correct readable output is returned.
    """
    from ForcepointEventCollector import create_exception_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules/exceptions?type=DLP&policyName=test_policy&ruleName=test_rule",
        json={
            "parent_policy_name": "test_policy",
            "parent_rule_name": "test_rule",
            "policy_type": "DLP",
            "exception_rules": [],
        },
        status_code=HTTPStatus.OK,
    )

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names?type=DLP",
        json={"enabled_policies": ["test_policy"]},  # "TestPolicy" does not exist
        status_code=HTTPStatus.OK,
    )

    requests_mock.post(
        url=f"{mock_client._base_url}/policy/rules/exceptions",
        status_code=HTTPStatus.CREATED,
    )

    args = {
        "parent_policy_name": "test_policy",
        "parent_rule_name": "test_rule",
        "policy_type": "DLP",
        "exception_rule_name": "new_exception_rule",
        "enabled": "true",
        "description": "New exception rule",
        "parts_count_type": "CROSS_COUNT",
        "condition_relation_type": "AND",
        "condition_enabled": "true",
        "source_enabled": "false",
        "destination_enabled": "false",
        "classifier_name": "new_classifier",
        "classifier_predefined": "false",
        "classifier_position": 1,
        "classifier_threshold_type": "CHECK_GREATER_THAN",
        "classifier_threshold_value_from": 1,
        "classifier_threshold_calculate_type": "ALL",
        "severity_classifier_max_matches": "SUM_ALL",
        "severity_classifier_selected": "false",
        "severity_classifier_number_of_matches": 3,
        "severity_classifier_severity_type": "LOW",
        "severity_classifier_action_plan": "Audit Only",
    }

    result = create_exception_rule_command(mock_client, args)

    assert result.readable_output == (
        "Exception rule 'new_exception_rule' was successfully created in rule 'test_rule' under policy 'test_policy'."
    )


def test_update_exception_rule_command_success(requests_mock, mock_client: Client):
    """
    Scenario: Successfully update an existing exception rule for a specified parent rule and policy type.
    Given:
     - A valid parent policy name, rule name, and updated exception rule details are provided.
    When:
     - The `update_exception_rule_command` is executed.
    Then:
     - Ensure the exception rule is successfully updated.
     - Ensure the correct readable output is returned.
    """
    from ForcepointEventCollector import update_exception_rule_command

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/rules/exceptions?type=DLP&policyName=test_policy&ruleName=test_rule",
        json=load_mock_response("get_exception_rule.json"),
        status_code=HTTPStatus.OK,
    )

    requests_mock.get(
        url=f"{mock_client._base_url}/policy/enabled-names",
        json={"enabled_policies": ["test_policy"]},
        status_code=HTTPStatus.OK,
    )

    requests_mock.post(
        url=f"{mock_client._base_url}/policy/rules/exceptions",
        status_code=HTTPStatus.CREATED,
    )

    args = {
        "parent_policy_name": "test_policy",
        "parent_rule_name": "test_rule",
        "policy_type": "DLP",
        "exception_rule_name": "testbeniex",
        "enabled": "true",
        "description": "Updated exception rule",
        "parts_count_type": "INTERNAL_COUNT",
        "condition_relation_type": "OR",
        "condition_enabled": "true",
        "source_enabled": "false",
        "destination_enabled": "false",
        "classifier_name": ".htpasswd File Name",
        "classifier_predefined": "true",
        "classifier_position": 1,
        "classifier_threshold_type": "CHECK_EMPTY",
        "classifier_threshold_value_from": 0,
        "classifier_threshold_calculate_type": "ALL",
        "severity_classifier_max_matches": "SUM_ALL",
        "severity_classifier_selected": "true",
        "severity_classifier_number_of_matches": 2,
        "severity_classifier_severity_type": "HIGH",
        "severity_classifier_action_plan": "Block",
    }

    result = update_exception_rule_command(mock_client, args)

    assert result.readable_output == (
        "Exception rule 'testbeniex' was successfully updated in rule 'test_rule' under policy 'test_policy'."
    )


def test_list_incidents_command(requests_mock, mock_client: Client):
    """
    Scenario: List enabled policies with a limit of 50.
    Given:
     - User provides a type and limit in the command arguments.
    When:
     - The `list_incidents_command` command is called.
    Then:
     - Ensure that the correct number of policies are returned.
     - Ensure outputs prefix and key field are correct.
     - Ensure the response matches the mocked data.
    """
    from ForcepointEventCollector import list_incidents_command

    json_response = load_mock_response("list_incidents.json")

    requests_mock.post(
        url=f"{mock_client._base_url}/incidents",
        json=json_response,
        status_code=HTTPStatus.OK,
    )
    result = list_incidents_command(
        mock_client,
        {
            "from_date": "3 months",
            "to_date": "now",
        },
    )

    assert result.outputs_prefix == "ForcepointDlp.Incident"
    assert result.outputs_key_field == "id"


def test_update_incident_command(requests_mock, mock_client: Client):
    """
    Scenario: List enabled policies with a limit of 50.
    Given:
     - User provides a type and limit in the command arguments.
    When:
     - The `list_incidents_command` command is called.
    Then:
     - Ensure that the correct number of policies are returned.
     - Ensure outputs prefix and key field are correct.
     - Ensure the response matches the mocked data.
    """
    from ForcepointEventCollector import update_incident_command

    requests_mock.post(
        url=f"{mock_client._base_url}/incidents/update",
        status_code=HTTPStatus.OK,
    )
    result = update_incident_command(
        mock_client,
        {
            "event_ids": "1234s",
            "type": "INCIDENTS",
            "severity": "LOW",
        },
    )
    result.readable_output == "Rule `TestRule` was successfully created in policy 'TestPolicy'."


def test_validate_authentication(mock_client: Client, context_patch, decorated_dummy):
    """
    Scenario: Access token is still valid.
    Given:
    - A valid access token is already stored and not expired.
    When:
    - A decorated Client method is called.
    Then:
    - Ensure that no new authentication is performed.
    - Ensure existing token is used in headers.
    - Ensure context_patch wasn't changed.
    """
    now = datetime.now(timezone.utc)
    context = {
        "access_token": "valid-token",
        "access_token_expiry_date": (now + timedelta(minutes=10)).isoformat(),
        "refresh_token": "valid-refresh",
        "refresh_token_expiry_date": (now + timedelta(minutes=30)).isoformat(),
    }
    context_patch.update(context)

    result = decorated_dummy(mock_client)

    assert result == "API_CALL_OK"
    assert mock_client._headers["Authorization"] == "Bearer valid-token"
    assert context == context_patch


def test_validate_authentication_get_access_token(requests_mock, mock_client: Client, context_patch, decorated_dummy):
    """
    Scenario: Access token expired, refresh token is still valid.
    Given:
    - An expired access token.
    - A valid, non-expired refresh token.
    When:
    - A decorated API function is called.
    Then:
    - Ensure the access token is refreshed.
    - Ensure the new token is used in headers.
    - Ensure access_token token in context was changed.
    - Ensure access_token_expiry_date token in context was changed.
    - Ensure refresh_token token in context wasn't changed.
    - Ensure refresh_token_expiry_date token in context wasn't changed.
    """
    now = datetime.now(timezone.utc)
    context = {
        "access_token": "expired-token",
        "access_token_expiry_date": (now - timedelta(minutes=1)).isoformat(),
        "refresh_token": "valid-refresh",
        "refresh_token_expiry_date": (now + timedelta(minutes=30)).isoformat(),
    }
    context_patch.update(context)
    requests_mock.post(
        f"https://test.com/dlp/rest/v1/auth/access-token",
        json={
            "access_token": "new-access-token",
            "access_token_expires_in": 1800,
        },
        status_code=HTTPStatus.OK,
        headers={"Date": format_datetime(now)},
    )

    result = decorated_dummy(mock_client)

    assert result == "API_CALL_OK"
    assert mock_client._headers["Authorization"] == "Bearer new-access-token"
    assert context_patch["access_token"] == "new-access-token"
    assert context_patch["access_token_expiry_date"] != context["access_token_expiry_date"]
    assert context_patch["refresh_token"] == context["refresh_token"]
    assert context_patch["refresh_token_expiry_date"] == context["refresh_token_expiry_date"]


def test_validate_authentication_get_refresh_token(requests_mock, mock_client: Client, context_patch, decorated_dummy):
    """
    Scenario: Both access and refresh tokens are missing or expired.
    Given:
    - No tokens or expired tokens in the integration context.
    When:
    - A decorated API function is called.
    Then:
    - Ensure the full authentication flow is triggered.
    - Ensure new tokens are stored and used.
    """
    now = datetime.now(timezone.utc)
    context_patch.clear()
    requests_mock.post(
        f"https://test.com/dlp/rest/v1/auth/refresh-token",
        json={
            "access_token": "new-access-token",
            "access_token_expires_in": 1800,
            "refresh_token": "new-refresh-token",
            "refresh_token_expires_in": 3600,
        },
        status_code=HTTPStatus.OK,
        headers={"Date": format_datetime(now)},
    )

    result = decorated_dummy(mock_client)

    assert result == "API_CALL_OK"
    assert mock_client._headers["Authorization"] == "Bearer new-access-token"
    assert context_patch["access_token"] == "new-access-token"
    assert context_patch["access_token_expiry_date"]
    assert context_patch["refresh_token"] == "new-refresh-token"
    assert context_patch["refresh_token_expiry_date"]
