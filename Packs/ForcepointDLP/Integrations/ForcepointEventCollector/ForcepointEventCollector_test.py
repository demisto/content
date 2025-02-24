import dateparser
import pytest
import os
import json
from http import HTTPStatus

import demistomock as demisto
from ForcepointEventCollector import fetch_events, Client, get_events_command
from CommonServerPython import *


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
    "scenario, first_fetch, utc_now, max_fetch, last_fetch_time, api_limit, last_events_ids, incidents_per_time,"
    "returned_events_ids, forward_last_events_ids, forward_last_fetch, backward_done, backward_last_events_ids,"
    "backward_last_fetch, backward_to_time",
    [
        (
            "get all events between the timespan",  # scenario
            "01/01/2020 00:00:00",  # first fetch
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
            "01/01/2020 00:00:00",  # first fetch
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
            "01/01/2020 00:00:00",  # first fetch
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
    first_fetch,
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
        first_fetch=first_fetch,
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
    from ForcepointEventCollector import list_policy_command, NO_CONTENT_CODE, NO_CONTENT_MESSAGE

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
    from ForcepointEventCollector import (
        list_policy_rule_command,
        NO_CONTENT_CODE,
        NO_CONTENT_MESSAGE,
    )

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
        "classifier_selected": "true",
        "classifier_number_of_matches": 3,
        "classifier_severity_type": "MEDIUM",
        "classifier_action_plan": "Audit Only",
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


def test_build_rule_payload():
    """
    Test case for build_rule_payload function.
    Validates both the update and creation scenarios of the rule payload.
    """
    from ForcepointEventCollector import build_rule_payload

    policy = load_mock_response("list_policy_rules.json")
    # test when classifier is exists
    result = build_rule_payload(
        dlp_version="10.2.0",
        policy_name="hard4",
        policy_enabled="true",
        predefined_policy="false",
        rule_name="rule1",
        rule_enabled="false",
        parts_count_type="ANY",
        condition_relation_type="OR",
        classifier_name="test",
        classifier_predefined="true",
        classifier_position=1,
        threshold_type="CHECK_EMPTY",
        threshold_value_from=0,
        threshold_value_to=0,
        threshold_calculate_type="ALL",
        description="Updated description",
        policy_level=3,
        policy_level_data_type="NEW_NETWORKING",
        policy=policy,
    )

    assert result["rules"][0]["enabled"] == "false"
    assert result["rules"][0]["parts_count_type"] == "ANY"
    assert result["rules"][0]["condition_relation_type"] == "OR"
    assert result["rules"][0]["classifiers"][0]["threshold_type"] == "CHECK_EMPTY"

    # test when classifier is not exists
    result = build_rule_payload(
        dlp_version="10.2.0",
        policy_name="hard4",
        policy_enabled="true",
        predefined_policy="false",
        rule_name="rule1",
        rule_enabled="false",
        parts_count_type="ANY",
        condition_relation_type="OR",
        classifier_name="test",
        classifier_predefined="true",
        classifier_position=2,
        threshold_type="CHECK_EMPTY",
        threshold_value_from=0,
        threshold_value_to=0,
        threshold_calculate_type="ALL",
        description="Updated description",
        policy_level=3,
        policy_level_data_type="NEW_NETWORKING",
        policy=policy,
    )

    assert result["rules"][0]["classifiers"][1]["threshold_type"] == "CHECK_EMPTY"

    # test when rule is not exist
    result = build_rule_payload(
        dlp_version="10.2.0",
        policy_name="hard4",
        policy_enabled="true",
        predefined_policy="false",
        rule_name="new_rule",
        rule_enabled="true",
        parts_count_type="CROSS_COUNT",
        condition_relation_type="AND",
        classifier_name="new_classifier",
        classifier_predefined="false",
        classifier_position=1,
        threshold_type="CHECK_GREATER_THAN",
        threshold_value_from=1,
        threshold_value_to=5,
        threshold_calculate_type="UNIQUE",
        description="New rule description",
        policy_level=2,
        policy_level_data_type="NETWORKING",
        policy=None,
    )
    assert result["rules"][0]["rule_name"] == "new_rule"
    assert result["rules"][0]["classifiers"][0]["classifier_name"] == "new_classifier"
    assert result["description"] == "New rule description"

    # test when using payload
    # result = build_rule_payload(
    #     dlp_version="10.2.0",
    #     policy_name="hard4",
    #     policy_enabled="true",
    #     predefined_policy="false",
    #     rule_name="rule1",
    #     rule_enabled="false",
    #     parts_count_type="ANY",
    #     condition_relation_type="OR",
    #     classifier_name="test",
    #     classifier_predefined="true",
    #     classifier_position=1,
    #     threshold_type="CHECK_EMPTY",
    #     threshold_value_from=0,
    #     threshold_value_to=0,
    #     threshold_calculate_type="ALL",
    #     description="Updated description",
    #     policy_level=3,
    #     policy_level_data_type="NEW_NETWORKING",
    #     policy=policy,
    #     payload={"payload": "yes"},
    # )
    # assert result["payload"] == "yes"


@pytest.mark.parametrize(
    "rule_name, rule_type,rule_count_type, rule_count_period, rule_rate_match_period, \
        rule_max_matches, classifier_selected, classifier_number_of_matches, override_classifier_number_of_matches,\
              classifier_severity_type, classifier_action_plan, expected",
    [
        # Update existing classifier
        (
            "rule1",
            "EVERY_MATCHED_CONDITION",
            None,
            None,
            None,
            "LEAST_NUMBER",
            "true",
            0,
            None,
            "HIGH",
            "Block",
            [0, 2, 3],
        ),
        # Replace wxisting classifier
        (
            "rule1",
            "EVERY_MATCHED_CONDITION",
            None,
            None,
            None,
            "LEAST_NUMBER",
            "true",
            5,
            0,
            "LOW",
            "Monitor",
            [5, 2, 3],
        ),
    ],
)
def test_build_severity_action_payload(
    rule_name,
    rule_type,
    rule_count_type,
    rule_count_period,
    rule_rate_match_period,
    rule_max_matches,
    classifier_selected,
    classifier_number_of_matches,
    override_classifier_number_of_matches,
    classifier_severity_type,
    classifier_action_plan,
    expected,
):
    from ForcepointEventCollector import build_severity_action_payload

    policy = load_mock_response("get_severity_action_rules.json")

    result = build_severity_action_payload(
        rule_name=rule_name,
        rule_type=rule_type,
        rule_max_matches=rule_max_matches,
        rule_count_type=rule_count_type,
        rule_count_period=rule_count_period,
        rule_rate_match_period=rule_rate_match_period,
        classifier_selected=classifier_selected,
        classifier_number_of_matches=classifier_number_of_matches,
        override_classifier_number_of_matches=override_classifier_number_of_matches,
        classifier_severity_type=classifier_severity_type,
        classifier_action_plan=classifier_action_plan,
        policy=policy,
    )
    for rule in result["rules"]:
        if rule["rule_name"] == rule_name:
            assert rule["type"] == rule_type
            assert rule["max_matches"] == rule_max_matches
            assert rule["type"] == rule_type
            for i, clsf in enumerate(rule["classifier_details"]):
                assert clsf["number_of_matches"] == expected[i]
                if clsf["number_of_matches"] == classifier_number_of_matches:
                    assert clsf["selected"] == classifier_selected
                    assert clsf["severity_type"] == classifier_severity_type
                    assert clsf["action_plan"] == classifier_action_plan


@pytest.mark.parametrize(
    "rule_name, endpoint_channel_machine_type, endpoint_connection_type,\
          email_monitor_directions, channel_type, channel_enabled, resource_name,\
              resource_type, resource_include, payload, expected",
    [
        # Update existing channel
        (
            "rule1",
            "TEST_SPECIFIC_MACHINES",
            "VPN_ONLY",
            ["OUTGOING"],
            "SPECIFIC_MACHINES",
            "false",
            "Excluded Resources",
            "DEPARTMENT",
            "true",
            None,
            1,
        ),
        # Update existing channel with new channel
        (
            "rule1",
            "TEST_SPECIFIC_MACHINES",
            "VPN_ONLY",
            ["OUTGOING"],
            "SPECIFIC_MACHINES",
            "false",
            "Excluded Resources2",
            "DEPARTMENT",
            "true",
            None,
            1,
        ),
        # Add a new channel
        (
            "rule1",
            "SPECIFIC_MACHINES",
            "VPN_ONLY",
            ["OUTGOING"],
            "FTP",
            "true",
            "New Resource",
            "TEAM",
            "true",
            None,
            2,
        ),
    ],
)
def test_build_source_destination_payload(
    rule_name,
    endpoint_channel_machine_type,
    endpoint_connection_type,
    email_monitor_directions,
    channel_type,
    channel_enabled,
    resource_name,
    resource_type,
    resource_include,
    payload,
    expected,
):
    from ForcepointEventCollector import build_source_destination_payload

    result = build_source_destination_payload(
        rule_name=rule_name,
        endpoint_channel_machine_type=endpoint_channel_machine_type,
        endpoint_connection_type=endpoint_connection_type,
        email_monitor_directions=email_monitor_directions,
        channel_type=channel_type,
        channel_enabled=channel_enabled,
        resource_name=resource_name,
        resource_type=resource_type,
        resource_include=resource_include,
        policy=load_mock_response("get_source_destination_rules.json"),
        payload=payload,
    )

    assert len(result["rules"][0]["rule_destination"]["channels"]) == expected
    for rule in result["rules"]:
        if rule["rule_name"] != rule_name:
            continue
        for channel in rule["rule_destination"]["channels"]:
            if channel["channel_type"] != channel_type:
                continue
            for resource in channel["resources"]:
                if resource["resource_name"] == resource_name:
                    assert resource["type"] == resource_type
                    assert resource["include"] == resource_include
                    break
            else:
                raise DemistoException("resource was not found")
            break
        else:
            raise DemistoException("channel was not found")
        break
    else:
        raise DemistoException("rule was not found")


@pytest.mark.parametrize(
    "parent_policy_name, parent_rule_name, policy_type, exception_rule_name, enabled, description, "
    "parts_count_type, condition_relation_type, classifier_name, classifier_predefined, classifier_position, "
    "classifier_threshold_type, classifier_threshold_value_from, classifier_threshold_calculate_type, "
    "severity_classifier_max_matches, severity_classifier_selected, severity_classifier_number_of_matches, "
    "severity_classifier_severity_type, severity_classifier_action_plan, exception_policy, payload, "
    "override_severity_classifier_number_of_matches",
    [
        # Test updating an existing exception rule
        (
            "test_policy",
            "test_rule",
            "DLP",
            "testbeniex",
            "true",
            "Updated exception rule",
            "INTERNAL_COUNT",
            "OR",
            ".htpasswd File Name",
            "true",
            1,
            "CHECK_EMPTY",
            0,
            "ALL",
            "SUM_ALL",
            "true",
            5,
            "HIGH",
            "Block",
            "get_exception_rule.json",
            None,
            0,
        ),
        # Test appending a new exception rule
        (
            "test_policy",
            "test_rule",
            "DLP",
            "new_exception_rule",
            "true",
            "New exception rule",
            "CROSS_COUNT",
            "AND",
            "new_classifier",
            "false",
            1,
            "CHECK_GREATER_THAN",
            1,
            "ALL",
            "SUM_ALL",
            "false",
            3,
            "LOW",
            "Audit Only",
            "get_exception_rule.json",
            None,
            None,
        ),
    ],
)
def test_build_exception_rule_payload(
    parent_policy_name,
    parent_rule_name,
    policy_type,
    exception_rule_name,
    enabled,
    description,
    parts_count_type,
    condition_relation_type,
    classifier_name,
    classifier_predefined,
    classifier_position,
    classifier_threshold_type,
    classifier_threshold_value_from,
    classifier_threshold_calculate_type,
    severity_classifier_max_matches,
    severity_classifier_selected,
    severity_classifier_number_of_matches,
    severity_classifier_severity_type,
    severity_classifier_action_plan,
    exception_policy,
    payload,
    override_severity_classifier_number_of_matches,
):
    from ForcepointEventCollector import build_exception_rule_payload

    exception_policy = load_mock_response("get_exception_rule.json")

    result = build_exception_rule_payload(
        parent_policy_name=parent_policy_name,
        parent_rule_name=parent_rule_name,
        policy_type=policy_type,
        exception_rule_name=exception_rule_name,
        enabled=enabled,
        description=description,
        parts_count_type=parts_count_type,
        condition_relation_type=condition_relation_type,
        condition_enabled="true",
        source_enabled="true",
        destination_enabled="destination_enabled",
        classifier_name=classifier_name,
        classifier_predefined=classifier_predefined,
        classifier_position=classifier_position,
        classifier_threshold_type=classifier_threshold_type,
        classifier_threshold_value_from=classifier_threshold_value_from,
        classifier_threshold_calculate_type=classifier_threshold_calculate_type,
        severity_classifier_max_matches=severity_classifier_max_matches,
        severity_classifier_selected=severity_classifier_selected,
        severity_classifier_number_of_matches=severity_classifier_number_of_matches,
        severity_classifier_severity_type=severity_classifier_severity_type,
        severity_classifier_action_plan=severity_classifier_action_plan,
        exception_policy=exception_policy,
        payload=payload,
        override_severity_classifier_number_of_matches=override_severity_classifier_number_of_matches,
    )
    for rule in result["exception_rules"]:
        if rule["exception_rule_name"] != exception_rule_name:
            continue
        for classifier in rule["classifiers"]:
            if classifier["classifier_name"] == classifier_name:
                assert classifier["predefined"] == classifier_predefined
                assert classifier["position"] == classifier_position
                assert classifier["threshold_type"] == classifier_threshold_type
                break
        else:
            raise DemistoException("classifier was not found")
        for classifier in rule["severity_action"]["classifier_details"]:
            if classifier["number_of_matches"] == severity_classifier_number_of_matches:
                assert classifier["severity_type"] == severity_classifier_severity_type
                break
        else:
            raise DemistoException("severity classifier was not found")
        break
    else:
        raise DemistoException("rule was not found")


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
