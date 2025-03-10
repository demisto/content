import json
from copy import deepcopy

import pytest
from NetscoutArborSightline import (
    NetscoutClient,
    fetch_incidents_command,
    list_alerts_command,
    alert_annotation_list_command,
    mitigation_list_command,
    mitigation_template_list_command,
    router_list_command,
    tms_group_list_command,
    managed_object_list_command,
    mitigation_create_command,
    clean_links,
    validate_json_arg,
    build_human_readable,
)
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import


# from Packs


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


client = NetscoutClient(base_url="dummy_url", verify=False, proxy=False, first_fetch="3 days", max_fetch=10)
http_responses = util_load_json("test_data/http_responses.json")
command_results = util_load_json("test_data/command_results.json")


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch.object(demisto, "debug")


def test_fetch_incidents_command(mocker):
    """
    Given:
    - NetscoutClient client.

    When:
     - Fetching incidents.

    Then:
     - Ensure that the incidents returned are as expected.
    """
    alerts_http_response = http_responses["incidents"]
    alerts_command_results = command_results["fetched_incidents"]

    mocker.patch.object(client, "list_alerts", return_value=alerts_http_response)
    mocker.patch.object(client, "calculate_amount_of_incidents", return_value=40)
    mocker.patch.object(demisto, "incidents")

    fetch_incidents_command(client)
    demisto.incidents.assert_called_with(alerts_command_results)


@pytest.mark.parametrize(
    "function_to_mock, function_to_test, args, http_response_key, expected_command_results_key",
    [
        ("list_alerts", list_alerts_command, {}, "incidents", "get_incidents"),
        ("get_alert", list_alerts_command, {"alert_id": 1}, "incident", "get_incident"),
        ("get_annotations", alert_annotation_list_command, {"alert_id": "2009"}, "annotations", "list_annotations"),
        ("list_mitigations", mitigation_list_command, {"limit": "3"}, "mitigations", "list_mitigations"),
        (
            "create_mitigation",
            mitigation_create_command,
            {
                "description": "just desc",
                "ip_version": "IPv4",
                "name": "test_mit",
                "ongoing": "true",
                "sub_object": '{"protection_prefixes": ["192.0.2.0/24"]}',
                "sub_type": "flowspec",
            },
            "mitigation",
            "create_mitigation",
        ),
        ("mitigation_template_list", mitigation_template_list_command, {}, "mitigation_templates", "list_mitigation_templates"),
        ("router_list", router_list_command, {}, "routers", "list_routers"),
        ("managed_object_list", managed_object_list_command, {}, "managed_objects", "list_managed_objects"),
        ("tms_group_list", tms_group_list_command, {}, "tms_groups", "list_tms_group"),
    ],
)
def test_commands(mocker, function_to_mock, function_to_test, args, http_response_key, expected_command_results_key):
    """
    Given:
    - NetscoutClient client.

    When:
     - Case A: Calling the list_alerts_command function.
     - Case B: Calling the list_alerts_command function with a specific alert.
     - Case C: Calling the alert_annotation_list_command function.
     - Case D: Calling the mitigation_list_command function with a specific alert.
     - Case E: Calling the mitigation_create_command function with mitigation details.
     - Case F: Calling the mitigation_template_list_command function.
     - Case G: Calling the router_list_command function.
     - Case H: Calling the managed_object_list_command function.
     - Case I: Calling the tms_group_list_command function.

    Then:
     - Case A: Assert that the command results has the relevant alerts with the relevant extracted fields.
     - Case B: Assert that the command results has only one alert and that it has the relevant extracted fields.
     - Case C: Assert that the command results has the relevant annotations with the relevant extracted fields.
     - Case D: Assert that the command results contains the alert ID and has the relevant mitigations with the relevant
            extracted fields.
     - Case E: Assert that the command results has the newly create mitigation with its relevant extracted fields.
     - Case F: Assert that the command results has the relevant mitigation template list with the relevant extracted
            fields.
     - Case G: Assert that the command results has the relevant router list with the relevant extracted fields.
     - Case H: Assert that the command results has the relevant list of manged groups with the relevant extracted
            fields.
     - Case I: Assert that the command results has the relevant list of tms groups with the relevant extracted fields.

    """
    mocked_http_response = http_responses[http_response_key]
    expected_command_results = command_results[expected_command_results_key]

    mocker.patch.object(client, function_to_mock, return_value=mocked_http_response)

    command_result: CommandResults = function_to_test(client, args)
    assert command_result.outputs == expected_command_results


@pytest.mark.parametrize(
    "http_response_key, expected_number_of_pages",
    [("amount_of_incidents_vanilla_case", 25), ("amount_of_incidents_one_result", 1), ("amount_of_incidents_no_results", 0)],
)
def test_calculate_amount_of_incidents(mocker, http_response_key, expected_number_of_pages):
    """
    Given:
     - Case A: A "regular" query that returns response with 25 pages.
     - Case B: A query that returns response with only one page.
     - Case C: A query that response with no pages and data.

    When:
    Calculating the amount of relevant incidents by counting the amount of pages

    Then:
     - Case A: Assert the the amount of incidents calculated is 25
     - Case B: Assert the the amount of incidents calculated is 1
     - Case C: Assert the the amount of incidents calculated is 0

    """
    mocked_http_response = http_responses[http_response_key]

    mocker.patch.object(client, "list_alerts", return_value=mocked_http_response)
    number_of_pages = client.calculate_amount_of_incidents("", {})
    assert number_of_pages == expected_number_of_pages


def test_calculate_amount_of_incidents_raise_error(mocker):
    mocked_http_response = http_responses["amount_of_incidents_broken_last_page"]

    mocker.patch.object(client, "list_alerts", return_value=mocked_http_response)

    with pytest.raises(
        DemistoException,
        match="Could not calculate page size, last page number was not found:\n" "https://xsoar-example:57585/api/sp/v7/alerts/?",
    ):
        client.calculate_amount_of_incidents("", {})


@pytest.mark.parametrize(
    "object_to_clean",
    [
        ({}),
        ({"some_key": "some_value"}),
        ({"some_key": "some_value", "links": {"self": "some_link"}}),
        ([{"some_key": "some_value", "links": {"self": "some_link"}}]),
        ({"some_key": {"links": {"self": "some_link"}}}),
        ({"some_key": [{"links": {"self": "some_link"}}]}),
        ({"some_key": [{"links": {"self": "some_link"}}, {"links": {"self": "some_other_link"}}]}),
        ([{"some_key": [{"links": {"self": "some_link"}}, {"links": {"self": "some_other_link"}}]}]),
    ],
)
def test_clean_links(object_to_clean):
    """
    Given:
     - Case A: An empty dict.
     - Case B: A dict with no 'links' key in it.
     - Case C: A dict with a 'links' key in it.
     - Case D: A list containing a dict with a 'links' key in it.
     - Case E: A dict containing another dict with a 'links' key in it.
     - Case F: A dict containing a list containing another dict with a 'links' key in it.
     - Case F: A dict containing a list containing additional dict with a 'links' key in them.
     - Case F: A list containing a dict containing another list containing additional dict with a 'links' key in them.

    When:
    Running the clean_links function

    Then:
    No links key appear in transformed dict (checking by parsing the dict into a string)

    """
    copy_of_object = deepcopy(object_to_clean)
    clean_links(copy_of_object)
    str_result = json.dumps(copy_of_object)
    assert str_result.find("link") == -1


def test_validate_json_arg():
    """
    Given:
    - A string representing a json object.

    When:
     - Validating a string has a dict structure

    Then:
     - Ensure no parsing error was returned.
    """
    validate_json_arg('{"some_key": "some_value"}', "")


def test_validate_json_arg_raise_error():
    """
    Given:
    - A string that has no json format.

    When:
     - Validating a string has a json structure.

    Then:
     - Ensure a parsing error was raised
    """
    with pytest.raises(
        DemistoException, match="The value given in the  argument is not a valid JSON format:\n" '{"some_key" "some_value"}'
    ):
        validate_json_arg('{"some_key" "some_value"}', "")


@pytest.mark.parametrize(
    "object_to_build, expected_result",
    [
        ({}, {}),
        ({"attributes": {"key_1": "val_1"}, "key_2": "val_2"}, {"key_1": "val_1", "key_2": "val_2"}),
        (
            {
                "attributes": {"key_1": "val_1"},
                "key_2": "val_2",
                "relationships": [{"key_3": "val_3"}],
                "subobject": {"key_4": "val_4"},
            },
            {"key_1": "val_1", "key_2": "val_2"},
        ),
    ],
)
def test_build_human_readable(object_to_build, expected_result):
    """
    Given:
    - Case A: A dict with two keys: 'attributes' and 'key_2`.
    - Case B: A dict with four keys: 'attributes', 'relationships', 'subobject' and 'key_2'.

    When:
     - Building the human readable from a response dict.

    Then:
     - Case A:
         1. Keys under the 'attributes' key are extracted to the root level.
         2. The second key - 'key_2' still appears in the object.
     - Case B: Ensure that:
         1. Keys under the 'attributes' key are extracted to the root level.
         2. The second key - 'key_2' still appears in the object.
         3. That the 'relationships' and 'subobject' keys are missing from the object.
    """
    result = build_human_readable(object_to_build)
    assert result == expected_result


@pytest.mark.parametrize(
    "args_dict, expected_json_str",
    [
        (
            {
                "limit": "10",
                "page": "2",
                "alert_id": "123",
                "alert_class": "bgp",
                "alert_type": "bgp_hijack",
                "classification": "Flash Crowd",
                "importance": "1",
                "ongoing": "true",
                "start_time": "2021-01-11T13:15:00",
                "stop_time": "2021-01-12T13:15:00",
            },
            "/data/attributes/limit=10 AND /data/attributes/page=2 AND /data/attributes/alert_id=123 AND "
            "/data/attributes/alert_class=bgp AND /data/attributes/alert_type=bgp_hijack AND "
            "/data/attributes/classification=Flash Crowd AND /data/attributes/importance=1 AND "
            "/data/attributes/ongoing=true AND /data/attributes/start_time=2021-01-11T13:15:00 AND "
            "/data/attributes/stop_time=2021-01-12T13:15:00",
        ),
        (
            {
                "importance": "1",
                "importance_operator": "=",
                "start_time": "2021-01-11T13:15:00",
                "start_time_operator": ">",
                "stop_time": "2021-01-12T13:15:00",
                "stop_time_operator": "<",
            },
            "/data/attributes/importance=1 AND /data/attributes/start_time>2021-01-11T13:15:00 AND "
            "/data/attributes/stop_time<2021-01-12T13:15:00",
        ),
    ],
)
def test_build_relationships(args_dict, expected_json_str):
    """
    Given:
    - Case A: A dict of possible relationship filters`.
    - Case B: A dict of possible relationship filters in addition to special allowed operators.

    When:
     - Building a relationship string representation to be sent in the url query.

    Then:
     - Case A: Assert that all filters are uses the `=` operator and are chained using the `AND` operator.
     - Case B: Assert that start_time uses the '>' operator, stop_time uses the '<' operator and importance uses the '='
         operator.
    """
    result = client.build_data_attribute_filter(args_dict)
    assert result == expected_json_str
