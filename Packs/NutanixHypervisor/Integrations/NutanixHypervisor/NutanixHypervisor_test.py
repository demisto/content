"""Nutanix Integration for Cortex XSOAR - Unit Tests file"""

import io
import json
from datetime import datetime
from typing import *

import pytest

from CommonServerPython import DemistoException, CommandResults
from NutanixHypervisor import Client
from NutanixHypervisor import USECS_ENTRIES_MAPPING
from NutanixHypervisor import (
    nutanix_hypervisor_hosts_list_command,
    nutanix_hypervisor_vms_list_command,
    nutanix_hypervisor_vm_power_status_change_command,
    nutanix_hypervisor_task_results_get_command,
    nutanix_hpyervisor_alerts_list_command,
    nutanix_hypervisor_alert_acknowledge_command,
    nutanix_hypervisor_alert_resolve_command,
    nutanix_hypervisor_alerts_acknowledge_by_filter_command,
    nutanix_hypervisor_alerts_resolve_by_filter_command,
    get_alert_status_filter,
    get_optional_boolean_arg,
    convert_epoch_time_to_datetime,
    get_optional_time_parameter_as_epoch,
    add_iso_entries_to_dict,
    get_human_readable_headers,
    task_exists,
)

MOCKED_BASE_URL = "https://prefix:11111/PrismGateway/services/rest/v2.0"
client = Client(base_url=MOCKED_BASE_URL, verify=False, proxy=False, auth=("fake_username", "fake_password"))


def util_load_json(path):
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


command_tests_data = util_load_json("test_data/test_command_data.json")


@pytest.mark.parametrize(
    "args, argument_name, expected",
    [
        ({"resolved": "true"}, "resolved", True),
        ({"resolved": "false"}, "resolved", False),
        ({}, "resolved", None),
    ],
)
def test_get_optional_boolean_arg_valid(args, argument_name, expected):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as boolean.

    When:
     - Case a: Argument exists, and is true.
     - Case b: Argument exists, and is false.
     - Case b: Argument does not exist.

    Then:
     - Case a: Ensure that True is returned.
     - Case b: Ensure that False is returned.
     - Case c: Ensure that None is returned.
    """
    assert (get_optional_boolean_arg(args, argument_name)) == expected


@pytest.mark.parametrize(
    "args, argument_name, expected_error_message",
    [
        ({"resolved": "unknown_boolean_value"}, "resolved", "Argument does not contain a valid boolean-like value"),
        ({"resolved": 123}, "resolved", "Argument is neither a string nor a boolean"),
    ],
)
def test_get_optional_boolean_arg_invalid_argument(args, argument_name, expected_error_message):
    """
    Given:
     - Demisto arguments.
     - Argument name to extract from Demisto arguments as boolean.

    When:
     - Case a: Argument is a non boolean string.
     - Case b: Argument is a number.

    Then:
     - Case a: Ensure that DemistoException is thrown with error message which indicates that string cannot be
       parsed to boolean.
     - Case b: Ensure that DemistoException is thrown with error message which indicates that type of the argument
       is not bool or string that can be parsed.
    """
    with pytest.raises(ValueError, match=expected_error_message):
        get_optional_boolean_arg(args, argument_name)


@pytest.mark.parametrize(
    "arg, expected",
    [
        ("2020-11-22T16:31:14", 1606062674000000),
        (None, None),
    ],
)
def test_get_optional_time_parameter_valid_time_argument(arg, expected):
    """
    Given:
     - Demisto arguments.
     - Argument of type time to extract from Demisto arguments as epoch time.

    When:
     - Case a: Argument exists, and has the expected date format.
     - Case b: Argument does not exist.

    Then:
     - Case a: Ensure that the corresponding epoch time is returned.
     - Case b: Ensure that None is returned.
    """
    assert (get_optional_time_parameter_as_epoch(arg)) == expected


@pytest.mark.parametrize(
    "command_function, args, url_suffix, response, expected",
    [
        (
            nutanix_hypervisor_hosts_list_command,
            command_tests_data["nutanix-hypervisor-hosts-list"]["args"],
            command_tests_data["nutanix-hypervisor-hosts-list"]["suffix"],
            command_tests_data["nutanix-hypervisor-hosts-list"]["response"],
            command_tests_data["nutanix-hypervisor-hosts-list"]["expected"],
        ),
        (
            nutanix_hypervisor_vms_list_command,
            command_tests_data["nutanix-hypervisor-vms-list"]["args"],
            command_tests_data["nutanix-hypervisor-vms-list"]["suffix"],
            command_tests_data["nutanix-hypervisor-vms-list"]["response"],
            command_tests_data["nutanix-hypervisor-vms-list"]["expected"],
        ),
        (
            nutanix_hpyervisor_alerts_list_command,
            command_tests_data["nutanix-hypervisor-alerts-list"]["args"],
            command_tests_data["nutanix-hypervisor-alerts-list"]["suffix"],
            command_tests_data["nutanix-hypervisor-alerts-list"]["response"],
            command_tests_data["nutanix-hypervisor-alerts-list"]["expected"],
        ),
    ],
)
def test_commands_get_methods(
    requests_mock,
    command_function: Callable[[Client, Dict], CommandResults],
    args: Dict,
    url_suffix: str,
    response: Dict,
    expected: Dict,
):
    """
    Given:
     - command function.
     - Demisto arguments.
     - url suffix of the Nutanix service endpoint that the command function will use (needed to mock the request).
     - response returned from Nutanix.
     - expected CommandResults object to be returned from the command function.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    requests_mock.get(f"{MOCKED_BASE_URL}/{url_suffix}", json=response)
    expected_command_results = CommandResults(
        outputs_prefix=expected.get("outputs_prefix"),
        outputs_key_field=expected.get("outputs_key_field"),
        outputs=expected.get("outputs"),
    )
    returned_command_results = command_function(client, args)

    assert returned_command_results.outputs_prefix == expected_command_results.outputs_prefix
    assert returned_command_results.outputs_key_field == expected_command_results.outputs_key_field
    assert returned_command_results.outputs == expected_command_results.outputs


@pytest.mark.parametrize(
    "command_function, args, url_suffix, response, expected",
    [
        (
            nutanix_hypervisor_vm_power_status_change_command,
            command_tests_data["nutanix-hypervisor-vm-powerstatus-change"]["args"],
            command_tests_data["nutanix-hypervisor-vm-powerstatus-change"]["suffix"],
            command_tests_data["nutanix-hypervisor-vm-powerstatus-change"]["response"],
            command_tests_data["nutanix-hypervisor-vm-powerstatus-change"]["expected"],
        ),
        (
            nutanix_hypervisor_task_results_get_command,
            command_tests_data["nutanix-hypervisor-task-results-get"]["args"],
            command_tests_data["nutanix-hypervisor-task-results-get"]["suffix"],
            command_tests_data["nutanix-hypervisor-task-results-get"]["response"],
            command_tests_data["nutanix-hypervisor-task-results-get"]["expected"],
        ),
        (
            nutanix_hypervisor_alert_acknowledge_command,
            command_tests_data["nutanix-hypervisor-alert-acknowledge"]["args"],
            command_tests_data["nutanix-hypervisor-alert-acknowledge"]["suffix"],
            command_tests_data["nutanix-hypervisor-alert-acknowledge"]["response"],
            command_tests_data["nutanix-hypervisor-alert-acknowledge"]["expected"],
        ),
        (
            nutanix_hypervisor_alert_resolve_command,
            command_tests_data["nutanix-hypervisor-alert-resolve"]["args"],
            command_tests_data["nutanix-hypervisor-alert-resolve"]["suffix"],
            command_tests_data["nutanix-hypervisor-alert-resolve"]["response"],
            command_tests_data["nutanix-hypervisor-alert-resolve"]["expected"],
        ),
        (
            nutanix_hypervisor_alerts_acknowledge_by_filter_command,
            command_tests_data["nutanix-hypervisor-alerts-acknowledge-by-filter"]["args"],
            command_tests_data["nutanix-hypervisor-alerts-acknowledge-by-filter"]["suffix"],
            command_tests_data["nutanix-hypervisor-alerts-acknowledge-by-filter"]["response"],
            command_tests_data["nutanix-hypervisor-alerts-acknowledge-by-filter"]["expected"],
        ),
        (
            nutanix_hypervisor_alerts_resolve_by_filter_command,
            command_tests_data["nutanix-hypervisor-alerts-resolve-by-filter"]["args"],
            command_tests_data["nutanix-hypervisor-alerts-resolve-by-filter"]["suffix"],
            command_tests_data["nutanix-hypervisor-alerts-resolve-by-filter"]["response"],
            command_tests_data["nutanix-hypervisor-alerts-resolve-by-filter"]["expected"],
        ),
    ],
)
def test_commands_post_methods(
    requests_mock,
    command_function: Callable[[Client, Dict], CommandResults],
    args: Dict,
    url_suffix: str,
    response: Dict,
    expected: Dict,
):
    """
    Given:
     - command function.
     - Demisto arguments.
     - url suffix of the Nutanix service endpoint that the command function will use (needed to mock the request).
     - response returned from Nutanix.
     - expected CommandResults object to be returned from the command function.

    When:
     - Executing a command

    Then:
     - Ensure that the expected CommandResults object is returned by the command function.
    """
    requests_mock.post(f"{MOCKED_BASE_URL}/{url_suffix}", json=response)
    expected_command_results = CommandResults(
        outputs_prefix=expected.get("outputs_prefix"),
        outputs_key_field=expected.get("outputs_key_field"),
        outputs=expected.get("outputs"),
    )
    returned_command_results = command_function(client, args)

    assert returned_command_results.outputs_prefix == expected_command_results.outputs_prefix
    assert returned_command_results.outputs_key_field == expected_command_results.outputs_key_field
    assert returned_command_results.outputs == expected_command_results.outputs


def test_fetch_incidents(requests_mock):
    """
    Given:
     - Demisto parameters.
     - Demisto arguments.
     - Last run of fetch-incidents

    When:
     - Fetching incidents, not first run. last run fetch time is before both alerts.

    Then:
     Ensure that alerts are returned as incidents.
     Ensure that last run is set with latest alert time stamp.
    """
    last_run = {"last_fetch_epoch_time": 1610360118147914}
    requests_mock.get(
        f"{MOCKED_BASE_URL}/alerts?start_time_in_usecs=1610360118147914",
        json=command_tests_data["nutanix-fetch-incidents"]["response"],
    )
    current_time = int(datetime.utcnow().timestamp() * 1000000)
    incidents, next_run = client.fetch_incidents(params={}, last_run=last_run)
    incidents_raw_json = [json.loads(incident["rawJSON"]) for incident in incidents]
    assert next_run.get("last_fetch_epoch_time") >= current_time
    assert incidents_raw_json == command_tests_data["nutanix-fetch-incidents"]["expected"]["outputs"]


@pytest.mark.parametrize(
    "true_value, false_value, alert_status_filters, expected",
    [
        ("Resolved", "Unresolved", ["Resolved", "Acknowledged"], True),
        ("Resolved", "Unresolved", ["Unresolved", "Acknowledged"], False),
        ("Resolved", "Unresolved", ["Acknowledged"], None),
        ("Resolved", "Unresolved", None, None),
    ],
)
def test_get_alert_status_filter_valid_cases(true_value, false_value, alert_status_filters, expected):
    """
    Given:
     - The argument name which corresponds for True value inside 'alert_status_filters' list.
     - The argument name which corresponds for False value inside 'alert_status_filters' list.
     - Alert status filters, contains all the selects for filters done by user.

    When:
     - Case a: User selected argument that corresponds for True value.
     - Case b: User selected argument that corresponds for False value.
     - Case c: User did not select argument that corresponds to true or false value.

    Then:
     - Case a: Ensure True is returned.
     - Case b: Ensure False is returned.
     - Case c: Ensure None is returned.
    """
    assert get_alert_status_filter(true_value, false_value, alert_status_filters) == expected


@pytest.mark.parametrize(
    "true_value, false_value, alert_status_filters",
    [
        ("Resolved", "Unresolved", ["Resolved", "Unresolved"]),
        ("Acknowledged", "Unacknowledged", ["Acknowledged", "Unacknowledged"]),
        ("Auto Resolved", "Not Auto Resolved", ["Auto Resolved", "Not Auto Resolved"]),
    ],
)
def test_get_alert_status_filter_invalid_case(true_value, false_value, alert_status_filters):
    """
    Given:
     - The argument name which corresponds for True value inside 'alert_status_filters' list.
     - The argument name which corresponds for False value inside 'alert_status_filters' list.
     - Alert status filters, contains all the selects for filters done by user.

    When:
     - Case a: User selected argument that corresponds for both True and False values.
     - Case b: User selected argument that corresponds for both True and False values.
     - Case c: User selected argument that corresponds for both True and False values.

    Then:
     - Case a: Ensure DemistoException is thrown with the expected message error.
     - Case b: Ensure DemistoException is thrown with the expected message error.
     - Case c: Ensure DemistoException is thrown with the expected message error.
    """
    with pytest.raises(
        DemistoException,
        match=f"Invalid alert status filters configurations, only one of {true_value},{false_value} " "can be chosen.",
    ):
        get_alert_status_filter(true_value, false_value, alert_status_filters)


@pytest.mark.parametrize("epoch_time, expected", [(0, None), (None, None), (1600000000000000, "2020-09-13T12:26:40+00:00")])
def test_convert_epoch_time_to_datetime_valid_cases(epoch_time, expected):
    """
    Given:
     - Time to be converted to date time in UTC timezone.

    When:
     - Case a: Epoch time is 0.
     - Case b: Epoch time is not given.
     - Case c: Valid epoch time is given.

    Then:
     - Case a: Ensure None is returned.
     - Case b: Ensure None is returned.
     - Case c: Ensure the corresponding date time string is returned.
    """
    assert convert_epoch_time_to_datetime(epoch_time) == expected


def test_add_iso_entries_to_dict():
    """
    Given:
     - Dict containing entries with epoch time.

    When:
     - Adding to entries with epoch time entries with iso time.

    Then:
     - All 'usecs' keys in the dict are replaced with 'iso time' entries with correct iso values.
    """
    tested_dict = {usec_entry: 1600000000000000 for usec_entry in USECS_ENTRIES_MAPPING.keys()}
    tested_dict["host_name"] = "Nutanix Host"
    add_iso_entries_to_dict([tested_dict])
    assert tested_dict["host_name"] == "Nutanix Host"
    assert all(tested_dict.get(iso_entry) == "2020-09-13T12:26:40+00:00" for iso_entry in USECS_ENTRIES_MAPPING.values())
    assert len(tested_dict) == (1 + (len(USECS_ENTRIES_MAPPING) * 2))


@pytest.mark.parametrize(
    "outputs, expected_outputs",
    [
        ([{1: 2, 3: 4, "a": "b"}], [1, 3, "a"]),
        ([{"a": {2: 3}}], []),
        ([{1: 2, 3: 4, "a": {1: 2}}, {1: 2, "abc": "def", "lst": [1, {2: 3}, 3, [4, 5, 6]]}], [1]),
        ([{"a": [[[[[[{1: 2}]]]]]]}], []),
        ([], []),
    ],
)
def test_get_human_readable_headers(outputs, expected_outputs):
    """
    Given:
     - List of outputs.

    When:
     - Creating human readable keys by given outputs

    Then:
     - All keys that don't contains inner dicts are returned.
    """
    readable_headers = get_human_readable_headers(outputs)
    assert all(readable_header in expected_outputs for readable_header in readable_headers)
    assert len(readable_headers) == len(expected_outputs)


def test_task_id_exists_task_exists(requests_mock):
    """
    Given:
     - Task Id.
     - Nutanix client.

    When:
     Task to be polled exists in Nutanix.

    Then:
     True is returned
    """
    task_id = "abcd1234-ab12-cd34-1a2s3d5f7hh4"
    requests_mock.get(f"{MOCKED_BASE_URL}/tasks/{task_id}", json={})
    assert task_exists(client, task_id)


def test_task_id_exists_task_does_not_exist(requests_mock):
    """
    Given:
     - Task Id.
     - Nutanix client.

    When:
     Task to be polled does not exist in Nutanix.

    Then:
     False is returned
    """
    task_id = "abcd1234-ab12-cd34-1a2s3d5f7hh4"
    requests_mock.get(f"{MOCKED_BASE_URL}/tasks/{task_id}", exc=DemistoException(f"Task with id {task_id} is not found"))
    assert not task_exists(client, task_id)


def test_task_id_exists_unexpected_exception(requests_mock):
    """
    Given:
     - Task Id.
     - Nutanix client.

    When:
     Unexpected exception is thrown during call to Nutanix service.

    Then:
     The unexpected exception is raised and not passed silently
    """
    task_id = "abcd1234-ab12-cd34-1a2s3d5f7hh4"
    requests_mock.get(f"{MOCKED_BASE_URL}/tasks/{task_id}", exc=DemistoException("Unexpected exception"))
    with pytest.raises(DemistoException, match="Unexpected exception"):
        task_exists(client, task_id)
