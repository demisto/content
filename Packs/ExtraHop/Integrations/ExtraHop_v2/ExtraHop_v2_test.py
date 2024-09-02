"""Test File for ExtraHop Integration."""
from copy import copy
import datetime
from unittest import mock
import ExtraHop_v2
import json
import pytest
import os

from CommonServerPython import DemistoException

BASE_URL = "https://dummy-base-url.com"
API_KEY = "dummy-api-key"
CLIENT_ID = "dummy-client-id"
CLIENT_SECRET = "dummy-client-secret"
EXTRAHOP_DEVICE = "ExtraHop.Device"
GET_PROTOCOL_FILE = "get_protocol_get_peers.json"
GET_PROTOCOL_NETWORKS_FILE = "get_protocol_networks.json"

PACKETS_SEARCH_URL = "/api/v1/packets/search"
GET_ALL_TAGS_URL = "/api/v1/tags"
TAG_DEVICE_URL = "/api/v1/tags/12/devices"
INVALID_AUTH_HEADER = "Authorization header is invalid"
LIST_DETECTIONS_SUCCESS = "list_detections_success.json"


def get_packets_search_args():
    """
    A common function to return arguments for packet-search command.
    """
    return {
        "output": "zip",
        "limit_bytes": "10MB",
        "limit_search_duration": "5m",
        "query_from": "-10m",
        "query_until": "now",
        "bpf": "ip[1] != 0",
        "ip1": "0.0.0.0",
        "port1": "8080",
        "ip2": "0.0.0.0",
        "port2": "8081",
    }


def get_device_tag_args():
    """
    A common function to return arguments for devices-tag command.
    """
    return {"tag": "MyTag", "add": "1,2", "remove": "3,4"}


# pytest fixture for testing arguments of a function and calling
# BaseClient's "_http_request" method.
@pytest.fixture
def argtest():
    def _argtest(**_kwargs):
        class TestArgs(object):
            def __call__(self, *args, **kwargs):
                self.args = list(args)
                self.kwargs = kwargs
                return _kwargs["_http_request"](*args, **kwargs)

        return TestArgs()

    return _argtest


@pytest.fixture
def get_devices_by_ip_or_id_fixture(mocker):
    """
    A pytest fixture to mock the "get_devices_by_ip_or_id" function.

    Args:
        mocker: An object to mock specific function of ExtraHop_v2 module.
    """
    return mocker.patch(
        "ExtraHop_v2.get_devices_by_ip_or_id", side_effect=[[1, 2], [3, 4]]
    )


def init_mock_client(requests_mock, on_cloud):
    """
    Extrahop mock client based on on_cloud param.

    Args:
        requests_mock: Mock object of the request.
        on_cloud (bool): whether client created on cloud or on-prem instance.
    """
    if on_cloud:
        access_token_response = load_mock_response("auth_token.json")
        requests_mock.post("/oauth2/token", json=access_token_response)

    return ExtraHop_v2.ExtraHopClient(
        base_url=BASE_URL,
        api_key=API_KEY,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        verify=True,
        use_proxy=False,
        ok_codes=(200, 201, 204),
        on_cloud=on_cloud,
    )


def load_mock_response(file_name: str) -> dict:
    """
    Load one of the mock responses to be used for assertion.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(
        os.path.join(os.path.dirname(__file__), f"test_data/{file_name}"),
        mode="r",
        encoding="utf-8",
    ) as json_file:
        return json.loads(json_file.read())


def load_file(file_name: str) -> str:
    """
    Load file to be used for assertion.

    Args:
        file_name (str): Name of the mock response JSON file to return.
    """
    with open(
        os.path.join(os.path.dirname(__file__), f"test_data/{file_name}"), mode="r"
    ) as file:
        return file.read()


@pytest.mark.parametrize(
    "on_cloud, hr_output",
    [
        (False, load_file("watchlist_get_hr.md")),
        (True, load_file("watchlist_get_command_on_cloud.md")),
    ],
)
def test_watchlist_get_command(on_cloud, hr_output, requests_mock) -> None:
    """
    Test case scenario for successful execution of watchlist-get command.

    Given:
     - User has provided valid credentials.
    When:
     - watchlist_get_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    """
    watchlist_mock_response = load_mock_response("watchlist_get.json")
    requests_mock.get("/api/v1/watchlist/devices", json=watchlist_mock_response)

    network_mock_response = load_mock_response("network_get.json")
    requests_mock.get("/api/v1/networks", json=network_mock_response)
    client = init_mock_client(requests_mock, on_cloud)
    result = ExtraHop_v2.watchlist_get_command(client, on_cloud)

    assert len(result.outputs) == 3  # type: ignore
    assert result.outputs_prefix == EXTRAHOP_DEVICE
    assert result.readable_output == hr_output


@pytest.mark.parametrize("on_cloud", [False, True])
def test_create_or_edit_alert_rule_command(on_cloud, requests_mock) -> None:
    """
    Test case scenario for successful execution of create-or-edit-alert-rule command.

    Given:
     - User has provided valid credentials.
    When:
     - create_or_edit_alert_rule_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    """
    alert_mock_response = load_mock_response("/alerts/create_alert.json")
    requests_mock.post("/api/v1/alerts", status_code=201)

    client = init_mock_client(requests_mock, on_cloud)
    result = ExtraHop_v2.create_or_edit_alert_rule_command(client, alert_mock_response)

    assert result.readable_output == "Successfully created alert rule."


@pytest.mark.parametrize("on_cloud", [False, True])
def test_create_or_edit_alert_rule_command_invalid_type(
    on_cloud, requests_mock
) -> None:
    """
    Test case scenario for invalid type of create-or-edit-alert-rule command.

    Given:
     - User has provided valid credentials.
    When:
     - create_or_edit_alert_rule_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    alert_mock_response = load_mock_response("/alerts/create_alert_validation.json")
    client = init_mock_client(requests_mock, on_cloud)

    with pytest.raises(ExtraHop_v2.InvalidValueError):
        ExtraHop_v2.create_or_edit_alert_rule_command(client, alert_mock_response)


@pytest.mark.parametrize("on_cloud", [False, True])
def test_create_or_edit_alert_rule_command_invalid_object_type(
    on_cloud, requests_mock
) -> None:
    """
    Test case scenario for invalid object type of create-or-edit-alert-rule command.

    Given:
     - User has provided valid credentials.
    When:
     - Create_or_edit_alert_rule_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    alert_mock_response = load_mock_response(
        "/alerts/create_alert_validation_object_type.json"
    )
    client = init_mock_client(requests_mock, on_cloud)

    with pytest.raises(ExtraHop_v2.InvalidValueError):
        ExtraHop_v2.create_or_edit_alert_rule_command(client, alert_mock_response)


@pytest.mark.parametrize(
    ("refire_interval", "severity", "on_cloud"),
    [["10", "1", True], ["300", "8", True], ["10", "1", False], ["300", "8", False]],
)
def test_create_or_edit_alert_rule_command_invalid_rule_arguments(
    on_cloud, refire_interval, severity, requests_mock
) -> None:
    """
    Test case scenario for invalid rule arguments of create-or-edit-alert-rule command.

    Given:
     - User has provided valid credentials.
    When:
     - create_or_edit_alert_rule_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    alert_mock_response = {"refire_interval": refire_interval, "severity": severity}
    client = init_mock_client(requests_mock, on_cloud)

    with pytest.raises(ExtraHop_v2.InvalidValueError):
        ExtraHop_v2.create_or_edit_alert_rule_command(client, alert_mock_response)


@pytest.mark.parametrize(
    ("interval_length", "operator", "units", "on_cloud"),
    [
        ["31", "==", "none", True],
        ["30", "!=", "none", True],
        ["30", "==", "nones", True],
        ["31", "==", "none", False],
        ["30", "!=", "none", False],
        ["30", "==", "nones", False],
    ],
)
def test_create_or_edit_alert_rule_command_invalid_thresold_argument(
    on_cloud, interval_length, operator, units, requests_mock
) -> None:
    """
    Test case scenario for validate type of create-or-edit-alert-rule command.

    Given:
     - User has provided valid credentials.
    When:
     - create_or_edit_alert_rule_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    alert_mock_response = {
        "type": "threshold",
        "interval_length": interval_length,
        "operator": operator,
        "units": units,
    }
    client = init_mock_client(requests_mock, on_cloud)

    with pytest.raises(ExtraHop_v2.InvalidValueError):
        ExtraHop_v2.create_or_edit_alert_rule_command(client, alert_mock_response)


def test_update_alert_rule_command(requests_mock) -> None:
    """
    Test case scenario for create-or-edit-alert-rule command.

    Given:
     - User has provided valid credentials.
    When:
     - create_or_edit_alert_rule_command is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
    """
    alert_id = 212
    alert_mock_response = {
        "type": "threshold",
        "interval_length": "30",
        "operator": "==",
        "units": "none",
        "alert_id": alert_id,
    }
    client = init_mock_client(requests_mock, on_cloud=False)

    requests_mock.patch(f"/api/v1/alerts/{alert_id}", status_code=204)
    result = ExtraHop_v2.create_or_edit_alert_rule_command(client, alert_mock_response)

    assert result.readable_output == "Successfully updated alert rule."


@pytest.mark.parametrize(
    "args, error_msg",
    [
        (
            {
                "cycle": "dummy",
                "object_type": "device",
                "from": "-30m",
                "until": "-20m",
                "metric_category": "http",
                "objects_ids": [0],
                "metric_specs": '[{"name": "rsp"}]',
            },
            f"dummy is an invalid value for cycle. Possible values are: {ExtraHop_v2.VALID_CYCLES}",
        ),
        (
            {
                "cycle": "auto",
                "object_type": "dummy",
                "from": "-30m",
                "until": "-20m",
                "metric_category": "http",
                "objects_ids": [0],
                "metric_specs": '[{"name": "rsp"}]',
            },
            f"dummy is an invalid value for object_type. Possible values are: {ExtraHop_v2.VALID_OBJECT_TYPES}",
        ),
        (
            {
                "cycle": "auto",
                "object_type": "device",
                "from": "-30m",
                "until": "-20m",
                "metric_category": "http",
                "objects_ids": [0],
                "metric_specs": "{'test': dummy}",
            },
            "Invalid JSON string provided for metric specs.",
        ),
    ],
)
def test_metrics_list_command_invalid_args(requests_mock, args, error_msg):
    """Test case scenario for invalid arguments while execution of metrics-list command.

    Given:
     - User has provided invalid arguments.
    When:
     - metrics_list_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    with pytest.raises(Exception) as error:
        ExtraHop_v2.metrics_list_command(client, args)
    assert str(error.value) == error_msg


def test_metrics_list_command_successful_execution(requests_mock):
    """Test case scenario for successful execution of metrics-list command.

    Given:
     - User has provided valid credentials.
    When:
     - metrics_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {
        "cycle": "24hr",
        "from": "-30m",
        "until": "0",
        "metric_category": "http",
        "metric_specs": '[{"name": "rsp"}]',
        "object_ids": [0],
        "object_type": "network",
    }

    response = load_mock_response("metrics_list_success.json")

    expected_hr = load_file("metrics_list_success_hr.md")

    requests_mock.post(f"{BASE_URL}/api/v1/metrics", json=response)

    results = ExtraHop_v2.metrics_list_command(client, args=args)

    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ExtraHop.Metrics"


def test_metrics_list_command_using_advanced_filter(requests_mock):
    """Test case scenario for successful execution of metrics-list command using advanced_filter argument.

    Given:
     - User has provided valid credentials.
    When:
     - metrics_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)

    advanced_filter = """{\"cycle\": \"auto\",
                \"from\": \"-30m\",
                \"metric_category\": \"http\",
                \"metric_specs\": [{\"name\":\"rsp\"}],
                \"object_ids\": [0],
                \"object_type\": \"application\",
                \"until\": \"0\"}"""

    response = load_mock_response("metrics_list_success.json")

    expected_hr = load_file("metrics_list_success_hr.md")

    requests_mock.post(f"{BASE_URL}/api/v1/metrics", json=response)

    results = ExtraHop_v2.metrics_list_command(client, advanced_filter=advanced_filter)
    assert results.readable_output == expected_hr


def test_metrics_list_commands_using_advance_filter_invalid_args(requests_mock):
    """Test case scenario for failure of metrics-list command using invalid advanced_filter argument.

    Given:
     - User has provided valid credentials.
    When:
     - metrics_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)

    advanced_filter = """{\"cycles\": \"auto\",
                    \"from\": \"-30m\",
                    \"metric_category\": \"http\",
                    \"metric_specs\": [{\"name\":\"rsp\"}],
                    \"object_ids\": [0],
                    \"object_type\": \"application\",
                    \"until\": \"0\"}"""

    response = load_mock_response("metrics_list_success.json")

    requests_mock.post(f"{BASE_URL}/api/v1/metrics", json=response)

    with pytest.raises(Exception) as error:
        ExtraHop_v2.metrics_list_command(client, advanced_filter=advanced_filter)
    assert (
        str(error.value)
        == "cycles is an invalid value for keys. Possible values are: ['cycle', 'from', "
        "'metric_category', 'metric_specs', 'object_ids', 'object_type', 'until']"
    )


def test_metrics_list_command_error_code_400(requests_mock):
    """Test case scenario for failure metrics-list command when status code is 400.

    Given:
     - User has provided invalid json input.
    When:
     - metrics_list_command is called.
    Then:
     - Ensure error is raised with error code.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {
        "cycle": "24hr",
        "from": "-30m",
        "until": "0",
        "metric_category": "http",
        "metric_specs": '[{"name": "rsp"}]',
        "object_ids": [0],
        "object_type": "network",
    }

    response = {
        "type": "invalid_request",
        "detail": "The JSON payload specified in the request is invalid.",
    }

    requests_mock.post(f"{BASE_URL}/api/v1/metrics", json=response, status_code=400)

    with pytest.raises(Exception) as error:
        ExtraHop_v2.metrics_list_command(client, args)
    assert (
        str(error.value)
        == 'Error in API call [400] - None\n{"type": "invalid_request", "detail": "The JSON '
        'payload specified in the request is invalid."}'
    )


def test_metrics_list_command_error_code_401(requests_mock):
    """Test case scenario for failure metrics-list command when status code is 401.

    Given:
     - User has provided invalid json input.
    When:
     - metrics_list_command is called.
    Then:
     - Ensure error is raised with error code.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {
        "cycle": "24hr",
        "from": "-30m",
        "until": "0",
        "metric_category": "http",
        "metric_specs": '[{"name": "rsp"}]',
        "object_ids": [0],
        "object_type": "network",
    }

    response = {"error_message": "API Key is invalid"}

    requests_mock.post(f"{BASE_URL}/api/v1/metrics", json=response, status_code=401)

    with pytest.raises(Exception) as error:
        ExtraHop_v2.metrics_list_command(client, args)
    assert (
        str(error.value)
        == 'Error in API call [401] - None\n{"error_message": "API Key is invalid"}'
    )


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"from": "123s"}, '"123s" is not a valid number'),
        (
            {"limit": 0},
            "Invalid input for field limit. It should have numeric value greater than zero.",
        ),
        (
            {"offset": -1},
            "Invalid input for field offset. It should have numeric value greater than or equal to zero.",
        ),
        (
            {"from": "1673508360001", "until": "1673508360000"},
            'Input for "from" should always be less than that of "until".',
        ),
        (
            {"from": "-1673508360001", "until": "-1673508360002"},
            'Input for "from" should always be less than that of "until".',
        ),
        ({"filter": "{'limit': 1}"}, "Invalid json string provided for filter."),
        (
            {"sort": "id asc desc"},
            'Incorrect input provided for argument "sort". Please follow the format mentioned in description.',
        ),
        (
            {"sort": "id asd"},
            'Incorrect input provided for argument "sort". Allowed values for direction are: asc, desc',
        ),
        (
            {"filter": '{"invalid_arg": 1}'},
            "invalid_arg is an invalid value for key. Possible values are: ['assignee', "
            "'categories', 'category', 'resolution', 'risk_score_min', 'status', 'ticket_id', 'types']",
        ),
    ],
)
def test_detections_list_command_invalid_args(requests_mock, args, error_msg):
    """Test case scenario for invalid arguments while execution of detections list command.

    Given:
     - User has provided invalid arguments.
    When:
     - detections_list_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud=False)
    with pytest.raises(Exception) as error:
        ExtraHop_v2.detections_list_command(client, args)
    assert str(error.value) == error_msg


def test_detections_list_command_failure_when_firmware_version_is_outdated(requests_mock):
    """Test case scenario for execution of detections list command when ExtraHop firmware version is less than 9.3.0.

    Given:
       - Arguments for detections list command.
    When:
       - detections_list_command is called.
    Then:
       - Returns a valid error message.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.1.2.1943"}
    )
    with pytest.raises(DemistoException) as err:
        ExtraHop_v2.detections_list_command(client, {}, True, '{}')
    assert (
        str(err.value)
        == "This integration works with ExtraHop firmware version greater than or equal to 9.3.0"
    )


@pytest.mark.parametrize("on_cloud", [False, True])
def test_list_detections_command_successful_execution_with_categories(on_cloud, requests_mock):
    """Test case scenario for successful execution of detections-list command with categories.

    Given:
     - User has provided valid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud)
    args = {
        "limit": "2",
        "filter": """{
        \"categories\": [\"sec.attack\"],
        \"risk_score_min\": 51
    }""",
        "from": "1573500360001",
        "offset": "2",
        "sort": "end_time asc,id desc",
        "until": "1673569370001",
    }
    response = load_mock_response(LIST_DETECTIONS_SUCCESS)

    expected_hr = load_file("list_detections_success_hr.md")

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    results = ExtraHop_v2.detections_list_command(client, args)

    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ExtraHop.Detections"


@pytest.mark.parametrize("on_cloud", [False, True])
def test_list_detections_command_successful_execution_with_category(on_cloud, requests_mock):
    """Test case scenario for successful execution of detections-list command with category.

    Given:
     - User has provided valid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud)
    args = {
        "limit": "2",
        "filter": """{
        \"category\": \"sec.attack\",
        \"risk_score_min\": 51
    }""",
        "from": "1573500360001",
        "offset": "2",
        "sort": "end_time asc,id desc",
        "until": "1673569370001",
    }
    response = load_mock_response(LIST_DETECTIONS_SUCCESS)

    expected_hr = load_file("list_detections_success_hr.md")

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    results = ExtraHop_v2.detections_list_command(client, args)

    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ExtraHop.Detections"


@pytest.mark.parametrize("on_cloud", [False, True])
def test_list_detections_command_successful_execution_without_category(on_cloud, requests_mock):
    """Test case scenario for successful execution of detections-list command without categories.

    Given:
     - User has provided valid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud)
    args = {
        "limit": "2",
        "filter": """{
        \"risk_score_min\": 51
    }""",
        "from": "1573500360001",
        "offset": "2",
        "sort": "end_time asc,id desc",
        "until": "1673569370001",
    }
    response = load_mock_response(LIST_DETECTIONS_SUCCESS)

    expected_hr = load_file("list_detections_success_hr.md")

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    results = ExtraHop_v2.detections_list_command(client, args)

    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ExtraHop.Detections"


@pytest.mark.parametrize("on_cloud", [False, True])
def test_list_detections_command_when_description_has_metric_link(on_cloud, requests_mock):
    """Test case scenario for successful execution of detections-list command when description has metrics link.

    Given:
     - User has provided valid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud)
    args = {
        "limit": "1",
        "filter": """{
        \"categories\": [\"sec.attack\"],
        \"risk_score_min\": 30
    }""",
        "from": "1573500360001",
        "offset": "2",
        "sort": "end_time asc,id desc",
        "until": "1673569370001",
    }
    response = load_mock_response("list_detections_with_description_url.json")

    expected_hr = load_file("list_detections_with_description_url.md")

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    results = ExtraHop_v2.detections_list_command(client, args)

    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ExtraHop.Detections"


@pytest.mark.parametrize("on_cloud", [False, True])
def test_list_detections_command_when_description_has_complete_metric_link(on_cloud, requests_mock):
    """Test case scenario for successful execution of detections-list command when description has metrics link which
    has only base url missing.

    Given:
     - User has provided valid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud)
    args = {
        "limit": "1",
        "filter": """{
        \"categories\": [\"sec.attack\"],
        \"risk_score_min\": 30
    }""",
        "from": "1573500360001",
        "offset": "2",
        "sort": "end_time asc,id desc",
        "until": "1673569370001",
    }
    response = load_mock_response("list_detections_with_complete_description_url.json")

    expected_hr = load_file("list_detections_with_complete_description_url.md")

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    results = ExtraHop_v2.detections_list_command(client, args)

    assert results.readable_output == expected_hr
    assert results.outputs_prefix == "ExtraHop.Detections"


def test_list_detections_command_using_advanced_filter(requests_mock):
    """Test case scenario for successful execution of detections list using advanced_filter argument.

    Given:
     - User has provided valid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {}
    advanced_filter = """{\"filter\": {\"categories\": [\"sec.attack\"],\"risk_score_min\": 51},
                \"limit\": 1,\"offset\": 0,
                \"sort\": [
                    {
                    \"direction\": \"desc\",
                    \"field\": \"end_time\"
                    }
                ]
            }"""

    response = load_mock_response(LIST_DETECTIONS_SUCCESS)

    expected_hr = load_file("list_detections_success_hr.md")

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    results = ExtraHop_v2.detections_list_command(
        client, args, json.loads(advanced_filter)
    )
    assert results.readable_output == expected_hr


def test_list_detections_command_using_advanced_filter_invalid_arg(requests_mock):
    """Test case scenario for execution of detections list using advanced_filter argument.

    Given:
     - User has provided invalid arguments in body.
    When:
     - detections_list_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {}
    advanced_filter = """{\"filter\": {\"categories\": [\"sec.attack\"],\"risk_score_min\": 51},
                \"limit\": 1,\"offset\": 0,\"invalid_arg\": 0,
                \"sort\": [
                    {
                    \"direction\": \"desc\",
                    \"field\": \"end_time\"
                    }
                ]
            }"""

    response = load_mock_response(LIST_DETECTIONS_SUCCESS)

    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=response)

    with pytest.raises(Exception) as error:
        ExtraHop_v2.detections_list_command(client, args, advanced_filter=json.loads(advanced_filter))
    assert str(error.value) == "invalid_arg is an invalid value for key. Possible values are: ['filter', 'limit', " \
                               "'offset', 'from', 'until', 'sort', 'mod_time']"


def test_list_detections_command_error_code_400(requests_mock):
    """Test case scenario for failure detections list when status code is 400.

    Given:
     - User has provided invalid json input.
    When:
     - detections_list_command is called.
    Then:
     - Ensure error is raised with error code.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {
        "limit": "2",
    }
    response = {
        "type": "invalid_request",
        "detail": "The JSON payload specified in the request is invalid.",
    }
    requests_mock.post(
        f"{BASE_URL}/api/v1/detections/search", json=response, status_code=400
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.detections_list_command(client, args)
    assert (
        str(error.value)
        == 'Error in API call [400] - None\n{"type": "invalid_request", "detail": "The JSON '
        'payload specified in the request is invalid."}'
    )


def test_list_detections_command_error_code_502(requests_mock):
    """Test case scenario for failure detections list when status code is 502.

    Given:
     - User has provided invalid arguments.
    When:
     - detections_list_command is called.
    Then:
     - Ensure error is raised with error code.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {}
    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", status_code=502)
    with pytest.raises(Exception) as error:
        ExtraHop_v2.detections_list_command(client, args)
    assert str(error.value) == "Error in API call [502] - None\n"  # - Bad Gateway


def test_list_detections_command_error_code_401(requests_mock):
    """Test case scenario for failure detections list when status code is 401.

    Given:
     - User has provided invalid credentials.
    When:
     - detections_list_command is called.
    Then:
     - Ensure error is raised with error code.
    """
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"limit": "2"}
    response = {"error_message": "API Key is invalid"}
    requests_mock.post(
        f"{BASE_URL}/api/v1/detections/search", status_code=401, json=response
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.detections_list_command(client, args)
    assert (
        str(error.value)
        == 'Error in API call [401] - None\n{"error_message": "API Key is invalid"}'
    )


@pytest.mark.parametrize(
    "detection_status, close_reason, incident_owner, expected",
    [
        (
            "2",
            "Resolved",
            "abc",
            {
                "ticket_id": "incident_id",
                "status": "closed",
                "assignee": "abc",
                "resolution": "action_taken",
            },
        ),
        (
            "2",
            "Duplicate",
            None,
            {
                "ticket_id": "incident_id",
                "status": "closed",
                "assignee": None,
                "resolution": "no_action_taken",
            },
        ),
        (
            "1",
            "Duplicate",
            None,
            {"ticket_id": "incident_id", "status": "in_progress", "assignee": None},
        ),
        (
            "2",
            "Not resolved",
            None,
            {"ticket_id": "incident_id", "status": "closed", "assignee": None},
        ),
    ],
)
def test_ticket_track_command_successful_execution(
    mocker, detection_status, close_reason, incident_owner, expected, requests_mock
) -> None:
    """
    Test case scenario for successful execution of ticket-track command.

    Given:
     - User has provided valid argument values.
    When:
     - ticket_track_command is called.
    Then:
     - Ensure outputs_prefix is correct.
     - Ensure readable_output is correct.
     - Ensure command output is correct.
     - Ensure patch_detections method is called with expected arguments.
    """
    args = {
        "incident_id": "incident_id",
        "detection_id": "detection_id",
        "incident_status": detection_status,
        "incident_close_reason": close_reason,
        "incident_owner": incident_owner,
    }

    client = init_mock_client(requests_mock, on_cloud=False)
    mocker.patch("ExtraHop_v2.ExtraHopClient.patch_detections")
    result = ExtraHop_v2.ticket_track_command(client, args)

    assert result.outputs_prefix == "ExtraHop"
    assert (
        result.readable_output
        == "Successfully linked detection(detection_id) with incident(incident_id)"
    )
    assert result.outputs == {"TicketId": "incident_id"}

    ExtraHop_v2.ExtraHopClient.patch_detections.assert_called_once_with(
        "detection_id", expected
    )


def test_validate_ticket_track_arguments_failed_execution():
    """
    Test case for ticket-track command that raise error for invalid argument.

    Given:
     - User has provided invalid incident_status.
    When:
     - validate_ticket_track_arguments is called.
    Then:
     - Ensure error is raised with extecpted error message.
    """
    # Verify invalid value
    with pytest.raises(ExtraHop_v2.InvalidValueError) as err:
        ExtraHop_v2.validate_ticket_track_arguments("4")

    assert (
        str(err.value)
        == "4 is an invalid value for incident_status. Possible values are: ['0', '1', '2', '3']"
    )


def test_validate_ticket_track_arguments_successful_execution():
    """
    Test case scenarios for successful execution of ticket-track command.

    Given:
     - User has provided valid incident_status.
    When:
     - validate_ticket_track_arguments is called.
    Then:
     - Ensure error is not raised for valid argument.
    """

    # Verify valid value
    assert not ExtraHop_v2.validate_ticket_track_arguments("3")


@pytest.mark.parametrize(
    "add_arg, remove_arg, expected",
    [
        [
            "id1, id2",
            "",
            "Successfully added new devices(id1, id2) in the watchlist \n",
        ],
        ["", "id1, id2", "Successfully removed devices(id1, id2) from the watchlist"],
        [
            "id1, id2",
            "id3",
            "Successfully added new devices(id1, id2) in the watchlist \n"
            "Successfully removed devices(id3) from the watchlist",
        ],
    ],
)
def test_watch_list_edit_command_successful_execution(
    requests_mock, mocker, add_arg, remove_arg, expected
):
    """
    Test case scenario for successful execution of watchlist-edit command.

    Given:
     - User has provided different arguments for watchlist-edit command.
    When:
     - watchlist-edit is called.
    Then:
     - Ensure readable_output is correct.
    """
    args = {"add": add_arg, "remove": remove_arg}

    client = init_mock_client(requests_mock, on_cloud=False)
    requests_mock.post(f"{BASE_URL}/api/v1/watchlist/devices")
    mocker.patch("ExtraHop_v2.get_devices_by_ip_or_id", return_value=[])

    actual = ExtraHop_v2.watchlist_edit_command(client, args)

    assert actual.readable_output == expected


def test_packets_search_invalid_output(requests_mock):
    """
    Test case scenario for invalid output in packets-search command.

    Given:
        User has provided valid credentials but invalid arguments.
    When:
        extrahop-packets-search command is called.
    Then:
        Raise error with right error message.
    """

    args_copy = copy(get_packets_search_args())
    args_copy["output"] = "gzip"
    with pytest.raises(ExtraHop_v2.InvalidValueError) as e:
        ExtraHop_v2.packets_search_command(
            init_mock_client(requests_mock, False), args_copy
        )
    assert (
        str(e.value)
        == "gzip is an invalid value for output. Possible values are: ['pcap', 'keylog_txt', 'zip']"
    )


def test_packets_search_204_status_code(requests_mock):
    """
    Test case scenario for packets-search command when no packets are returned from the API.

    Given:
        User has provided valid credentials.
    When:
        extrahop-packets-search command is called.
    Then:
        Return message about packets not found.
    """

    requests_mock.get(BASE_URL + PACKETS_SEARCH_URL, status_code=204)

    response = ExtraHop_v2.packets_search_command(
        init_mock_client(requests_mock, False), get_packets_search_args()
    )

    assert response == "Search matched no packets."


def test_packets_search_invalid_filename_headers(requests_mock):
    """
    Test case scenario to raise error when unexpected filename format found in the response headers for packet-search
    command.

    Given:
        User has provided valid credentials and packet are found in the API.
    When:
        extrahop-packets-search command is called.
    Then:
        Return right error message.
    """

    requests_mock.get(
        BASE_URL + PACKETS_SEARCH_URL,
        headers={"content-disposition": "file=packets.zip"},
        content="this is dummy packets".encode("ascii"),
    )

    with pytest.raises(ExtraHop_v2.DemistoException) as e:
        ExtraHop_v2.packets_search_command(
            init_mock_client(requests_mock, False), get_packets_search_args()
        )

    assert str(e.value) == "Error filename could not be found in response header."


def test_packets_search_file_data(requests_mock):
    """
    Test case scenario for packets-search command when packets received from the API.

    Given:
        User has provided valid credentials.
    When:
        extrahop-packets-search command is called.
    Then:
        Return file response.
    """
    requests_mock.get(
        BASE_URL + PACKETS_SEARCH_URL,
        headers={"content-disposition": "filename=packets.zip"},
        content="this is dummy packets".encode("ascii"),
    )

    response = ExtraHop_v2.packets_search_command(
        init_mock_client(requests_mock, False), get_packets_search_args()
    )

    assert response.get("File") == "packets.zip"


def test_devices_tag_invalid_args(requests_mock):
    """
    Test case scenario to verify devices-tag command when "add" and "remove" tags not found in the args.

    Given:
        User has provided valid credentials.
    When:
        extrahop-devices-tag command is called.
    Then:
        Raise error with valid error message.
    """
    with pytest.raises(ExtraHop_v2.DemistoException) as e:
        ExtraHop_v2.devices_tag_command(
            init_mock_client(requests_mock, False),
            {"tag": "MyTag", "add": None, "remove": None},
        )

    assert str(e.value) == "No device id provided to add or remove arguments."


@pytest.mark.parametrize(
    "add, remove, expected_data",
    [
        ("1,2", "3,4", '{"assign": [1, 2], "unassign": [3, 4]}'),
        ("1,2", None, '{"assign": [1, 2]}'),
        (None, "1,2", '{"unassign": [1, 2]}'),
    ],
)
def test_devices_tag(
    add, remove, expected_data, requests_mock, get_devices_by_ip_or_id_fixture
):
    """Test case scenario to verify devices-tag command when valid arguments provided.

    Given:
        User has provided valid credentials, and "add" or "remove" is present in demisto args.
    When:
        extrahop-devices-tag command is called.
    Then:
        User is informed of tag-untag devices.
    """
    args_copy = copy(get_device_tag_args())
    args_copy["add"] = add
    args_copy["remove"] = remove

    requests_mock.get(
        BASE_URL + GET_ALL_TAGS_URL,
        json=[
            {"id": "12", "name": "MyTag"},
            {"id": "13", "name": "TestTag"},
            {"id": "14", "name": "DummyTag"},
        ],
    )

    requests_mock.post(BASE_URL + TAG_DEVICE_URL)

    response = ExtraHop_v2.devices_tag_command(
        init_mock_client(requests_mock, False), args_copy
    )

    assert response == "Successfully tagged untagged the device/s."
    assert requests_mock.request_history[1].text == expected_data


@pytest.mark.parametrize(
    "add, remove, expected_data",
    [
        ("1,2", "3,4", '{"assign": [1, 2], "unassign": [3, 4]}'),
        ("1,2", None, '{"assign": [1, 2]}'),
    ],
)
def test_devices_tag_create_new_tag(
    add, remove, expected_data, get_devices_by_ip_or_id_fixture, requests_mock
):
    """
    Test case scenario for creating new Tag with tag name if no tag is found with
    expected name from the tags list, and call "tag_untag_devices" for that tag.

    Given:
        User has provided valid credentials.
    When:
        extrahop-devices-tag command is called.
    Then:
        Verify valid tag id was present in the tag-untag URL with expected json body.
    """
    args_copy = copy(get_device_tag_args())
    args_copy["add"] = add
    args_copy["remove"] = remove

    requests_mock.get(
        BASE_URL + GET_ALL_TAGS_URL,
        json=[
            {"id": "t1", "name": "NotMyTag"},
            {"id": "t2", "name": "TestTag"},
            {"id": "t3", "name": "DummyTag"},
        ],
    )

    requests_mock.post(BASE_URL + TAG_DEVICE_URL)

    requests_mock.post(BASE_URL + GET_ALL_TAGS_URL, headers={"location": "US/12"})

    response = ExtraHop_v2.devices_tag_command(
        init_mock_client(requests_mock, False), args_copy
    )

    assert response == "Successfully tagged untagged the device/s."
    assert requests_mock.request_history[2].path == TAG_DEVICE_URL
    assert requests_mock.request_history[2].text == expected_data


def test_devices_tag_nothing_to_remove(requests_mock, get_devices_by_ip_or_id_fixture):
    """
    Test case scenario to raise error when expected Tag not found from Reveal(X)
    and "remove" is present and "add" is not present in demisto args.

    Given:
        User has provided valid credentials.
    When:
        extrahop-devices-tag command is called.
    Then:
        Raise error with informative error message.
    """
    args_copy = copy(get_device_tag_args())
    del args_copy["add"]

    requests_mock.get(
        BASE_URL + GET_ALL_TAGS_URL,
        json=[
            {"id": "t1", "name": "NotMyTag"},
            {"id": "t2", "name": "TestTag"},
            {"id": "t3", "name": "DummyTag"},
        ],
    )

    requests_mock.post(BASE_URL + TAG_DEVICE_URL)

    with pytest.raises(ExtraHop_v2.DemistoException) as e:
        ExtraHop_v2.devices_tag_command(
            init_mock_client(requests_mock, False), args_copy
        )

    assert str(e.value) == "The tag MyTag does not exist, nothing to remove."


@pytest.mark.parametrize(
    "devices_str, id_only, expected_data",
    [
        ("1", True, [1]),
        ("1", False, [{"id": 1, "ip": "0.0.0.0"}]),
        ("0.0.0.0", True, [1]),
        ("0.0.0.0", False, [{"id": 1, "ip": "0.0.0.0"}]),
    ],
)
def test_get_devices_by_ip_or_id(
    devices_str, id_only, expected_data, requests_mock, mocker
):
    """
    Test case scenario to return devices list by IP address or device ID.

    Given:
        User has provided valid credentials, "add" or "remove" is present in the demisto args,
        ip addresses/device ids are provided in the device list string and id_only is true/false.
    When:
        extrahop-devices-tag command is called.
    Then:
        Return list of ids if id_only flag is Tue else device info.
    """
    requests_mock.get(BASE_URL + "/api/v1/devices/1", json={"id": 1, "ip": "0.0.0.0"})

    mocker.patch(
        "ExtraHop_v2.get_device_by_ip", return_value={"id": 1, "ip": "0.0.0.0"}
    )

    devices = ExtraHop_v2.get_devices_by_ip_or_id(
        init_mock_client(requests_mock, False), devices_str, id_only=id_only
    )

    assert devices == expected_data


def test_get_devices_by_ip_or_id_invalid_ip_address(requests_mock):
    """
    Test case scenario to raise error when invalid IP address found from the add/remove args.

    Given:
        User has provided valid credentials, "add" or "remove" is present in the
        demisto args and ip addresses are provided in the device list string.
    When:
        extrahop-devices-tag command is called.
    Then:
        Raise error with informative error message.
    """
    with pytest.raises(ExtraHop_v2.DemistoException) as e:
        ExtraHop_v2.get_devices_by_ip_or_id(
            init_mock_client(requests_mock, False), "10.0.0.0.1"
        )
    assert str(e.value) == "Error parsing IP Address 10.0.0.0.1"


@pytest.mark.parametrize("location", [None, "US/NYC"])
def test_parse_location_header_invalid_location(location):
    """
    Test case scenario to raise error when no location response found from headers of "client.create_new_tag".

    Given:
        User has provided valid credentials, expected tag is not found in
        the tag list, and "add" and "remove" is present in demisto args.
    When:
        extrahop-devices-tag command is called.
    Then:
        Raise error with informative error message.
    """
    with pytest.raises(ExtraHop_v2.DemistoException) as e:
        ExtraHop_v2.parse_location_header(location)
    assert (
        str(e.value) == "Error unable to parse ExtraHop API response location header."
    )


def test_parse_location_header():
    """Test case scenario to parse location data from "client.create_new_tag" API response.

    Given:
        User has provided valid credentials, expected tag is not found in
        the tag list, and "add" and "remove" is present in demisto args.
    When:
        extrahop-devices-tag command is called.
    Then:
        Return tag id from the response.
    """
    tag_id = ExtraHop_v2.parse_location_header("US/12")

    assert tag_id == "12"


@pytest.mark.parametrize("on_cloud", [False, True])
def test_extrahop_devices_search_command_success(on_cloud, requests_mock):
    """
    Test case scenario for successful execution of device search command.

    Given:
     - User has provided valid arguments.
    When:
     - devices_search_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=on_cloud)
    args = {"limit": 2}
    expected_response = load_mock_response("devices_search_response_success.json")
    networks = load_mock_response("get_networks.json")
    expected_readable_output = load_file("devices_search_response_success.md")
    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=200
    )
    requests_mock.get(f"{BASE_URL}/api/v1/networks", json=networks, status_code=200)

    result = ExtraHop_v2.devices_search_command(client, args, False)
    assert result.outputs_prefix == EXTRAHOP_DEVICE
    assert result.readable_output == expected_readable_output


def test_extrahop_devices_search_command_success_empty_response(requests_mock):
    """
    Test case scenario for successful execution of device search command.

    Given:
     - User has provided valid arguments.
    When:
     - devices_search_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"limit": 2}
    expected_response = []
    networks = load_mock_response("get_networks.json")
    expected_readable_output = "No Devices found"
    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=200
    )
    requests_mock.get(f"{BASE_URL}/api/v1/networks", json=networks, status_code=200)

    result = ExtraHop_v2.devices_search_command(client, args, False)
    assert result.outputs_prefix == EXTRAHOP_DEVICE
    assert result.readable_output == expected_readable_output


@pytest.mark.parametrize(
    "args, message",
    [
        (
            {"role": "dbserver"},
            f"dbserver is an invalid value for role. Possible values are: {ExtraHop_v2.VALID_DEVICE_ROLES}",
        ),
        (
            {"software": "MacOS"},
            f"MacOS is an invalid value for software. Possible values are: {ExtraHop_v2.VALID_DEVICE_SOFTWARES}",
        ),
        (
            {"vendor": "lenovo"},
            f"lenovo is an invalid value for vendor. Possible values are: {ExtraHop_v2.VALID_DEVICE_VENDORS}",
        ),
        (
            {"match_type": "nor"},
            f"nor is an invalid value for match_type. Possible values are: {ExtraHop_v2.VALID_DEVICE_MATCH_TYPES}",
        ),
        (
            {"operator": "=="},
            f"== is an invalid value for operator. Possible values are: {ExtraHop_v2.VALID_DEVICE_OPERATORS}",
        ),
        (
            {"activity": "abc_client"},
            f"abc_client is an invalid value for activity. Possible values are: {ExtraHop_v2.VALID_DEVICE_ACTIVITIES}",
        ),
    ],
)
def test_extrahop_devices_search_command_with_invalid_arguments(
    args, message, requests_mock
):
    """
    Test case scenario for invalid arguments while execution of device search command.

    Given:
     - User has provided invalid arguments.
    When:
     - devices_search_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    with pytest.raises(ExtraHop_v2.InvalidValueError) as error:
        ExtraHop_v2.devices_search_command(client, args, False)

    assert str(error.value) == message


def test_extrahop_devices_search_command_failure_400(requests_mock):
    """
    Test case scenario for execution of device search command when invalid id is passed.

    Given:
     - User has provided invalid arguments.
    When:
     - devices_search_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"limit": "2"}
    expected_response = {
        "type": "invalid_request",
        "detail": "'limit' must be one of the following types: int",
    }
    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=400
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.devices_search_command(client, args, False)
    assert (
        str(error.value)
        == 'Error in API call [400] - None\n{"type": "invalid_request", "detail": "\'limit\' must be one'
        ' of the following types: int"}'
    )


def test_extrahop_devices_search_command_failure_401(requests_mock):
    """
    Test case scenario for execution of device search command when authentication is invalid.

    Given:
     - User has provided valid arguments.
    When:
     - devices_search_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"limit": 2}
    expected_response = {"error_message": INVALID_AUTH_HEADER}

    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=401
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.devices_search_command(client, args, False)
    assert (
        str(error.value)
        == 'Error in API call [401] - None\n{"error_message": "'
        + INVALID_AUTH_HEADER
        + '"}'
    )


@pytest.mark.parametrize(
    "args, message",
    [
        ({"ip_or_id": "10:1:1"}, "Error parsing IP Address 10:1:1"),
    ],
)
def test_extrahop_protocols_get_invalid_ip(args, message, requests_mock):
    """
    Test case scenario for passing invalid ip while execution of protocol get command.

    Given:
     - User has provided invalid ip address.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    with pytest.raises(Exception) as error:
        ExtraHop_v2.protocols_get_command(client, args, False)

    assert str(error.value) == message


def test_extrahop_protocols_get_failure_404(requests_mock):
    """
    Test case scenario for execution of protocol get command when id is not found.

    Given:
     - User has provided valid arguments.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "23133113"}
    expected_response = '{"error_message": "The specified object was not found."}'
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=404,
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.protocols_get_command(client, args, False)
    assert (
        str(error.value)
        == 'Error in API call [404] - None\n"{\\"error_message\\": \\"The specified object was '
        'not found.\\"}"'
    )


def test_extrahop_protocols_get_failure_401(requests_mock):
    """
    Test case scenario for execution of protocol get command when authentication is invalid.

    Given:
     - User has provided valid arguments.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "2"}
    expected_response = {"error_message": INVALID_AUTH_HEADER}

    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=401,
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.protocols_get_command(client, args, False)
    assert (
        str(error.value)
        == 'Error in API call [401] - None\n{"error_message": "'
        + INVALID_AUTH_HEADER
        + '"}'
    )


@pytest.mark.parametrize("on_cloud", [False, True])
def test_extrahop_protocols_get_success_get_device_by_id(on_cloud, requests_mock):
    """
    Test case scenario for successful execution of protocol get command when id is passed.

    Given:
     - User has provided valid arguments.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=on_cloud)
    args = {"ip_or_id": "3564"}
    expected_response = load_mock_response(
        "protocols_get_success_get_device_by_id.json"
    )
    expected_readable_output = load_file("get_protocol_readable_output.md")
    expected_activity_map = load_mock_response(GET_PROTOCOL_FILE)
    expected_networks = load_mock_response(GET_PROTOCOL_NETWORKS_FILE)
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=200,
    )
    requests_mock.post(
        f"{BASE_URL}/api/v1/activitymaps/query",
        json=expected_activity_map,
        status_code=200,
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", json=expected_networks, status_code=200
    )
    result = ExtraHop_v2.protocols_get_command(client, args, False)

    assert result.outputs_prefix == EXTRAHOP_DEVICE
    assert result.readable_output == expected_readable_output


def test_extrahop_protocols_get_success_get_device_by_ip(requests_mock):
    """
    Test case scenario for successful execution of protocol get command when valid ip is passed.

    Given:
     - User has provided valid arguments.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "0.0.0.0"}
    expected_response = load_mock_response(
        "protocols_get_success_get_device_by_ip.json"
    )
    expected_readable_output = load_file("get_protocol_readable_output.md")
    expected_activity_map = load_mock_response(GET_PROTOCOL_FILE)
    expected_networks = load_mock_response(GET_PROTOCOL_NETWORKS_FILE)
    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=200
    )
    requests_mock.post(
        f"{BASE_URL}/api/v1/activitymaps/query",
        json=expected_activity_map,
        status_code=200,
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", json=expected_networks, status_code=200
    )
    result = ExtraHop_v2.protocols_get_command(client, args, False)

    assert result.outputs_prefix == EXTRAHOP_DEVICE
    assert result.readable_output == expected_readable_output


def test_extrahop_protocols_get_ip_not_present_in_extrahop(requests_mock):
    """Test case scenario for passing valid ip but is not present in extrahop while execution of protocol get command.

    Given:
     - User has provided valid arguments.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure appropriate error is raised.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "0.0.0.0"}
    expected_error_message = (
        f"Error the IP Address {args['ip_or_id']} was not found in ExtraHop."
    )
    expected_response = []
    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=200
    )
    with pytest.raises(DemistoException) as error:
        ExtraHop_v2.protocols_get_command(client, args, False)

    assert str(error.value) == expected_error_message


def test_extrahop_protocols_get_device_by_id_discovery(requests_mock):
    """
    Test case scenario for execution of protocol get command when the device has analysis field as discovery.

    Given:
     - User has provided valid arguments.
    When:
     - protocols_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "567"}
    expected_response = load_mock_response(
        "protocols_get_success_get_device_by_id_discovery.json"
    )
    expected_activity_map = load_mock_response(GET_PROTOCOL_FILE)
    expected_networks = load_mock_response(GET_PROTOCOL_NETWORKS_FILE)
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=200,
    )
    requests_mock.post(
        f"{BASE_URL}/api/v1/activitymaps/query",
        json=expected_activity_map,
        status_code=200,
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", json=expected_networks, status_code=200
    )
    result = ExtraHop_v2.protocols_get_command(client, args, False)

    assert result.outputs_prefix == EXTRAHOP_DEVICE
    assert result.readable_output == "No Protocol activity found"


@pytest.mark.parametrize("on_cloud", [False, True])
def test_alerts_rules_get_command_success(on_cloud, requests_mock):
    """Test case scenario for successful execution of alert rules get command.

    Given:
     - User has provided valid credentials.
    When:
     - alerts_rules_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=on_cloud)
    expected_response = load_mock_response("alerts_get.json")

    expected_readable_output = load_file("alerts_get.md")
    requests_mock.get(f"{BASE_URL}/api/v1/alerts", json=expected_response)
    result = ExtraHop_v2.alerts_rules_get_command(client)
    assert result.outputs_prefix == "ExtraHop.Alert"
    assert result.readable_output == expected_readable_output


def test_alerts_rules_get_command_success_no_alerts(requests_mock):
    """Test case scenario for successful execution of alert rules get command.

    Given:
     - User has provided valid credentials.
    When:
     - alerts_rules_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    expected_response = []
    expected_readable_output = "No Alerts were found."
    requests_mock.get(
        f"{BASE_URL}/api/v1/alerts", json=expected_response, status_code=200
    )
    result = ExtraHop_v2.alerts_rules_get_command(client)

    assert result.outputs_prefix == "ExtraHop.Alert"
    assert result.readable_output == expected_readable_output


def test_alerts_rules_get_command_failure_401(requests_mock):
    """Test case scenario for execution of alert rules get command when authentication is invalid.

    Given:
     - User has provided invalid credentials.
    When:
     - alerts_rules_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    expected_response = {"error_message": INVALID_AUTH_HEADER}

    requests_mock.get(
        f"{BASE_URL}/api/v1/alerts", json=expected_response, status_code=401
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.alerts_rules_get_command(client)
    assert (
        str(error.value)
        == 'Error in API call [401] - None\n{"error_message": "'
        + INVALID_AUTH_HEADER
        + '"}'
    )


def test_activity_map_get_command_failure_401(requests_mock):
    """Test case scenario for execution of activity map get command when authentication is invalid.

    Given:
     - User has provided invalid credentials.
    When:
     - activity_map_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "3564"}
    expected_response = {"error_message": INVALID_AUTH_HEADER}

    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=401,
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.activity_map_get_command(client, args, False)
    assert (
        str(error.value)
        == 'Error in API call [401] - None\n{"error_message": "'
        + INVALID_AUTH_HEADER
        + '"}'
    )


def test_activity_map_get_command_failure_404(requests_mock):
    """Test case scenario for execution of activity map get command when id is not found.

    Given:
     - User has provided valid arguments.
    When:
     - activity_map_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "23133113"}
    expected_response = '{"error_message": "The specified object was not found."}'
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=404,
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.activity_map_get_command(client, args, False)
    assert (
        str(error.value)
        == 'Error in API call [404] - None\n"{\\"error_message\\": \\"The specified object was '
        'not found.\\"}"'
    )


@pytest.mark.parametrize(
    "args, message",
    [
        (
            {"ip_or_id": "10.1.2"},
            "'10.1.2' does not appear to be an IPv4 or IPv6 address",
        ),
        (
            {"ip_or_id": "0.0.0.0", "time_interval": "1 hour"},
            f"1 hour is an invalid value for time_interval. "
            f"Possible values are: {ExtraHop_v2.VALID_TIME_INTERVALS}",
        ),
        (
            {"ip_or_id": "0.0.0.0", "from_time": "30m"},
            'Invalid number: "from_time"="30m"',
        ),
        (
            {"ip_or_id": "0.0.0.0", "until_time": "50m"},
            'Invalid number: "until_time"="50m"',
        ),
        (
            {"ip_or_id": "0.0.0.0", "peer_role": "temp"},
            f"temp is an invalid value for peer_role. "
            f"Possible values are: {ExtraHop_v2.VALID_PEER_ROLES}",
        ),
        (
            {"ip_or_id": "0.0.0.0", "protocol": "ICAMP"},
            f"ICAMP is an invalid value for protocol. "
            f"Possible values are: {ExtraHop_v2.VALID_PROTOCOLS}",
        ),
    ],
)
def test_activity_map_get_command_invalid_arguments(args, message, requests_mock):
    """Test case scenario for execution of activity map get command when invalid arguments are passed.

    Given:
     - User has provided invalid arguments.
    When:
     - activity_map_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    with pytest.raises(Exception) as error:
        ExtraHop_v2.activity_map_get_command(client, args, False)
    assert str(error.value) == message


@pytest.mark.parametrize(
    "args, message",
    [
        (
            {"ip_or_id": "3564", "from_time": "30"},
            "When using a fixed time range both from_time and until_time "
            "timestamps need to be provided.",
        ),
        (
            {"ip_or_id": "3564", "until_time": "30"},
            "When using a fixed time range both from_time and until_time "
            "timestamps need to be provided.",
        ),
    ],
)
def test_activity_map_get_command_failure_when_either_from_time_or_until_time_is_given(
    args, message, requests_mock
):
    """Test case scenario for execution of activity map get command when either from_time or until_time is given.

    Given:
     - User has provided valid arguments.
    When:
     - activity_map_get_command is called.
    Then:
     - Ensure appropriate error is generated.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    expected_response = load_mock_response("activity_map_devices_by_id.json")
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=200,
    )
    with pytest.raises(Exception) as error:
        ExtraHop_v2.activity_map_get_command(client, args, False)
    assert str(error.value) == message


@pytest.mark.parametrize("on_cloud", [False, True])
def test_activity_map_get_command_success_id(on_cloud, requests_mock):
    """Test case scenario for successful execution of activity map get command when valid id is passed.

    Given:
     - User has provided valid arguments.
    When:
     - activity_map_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=on_cloud)
    args = {"ip_or_id": "3564"}
    expected_response = load_mock_response("activity_map_devices_by_id.json")
    expected_network = load_mock_response("activity_get_networks.json")
    expected_readable_output = load_file("activity_map_get_readable_output.md")
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/{args['ip_or_id']}",
        json=expected_response,
        status_code=200,
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", json=expected_network, status_code=200
    )
    result = ExtraHop_v2.activity_map_get_command(client, args, False)

    assert result.outputs_prefix == "ExtraHop.ActivityMap"
    assert result.readable_output == str(expected_readable_output)


def test_activity_map_get_command_success_ip(requests_mock):
    """Test case scenario for successful execution of activity map get command when valid ip is passed.

    Given:
     - User has provided valid arguments.
    When:
     - activity_map_get_command is called.
    Then:
     - Ensure human-readable output is correct.
     - Ensure outputs prefix is correct.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    args = {"ip_or_id": "0.0.0.0"}
    expected_response = load_mock_response("activity_map_devices_by_ip.json")
    expected_network = load_mock_response("activity_get_networks.json")
    expected_readable_output = load_file("activity_map_get_readable_output.md")
    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", json=expected_response, status_code=200
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", json=expected_network, status_code=200
    )
    result = ExtraHop_v2.activity_map_get_command(client, args, False)

    assert result.outputs_prefix == "ExtraHop.ActivityMap"
    assert result.readable_output == str(expected_readable_output)


def setup_peers_get_command_by_id(
    is_discovery: bool, is_check_for_empty: bool, requests_mock
) -> ExtraHop_v2.CommandResults:
    """Mock the result of extrahop-peers-get command.

    Args:
        is_discovery: Set true for mock response has analysis set to discovery.
        is_check_for_empty: Set true for test empty device output.
        requests_mock: This parameter is used for creating mock_request.

    Returns:
        Command result object which have output for extrahop-peers-get command.
    """
    mock_response_uuid = load_mock_response("appliance_uuids_get_success.json")
    mock_response_for_activity_map = load_mock_response("get_peers_activity_maps.json")
    mock_response_for_get_device_id = load_mock_response("get_peer_device_by_id.json")

    if is_discovery:
        mock_response_for_get_device_id["analysis"] = "discovery"
    if is_check_for_empty:
        mock_response_for_activity_map["edges"] = []

    requests_mock.post(
        f"{BASE_URL}/api/v1/activitymaps/query",
        status_code=200,
        json=mock_response_for_activity_map,
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", status_code=200, json=mock_response_uuid
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/206",
        status_code=200,
        json=mock_response_for_get_device_id,
    )

    mock_client = init_mock_client(requests_mock, on_cloud=False)
    args = {
        "ip_or_id": 206,
        "query_from": "-60m",
        "query_until": "0",
        "protocol": "any",
        "peer_role": "any",
    }
    result = ExtraHop_v2.peers_get_command(mock_client, args, False)
    return result


def test_peers_get_command_on_prem_by_ip_success(requests_mock) -> None:
    """Test case scenario to validate peers_get command with valid ip value.

    Given:
     - User has provided valid ip and arguments.
    When:
     - Peers-get-command is called.
    Then:
     - Ensure number of arguments are correct.
     - Ensure command returns proper output.

    """
    mock_response_devices = load_mock_response("get_peers_device_search.json")
    mock_response_uuid = load_mock_response("appliance_uuids_get_success.json")

    mock_response_for_activity_map = load_mock_response("get_peers_activity_maps.json")
    mock_response_for_get_device_id = load_mock_response("get_peer_device_by_id.json")

    requests_mock.post(
        f"{BASE_URL}/api/v1/devices/search", status_code=200, json=mock_response_devices
    )
    requests_mock.post(
        f"{BASE_URL}/api/v1/activitymaps/query",
        status_code=200,
        json=mock_response_for_activity_map,
    )

    requests_mock.get(
        f"{BASE_URL}/api/v1/networks", status_code=200, json=mock_response_uuid
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/devices/3564",
        status_code=200,
        json=mock_response_for_get_device_id,
    )

    mock_client = init_mock_client(requests_mock, on_cloud=False)
    args = {
        "ip_or_id": "0.0.0.0",
        "query_from": "-60m",
        "query_until": "0",
        "protocol": "any",
    }

    result = ExtraHop_v2.peers_get_command(mock_client, args, False)

    peer_get_success_result = load_mock_response(
        "peer_get_command_on_prem_ip_success.json"
    )

    peer_get_hr_result = load_file("peer_get_command_on_prem_ip_success.md")

    assert result.outputs == ExtraHop_v2.remove_empty_elements_from_response(
        peer_get_success_result
    )
    assert result.readable_output == peer_get_hr_result
    assert result.outputs_key_field == "id"
    assert result.raw_response == peer_get_success_result
    assert result.outputs_prefix == EXTRAHOP_DEVICE


def test_peers_get_command_on_prem_by_id_success(requests_mock) -> None:
    """Test case scenario to validate peers_get command with valid id value.

    Given:
     - User has provided valid ip and arguments.
    When:
     - Peers-get-command is called.
    Then:
     - Ensure number of arguments are correct.
     - Ensure command returns proper output.

    """
    result = setup_peers_get_command_by_id(False, False, requests_mock)
    peer_get_success_result = load_mock_response(
        "peer_get_command_on_prem_id_success.json"
    )

    peer_get_hr_result = load_file("peer_get_command_on_prem_id_success.md")

    assert result.outputs == ExtraHop_v2.remove_empty_elements_from_response(
        peer_get_success_result
    )
    assert result.readable_output == peer_get_hr_result
    assert result.outputs_key_field == "id"
    assert result.raw_response == peer_get_success_result
    assert result.outputs_prefix == EXTRAHOP_DEVICE


def test_peers_get_command_with_discovery_success(requests_mock) -> None:
    """Test case scenario command with mock response has set analysis field set to discovery runs successfully.

    Given:
     - User has provided valid id and arguments and response has analysis field set to discovery.
    When:
     - Peers-get-command is called.
    Then:
     - Ensure number of arguments are correct.
     - Ensure command returns proper output.
    """
    result = setup_peers_get_command_by_id(True, False, requests_mock)

    peer_discovery_success_result = load_mock_response("get_peer_discovery_output.json")
    peer_discovery_hr = load_file("get_peer_discovery_output.md")

    assert peer_discovery_success_result == result.raw_response
    assert peer_discovery_hr == result.readable_output


@pytest.mark.parametrize(
    "args, error_message",
    [
        (
            {
                "ip_or_id": 206,
                "query_from": "-60m",
                "query_until": "0",
                "protocol": "asdf",
                "peer_role": "any",
            },
            f"asdf is an invalid value for protocol. Possible values are: {ExtraHop_v2.VALID_PROTOCOLS}",
        ),
        (
            {
                "ip_or_id": 206,
                "query_from": "-60m",
                "query_until": "0",
                "protocol": "any",
                "peer_role": "asdf",
            },
            f"asdf is an invalid value for peer_role. Possible values are: {ExtraHop_v2.VALID_PEER_ROLES}",
        ),
    ],
)
def test_validate_arguments_for_get_peer_command_failure(
    args: dict, error_message: str, requests_mock
) -> None:
    """Test case scenario for invalid arguments while execution of peers-get-command.

    Given:
     - User has provided invalid arguments.
    When:
     - Peers-get-command is called.
    Then:
     - Ensure appropriate error raised.
    """
    mock_client = init_mock_client(on_cloud=False, requests_mock=requests_mock)
    with pytest.raises(ExtraHop_v2.InvalidValueError) as error:
        _ = ExtraHop_v2.peers_get_command(mock_client, args, False)
    assert error_message == str(error.value)


def test_validate_ip_for_get_peer_command_failure(requests_mock) -> None:
    """Test case scenario for invalid ip value while execution of peers-get-command.

    Given:
     - User has provided invalid ip.
    When:
     - Peers-get-command is called.
    Then:
     - Ensure appropriate error raised.
    """
    args = {"ip_or_id": "1:1:1"}
    mock_client = init_mock_client(on_cloud=False, requests_mock=requests_mock)
    with pytest.raises(ExtraHop_v2.DemistoException) as error:
        _ = ExtraHop_v2.peers_get_command(mock_client, args, False)
    assert "Error parsing IP Address 1:1:1" == str(error.value)


def test_empty_response_of_device_failure_for_peers_get_command(requests_mock) -> None:
    """Test case scenario for validating provided ip is not found.

    Given:
     - User has provided valid arguments.
    When:
     - Peers-get-command is called but provided ip can't find on ExtraHop instance.
    Then:
     - Ensure appropriate error raised.
    """
    requests_mock.post(f"{BASE_URL}/api/v1/devices/search", status_code=404, json=[])
    mock_client = init_mock_client(on_cloud=False, requests_mock=requests_mock)
    args = {
        "ip_or_id": "0.0.0.0",
        "query_from": "-60m",
        "query_until": "0",
        "protocol": "any",
    }
    with pytest.raises(ExtraHop_v2.DemistoException) as error:
        _ = ExtraHop_v2.peers_get_command(mock_client, args, False)
    assert "Error in API call [404] - None\n[]" == str(error.value)


def test_for_prepare_device_get_output_success(requests_mock) -> None:
    """Test case scenario for validating empty response.

    Given:
     - User has provided valid ip and arguments.
    When:
     - Peers-get-command is called but ExtraHop returns empty response.
    Then:
     - Ensure command returns proper output.
    """
    result = setup_peers_get_command_by_id(False, True, requests_mock)

    assert "No Devices found" == result.readable_output
    assert [] == result.raw_response


def test_module_on_prem_success(requests_mock) -> None:
    """Test case scenario for test connection with on-prem instance.

    Given:
     - User has provided valid arguments.
    When:
     - Test_module is called.
    Then:
     - Ensure command returns proper output.
    """
    mock_client = init_mock_client(on_cloud=False, requests_mock=requests_mock)
    success_response = load_mock_response("test_module_on_prem.json")
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop", status_code=200, json=success_response
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version",
        status_code=200,
        json={"version": "9.9.9"},
    )
    result = ExtraHop_v2.test_module(mock_client)

    assert result == "ok"


def test_module_on_cloud(requests_mock) -> None:
    """Test case scenario for test connection with on-cloud instance returns success.

    Given:
     - User has provided valid arguments.
    When:
     - Test_module is called.
    Then:
     - Ensure command returns proper output.
    """
    mock_client = init_mock_client(on_cloud=False, requests_mock=requests_mock)
    success_response = load_mock_response("test_module_on_cloud.json")
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop", status_code=200, json=success_response
    )
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version",
        status_code=200,
        json={"version": "9.9.9"},
    )
    result = ExtraHop_v2.test_module(mock_client)

    assert result == "ok"


def test_module_failure_on_prem_failure(requests_mock) -> None:
    """Unit test case scenario for test connection with on-prem instance for validating failure.

    Given:
     - User has provided invalid arguments.
    When:
     - Test_module is called.
    Then:
     - Ensure appropriate error raised.
    """
    mock_client = init_mock_client(on_cloud=False, requests_mock=requests_mock)
    requests_mock.get(f"{BASE_URL}/api/v1/extrahop", status_code=401, json=[])
    with pytest.raises(ValueError) as error:
        _ = ExtraHop_v2.test_module(mock_client)

    assert str(error.value) == "Error code 401: Invalid credentials provided."


@pytest.mark.parametrize(
    "parameters, error_msg, last_run",
    [
        ({"first_fetch": "++"}, '"++" is not a valid date', {}),
        (
            {"advanced_filter": "{'risk_score_min':50}"},
            "Invalid JSON string provided for advanced filter.",
            {},
        ),
    ],
)
def test_fetch_detection_when_invalid_arguments_provided(
    parameters, error_msg, last_run, requests_mock
):
    """Test case scenario for execution of fetch_detections when invalid arguments are provided.

    Given:
       - Parameters for fetch_incident
    When:
       - Calling `fetch_incidents` function
    Then:
       - Returns a valid error message.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    with pytest.raises(ValueError) as err:
        ExtraHop_v2.fetch_incidents(client, parameters, last_run, False)
    assert str(err.value) == error_msg


def test_fetch_detections_failure_when_firmware_version_is_outdated(requests_mock):
    """Test case scenario for execution of fetch_detections when ExtraHop firmware version is less than 9.3.0.

    Given:
       - Parameters for fetch_incident
    When:
       - Calling `fetch_incidents` function
    Then:
       - Returns a valid error message.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.1.2.1943"}
    )
    with pytest.raises(DemistoException) as err:
        ExtraHop_v2.fetch_incidents(client, {}, {}, False)
    assert (
        str(err.value)
        == "This integration works with ExtraHop firmware version greater than or equal to 9.3.0"
    )


@pytest.mark.parametrize("advanced_filter", ["{}", '{"categories":["sec.attack"]}'])
def test_fetch_detection_success_with_last_run(requests_mock, advanced_filter):
    """Test case scenario for execution of fetch_detections when last_run is present.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid output
    """
    incidents = load_mock_response("mock_incidents.json")

    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )

    mock_response = load_mock_response("fetch_detections_success.json")
    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=mock_response)

    mock_device_data = load_mock_response("mock_device_data.json")
    requests_mock.get(f"{BASE_URL}/api/v1/devices/1904", json=mock_device_data)

    mock_time = datetime.datetime.now()
    mock_time = int(
        (mock_time.timestamp() + 10) * 1000
    )  # adding 10 seconds to time and then convert to milliseconds
    client = init_mock_client(requests_mock, on_cloud=False)
    last_run = {
        "detection_start_time": 1676896891452,
        "offset": 0,
        "version_recheck_time": mock_time,
    }
    actual_incidents, next_run = ExtraHop_v2.fetch_incidents(
        client, {"advanced_filter": advanced_filter}, last_run, False)

    assert next_run == {
        "detection_start_time": 1673518450001,
        "offset": 0,
        "version_recheck_time": mock_time,
        'already_fetched': [997222]
    }
    assert actual_incidents[0]["name"] == incidents[0]["name"]
    assert actual_incidents[0]["occurred"] == incidents[0]["occurred"]
    assert actual_incidents[0]["rawJSON"] == json.dumps(incidents[0]["rawJSON"])


def test_fetch_detection_participants_is_empty(requests_mock):
    """Test case scenario for execution of fetch_detections when participant is empty list.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid output
    """
    incidents = load_mock_response("mock_incidents_no_participants.json")

    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )

    mock_response = load_mock_response("fetch_detections_empty_participants.json")
    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=mock_response)

    mock_time = datetime.datetime.now()
    mock_time = int(
        (mock_time.timestamp() + 10) * 1000
    )  # adding 10 seconds to time and then convert to milliseconds
    client = init_mock_client(requests_mock, on_cloud=False)
    last_run = {
        "detection_start_time": 1676896891452,
        "offset": 0,
        "version_recheck_time": mock_time,
    }
    actual_incidents, next_run = ExtraHop_v2.fetch_incidents(client, {}, last_run, False)

    assert next_run == {
        "detection_start_time": 1673518450001,
        "offset": 0,
        "version_recheck_time": mock_time,
        'already_fetched': [997222]
    }
    assert actual_incidents[0]["name"] == incidents[0]["name"]
    assert actual_incidents[0]["occurred"] == incidents[0]["occurred"]
    assert actual_incidents[0]["rawJSON"] == json.dumps(incidents[0]["rawJSON"])


@mock.patch("ExtraHop_v2.MAX_FETCH", 1)
def test_fetch_detections_success_when_detections_equal_to_max_fetch(requests_mock):
    """Test case scenario for execution of fetch_detections when no of records are equal or greater than max_fetch.

    Given:
        - command arguments for fetch_incidents
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid output
    """
    incidents = load_mock_response("mock_incidents.json")

    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )

    mock_response = load_mock_response("fetch_detections_success.json")
    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=mock_response)

    mock_device_data = load_mock_response("mock_device_data.json")
    requests_mock.get(f"{BASE_URL}/api/v1/devices/1904", json=mock_device_data)

    client = init_mock_client(requests_mock, on_cloud=False)
    actual_incidents, next_run = ExtraHop_v2.fetch_incidents(client, {}, {}, False)

    assert next_run["offset"] == 1
    assert actual_incidents[0]["name"] == incidents[0]["name"]
    assert actual_incidents[0]["occurred"] == incidents[0]["occurred"]
    assert actual_incidents[0]["rawJSON"] == json.dumps(incidents[0]["rawJSON"])


def test_fetch_incident_empty_response(requests_mock):
    """Test case scenario for execution of fetch_detections when no records are returned from API.

    Given:
        - command arguments for fetch_incidents
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid output
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    last_run = {"update_or_mod_time": "update_time"}
    parameters = {"first_fetch": "1 Jan"}
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    requests_mock.post(f"{BASE_URL}/api/v1/detections/search", json=[], status_code=200)
    actual_incidents, next_run = ExtraHop_v2.fetch_incidents(
        client, parameters, last_run, False
    )

    assert actual_incidents == []


def test_test_module_failure_extrahop_version_is_outdated(requests_mock):
    """Test case scenario for execution of test_module when ExtraHop firmware version is outdated.

    Given:
        - command arguments for test_module
    When:
        - Calling `test_module` function
    Then:
        - Returns a valid error message.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    requests_mock.get(f"{BASE_URL}/api/v1/extrahop", json={})
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.1.2.1943"}
    )
    with pytest.raises(DemistoException) as err:
        ExtraHop_v2.test_module(client)
    assert (
        str(err.value)
        == "This integration works with ExtraHop firmware version greater than or equal to 9.3.0"
    )


def test_test_module_failure(requests_mock):
    """Test case scenario for failure of test_module.

    Given:
        - command arguments for test_module
    When:
        - Calling `test_module` function
    Then:
        - Returns a valid error message.
    """
    client = init_mock_client(requests_mock, on_cloud=False)
    requests_mock.get(f"{BASE_URL}/api/v1/extrahop", json={})
    requests_mock.get(
        f"{BASE_URL}/api/v1/extrahop/version", json={"version": "9.3.0.1319"}
    )
    with pytest.raises(ValueError) as err:
        ExtraHop_v2.test_module(client)
    assert str(err.value) == "Failed to establish connection with provided credentials."
