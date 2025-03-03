"""Test file for Illumio Integration."""

import re

import pytest
import illumio
from illumio import (
    TrafficFlow,
    ServiceBinding,
    Workload,
    PolicyVersion,
    PolicyComputeEngine,
    VirtualService,
    IllumioException,
    EnforcementBoundary,
    IPList,
    Rule,
    RuleSet,
)

from CommonServerPython import *  # noqa
from IllumioCore import (
    command_test_module,
    InvalidValueError,
    VALID_POLICY_DECISIONS,
    VALID_PROTOCOLS,
    traffic_analysis_command,
    prepare_traffic_analysis_output,
    virtual_service_create_command,
    prepare_virtual_service_output,
    service_binding_create_command,
    prepare_service_binding_output,
    object_provision_command,
    prepare_object_provision_output,
    workload_get_command,
    prepare_workload_get_output,
    workloads_list_command,
    prepare_workloads_list_output,
    enforcement_boundary_create_command,
    prepare_enforcement_boundary_create_output,
    prepare_update_enforcement_mode_output,
    update_enforcement_mode_command,
    ip_list_get_command,
    prepare_ip_list_get_output,
    prepare_ip_lists_get_output,
    rule_create_command,
    ip_lists_get_command,
    ruleset_create_command,
    prepare_ruleset_create_output,
    prepare_rule_create_output,
)

""" CONSTANTS """

WORKLOAD_EXP_URL = "/orgs/1/workloads/dummy"
WORKLOAD_URL = re.compile("/orgs/1/workloads")
VIRTUAL_SERVICE_EXP_URL = "/orgs/1/sec_policy/active/virtual_services/dummy"
TEST_DATA_DIRECTORY = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "test_data"
)
INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE = (
    "{} is an invalid value for port. Value must be in 0 to 65535 or -1."
)
INVALID_PORT_NUMBER_EXCEPTION_MESSAGE = (
    "{} is an invalid value for port. Value must be in 1 to 65535."
)
CONVERT_PROTOCOL_EXCEPTION_MESSAGE = (
    "{} is an invalid value for protocol. Possible values are: ['tcp', 'udp']."
)
MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE = (
    "{} is a required parameter. Please provide correct value."
)
NOT_VALID_NUMBER_EXCEPTION_MESSAGE = 'Invalid number: "{}"="{}"'
INVALID_ENFORCEMENT_MODES_EXCEPTION_MESSAGE = "{} is an invalid enforcement mode."
INVALID_VISIBILITY_LEVEL_EXCEPTION_MESSAGE = "{} is an invalid visibility level."
INVALID_BOOLEAN_EXCEPTION_MESSAGE = (
    "Argument does not contain a valid boolean-like value"
)
INVALID_MAX_RESULTS_EXCEPTION_MESSAGE = (
    "{} is an invalid value for max results. Max results must be between 0 and 500"
)
INVALID_VALUE_EXCEPTION_MESSAGE = "{} is an invalid for {}."
INVALID_HREF_ENFORCEMENT_BOUNDARY = "Invalid HREF in policy provision changeset: {}"
UPDATE_WORKLOAD_URL = re.compile("/orgs/1/workloads/bulk_update")


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    client = PolicyComputeEngine(url="https://127.0.0.1:8443", port=8443, org_id=1)
    client.set_credentials("dummy", "dummy-1")

    return client


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture(scope="module")
def traffic_analysis_success():
    """Retrieve the json response for traffic analysis."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "traffic_analysis_download_data.json")
    )


@pytest.fixture(scope="module")
def traffic_analysis_success_hr():
    """Retrieve the human-readable for traffic analysis."""
    with open(
        os.path.join(TEST_DATA_DIRECTORY, "traffic_analysis_success_hr.md")
    ) as file:
        hr_output = file.read()
    return hr_output


@pytest.fixture(scope="module")
def virtual_service_create_success():
    """Retrieve the json response for virtual service."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY, "create_virtual_service_success_response.json"
        )
    )


@pytest.fixture(scope="module")
def virtual_service_create_success_udp():
    """Retrieve the json response for virtual service for UDP protocol."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY,
            "create_virtual_service_success_response_protocol_as_udp.json",
        )
    )


@pytest.fixture(scope="module")
def virtual_service_success_hr():
    """Retrieve the human-readable response for virtual service."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY, "create_virtual_service_success_response_hr.md"
        )
    ) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def virtual_service_success_udp_hr():
    """Retrieve the human-readable response for virtual service for UDP protocol."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY,
            "create_virtual_service_success_response_protocol_as_udp_hr.md",
        )
    ) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def service_binding_success():
    """Retrieve the json response for service binding."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "create_service_binding_success_resp.json")
    )


@pytest.fixture(scope="module")
def service_binding_success_hr():
    """Retrieve the human-readable for service binding."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY, "create_service_binding_success_response_hr.md"
        )
    ) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def object_provision_success():
    """Retrieve the json response for object provision."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "object_provision_success.json")
    )


@pytest.fixture(scope="module")
def object_provision_success_hr():
    """Retrieve the human-readable for object provision."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "object_provision_success.md")) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def service_binding_reference_success():
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY, "create_virtual_service_success_response.json"
        )
    )


@pytest.fixture(scope="module")
def workload_get_success():
    """Retrieve the json response for ip workload get success."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "workload_get_success_response.json")
    )


@pytest.fixture(scope="module")
def workload_get_success_hr():
    """Retrieve the human-readable response for workload get success."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "workload_get_response_hr.md")) as f:
        expected_hr_output = f.read()
    return expected_hr_output


@pytest.fixture(scope="module")
def workloads_list_success():
    """Retrieve the json response for workloads list."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "workloads_list_success_response.json")
    )


@pytest.fixture(scope="module")
def workloads_list_success_hr():
    """Retrieve the human-readable response for workloads list."""
    with open(
        os.path.join(TEST_DATA_DIRECTORY, "workloads_list_success_response_hr.md")
    ) as f:
        expected_hr_output = f.read()

    return expected_hr_output


@pytest.fixture(scope="module")
def enforcement_boundary_success():
    """Retrieve the json response for enforcement boundary create."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY,
            "enforcement_boundary_create_command_success_response.json",
        )
    )


@pytest.fixture(scope="module")
def enforcement_boundary_success_hr():
    """Retrieve the human-readable response for enforcement boundary create."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY,
            "enforcement_boundary_create_command_success_response_hr.md",
        )
    ) as f:
        expected_hr_output = f.read()

    return expected_hr_output


@pytest.fixture(scope="module")
def enforcement_mode_success():
    """Retrieve the json response for enforcement mode update success."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY,
            "enforcement_mode_update_success_expected_response.json",
        )
    )


@pytest.fixture(scope="module")
def enforcement_mode_success_hr():
    """Retrieve the human-readable response for enforcement mode update success."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY, "enforcement_mode_update_success_response_hr.md"
        )
    ) as f:
        expected_hr_output = f.read()

    return expected_hr_output


@pytest.fixture(scope="module")
def enforcement_mode_failure_expected():
    """Retrieve the expected json response for enforcement mode update failure."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY,
            "enforcement_mode_update_failure_expected_response.json",
        )
    )


@pytest.fixture(scope="module")
def enforcement_mode_failure_hr():
    """Retrieve the human-readable response for enforcement mode update failure."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY, "enforcement_mode_update_failure_response_hr.md"
        )
    ) as f:
        expected_hr_output = f.read()

    return expected_hr_output


@pytest.fixture(scope="module")
def enforcement_mode_failure():
    """Retrieve the json response for enforcement mode update failure."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY, "enforcement_mode_update_failure_response.json"
        )
    )


@pytest.fixture(scope="module")
def ip_list_get_success():
    """Retrieve the json response for ip list get."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "get_ip_list_success_resp.json")
    )


@pytest.fixture(scope="module")
def ip_list_get_success_hr():
    """Retrieve the human-readable response for ip list get."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "get_ip_list_success_resp_hr.md")) as f:
        expected_hr_output = f.read()

    return expected_hr_output


@pytest.fixture(scope="module")
def ip_lists_success():
    """Retrieve the json response for ip lists get success."""
    return util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY, "ip_lists_get_command_for_success_response.json"
        )
    )


@pytest.fixture(scope="module")
def ip_lists_success_hr():
    """Retrieve the human-readable response for ip lists get success."""
    with open(
        os.path.join(
            TEST_DATA_DIRECTORY, "ip_lists_get_command_for_success_response_hr.md"
        )
    ) as f:
        expected_hr_output = f.read()

    return expected_hr_output


@pytest.fixture(scope="module")
def ruleset_create_success():
    """Retrieve the json response for ruleset create."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "create_ruleset_success.json")
    )


@pytest.fixture(scope="module")
def ruleset_create_success_hr():
    """Retrieve the human-readable response for ruleset create."""
    with open(
        os.path.join(TEST_DATA_DIRECTORY, "create_ruleset_success_hr.md")
    ) as file:
        f = file.read()
    return f


@pytest.fixture(scope="module")
def ruleset_get_success():
    """Retrieve the json response for ruleset get."""
    return util_load_json(
        os.path.join(TEST_DATA_DIRECTORY, "get_ruleset_success.json")
    )


@pytest.fixture(scope="module")
def rule_create_success():
    """Retrieve the json response for rule create."""
    return util_load_json(os.path.join(TEST_DATA_DIRECTORY, "create_rule_success.json"))


@pytest.fixture(scope="module")
def rule_create_success_hr():
    """Retrieve the human-readable for rule create."""
    with open(os.path.join(TEST_DATA_DIRECTORY, "create_rule_success_hr.md")) as file:
        hr_output = file.read()
    return hr_output


def test_command_test_module(mock_client, monkeypatch):
    """
    Test case scenario for successful execution of test-module.

    Given:
       - mock_client to call the function
    When:
       - Calling `command_test_module` function
    Then:
       - Returns an ok message.
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine, "check_connection", lambda *a: True
    )
    assert command_test_module(mock_client) == "ok"


@pytest.mark.parametrize(
    "args, err_msg, err_type",
    [
        (
            {
                "port": "",
                "protocol": "tcp",
                "start_time": "2022-07-17T12:58:33.528Z",
                "end_time": "2022-07-18T12:58:33.529Z",
                "policy_decisions": ["potentially_blocked"],
            },
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("port"),
            ValueError,
        ),
        (
            {
                "port": "dummy",
                "protocol": "tcp",
                "start_time": "2022-07-17T12:58:33.528Z",
                "end_time": "2022-07-18T12:58:33.529Z",
                "policy_decisions": ["potentially_blocked"],
            },
            '"dummy" is not a valid number',
            ValueError,
        ),
        (
            {
                "port": -300,
                "protocol": "tcp",
                "start_time": "2022-07-17T12:58:33.528Z",
                "end_time": "2022-07-18T12:58:33.529Z",
                "policy_decisions": ["potentially_blocked"],
            },
            INVALID_PORT_NUMBER_EXCEPTION_MESSAGE.format(-300),
            InvalidValueError,
        ),
        (
            {
                "port": 8443,
                "protocol": "tcp",
                "start_time": "2022-07-17T12:58:33.528Z",
                "end_time": "2022-07-18T12:58:33.529Z",
                "policy_decisions": ["dummy"],
            },
            "Invalid value for {}. Possible comma separated values are {}.".format(
                "policy_decisions", VALID_POLICY_DECISIONS
            ),
            InvalidValueError,
        ),
        (
            {
                "port": 8443,
                "protocol": "dummy",
                "start_time": "2022-07-17T12:58:33.528Z",
                "end_time": "2022-07-18T12:58:33.529Z",
                "policy_decisions": ["potentially_blocked"],
            },
            "{} is an invalid value for {}. Possible values are: {}.".format(
                "dummy", "protocol", VALID_PROTOCOLS
            ),
            InvalidValueError,
        ),
    ],
)
def test_traffic_analysis_command_for_invalid_arguments(
    args, err_msg, err_type, mock_client
):
    """
    Test case scenario for execution of traffic-analysis-command when invalid argument provided.

    Given:
        - command arguments for traffic_analysis_command
    When:
        - Calling `traffic_analysis_command` function
    Then:
        - Returns a valid error message
    """
    from IllumioCore import traffic_analysis_command

    with pytest.raises(err_type) as err:
        traffic_analysis_command(mock_client, args)
        assert str(err.value) == err_msg


def test_traffic_analysis_success(
    mock_client, monkeypatch, traffic_analysis_success
):
    """
    Test case scenario for successful execution of traffic-analysis-command function.

    Given:
        - traffic_analysis_success response and mock_client to call the function
    When:
        - Calling `traffic_analysis_Command` function
    Then:
        - Returns a valid raw_response.
    """
    args = {
        "port": 8443,
        "protocol": "tcp",
        "policy_decisions": "potentially_blocked",
        "start_time": "2022-07-17T12:58:33.528Z",
        "end_time": "2022-07-18T12:58:33.529Z",
    }

    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine,
        "get_traffic_flows_async",
        lambda *a, **k: [
            TrafficFlow.from_json(flow) for flow in traffic_analysis_success
        ],
    )

    resp = traffic_analysis_command(mock_client, args)

    assert resp.raw_response == traffic_analysis_success


def test_traffic_analysis_human_readable(
        traffic_analysis_success, traffic_analysis_success_hr
):
    """
    Test case scenario for successful execution of traffic-analysis-command function.

    Given:
        - traffic_analysis_success and traffic_analysis_success human-readable
    When:
        - Calling `traffic_analysis_Command` function
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_traffic_analysis_output(traffic_analysis_success)
    assert resp == traffic_analysis_success_hr


def test_virtual_service_create_command_for_success(
    mock_client, virtual_service_create_success, monkeypatch
):
    """Test case scenario for execution of virtual-service-create-command when valid and all arguments are provided.

    Given:
        - virtual_service_create_success response and mock_client to call the function
    When:
        - Valid name, port, and protocol are provided in the command argument
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a: VirtualService.from_json(virtual_service_create_success),
    )
    resp = virtual_service_create_command(
        mock_client,
        {"name": "test_create_virtual_service", "port": 3000, "protocol": "tcp"},
    )
    assert resp.raw_response == virtual_service_create_success


def test_virtual_service_create_command_for_human_readable(
    virtual_service_create_success, virtual_service_success_hr
):
    """Test case scenario for execution of virtual-service-create-command when valid and all arguments are provided.

    Given:
        - virtual_service_create_success response and virtual_service_success human-readable
    When:
        - Valid name, port, and protocol are provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_virtual_service_output(virtual_service_create_success)
    assert resp == virtual_service_success_hr


def test_virtual_service_create_command_for_success_with_protocol_as_udp(
    mock_client, virtual_service_create_success_udp, monkeypatch
):
    """Test case scenario for execution of virtual-service-create-command with protocol as udp.

    Given:
        - virtual_service_create_success response and mock_client to call the function.
    When:
        - Valid name, port, and protocol are provided in the command argument.
    Then:
        - Return a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a: VirtualService.from_json(virtual_service_create_success_udp),
    )
    resp = virtual_service_create_command(
        mock_client, {"name": "test_create_virtual_service", "port": "3000"}
    )

    assert resp.raw_response == virtual_service_create_success_udp


def test_virtual_service_create_command_for_human_readable_with_protocol_as_udp(
    virtual_service_create_success_udp, virtual_service_success_udp_hr
):
    """Test case scenario for execution of virtual-service-create-command with protocol as udp.

    Given:
        - virtual_service_create_success_udp response and virtual_service_success_udp human-readable
    When:
        - Valid name, port, and protocol are provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_virtual_service_output(virtual_service_create_success_udp)
    assert resp == virtual_service_success_udp_hr


@pytest.mark.parametrize(
    "err_msg, args, err_type",
    [
        (
            NOT_VALID_NUMBER_EXCEPTION_MESSAGE.format("port", "300i0"),
            {"name": "test", "port": "300i0", "protocol": "tcp"},
            ValueError,
        ),
        (
            CONVERT_PROTOCOL_EXCEPTION_MESSAGE.format("tcpi"),
            {"name": "test", "port": "30000", "protocol": "tcpi"},
            InvalidValueError,
        ),
        (
            INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE.format(65536),
            {"name": "test", "port": "65536"},
            InvalidValueError,
        ),
        (
            INVALID_PORT_NUMBER_CREATE_VIRTUAL_SERVICE_EXCEPTION_MESSAGE.format(-3),
            {"name": "test", "port": "-3"},
            InvalidValueError,
        )
    ],
)
def test_virtual_service_create_command_when_invalid_arguments_provided(
    err_msg, args, err_type, mock_client
):
    """Test case scenario for execution of virtual-service-create-command when invalid argument provided.

    Given:
        - command arguments for virtual-service-create-command.
    When:
        - Calling `virtual_service_create_command` function.
    Then:
        - Returns a valid error message.
    """
    with pytest.raises(err_type) as err:
        virtual_service_create_command(mock_client, args)
        assert str(err.value) == err_msg


def test_service_binding_create_command_for_success(
    mock_client, service_binding_success, monkeypatch, service_binding_reference_success
):
    """Test case scenario for successful execution of service-binding-create.

    Given:
        - service_binding_success response, service_binding_reference_success response and
        mock_client to call the function
    When:
        - Valid virtual service href and valid list of workloads href are provided in the command argument
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a: ServiceBinding.from_json(service_binding_success),
    )

    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "get_by_reference",
        lambda *a: PolicyVersion.from_json(service_binding_reference_success),
    )

    args = {"workloads": WORKLOAD_EXP_URL, "virtual_service": VIRTUAL_SERVICE_EXP_URL}
    resp = service_binding_create_command(mock_client, args)
    assert resp.raw_response == service_binding_success


def test_service_binding_create_command_for_human_readable(service_binding_success_hr):
    """Test case scenario for successful execution of service-binding-create-command.

    Given:
        - service_binding_success human-readable
    When:
        - Valid virtual service href and valid list of workloads href are provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    create_service_binding_expected_resp_output = util_load_json(
        os.path.join(
            TEST_DATA_DIRECTORY, "create_service_binding_success_response_output.json"
        )
    )

    response = prepare_service_binding_output(
        create_service_binding_expected_resp_output
    )
    assert response == service_binding_success_hr


@pytest.mark.parametrize(
    "args",
    [
        ({"workloads": "abc", "virtual_service": VIRTUAL_SERVICE_EXP_URL}),
        ({"workloads": WORKLOAD_EXP_URL, "virtual_service": "abc"}),
    ],
)
def test_service_binding_create_when_invalid_arguments_provided(
    args, mock_client, requests_mock
):
    """Test case scenario when arguments provided to service-binding-create are invalid.

    Given:
        - command arguments for service-binding command
    When:
        - Calling `service_binding_create_command` function
    Then:
        - Returns a valid error message
    """
    requests_mock.post(
        re.compile("/service_bindings"),
        status_code=406,
        json=[{"token": "invalid_uri", "message": "Invalid URI: {abc}"}],
    )

    with pytest.raises(Exception) as err:
        service_binding_create_command(mock_client, args)

        assert (
            str(err.value)
            == "406 Client Error: None for url: https://127.0.0.1:8443/api/v2/orgs/1/service_bindings"
        )


@pytest.mark.parametrize(
    "err_msg, args",
    [
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("workloads"),
            {"workloads": "", "virtual_service": VIRTUAL_SERVICE_EXP_URL},
        ),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("virtual_service"),
            {"workloads": WORKLOAD_EXP_URL, "virtual_service": ""},
        ),
    ],
)
def test_create_service_binding_when_blank_arguments_provided(
    err_msg, args, mock_client
):
    """Test case scenario when arguments provided to service-binding-create are blank.

    Given:
        - command arguments for service-binding-create command
    When:
        - Calling `service_binding_create_command` function
    Then:
        - Returns a valid error message
    """
    with pytest.raises(Exception) as err:
        service_binding_create_command(mock_client, args)

        assert str(err.value) == err_msg


def test_object_provision_command_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of object-provision-command when invalid arguments are provided.

    Given:
        - object_provision_command function and mock_client to call the function
    When:
        - Invalid arguments (Empty values) provided in the arguments
    Then:
        - Should raise ValueError with proper error message
    """
    from IllumioCore import object_provision_command

    args = {"security_policy_objects": ""}
    err_msg = (
        "security_policy_objects is a required parameter. Please provide correct value."
    )

    with pytest.raises(ValueError) as err:
        object_provision_command(mock_client, args)

    assert str(err.value) == err_msg


def test_object_provision_command_when_valid_arguments_provided(
    mock_client, object_provision_success, monkeypatch
):
    """
    Test case scenario for execution of object-provision-command when valid arguments are provided.

    Given:
        - object_provision_success response and mock_client to call the function
    When:
        - Valid href is provided in the command argument
    Then:
        - Should return proper raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine,
        "provision_policy_changes",
        lambda *a, **k: PolicyVersion.from_json(object_provision_success),
    )
    mock_args = {"security_policy_objects": "/orgs/1/sec_policy/draft/rule_sets/1605"}
    response = object_provision_command(mock_client, mock_args)

    assert response.raw_response == object_provision_success


def test_object_provision_command_when_valid_arguments_provided_human_readable(
    mock_client, object_provision_success, object_provision_success_hr
):
    """
    Test case scenario for execution of object-provision-command when valid arguments are provided.

    Given:
        - object_provision_success response, object_provision_success human-readable and mock_client to call the function
    When:
        - Valid href is provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_object_provision_output(object_provision_success)
    assert resp == object_provision_success_hr


def test_workload_get_command_success(mock_client, workload_get_success, monkeypatch):
    """
    Test case scenario for successful execution of workload-get-command.

    Given:
        - workload_get_success response and mock_client to call the function
    When:
        - Calling `workload_get_command` function
    Then:
        - Returns a valid output
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "get_by_reference",
        lambda *a, **k: Workload.from_json(workload_get_success),
    )
    args = {"href": "/orgs/1/workloads/dummy"}
    resp = workload_get_command(mock_client, args)

    assert resp.raw_response == workload_get_success


def test_workload_get_command_human_readable(
    workload_get_success, workload_get_success_hr
):
    """
    Test case scenario for successful execution of workload-get-command.

    Given:
        - workload_get_success response and workload_get_success human-readable
    When:
        - Calling `workload_get_command` function
    Then:
        - Returns a valid human-readable output
    """
    hr_output = prepare_workload_get_output(workload_get_success)
    assert hr_output == workload_get_success_hr


@pytest.mark.parametrize(
    "err_msg, args",
    [(MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("href"), {"href": ""})],
)
def test_workload_get_command_when_blank_value_in_arguments_provided(
    err_msg, args, mock_client
):
    """
    Test case scenario for execution of workload-get-command when blank value in argument is provided.

    Given:
        - command arguments for workload_get_command
    When:
        - Calling `workload_get_command` function
    Then:
        - Returns a valid error message
    """
    with pytest.raises(Exception) as err:
        workload_get_command(mock_client, args)
    assert str(err.value) == err_msg


def test_workloads_list_command_for_success(
    mock_client, workloads_list_success, monkeypatch
):
    """
    Test case scenario for successful execution of workloads-list-command.

    Given:
        - workloads_list_success response and mock_client to call the function
    When:
        - Valid arguments are provided to the command
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "get",
        lambda *a, **k: [
            Workload.from_json(workload) for workload in workloads_list_success
        ],
    )
    resp = workloads_list_command(
        mock_client, {"max_results": "1", "online": "yes", "managed": "false"}
    )

    assert resp.raw_response == workloads_list_success


def test_workloads_list_command_human_readable(
    workloads_list_success, workloads_list_success_hr
):
    """
    Test case scenario for successful execution of workloads-list-command.

    Given:
        - workloads_list_success response and workloads_list_success human-readable
    When:
        - Calling `prepare_workloads_list_output` function
    Then:
        - Returns a valid human-readable
    """
    hr_output = prepare_workloads_list_output(workloads_list_success)
    assert hr_output == workloads_list_success_hr


@pytest.mark.parametrize(
    "err_msg, args, err_type",
    [
        (
            NOT_VALID_NUMBER_EXCEPTION_MESSAGE.format("max_results", "3i0"),
            {"max_results": "3i0"},
            ValueError,
        ),
        (
            INVALID_MAX_RESULTS_EXCEPTION_MESSAGE.format(0),
            {"max_results": "0"},
            InvalidValueError,
        ),
        (INVALID_BOOLEAN_EXCEPTION_MESSAGE, {"online": "yess"}, ValueError),
        (INVALID_BOOLEAN_EXCEPTION_MESSAGE, {"managed": "noo"}, ValueError),
        (
            INVALID_VALUE_EXCEPTION_MESSAGE.format("running", "enforcement_mode"),
            {"enforcement_mode": "running"},
            InvalidValueError,
        ),
        (
            INVALID_VALUE_EXCEPTION_MESSAGE.format("flow_on", "visibility_level"),
            {"visibility_level": "flow_on"},
            InvalidValueError,
        ),
    ],
)
def test_workloads_list_command_when_invalid_arguments_provided(
    err_msg, args, err_type, mock_client
):
    """
    Test case scenario for execution of workloads-list-command function when invalid arguments provided.

    Given:
        - command arguments for workload_list_command
    When:
        - Calling `workloads_list_command` function
    Then:
        - Returns a valid error message
    """
    with pytest.raises(err_type) as err:
        workloads_list_command(mock_client, args)
        assert str(err.value) == err_msg


def test_enforcement_boundary_create_command_success(
    mock_client, enforcement_boundary_success, monkeypatch
):
    """
    Test case scenario for successful execution of enforcement-boundary-create-command function.

    Given:
        - enforcement_boundary_success response and mock_client to call the function
    When:
        - Calling `enforcement_boundary_create_command` function
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a: EnforcementBoundary.from_json(enforcement_boundary_success),
    )
    resp = enforcement_boundary_create_command(
        mock_client,
        {
            "name": "test_enforcement_boundary_1",
            "port": 1,
            "protocol": "udp",
            "providers": ["/orgs/1/labels/1"],
            "consumers": "ams",
        },
    )

    assert resp.raw_response == enforcement_boundary_success


def test_enforcement_boundary_create_command_human_readable(
    enforcement_boundary_success, enforcement_boundary_success_hr
):
    """
    Test case scenario for successful execution of enforcement-boundary-create.

    Given:
        - enforcement_boundary_success response and enforcement_boundary_success human-readable
    When:
        - Calling `prepare_enforcement_boundary_output` function
    Then:
        - Returns a valid human-readable
    """
    hr_output = prepare_enforcement_boundary_create_output(enforcement_boundary_success)

    assert hr_output == enforcement_boundary_success_hr


@pytest.mark.parametrize(
    "err_msg, args, err_type",
    [
        (
            NOT_VALID_NUMBER_EXCEPTION_MESSAGE.format("port", "300i0"),
            {
                "name": "test",
                "port": "300i0",
                "protocol": "tcp",
                "providers": ["/orgs/1/labels/1"],
                "consumers": "ams",
            },
            ValueError,
        ),
        (
            CONVERT_PROTOCOL_EXCEPTION_MESSAGE.format("tcpi"),
            {
                "name": "test",
                "port": "30000",
                "protocol": "tcpi",
                "providers": ["/orgs/1/labels/1"],
                "consumers": "ams",
            },
            InvalidValueError,
        ),
        (MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("name"), {}, ValueError),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("port"),
            {"name": "test", "providers": ["/orgs/1/labels/1"], "consumers": "ams"},
            ValueError,
        ),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("providers"),
            {"name": "test", "port": "1", "consumers": "ams"},
            ValueError,
        ),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("consumers"),
            {"name": "test", "port": "1", "providers": "ams"},
            ValueError,
        ),
        (
            INVALID_HREF_ENFORCEMENT_BOUNDARY.format("/orgs/1/&%labels/1"),
            {
                "name": "test",
                "port": "1",
                "providers": ["/orgs/1/&%labels/1"],
                "consumers": "ams",
            },
            IllumioException,
        ),
        (
            INVALID_HREF_ENFORCEMENT_BOUNDARY.format("/orgs/1/&%labels/1"),
            {
                "name": "test",
                "port": "1",
                "consumers": "/orgs/1/&%labels/1",
                "providers": "ams",
            },
            IllumioException,
        ),
        (
            INVALID_HREF_ENFORCEMENT_BOUNDARY.format("amss"),
            {
                "name": "test",
                "port": "1",
                "consumers": "/orgs/1/labels/1",
                "providers": "amss",
            },
            IllumioException,
        ),
        (
            INVALID_HREF_ENFORCEMENT_BOUNDARY.format("amss"),
            {
                "name": "test",
                "port": "1",
                "providers": "/orgs/1/labels/1",
                "consumers": "amss",
            },
            IllumioException,
        ),
        (
            INVALID_PORT_NUMBER_EXCEPTION_MESSAGE.format(65536),
            {
                "name": "test",
                "port": "65536",
                "providers": ["/orgs/1/labels/1"],
                "consumers": "ams",
            },
            InvalidValueError,
        ),
        (
            INVALID_PORT_NUMBER_EXCEPTION_MESSAGE.format(-1),
            {
                "name": "test",
                "port": "-1",
                "providers": ["/orgs/1/labels/1"],
                "consumers": "ams",
            },
            InvalidValueError,
        ),
    ],
)
def test_enforcement_boundary_create_command_when_invalid_arguments_provided(
    err_msg, args, err_type, mock_client
):
    """
    Test case scenario for execution of enforcement-boundary-create-command function when invalid arguments provided.

    Given:
        - command arguments for enforcement_boundary_create_command
    When:
        - Calling `enforcement_boundary_create_command` function
    Then:
        - Returns a valid error message
    """
    with pytest.raises(err_type) as err:
        enforcement_boundary_create_command(mock_client, args)
        assert str(err.value) == err_msg


@pytest.mark.parametrize(
    "err_msg, args",
    [
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("workloads"),
            {"workloads": "", "enforcement_mode": "idle"},
        ),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("enforcement_mode"),
            {
                "workloads": ["/orgs/1/workloads/dummy", "/orgs/1/workloads/dummy1"],
                "enforcement_mode": "",
            },
        ),
    ],
)
def test_enforcement_mode_update_command_when_blank_arguments_provided(
    err_msg, args, mock_client
):
    """Test case scenario for enforcement-mode-update-command when blank arguments are provided.

    Given:
        - command arguments for enforcement_mode_update_command
    When:
        - Calling `enforcement_mode_update_command_command` function
    Then:
        - Returns a valid error message
    """
    with pytest.raises(ValueError) as err:
        update_enforcement_mode_command(mock_client, args)
    assert str(err.value) == err_msg


@pytest.mark.parametrize(
    "err_msg, args",
    [
        (
            "'idl' is not a valid EnforcementMode",
            {"enforcement_mode": "idl", "workloads": ["/orgs/1/workloads/dummy"]},
        )
    ],
)
def test_enforcement_mode_update_command_when_invalid_arguments_provided(
    err_msg, args, mock_client, requests_mock
):
    """Test case scenario for enforcement-mode-update-command when invalid arguments are provided.

    Given:
        - command arguments for enforcement_mode_update_command
    When:
        - Calling `enforcement_mode_update_command_command` function
    Then:
        - Returns a valid error message
    """
    requests_mock.put(
        UPDATE_WORKLOAD_URL,
        status_code=200,
        json=[
            {
                "href": "/orgs/1/workloads/dummy",
                "status": "validation_failure",
                "token": "invalid_uri",
                "message": "Invalid URI: {/orgs/1/workloads/dummy}",
            }
        ],
    )

    with pytest.raises(ValueError) as err:
        update_enforcement_mode_command(mock_client, args)
    assert str(err.value) == err_msg


def test_update_enforcement_mode_command_success(
    mock_client, enforcement_mode_success, monkeypatch
):
    """Test case scenario for successful execution of update-enforcement-mode-command.

    Given:
        - enforcement_mode_success response and mock_client to call the function
    When:
        - Calling `update_enforcement_mode_command` function
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "bulk_update",
        lambda *a: [
            Workload.from_json(workload) for workload in enforcement_mode_success
        ],
    )
    args = {
        "enforcement_mode": "idle",
        "workloads": ["/orgs/1/workloads/dummy", "/orgs/1/workloads/dummy1"],
    }
    resp = update_enforcement_mode_command(mock_client, args)

    assert resp.raw_response == enforcement_mode_success


def test_update_enforcement_mode_command_success_human_readable(
    enforcement_mode_success, enforcement_mode_success_hr
):
    """Test case scenario for successful execution of update-enforcement-mode-command.

    Given:
        - enforcement_mode_success response and enforcement_mode_success human-readable
    When:
        - Calling `update_enforcement_mode_command` function
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_update_enforcement_mode_output(enforcement_mode_success)

    assert resp == enforcement_mode_success_hr


def test_update_enforcement_mode_command_failure(
    mock_client, enforcement_mode_failure, monkeypatch
):
    """Test case scenario for execution of update-enforcement-mode-command for failure.

    Given:
        - enforcement_mode_failure response and mock_client to call the function
    When:
        - Calling `update_enforcement_mode_command` function
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "bulk_update",
        lambda *a: [
            Workload.from_json(workload) for workload in enforcement_mode_failure
        ],
    )
    args = {"enforcement_mode": "selective", "workloads": ["/orgs/1/workloads/dummy"]}
    resp = update_enforcement_mode_command(mock_client, args)

    assert resp.raw_response == enforcement_mode_failure


def test_update_enforcement_mode_command_failure_human_readable(
    enforcement_mode_failure_hr, enforcement_mode_failure_expected
):
    """
    Test case scenario for execution of update-enforcement-mode-command for failure.

    Given:
        - enforcement_mode_failure human-readable response and enforcement_mode_failure_expected response
    When:
        - Calling `update_enforcement_mode_command` function
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_update_enforcement_mode_output(enforcement_mode_failure_expected)

    assert resp == enforcement_mode_failure_hr


def test_ip_list_get_success(mock_client, ip_list_get_success, monkeypatch):
    """Test case scenario for execution of ip-list-get command when valid and all arguments are provided.

    Given:
        - ip_list_get_success response and mock_client to call the function
    When:
        - Valid href is provided in the command argument
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "get_by_reference",
        lambda *a: IPList.from_json(ip_list_get_success),
    )

    args = {"href": "/orgs/1/sec_policy/draft/ip_lists" + "/1"}
    resp = ip_list_get_command(mock_client, args)

    assert resp.raw_response == ip_list_get_success


def test_ip_list_get_success_hr(
    mock_client, ip_list_get_success, ip_list_get_success_hr, monkeypatch
):
    """Test case scenario for execution of ip-list-get command when valid and all arguments are provided.

    Given:
        - ip_list_get_success response, ip_list_get_success_hr human-readable and mock_client to call the function
    When:
        - Valid href is provided in the command argument
    Then:
        - Returns a valid human-readable
    """
    resp = prepare_ip_list_get_output(ip_list_get_success)
    assert resp == ip_list_get_success_hr


@pytest.mark.parametrize(
    "err_msg, args",
    [(MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("href"), {"href": ""})],
)
def test_ip_list_get_when_blank_arguments_provided(err_msg, args, mock_client):
    """
    Test case scenario for execution of ip-list-get-command when invalid arguments are provided.

    Given:
        -  command arguments to call ip_list_get_command
    When:
        - Invalid arguments (Empty values) provided in the arguments
    Then:
        - Returns a valid error message
    """
    with pytest.raises(Exception) as err:
        ip_list_get_command(mock_client, args)
        assert str(err.value) == err_msg


def test_ip_lists_get_command_for_success(mock_client, ip_lists_success, monkeypatch):
    """
    Test case scenario for successful execution of ip-lists-get-command function.

    Given:
        - ip_list_success response and mock_client to call the function
    When:
        - Calling `ip_lists_get_command` function
    Then:
        - Returns a valid raw_response
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "get",
        lambda *a, **k: [IPList.from_json(ip_list) for ip_list in ip_lists_success],
    )
    resp = ip_lists_get_command(
        mock_client,
        {
            "max_results": "1",
            "fqdn": "app",
            "ip_address": "127.0.0.1",
            "name": "a",
            "description": "a",
        },
    )

    assert resp.raw_response == remove_empty_elements(ip_lists_success)


def test_ip_lists_get_command_human_readable(ip_lists_success, ip_lists_success_hr):
    """
    Test case scenario for successful execution of ip-lists-get-command.

    Given:
        - ip_lists_success response and ip_lists_success_hr human-readable
    When:
        - Calling `ip_lists_get_command` function
    Then:
        - Returns a valid human-readable
    """
    hr_output = prepare_ip_lists_get_output(ip_lists_success)
    assert hr_output == ip_lists_success_hr


@pytest.mark.parametrize(
    "err_msg, args, err_type",
    [
        (
            NOT_VALID_NUMBER_EXCEPTION_MESSAGE.format("max_results", "3i0"),
            {"max_results": "3i0"},
            ValueError,
        ),
        (
            INVALID_MAX_RESULTS_EXCEPTION_MESSAGE.format(0),
            {"max_results": "0"},
            InvalidValueError,
        ),
    ],
)
def test_ip_lists_get_command_when_invalid_arguments_provided(
    err_msg, args, err_type, mock_client
):
    """
    Test case scenario for execution of ip-lists-get-command when invalid arguments provided.

    Given:
        - command arguments for ip_lists_get_command
    When:
        - Calling `ip_lists_get_command` function
    Then:
        - Returns a valid error message
    """
    from IllumioCore import ip_lists_get_command

    with pytest.raises(err_type) as err:
        ip_lists_get_command(mock_client, args)
        assert str(err.value) == err_msg


def test_ruleset_create_command_success(
    mock_client, ruleset_create_success, monkeypatch
):
    """Test case scenario for ruleset-create-command when valid arguments provided to the command.

    Given:
        - ruleset_create_success response and mock_client to call the function
    When:
        - Valid arguments are provided to the command.
    Then:
        - Command should return valid raw response.
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a, **k: RuleSet.from_json(ruleset_create_success),
    )

    mock_args = {"name": "Trial ruleset from test cases - 1"}
    resp = ruleset_create_command(mock_client, mock_args)

    assert resp.raw_response == ruleset_create_success


def test_ruleset_create_command_success_hr(
    ruleset_create_success, ruleset_create_success_hr
):
    """Test case scenario for ruleset-create-command when valid arguments provided to the command.

    Given:
        - ruleset_create_success response and ruleset_create_success human-readable
    When:
        - Creating human-readable output from response.
    Then:
        - Should return valid markdown string.
    """
    mock_name = "Trial ruleset from test cases - 1"
    resp = prepare_ruleset_create_output(ruleset_create_success, mock_name)
    assert resp == ruleset_create_success_hr


@pytest.mark.parametrize(
    "err_msg, args",
    [
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("ruleset_href"),
            {"ruleset_href": ""},
        ),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("providers"),
            {"ruleset_href": "test", "providers": ""},
        ),
        (
            MISSING_REQUIRED_PARAM_EXCEPTION_MESSAGE.format("consumers"),
            {"ruleset_href": "test", "providers": "test", "consumers": ""},
        ),
    ],
)
def test_rule_create_command_when_blank_arguments_provided(err_msg, args, mock_client):
    """
    Test case scenario for execution of rule-create-command when invalid arguments are provided.

    Given:
        - command arguments for rule_create_command
    When:
        - Invalid arguments (Empty values) provided in the arguments
    Then:
        - Returns a valid error message
    """
    with pytest.raises(Exception) as err:
        rule_create_command(mock_client, args)
        assert str(err.value) == err_msg


def test_rule_create_command_success(mock_client, rule_create_success, ruleset_get_success, monkeypatch):
    """Test case scenario for rule-create-command when valid arguments provided to the command.

    Given:
        - rule_create_success response, get_ruleset_success and mock_client to call the function
    When:
        - Valid arguments are provided to the command.
    Then:
        - Command should return valid raw response.
    """
    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "get_by_reference",
        lambda *a, **k: Rule.from_json(ruleset_get_success)
    )

    monkeypatch.setattr(
        illumio.pce.PolicyComputeEngine._PCEObjectAPI,
        "create",
        lambda *a, **k: Rule.from_json(rule_create_success),
    )

    mock_args = {
        "ruleset_href": "/orgs/1/sec_policy/draft/rule_sets/2220",
        "providers": "/orgs/1/labels/3",
        "consumers": "/orgs/1/labels/3",
        "ingress_services": "/orgs/1/sec_policy/draft/services/1745",
        "resolve_providers_as": "workloads",
        "resolve_consumers_as": "workloads",
    }
    resp = rule_create_command(mock_client, mock_args)

    assert resp.raw_response == rule_create_success


def test_rule_create_command_success_hr(rule_create_success, rule_create_success_hr):
    """Test case scenario for rule_create_command when valid arguments provided to the command.

    Given:
        - rule_create_success response and rule_create_success human-readable
    When:
        - Creating human-readable output from response.
    Then:
        - Should return valid markdown string.
    """
    resp = prepare_rule_create_output(rule_create_success)
    assert resp == rule_create_success_hr
