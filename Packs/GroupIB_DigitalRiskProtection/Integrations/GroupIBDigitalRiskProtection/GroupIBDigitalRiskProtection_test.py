import pytest
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
import GroupIBDigitalRiskProtection
from enum import Enum
import os
from json import load
from cyberintegrations.cyberintegrations import Parser

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

realpath = os.path.join(os.path.dirname(os.path.realpath(__file__)))

with open(f'{realpath}/test_data/brands_example.json') as example:
    BRANDS_RAW_JSON = load(example)

with open(f'{realpath}/test_data/subscriptions_example.json') as example:
    SUBSCRIPTIONS_RAW_JSON = load(example)

with open(f'{realpath}/test_data/violation_by_id_example.json') as example:
    VIOLATION_BY_ID_RAW_JSON = load(example)

with open(f'{realpath}/test_data/violations_example.json') as example:
    VIOLATIONS_RAW_JSON = load(example)

TEST_GET_FILES_BYTES = open(
    f'{realpath}/test_data/get_file_example_5a7bf6ece60ff635c6b844418a0528d97fa7016b362387125a96f4c0bf60a774.jpeg', 'rb').read()

TEST_VIOLATION_ID = "exampleid"
TEST_FILE_SHA = "5a7bf6ece60ff635c6b844418a0528d97fa7016b362387125a96f4c0bf60a774"


class Commands(Enum):
    GET_BRANDS = "gibdrp-get-brands"
    GET_SUBSCRIPTIONS = "gibdrp-get-subscriptions"
    GET_VIOLATION_BY_ID = "gibdrp-get-violation-by-id"
    CHANGE_VIOLATION_STATUS = "gibdrp-change-violation-status"
    TEST_MODULE = "test-module"
    FETCH_INCIDENTS = "fetch-incidents"


@pytest.fixture(scope="function")
def session_fixture(request):
    """
    Fixture for creating a client instance specific to each collection name.

    Given:
      - A list of predefined collection names that represent different types of data.

    When:
      - Each test function requests an instance of this fixture.

    Then:
      - Returns a tuple with the current collection name and an instantiated Client object.
      - The Client instance is configured to interact with the appropriate collection by connecting
        to the integration's base URL, using authentication, and including necessary headers.
    """

    return GroupIBDigitalRiskProtection.Client(
        base_url="https://drp.group-ib.com/client_api/",
        auth=("example@roup-ib.com", "exampleAPI_TOKEN"),
    )


def test_main_error():
    """
    Test for verifying the error-handling behavior in the main() function.

    Given:
      - A main() function configured to raise an exception when calling error_command.

    When:
      - The main function invokes error_command(), which is expected to trigger an error.

    Then:
      - Ensures that a SystemExit exception is raised as expected.
      - The test checks that the main function handles errors in a predictable and controlled
        manner, allowing graceful exits during failure.
    """
    with pytest.raises(SystemExit):
        GroupIBDigitalRiskProtection.main()["error_command"]()  # type: ignore


""" Clien Testing """


def test_get_brands(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_brands', return_value=[BRANDS_RAW_JSON])
    response = client.get_formatted_brands()
    assert isinstance(response, list)
    assert len(response) > 0


def test_get_subscriptions(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_subscriptions', return_value=[SUBSCRIPTIONS_RAW_JSON])
    response = client.get_formatted_subscriptions()
    assert isinstance(response, list)
    assert len(response) > 0


def test_get_violation_by_id(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_violation_by_id', return_value=Parser(chunk=VIOLATION_BY_ID_RAW_JSON, keys=[], iocs_keys=[]))
    response = client.get_formatted_violation_by_id(violation_id=TEST_VIOLATION_ID, get_images=False)
    assert isinstance(response[0], dict)


def test_get_file(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_file', return_value=[TEST_GET_FILES_BYTES, "image/jpeg"])
    response = client.get_file(file_sha=TEST_FILE_SHA)
    assert isinstance(response[0], bytes)


""" Commands Testins """


def test_get_avalible_commands():
    response_commands = GroupIBDigitalRiskProtection.Commands.get_avalible_commands()

    required_commands = [cmd.value for cmd in Commands]
    assert len(required_commands) == len(response_commands)
    assert "gibdrp" in str(response_commands)


def test_command_get_brands(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_brands', return_value=[BRANDS_RAW_JSON])
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_BRANDS.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
    ).get_results()
    assert result.outputs_prefix == "GIBDRP.OtherInfo"
    assert result.outputs_key_field == "id"
    assert isinstance(requested_method, str)
    assert (
        requested_method
        in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results
    )


def test_command_get_subscriptions(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_subscriptions', return_value=[SUBSCRIPTIONS_RAW_JSON])
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_SUBSCRIPTIONS.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
    ).get_results()
    assert result.outputs_prefix == "GIBDRP.OtherInfo"
    assert result.outputs_key_field == "subscriptions"
    assert isinstance(requested_method, str)
    assert (
        requested_method
        in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results
    )


def test_command_get_violation_by_id(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_violation_by_id', return_value=Parser(chunk=VIOLATION_BY_ID_RAW_JSON, keys=[], iocs_keys=[]))
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_VIOLATION_BY_ID.value,
        args={"id": TEST_VIOLATION_ID},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
    ).get_results()
    assert result[0].outputs_key_field == "id"
    assert isinstance(requested_method, str)
    assert (
        requested_method
        in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results
    )


def test_command_test_module(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, 'get_brands', return_value=[BRANDS_RAW_JSON])
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.TEST_MODULE.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
    ).get_results()
    assert isinstance(result, str)
    assert result == "ok"
    assert isinstance(requested_method, str)
    assert (
        requested_method
        in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results
    )
