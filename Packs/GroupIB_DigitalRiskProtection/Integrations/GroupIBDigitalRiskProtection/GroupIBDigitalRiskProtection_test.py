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

BRANDS_RAW_JSON = [
    {"name": "Example Brand 1", "id": "exampleid1223"},
    {"name": "Example Brand 2", "id": "exampleid321"},
]

SUBSCRIPTIONS_RAW_JSON = ["scam", "example"]

with open(f"{realpath}/test_data/violation_by_id_example.json") as example:
    VIOLATION_BY_ID_RAW_JSON = load(example)

with open(f"{realpath}/test_data/violations_example.json") as example:
    VIOLATIONS_RAW_JSON = load(example)

TEST_GET_FILES_BYTES = open(
    f"{realpath}/test_data/get_file_example_5a7bf6ece60ff635c6b844418a0528d97fa7016b362387125a96f4c0bf60a774.jpeg", "rb"
).read()

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
    mocker.patch.object(client, "get_formatted_brands", return_value=[BRANDS_RAW_JSON])
    response = client.get_formatted_brands()
    assert isinstance(response, list)
    assert len(response) > 0


def test_get_subscriptions(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, "get_formatted_subscriptions", return_value=[SUBSCRIPTIONS_RAW_JSON])
    response = client.get_formatted_subscriptions()
    assert isinstance(response, list)
    assert len(response) > 0


def test_get_violation_by_id(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, "get_violation_by_id", return_value=Parser(chunk=VIOLATION_BY_ID_RAW_JSON, keys=[], iocs_keys=[]))
    response = client.get_formatted_violation_by_id(violation_id=TEST_VIOLATION_ID, get_images=False)
    assert isinstance(response[0], dict)


def test_get_file(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, "get_file", return_value=[TEST_GET_FILES_BYTES, "image/jpeg"])
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
    mocker.patch.object(client, "get_formatted_brands", return_value=[BRANDS_RAW_JSON])
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_BRANDS.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
        only_typosquatting=False,
    ).get_results()
    assert result is not None
    assert isinstance(requested_method, str)
    assert requested_method in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results


def test_command_get_subscriptions(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, "get_formatted_subscriptions", return_value=[SUBSCRIPTIONS_RAW_JSON])
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_SUBSCRIPTIONS.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
        only_typosquatting=False,
    ).get_results()
    assert result is not None
    assert isinstance(requested_method, str)
    assert requested_method in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results


def test_command_get_violation_by_id(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, "get_violation_by_id", return_value=Parser(chunk=VIOLATION_BY_ID_RAW_JSON, keys=[], iocs_keys=[]))
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_VIOLATION_BY_ID.value,
        args={"id": TEST_VIOLATION_ID},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
        only_typosquatting=False,
    ).get_results()
    assert isinstance(result, list)
    first = result[0]
    assert first is not None
    assert isinstance(requested_method, str)
    assert requested_method in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results


def test_command_test_module(mocker, session_fixture):
    client = session_fixture
    mocker.patch.object(client, "get_formatted_brands", return_value=[BRANDS_RAW_JSON])
    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.TEST_MODULE.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
        only_typosquatting=False,
    ).get_results()
    assert isinstance(result, str)
    assert result == "ok"
    assert isinstance(requested_method, str)
    assert requested_method in GroupIBDigitalRiskProtection.Commands.methods_requiring_return_results


def test_client_get_violation_section_number_and_error(session_fixture):
    client = session_fixture
    assert client._get_violation_section_number("Web") == 1
    assert client._get_violation_section_number("Social Networks") == 4
    with pytest.raises(ValueError):
        client._get_violation_section_number("Unknown Section")


def test_client_generate_seq_update_calls_poller(session_fixture, mocker):
    client = session_fixture

    class PollerStub:
        def get_seq_update_dict(self, date, collection):
            return {"date": date, "collection": collection}

    client.poller = PollerStub()
    seq = client.generate_seq_update("2024-01-15")
    assert seq == {"date": "2024-01-15", "collection": GroupIBDigitalRiskProtection.Endpoints.VIOLATIONS.value}

    # invalid date -> DemistoException
    with pytest.raises(GroupIBDigitalRiskProtection.DemistoException):
        client.generate_seq_update("not-a-date")


def test_commonhelpers_convert_iso8601_with_timezone_and_invalid():
    s = "2024-10-30T15:12:34+0000"
    out = GroupIBDigitalRiskProtection.CommonHelpers.convert_iso8601_with_timezone(s)
    assert out == "2024-10-30T15:12:34+00:00"
    with pytest.raises(ValueError):
        GroupIBDigitalRiskProtection.CommonHelpers.convert_iso8601_with_timezone("bad")


def test_commonhelpers_format_dates_in_dict():
    data = {
        "first_detected": "2024-10-30T15:12:34+0000",
        "stages": ["2024-10-30T15:12:34+0000", "2024-10-30T16:12:34+0000"],
        "nested": {"dates_created_date": "2024-10-30T15:12:34+0000"},
    }
    out = GroupIBDigitalRiskProtection.CommonHelpers.format_dates_in_dict(data)
    assert out["first_detected"].endswith("+00:00")
    assert all(x.endswith("+00:00") for x in out["stages"])
    # Nested conversion only happens when the key itself is one of date_keys; convert nested dict explicitly.
    converted_nested = GroupIBDigitalRiskProtection.CommonHelpers.format_dates_in_dict(out["nested"])
    assert converted_nested["dates_created_date"].endswith("+00:00")


def test_commonhelpers_replace_empty_values_and_keys_cleanup():
    d = {"a": "", "b": [], "c": ["ok"], "d": [[], []]}
    out = GroupIBDigitalRiskProtection.CommonHelpers.replace_empty_values(d)
    assert isinstance(out, dict)
    out_dict = out if isinstance(out, dict) else {}
    assert out_dict.get("a") is None
    assert out_dict.get("b") is None
    assert out_dict.get("c") == ["ok"]
    assert out_dict.get("d") is None

    lst = [{"A_B": 1, "Some_Key": 2}]
    out2 = GroupIBDigitalRiskProtection.CommonHelpers.remove_underscore_and_lowercase_keys(lst)
    assert out2 == [{"ab": 1, "somekey": 2}]


def test_commonhelpers_data_pre_cleaning_and_source_mapping():
    feed = {"violation_uri": "//example.com", "tags": [None, "a"], "source": 1}
    feed = GroupIBDigitalRiskProtection.CommonHelpers.data_pre_cleaning(feed)
    assert feed["violation_uri"] == "example.com"
    assert feed["tags"] == ["a"]
    feed = GroupIBDigitalRiskProtection.CommonHelpers.violation_source_mapping(feed)
    assert feed["source"] == "WEB"


def test_commonhelpers_extract_mime_type():
    mt = GroupIBDigitalRiskProtection.CommonHelpers.extract_mime_type("image/png; charset=UTF-8")
    assert mt == "image/png"
    mt = GroupIBDigitalRiskProtection.CommonHelpers.extract_mime_type("")
    assert mt == "image/jpeg"


def test_incident_builder_transform_fields_to_grid_table(session_fixture):
    client = session_fixture
    builder = GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        max_requests=1,
        download_images=False,
        only_typosquatting=False,
        violation_subtypes=None,
        violation_section=None,
        brands=None,
    )
    incident = {
        "scores": {
            "type": ["risk", "position"],
            "score": [10, 99],
            "version": [1, 2],
        }
    }
    out = builder.transform_fields_to_grid_table(incident)
    assert isinstance(out["scores"], list)
    assert all(entry["type"] != "position" for entry in out["scores"])


def test_commands_fetch_incidents_flow(session_fixture):
    client = session_fixture

    class Portion:
        sequpdate = {"cursor": "abc"}

        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return [
                {
                    "id": "1",
                    "title": "t",
                    "violation_uri": "//example.com",
                    "source": 1,
                    "tags": [None, "x"],
                    "dates_created_date": "2024-10-30T15:12:34+0000",
                    "images": [],
                    "scores": {"type": ["risk", "position"], "score": [10, 99], "version": [1, 2]},
                }
            ]

    def generator():
        yield Portion()

    # override instance method with lightweight fake
    client.create_generator = lambda **kwargs: generator()  # type: ignore

    result, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.FETCH_INCIDENTS.value,
        args={},
        first_fetch="3 days",
        max_requests=1,
        download_images=False,
        violation_subtypes=None,
        only_typosquatting=False,
    ).get_results()

    assert isinstance(result, tuple)
    next_run, incidents = result
    assert isinstance(next_run, dict)
    assert "last_fetch" in next_run
    assert isinstance(incidents, list)
    assert len(incidents) == 1
    assert requested_method == "fetch_incidents"


def test_client_change_violation_status_paths(mocker, session_fixture):
    client = session_fixture

    class Resp:
        def __init__(self, raw_dict):
            self.raw_dict = raw_dict

    # perform POST path
    mocker.patch.object(
        client.poller,
        "search_feed_by_id",
        return_value=Resp({"violation": {"status": "detected", "approveState": "under_review"}}),
    )

    class HTTPResponse:
        status_code = 200

    mocker.patch.object(client, "_http_request", return_value=HTTPResponse())
    assert client.change_violation_status(feed_id="1", status="approve") == 200

    # cannot change path
    mocker.patch.object(
        client.poller, "search_feed_by_id", return_value=Resp({"violation": {"status": "approved", "approveState": "approved"}})
    )
    res = client.change_violation_status(feed_id="1", status="approve")
    assert isinstance(res, str)
    assert "Can not change" in res


def test_client_get_formatted_violation_by_id_with_images(session_fixture, mocker):
    client = session_fixture

    class FakeParser:
        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return [{"id": "1", "violation_uri": "//example.com", "source": 1, "images": ["abc"]}]

    mocker.patch.object(client, "get_violation_by_id", return_value=FakeParser())
    mocker.patch.object(client, "get_file", return_value=(b"bytes", "image/jpeg"))
    parsed, images = client.get_formatted_violation_by_id(violation_id="1", get_images=True)
    assert isinstance(parsed, dict)
    assert isinstance(images, list)
    assert len(images) > 0
    first = images[0]
    assert isinstance(first, dict)
    assert first.get("mime_type") == "image/jpeg"


def test_commonhelpers_get_table_data_returns_additional_tables():
    feed = {"scores": {"type": ["risk", "position"], "score": [10, 99], "version": [1, 2]}}
    updated_feed, additional_tables = GroupIBDigitalRiskProtection.CommonHelpers.get_table_data(feed)
    assert isinstance(updated_feed, dict)
    assert isinstance(additional_tables, list)
    assert len(additional_tables) > 0


def test_commands_change_violation_status_message(session_fixture, mocker):
    client = session_fixture
    mocker.patch.object(client, "change_violation_status", return_value=200)
    res, requested_method = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.CHANGE_VIOLATION_STATUS.value,
        args={"id": "1", "status": "approve"},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=None,
        only_typosquatting=False,
    ).get_results()
    assert isinstance(res, str)
    assert "Request to change violation status sent" in res
    assert requested_method == "change_violation_status"


def test_get_formatted_brands_and_subscriptions_no_methods(session_fixture):
    client = session_fixture

    class Dummy:
        pass

    client.poller = Dummy()  # type: ignore
    assert client.get_formatted_brands() == []
    assert client.get_formatted_subscriptions() == []
