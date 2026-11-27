import pytest
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
import GroupIBDigitalRiskProtection
from enum import Enum
import os
import json
import re
from json import load
from ciaops import Parser

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
    CREATE_VIOLATION = "gibdrp-create-violation"
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


""" Client Testing """


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


""" Commands Testing """


def test_get_available_commands():
    response_commands = GroupIBDigitalRiskProtection.Commands.get_available_commands()

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


def test_command_test_module_passes_with_zero_brands(mocker, session_fixture):
    """A company with valid credentials but no configured brands is a legitimate state -- the test
    checks that the API answers, not that it answers with something."""
    client = session_fixture
    mocker.patch.object(client, "get_formatted_brands", return_value=[])
    result, _ = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.TEST_MODULE.value,
        args={},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
        only_typosquatting=False,
    ).get_results()
    assert result == "ok"


def test_client_get_violation_section_number_and_error(session_fixture):
    client = session_fixture
    assert client._get_violation_section_number("Web") == 1
    assert client._get_violation_section_number("Social Networks") == 4
    with pytest.raises(ValueError):
        client._get_violation_section_number("Unknown Section")


def test_client_generate_seq_update_calls_poller(session_fixture, mocker):
    client = session_fixture

    class PollerStub:
        def get_seq_update_dict(self, date, collection_name):
            return {collection_name: 123}

    client.poller = PollerStub()
    seq = client.generate_seq_update("2024-01-15")
    assert seq == 123

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

    # changeable: the mutation is delegated to the library, not hand-rolled
    mocker.patch.object(
        client.poller,
        "search_feed_by_id",
        return_value=Resp({"violation": {"status": "detected", "approveState": "under_review"}}),
    )
    change_status = mocker.patch.object(client.poller, "change_status", return_value=None)
    client.change_violation_status(feed_id="1", status="approve")
    assert change_status.call_args.kwargs == {"feed_id": "1", "status": "approve"}

    # the library only writes to its own logger when the state is wrong, which from XSOAR looks
    # like success -- so the precondition is re-checked here and raises instead.
    for violation, expected in (
        ({"status": "found", "approveState": "under_review"}, "'found'"),
        ({"status": "detected", "approveState": "approved"}, "'approved'"),
        ({"status": "solved", "approveState": "approved"}, "'solved'"),
    ):
        mocker.patch.object(client.poller, "search_feed_by_id", return_value=Resp({"violation": violation}))
        change_status.reset_mock()
        with pytest.raises(GroupIBDigitalRiskProtection.DemistoException) as exc:
            client.change_violation_status(feed_id="1", status="approve")
        assert expected in str(exc.value)
        change_status.assert_not_called()
    assert "'solved'" in str(exc.value)


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
    mocker.patch.object(client, "change_violation_status", return_value=None)
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
    assert isinstance(res, GroupIBDigitalRiskProtection.CommandResults)
    # "sent" used to be the wording, and it overpromised: the precondition is checked before the
    # call and a refusal raises, so by the time this entry is returned the change did happen.
    assert res.readable_output == "Violation '1' was changed to 'approve'."
    # The entry names the violation id, a 64-hex string XSOAR would otherwise extract as a File indicator.
    assert res.ignore_auto_extract is True
    assert res.outputs == {"id": "1", "status": "approve", "approveState": "approved", "closeIncident": False}
    assert requested_method == "change_violation_status"


def test_change_violation_status_reports_the_instance_close_setting(session_fixture, mocker):
    """The instance decides whether the incident closes after a decision; the button script carries it out."""
    client = session_fixture
    mocker.patch.object(client, "change_violation_status", return_value=None)
    res, _ = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.CHANGE_VIOLATION_STATUS.value,
        args={"id": "1", "status": "reject"},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=None,
        only_typosquatting=False,
        close_incident_on_decision=True,
    ).get_results()
    assert res.outputs == {"id": "1", "status": "reject", "approveState": "rejected", "closeIncident": True}


def test_commands_change_violation_status_failure_raises(session_fixture, mocker):
    """The client's not-changeable error must propagate to the command
    boundary as an error entry instead of a success-looking note."""
    client = session_fixture
    mocker.patch.object(
        client,
        "change_violation_status",
        side_effect=GroupIBDigitalRiskProtection.DemistoException("approveState is 'approved'"),
    )
    with pytest.raises(GroupIBDigitalRiskProtection.DemistoException):
        GroupIBDigitalRiskProtection.Commands(
            client=client,
            command=Commands.CHANGE_VIOLATION_STATUS.value,
            args={"id": "1", "status": "approve"},
            first_fetch="",
            max_requests=1,
            download_images=False,
            violation_subtypes=None,
            only_typosquatting=False,
        ).get_results()


# ---------------------------------------------------------------------------
# Fetch-time deduplication helpers (flat {id: ts} cache)
# ---------------------------------------------------------------------------


SECONDS_PER_DAY = 86_400


def test_convert_dedup_lookback_days_to_seconds_basic():
    assert GroupIBDigitalRiskProtection.Deduplicator.convert_lookback_days_to_seconds(1) == SECONDS_PER_DAY
    assert GroupIBDigitalRiskProtection.Deduplicator.convert_lookback_days_to_seconds(365) == 365 * SECONDS_PER_DAY


def test_convert_dedup_lookback_days_to_seconds_zero():
    # Zero (and any non-positive) retention is the kill-switch handled by
    # `_prune_seen_incident_ids`, which drops the whole cache for `<= 0`.
    assert GroupIBDigitalRiskProtection.Deduplicator.convert_lookback_days_to_seconds(0) == 0


def test_get_dedup_lookback_days_from_params_default():
    assert GroupIBDigitalRiskProtection.Deduplicator.lookback_days_from_params({}) == 365
    assert GroupIBDigitalRiskProtection.Deduplicator.lookback_days_from_params({"dedup_lookback_days": ""}) == 365
    assert GroupIBDigitalRiskProtection.Deduplicator.lookback_days_from_params({"dedup_lookback_days": None}) == 365


def test_get_dedup_lookback_days_from_params_typed():
    assert GroupIBDigitalRiskProtection.Deduplicator.lookback_days_from_params({"dedup_lookback_days": 30}) == 30
    assert GroupIBDigitalRiskProtection.Deduplicator.lookback_days_from_params({"dedup_lookback_days": "90"}) == 90


def test_get_dedup_lookback_days_from_params_rejects_bool():
    with pytest.raises(ValueError):
        GroupIBDigitalRiskProtection.Deduplicator.lookback_days_from_params({"dedup_lookback_days": True})


def test_prune_seen_ids_returns_empty_for_zero_retention():
    cache = {"a": 1000.0, "b": 2000.0}
    assert GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=0, now=10_000.0) == {}


def test_prune_seen_ids_returns_empty_for_negative_retention():
    cache = {"a": 1000.0}
    assert GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=-1, now=10_000.0) == {}


def test_prune_seen_ids_keeps_entries_within_window():
    now = 10_000.0
    cache = {"fresh": now - 100, "older": now - 500}
    pruned = GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"fresh": now - 100, "older": now - 500}


def test_prune_seen_ids_drops_entries_older_than_window():
    now = 10_000.0
    cache = {"fresh": now - 100, "stale": now - 5000}
    pruned = GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"fresh": now - 100}


def test_prune_seen_ids_threshold_is_inclusive():
    """An ID exactly at the retention boundary must be kept (>=, not >)."""
    now = 10_000.0
    cache = {"boundary": now - 1000}
    pruned = GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"boundary": now - 1000}


def test_prune_seen_ids_drops_entries_just_past_threshold():
    now = 10_000.0
    cache = {"just_past": now - 1000.001}
    assert GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1000, now=now) == {}


def test_prune_seen_ids_drops_entries_with_malformed_timestamp():
    """Defensive: corrupt cache entries are dropped, never raised."""
    now = 10_000.0
    cache = {
        "ok": now - 100,
        "string_ts": "not-a-number",
        "none_ts": None,
        "negative": -1,
        "bool_ts": True,
    }
    pruned = GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1000, now=now)
    assert pruned == {"ok": now - 100}


def test_prune_seen_ids_does_not_mutate_input():
    cache = {"a": 1.0, "b": 2.0}
    snapshot = dict(cache)
    GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1, now=1000.0)
    assert cache == snapshot


def test_prune_seen_ids_drops_latest_id_when_older_than_retention():
    """Every entry obeys the retention window; the newest id is not pinned forever."""
    now = 10_000.0
    cache = {"ancient_but_latest": now - 99_999_999, "ancient_too": now - 99_999_998}
    assert GroupIBDigitalRiskProtection.Deduplicator.prune_seen_ids(cache, retention_seconds=1000, now=now) == {}


def test_update_fetch_seen_ids_cache_noop_for_empty_incidents():
    state = {"found_incident_ids": {"existing": 1.0}}
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(last_run_state=state, incidents=[], dedup_lookback_days=365)
    assert state == {"found_incident_ids": {"existing": 1.0}}


def test_update_fetch_seen_ids_cache_adds_new_ids(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    state: dict = {}
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": "alpha"}, {"id": "beta"}], dedup_lookback_days=365
    )
    assert state["found_incident_ids"] == {"alpha": fixed_now, "beta": fixed_now}


def test_update_fetch_seen_ids_cache_normalizes_non_string_ids(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    state: dict = {}
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": 42}, {"id": "alpha"}], dedup_lookback_days=365
    )
    assert state["found_incident_ids"] == {"42": fixed_now, "alpha": fixed_now}


def test_update_fetch_seen_ids_cache_skips_incidents_without_id(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    state: dict = {}
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": None}, {"name": "no-id"}, {"id": "ok"}], dedup_lookback_days=365
    )
    assert state["found_incident_ids"] == {"ok": fixed_now}


def test_update_fetch_seen_ids_cache_prunes_old_entries(mocker):
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    state = {
        "found_incident_ids": {
            "stale": fixed_now - (366 * SECONDS_PER_DAY),
            "fresh": fixed_now - (10 * SECONDS_PER_DAY),
        }
    }
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": "new"}], dedup_lookback_days=365
    )
    assert "stale" not in state["found_incident_ids"]
    assert "fresh" in state["found_incident_ids"]
    assert state["found_incident_ids"]["new"] == fixed_now


def test_update_fetch_seen_ids_cache_handles_corrupt_existing_value(mocker):
    """If `found_incident_ids` was somehow stored as a string, we don't crash."""
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    state: dict = {"found_incident_ids": "this-should-have-been-a-dict"}
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": "alpha"}], dedup_lookback_days=365
    )
    assert state["found_incident_ids"] == {"alpha": fixed_now}


def test_update_fetch_seen_ids_cache_one_to_one_retention_contract(mocker):
    """An id at exactly N days is retained; at N days + 1s it is pruned."""
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    n_days = 7
    retention_seconds = n_days * SECONDS_PER_DAY
    state = {
        "found_incident_ids": {
            "boundary": fixed_now - retention_seconds,
            "just_past": fixed_now - retention_seconds - 1,
        }
    }
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": "today"}], dedup_lookback_days=n_days
    )
    cache = state["found_incident_ids"]
    assert "boundary" in cache
    assert "just_past" not in cache
    assert cache["today"] == fixed_now


def test_update_fetch_seen_ids_cache_disables_when_retention_is_zero(mocker):
    """Kill-switch: `dedup_lookback_days = 0` drops the entire cache on next update."""
    fixed_now = 1_700_000_000.0
    mocker.patch.object(GroupIBDigitalRiskProtection.time, "time", return_value=fixed_now)
    state = {"found_incident_ids": {"old": fixed_now - 10}}
    GroupIBDigitalRiskProtection.Deduplicator.update_seen_cache(
        last_run_state=state, incidents=[{"id": "incoming"}], dedup_lookback_days=0
    )
    assert state["found_incident_ids"] == {}


def test_incident_builder_passes_a_known_violation_through_whatever_the_filters_say(session_fixture, mocker):
    """A violation the instance already created an incident for is an update: the status and
    approval filters apply to creation only, so the resolved, approved violation still reaches
    the pre-processing rule, which is what closes its incident."""
    client = session_fixture

    class Portion:
        sequpdate = 100

        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return [
                {
                    "id": "v-1",
                    "title": "Test",
                    "violation_uri": "//example.com",
                    "source": 1,
                    "tags": [],
                    "dates_created_date": "2024-10-30T15:12:34+0000",
                    "images": [],
                    "violation_status": "resolved",
                    "approve_state": "approved",
                }
            ]

    def gen():
        yield Portion()

    client.create_generator = lambda **kwargs: gen()  # type: ignore

    builder = GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={
            GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY: {
                "v-1": 1_000_000.0,
            }
        },
        first_fetch_time="3 days",
        max_requests=1,
        download_images=False,
        only_typosquatting=False,
        violation_subtypes=None,
        violation_section=None,
        brands=None,
        dedup_lookback_days=365,
        violation_statuses=["detected", "in_response"],
        only_approval_required=True,
    )
    mocker.patch("GroupIBDigitalRiskProtection.time.time", return_value=1_000_001.0)

    next_run, incidents = builder.build()
    assert [json.loads(inc["rawJSON"])["id"] for inc in incidents] == ["v-1"]
    # The update refreshes the timestamp, so a violation that keeps changing stays known.
    assert next_run[GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY]["v-1"] == 1_000_001.0


def test_incident_builder_records_a_new_id_in_the_cache(session_fixture, mocker):
    """First-time ids are emitted AND recorded in the cache for next run."""
    client = session_fixture

    class Portion:
        sequpdate = 100

        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return [
                {
                    "id": "v-2",
                    "title": "Test",
                    "violation_uri": "//example.com",
                    "source": 1,
                    "tags": [],
                    "dates_created_date": "2024-10-30T15:12:34+0000",
                    "images": [],
                }
            ]

    def gen():
        yield Portion()

    client.create_generator = lambda **kwargs: gen()  # type: ignore

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
        dedup_lookback_days=365,
    )
    mocker.patch("GroupIBDigitalRiskProtection.time.time", return_value=2_000_000.0)

    next_run, incidents = builder.build()
    assert len(incidents) == 1
    cache = next_run[GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY]
    assert "v-2" in cache
    # Flat {id: unix_seconds} layout.
    assert cache["v-2"] == 2_000_000.0


# ---------------------------------------------------------------------------
# Status filter / fetch cap / stages display
# ---------------------------------------------------------------------------


def test_validate_violation_statuses_accepts_supported():
    out = GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses(["detected", "Legal", "no_content"])
    assert out == {"detected", "legal", "no_content"}


def test_validate_violation_statuses_csv_string():
    out = GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses("detected, legal ,solved")
    assert out == {"detected", "legal", "solved"}


def test_validate_violation_statuses_empty():
    assert GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses(None) == set()
    assert GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses("") == set()
    assert GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses([]) == set()


def test_validate_violation_statuses_rejects_unknown():
    with pytest.raises(ValueError) as exc:
        GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses(["totally_invalid"])
    assert "totally_invalid" in str(exc.value)


def _make_portion(items: list[dict], sequpdate: int):
    """Builds an ad-hoc Portion stub that returns the given items."""

    class Portion:
        def __init__(self, payload, seq):
            self.sequpdate = seq
            self._payload = payload

        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return list(self._payload)

    return Portion(items, sequpdate)


def test_incident_builder_filters_by_violation_status(session_fixture):
    client = session_fixture

    base = {
        "title": "t",
        "violation_uri": "//example.com",
        "source": 1,
        "tags": [],
        "dates_created_date": "2024-10-30T15:12:34+0000",
        "images": [],
    }

    items = [
        {**base, "id": "v-1", "violation_status": "detected"},
        {**base, "id": "v-2", "violation_status": "on_tracking"},
        {**base, "id": "v-3", "violation_status": "no_content"},
    ]

    def gen():
        yield _make_portion(items, sequpdate=10)

    client.create_generator = lambda **kwargs: gen()  # type: ignore

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
        violation_statuses=["on_tracking", "no_content"],
    )

    next_run, incidents = builder.build()

    emitted_ids = [json.loads(inc["rawJSON"])["id"] for inc in incidents]
    assert emitted_ids == ["v-2", "v-3"]
    # seqUpdate still advances because filtering is portion-aligned.
    assert next_run["last_fetch"] == 10


def test_incident_builder_status_filter_disabled_when_empty(session_fixture):
    client = session_fixture
    items = [
        {
            "id": "v-1",
            "title": "t",
            "violation_uri": "//x",
            "source": 1,
            "tags": [],
            "images": [],
            "violation_status": "detected",
        },
        {
            "id": "v-2",
            "title": "t",
            "violation_uri": "//x",
            "source": 1,
            "tags": [],
            "images": [],
            "violation_status": "redirect",
        },
    ]
    client.create_generator = lambda **kwargs: iter([_make_portion(items, sequpdate=20)])  # type: ignore

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
        violation_statuses=None,
    )

    _, incidents = builder.build()
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["v-1", "v-2"]


def test_incident_builder_max_incidents_per_fetch_caps_output(session_fixture):
    """Cap is portion-aligned: the current portion fully drains, then we stop."""
    client = session_fixture
    items = [{"id": f"v-{i}", "title": "t", "violation_uri": "//x", "source": 1, "tags": [], "images": []} for i in range(5)]

    # Two portions, each with the same items so the second portion would
    # double the count if the cap were ignored.
    def gen():
        yield _make_portion(items, sequpdate=100)
        yield _make_portion([{**it, "id": f"{it['id']}-b"} for it in items], sequpdate=200)

    client.create_generator = lambda **kwargs: gen()  # type: ignore

    builder = GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        max_requests=10,
        download_images=False,
        only_typosquatting=False,
        violation_subtypes=None,
        violation_section=None,
        brands=None,
        max_incidents_per_fetch=3,  # below the size of one portion (5)
    )

    next_run, incidents = builder.build()
    # Cap is portion-aligned: the first portion (5 items) is fully drained,
    # then we stop because 5 >= 3. The second portion is not consumed.
    assert len(incidents) == 5
    assert next_run["last_fetch"] == 100


def test_incident_builder_max_incidents_per_fetch_zero_disables_cap(session_fixture):
    client = session_fixture
    items = [{"id": f"v-{i}", "title": "t", "violation_uri": "//x", "source": 1, "tags": [], "images": []} for i in range(3)]
    client.create_generator = lambda **kwargs: iter([_make_portion(items, sequpdate=50)])  # type: ignore

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
        max_incidents_per_fetch=0,
    )

    _, incidents = builder.build()
    assert len(incidents) == 3


def test_transform_fields_to_grid_table_enriches_stages(session_fixture):
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
        "stages": {
            "type": [4, 7, 12, 99],
            "datetime": [
                "2024-11-17T12:52:59+00:00",
                "2024-11-18T15:58:56+00:00",
                "2024-11-17T12:52:59+00:00",
                "2024-11-17T12:52:59+00:00",
            ],
            "times": [0, 0, 0, 0],
        }
    }
    out = builder.transform_fields_to_grid_table(incident)
    stages = out["stages"]
    assert isinstance(stages, list)
    assert len(stages) == 4

    by_type = {row["type"]: row["stagename"] for row in stages}
    assert by_type[4] == GroupIBDigitalRiskProtection.Mappings.STAGE_TYPE_LABELS[4]
    assert by_type[7] == GroupIBDigitalRiskProtection.Mappings.STAGE_TYPE_LABELS[7]
    assert by_type[12] == GroupIBDigitalRiskProtection.Mappings.STAGE_TYPE_LABELS[12]
    # Unknown codes fall back to "Unknown" instead of breaking the layout.
    assert by_type[99] == "Unknown"


def test_incident_builder_zero_retention_forgets_every_violation(session_fixture):
    """With `dedup_lookback_days=0` nothing is remembered: a cached id is filtered as if it were
    new, and the cache is written back empty."""
    client = session_fixture

    class Portion:
        sequpdate = 100

        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return [
                {"id": "v-3", "title": "X", "violation_uri": "//example.com", "source": 1, "tags": [], "images": []},
                {
                    "id": "v-4",
                    "title": "X",
                    "violation_uri": "//example.com",
                    "source": 1,
                    "tags": [],
                    "images": [],
                    "violation_status": "resolved",
                },
            ]

    def gen():
        yield Portion()

    client.create_generator = lambda **kwargs: gen()  # type: ignore

    builder = GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY: {"v-4": 1.0}},
        first_fetch_time="3 days",
        max_requests=1,
        download_images=False,
        only_typosquatting=False,
        violation_subtypes=None,
        violation_section=None,
        brands=None,
        dedup_lookback_days=0,
    )

    next_run, incidents = builder.build()
    assert [json.loads(inc["rawJSON"])["id"] for inc in incidents] == ["v-3"]
    assert next_run[GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY] == {}


def test_incident_builder_rejects_a_negative_retention(session_fixture):
    with pytest.raises(ValueError):
        GroupIBDigitalRiskProtection.IncidentBuilder(
            client=session_fixture,
            last_run={},
            first_fetch_time="3 days",
            max_requests=1,
            download_images=False,
            only_typosquatting=False,
            violation_subtypes=None,
            violation_section=None,
            brands=None,
            dedup_lookback_days=-1,
        )


# ---------------------------------------------------------------------------
# ciaops migration: create_generator argument adaptation
# ---------------------------------------------------------------------------


def test_client_create_generator_adapts_args_for_ciaops(session_fixture, mocker):
    """`brands` must reach ciaops as list[str] (the generator sends brands[0]
    as `brandIds[]`) and `section` as the scalar section id."""
    client = session_fixture
    create_update_generator = mocker.patch.object(client.poller, "create_update_generator", return_value=iter([]))
    mocker.patch.object(client, "generate_seq_update", return_value=42)

    client.create_generator(
        first_fetch_time="3 days",
        last_run={},
        only_typosquatting=False,
        brands="brand-id-1",
        section="Social Networks",
    )

    kwargs = create_update_generator.call_args.kwargs
    assert kwargs["brands"] == ["brand-id-1"]
    assert kwargs["section"] == 4
    assert kwargs["sequpdate"] == 42


def test_client_create_generator_without_optional_filters(session_fixture, mocker):
    client = session_fixture
    create_update_generator = mocker.patch.object(client.poller, "create_update_generator", return_value=iter([]))
    mocker.patch.object(client, "generate_seq_update", return_value=42)

    client.create_generator(first_fetch_time="3 days", last_run={}, only_typosquatting=False)

    kwargs = create_update_generator.call_args.kwargs
    assert kwargs["brands"] is None
    assert kwargs["section"] is None


# ---------------------------------------------------------------------------
# gibdrp-create-violation
# ---------------------------------------------------------------------------


def _run_create_violation(client, args):
    return GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.CREATE_VIOLATION.value,
        args=args,
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=None,
        only_typosquatting=False,
    ).get_results()


def test_client_create_violations_builds_items(session_fixture, mocker):
    client = session_fixture
    add_violations = mocker.patch.object(client.poller, "add_violations", return_value={"succeeded": []})
    client.create_violations(urls=["https://a.example", "https://b.example"], violation_subtype="phishing", brand_id="b-1")
    add_violations.assert_called_once_with(
        items=[
            {"url": "https://a.example", "violationSubtype": "phishing", "brandId": "b-1"},
            {"url": "https://b.example", "violationSubtype": "phishing", "brandId": "b-1"},
        ]
    )


def test_command_create_violation_success(session_fixture, mocker):
    client = session_fixture
    succeeded = [{"url": "https://a.example", "violationSubtype": "phishing", "brandId": "b-1"}]
    mocker.patch.object(client, "create_violations", return_value={"succeeded": succeeded})

    result, requested_method = _run_create_violation(
        client, {"url": "https://a.example", "violation_subtype": "phishing", "brand_id": "b-1"}
    )

    assert requested_method == "create_violation"
    assert result.outputs == {"succeeded": succeeded, "failed": []}
    assert "Created violations" in result.readable_output


def test_command_create_violation_partial_success_reports_failed(session_fixture, mocker):
    client = session_fixture
    succeeded = [{"url": "https://a.example"}]
    failed = [{"url": "https://b.example", "error": "invalid url"}]
    mocker.patch.object(client, "create_violations", return_value={"succeeded": succeeded, "failed": failed})

    result, _ = _run_create_violation(
        client, {"url": "https://a.example,https://b.example", "violation_subtype": "phishing", "brand_id": "b-1"}
    )

    assert result.outputs == {"succeeded": succeeded, "failed": failed}
    assert "Rejected violations" in result.readable_output


def test_command_create_violation_all_failed_raises(session_fixture, mocker):
    client = session_fixture
    mocker.patch.object(
        client, "create_violations", return_value={"succeeded": [], "failed": [{"url": "https://a.example", "error": "bad"}]}
    )
    with pytest.raises(GroupIBDigitalRiskProtection.DemistoException):
        _run_create_violation(client, {"url": "https://a.example", "violation_subtype": "phishing", "brand_id": "b-1"})


@pytest.mark.parametrize(
    "args",
    [
        {"url": "", "violation_subtype": "phishing", "brand_id": "b-1"},
        {"url": "https://a.example", "violation_subtype": "not-a-subtype", "brand_id": "b-1"},
        {"url": "https://a.example", "violation_subtype": "phishing", "brand_id": ""},
        {"url": ",".join(f"https://u{i}.example" for i in range(101)), "violation_subtype": "phishing", "brand_id": "b-1"},
    ],
)
def test_command_create_violation_rejects_invalid_args(session_fixture, mocker, args):
    client = session_fixture
    create_violations = mocker.patch.object(client, "create_violations")
    with pytest.raises(GroupIBDigitalRiskProtection.DemistoException):
        _run_create_violation(client, args)
    create_violations.assert_not_called()


def test_command_create_violation_connection_error_is_actionable(session_fixture, mocker):
    """HTTP 400 (all items rejected) reaches the command as ConnectionException;
    it must surface as an actionable DemistoException, not a raw traceback."""
    client = session_fixture
    mocker.patch.object(
        client,
        "create_violations",
        side_effect=GroupIBDigitalRiskProtection.ConnectionException("HTTP 400: Bad Credentials or Wrong request."),
    )
    with pytest.raises(GroupIBDigitalRiskProtection.DemistoException) as exc:
        _run_create_violation(client, {"url": "https://a.example", "violation_subtype": "phishing", "brand_id": "b-1"})
    assert "rejected the violation batch" in str(exc.value)


def test_commonhelpers_source_mapping_unknown_falls_back():
    feed = {"source": None}
    assert GroupIBDigitalRiskProtection.CommonHelpers.violation_source_mapping(feed)["source"] == "UNKNOWN"
    feed = {"source": 99}
    assert GroupIBDigitalRiskProtection.CommonHelpers.violation_source_mapping(feed)["source"] == "UNKNOWN"


def test_transform_additional_tables_without_position_score():
    """Violations without a `position` score row must not crash get-violation-by-id."""
    feed = {"scores": {"type": ["risk"], "score": [10], "version": [1]}}
    updated_feed, additional_tables = GroupIBDigitalRiskProtection.CommonHelpers.get_table_data(feed)
    assert isinstance(additional_tables, list)
    assert len(additional_tables) > 0


def test_data_pre_cleaning_current_date_fallback_and_type_labels():
    violation = {
        "violation_uri": "//example.com",
        "tags": [],
        "dates_current_status_date": None,
        "dates_current_date": "2024-10-30T15:12:34+0000",
        "violation_type": "PH",
    }
    out = GroupIBDigitalRiskProtection.CommonHelpers.data_pre_cleaning(violation)
    assert out["dates_current_status_date"] == "2024-10-30T15:12:34+0000"
    assert "dates_current_date" not in out
    assert out["violation_type"] == "Phishing"
    # Values outside the code table pass through unchanged.
    violation = {"violation_uri": "", "tags": [], "violation_type": "unknown_future_type"}
    assert GroupIBDigitalRiskProtection.CommonHelpers.data_pre_cleaning(violation)["violation_type"] == "unknown_future_type"


def test_incident_builder_skips_oversize_images(session_fixture, mocker):
    client = session_fixture
    items = [{"id": "v-1", "title": "t", "violation_uri": "//x", "source": 1, "tags": [], "images": ["sha-big", "sha-small"]}]
    client.create_generator = lambda **kwargs: iter([_make_portion(items, sequpdate=10)])  # type: ignore
    big = b"x" * (GroupIBDigitalRiskProtection.Consts.MAX_IMAGE_BYTES + 1)
    mocker.patch.object(
        client, "get_file", side_effect=lambda file_sha: (big, "image/jpeg") if file_sha == "sha-big" else (b"ok", "image/png")
    )

    builder = GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        max_requests=1,
        download_images=True,
        only_typosquatting=False,
        violation_subtypes=None,
        violation_section=None,
        brands=None,
    )
    _, incidents = builder.build()
    raw = json.loads(incidents[0]["rawJSON"])
    assert "sha-big" not in raw.get("images", "")
    assert "image/png" in raw.get("images", "")


def test_incident_builder_max_requests_consumes_exact_portion_count(session_fixture):
    """max_requests=1 must consume exactly one portion (no off-by-one)."""
    client = session_fixture
    items = [{"id": "v-1", "title": "t", "violation_uri": "//x", "source": 1, "tags": [], "images": []}]

    def gen():
        yield _make_portion(items, sequpdate=10)
        yield _make_portion([{**items[0], "id": "v-2"}], sequpdate=20)

    client.create_generator = lambda **kwargs: gen()  # type: ignore

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
    next_run, incidents = builder.build()
    assert len(incidents) == 1
    assert next_run["last_fetch"] == 10


def test_yml_enums_match_python_constants():
    """The yml UI option lists and the Python validation sets must not drift."""
    with open(f"{realpath}/GroupIBDigitalRiskProtection.yml") as f:
        yml = f.read()

    item = r"(?:[ \t]+- \"?\w+\"?\n)+"
    statuses_block = re.search(rf"name: violationStatuses.*?options:\n({item})", yml, re.S)
    assert statuses_block is not None
    statuses_yml = set(re.findall(r"- \"?(\w+)\"?", statuses_block.group(1)))
    assert statuses_yml == GroupIBDigitalRiskProtection.Mappings.SUPPORTED_VIOLATION_STATUSES

    subtypes_block = re.search(rf"name: violation_subtype.*?predefined:\n({item})", yml, re.S)
    assert subtypes_block is not None
    subtypes_yml = set(re.findall(r"- \"?(\w+)\"?", subtypes_block.group(1)))
    assert subtypes_yml == GroupIBDigitalRiskProtection.Mappings.SUPPORTED_VIOLATION_SUBTYPES


def test_command_create_violation_canonicalizes_subtype_case(session_fixture, mocker):
    """The API enum is case-sensitive; user input is mapped to the canonical value."""
    client = session_fixture
    create_violations = mocker.patch.object(
        client, "create_violations", return_value={"succeeded": [{"url": "https://a.example", "violationId": "v-1"}]}
    )
    _run_create_violation(client, {"url": "https://a.example", "violation_subtype": "partnerpolicycompliance", "brand_id": "b-1"})
    assert create_violations.call_args.kwargs["violation_subtype"] == "partnerPolicyCompliance"


# ---------------------------------------------------------------------------
# ViolationSubtypeFilter
# ---------------------------------------------------------------------------


def test_violation_subtype_filter_empty_matches_everything_and_selects_nothing():
    empty = GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(None)
    assert empty.is_empty
    assert empty.server_side_ids is None
    # Fetch-filter semantics: nothing selected -> no filtering.
    assert empty.matches("Phishing") is True
    # Opt-in semantics: nothing selected -> nothing opted in.
    assert empty.contains("Phishing") is False


def test_violation_subtype_filter_is_case_insensitive_and_canonicalizes():
    parsed = GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param("phishing, FRAUD")
    assert parsed.labels == {"Phishing", "Scam"}
    assert parsed.matches("phishing") is True
    assert parsed.matches("Counterfeit") is False


def test_violation_subtype_filter_sends_single_selection_to_the_api():
    single = GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing"])
    assert single.server_side_ids == [GroupIBDigitalRiskProtection.Mappings.VIOLATION_SUBTYPE_IDS["Phishing"]]


def test_violation_subtype_filter_keeps_multi_selection_client_side():
    """The ciaops generator serializes subtypes[0] only, so a multi-value
    selection must not be pushed to the API - it would drop every other value."""
    multi = GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing", "Scam"])
    assert multi.server_side_ids is None
    assert multi.matches("Scam") is True


def test_violation_subtype_filter_rejects_unknown_type():
    with pytest.raises(ValueError) as exc:
        GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing", "not-a-type"])
    assert "not-a-type" in str(exc.value)


def test_violation_subtype_filter_matches_nothing_for_missing_type():
    parsed = GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing"])
    assert parsed.matches(None) is False
    assert parsed.contains(None) is False


def test_violation_subtype_ids_cover_the_yml_options():
    """The yml option list and the id table must not drift apart."""
    with open(f"{realpath}/GroupIBDigitalRiskProtection.yml") as f:
        yml = f.read()

    for param in ("violationSubtypes", "createIndicatorsForSubtypes"):
        block = re.search(rf"name: {param}\n.*?options:\n((?:[ \t]+- [\w ]+\n)+)", yml, re.S)
        assert block is not None, param
        options = {line.strip(" -\n") for line in block.group(1).splitlines() if line.strip()}
        assert options == set(GroupIBDigitalRiskProtection.Mappings.VIOLATION_SUBTYPE_IDS), param


# ---------------------------------------------------------------------------
# Creation filters, severity, incident naming and dating, indicator flags
# ---------------------------------------------------------------------------


def _violation(**overrides):
    base = {
        "title": "t",
        "violation_uri": "//bad.example",
        "source": 1,
        "tags": [],
        "images": [],
        "dates_created_date": "2024-10-30T15:12:34+0000",
    }
    base.update(overrides)
    return base


def _build(client, items, sequpdate=10, **kwargs):
    client.create_generator = lambda **_: iter([_make_portion(items, sequpdate=sequpdate)])  # type: ignore
    defaults = {
        "last_run": {},
        "first_fetch_time": "3 days",
        "max_requests": 1,
        "download_images": False,
        "only_typosquatting": False,
        "violation_subtypes": None,
        "violation_section": None,
        "brands": None,
    }
    defaults.update(kwargs)
    return GroupIBDigitalRiskProtection.IncidentBuilder(client=client, **defaults).build()


def test_incident_builder_filters_by_violation_type(session_fixture):
    items = [
        _violation(id="v-1", violation_type="PH"),
        _violation(id="v-2", violation_type="FR"),
        _violation(id="v-3", violation_type="AK"),
    ]
    _, incidents = _build(
        session_fixture,
        items,
        violation_subtypes=GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing", "Counterfeit"]),
    )
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["v-1", "v-3"]


def test_incident_builder_pushes_single_violation_type_to_the_api(session_fixture):
    client = session_fixture
    seen = {}

    def fake_generator(**kwargs):
        seen.update(kwargs)
        return iter([])

    client.create_generator = fake_generator  # type: ignore
    GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        max_requests=1,
        download_images=False,
        only_typosquatting=False,
        violation_subtypes=GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing"]),
        violation_section=None,
        brands=None,
        only_approval_required=True,
    ).build()

    assert seen["violation_subtypes"] == [GroupIBDigitalRiskProtection.Mappings.VIOLATION_SUBTYPE_IDS["Phishing"]]
    # Approval is a state the violation leaves once decided, so it never narrows the API query:
    # the decided violation must keep arriving as an update of its incident.
    assert "approve_states" not in seen


def test_incident_builder_only_approval_required_drops_settled_violations(session_fixture):
    items = [
        _violation(id="v-1", approve_state="under_review"),
        _violation(id="v-2", approve_state="approved"),
        _violation(id="v-3", approve_state=None),
    ]
    _, incidents = _build(session_fixture, items, only_approval_required=True)
    assert [json.loads(i["rawJSON"])["id"] for i in incidents] == ["v-1"]


def test_incident_builder_applies_configured_severity(session_fixture):
    _, incidents = _build(
        session_fixture,
        [_violation(id="v-1")],
        incident_severity=GroupIBDigitalRiskProtection.IncidentSeverity.CRITICAL,
    )
    assert incidents[0]["severity"] == GroupIBDigitalRiskProtection.IncidentSeverity.CRITICAL


def test_incident_builder_omits_severity_when_not_configured(session_fixture):
    _, incidents = _build(session_fixture, [_violation(id="v-1")])
    assert "severity" not in incidents[0]


def test_incident_builder_marks_the_incident_as_wanting_an_indicator_for_selected_types_only(session_fixture):
    """The fetch creates no indicator itself (one created there had no source, no incident link
    and no lifecycle); it marks the incident, and the postprocessing playbook creates the
    indicator from it."""
    items = [
        _violation(id="v-1", violation_type="PH"),
        _violation(id="v-2", violation_type="FR", violation_uri="//scam.example"),
    ]
    _, incidents = _build(
        session_fixture,
        items,
        indicator_subtypes=GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Phishing"]),
        expire_indicator_on_close=True,
    )
    raw = [json.loads(inc["rawJSON"]) for inc in incidents]
    assert [item["indicator_wanted"] for item in raw] == [True, False]
    assert [item["indicator_expire_on_close"] for item in raw] == [True, True]


def test_incident_builder_wants_no_indicator_by_default(session_fixture):
    _, incidents = _build(session_fixture, [_violation(id="v-1", violation_type="PH")])
    raw = json.loads(incidents[0]["rawJSON"])
    assert raw["indicator_wanted"] is False
    assert raw["indicator_expire_on_close"] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"violation_status": "resolved"},
        {"violation_status": "solved"},
        {"violation_status": "legal"},
        {"violation_status": "false_status"},
        {"approve_state": "rejected"},
    ],
)
def test_incident_builder_creates_no_incident_for_a_finished_violation(session_fixture, overrides):
    """A first fetch of a long-running tenant must not create an incident per resolved
    violation; and no filter selection can ask for one, since it would be closed at once."""
    items = [_violation(id="v-1", **overrides), _violation(id="v-2", violation_status="detected")]
    statuses = list(GroupIBDigitalRiskProtection.Mappings.SUPPORTED_VIOLATION_STATUSES)
    next_run, incidents = _build(session_fixture, items, violation_statuses=statuses)
    assert [json.loads(inc["rawJSON"])["id"] for inc in incidents] == ["v-2"]
    assert "v-1" not in next_run[GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY]


def test_incident_builder_passes_a_known_violation_through_when_it_finishes(session_fixture):
    """The finished-violation rule is about creation: the resolution of a known violation is the
    update that closes its incident."""
    items = [_violation(id="v-1", violation_status="resolved")]
    _, incidents = _build(
        session_fixture,
        items,
        last_run={
            GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY: {"v-1": GroupIBDigitalRiskProtection.time.time()}
        },
    )
    assert [json.loads(inc["rawJSON"])["id"] for inc in incidents] == ["v-1"]


def test_incident_builder_forgets_a_violation_past_the_retention_before_the_fetch(session_fixture):
    """A violation that went quiet for longer than the retention is filtered as new again."""
    items = [_violation(id="v-1", violation_status="resolved")]
    next_run, incidents = _build(
        session_fixture,
        items,
        last_run={GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY: {"v-1": 1.0}},
    )
    assert incidents == []
    assert next_run[GroupIBDigitalRiskProtection.Consts.LAST_RUN_SEEN_INCIDENT_IDS_KEY] == {}


def test_incident_name_is_type_brand_and_uri():
    name = GroupIBDigitalRiskProtection.IncidentBuilder.incident_name(
        {"violation_type": "Phishing", "brand": "Acme", "violation_uri": "acme-login.example/verify", "title": "Phishing page"}
    )
    assert name == "Phishing · Acme · acme-login.example/verify"


def test_incident_name_skips_missing_parts_and_falls_back_to_the_title():
    builder = GroupIBDigitalRiskProtection.IncidentBuilder
    assert builder.incident_name({"violation_type": "Scam", "brand": None, "violation_uri": "seller-42"}) == "Scam · seller-42"
    assert builder.incident_name({"title": "Some title", "id": "v-1"}) == "Some title"
    assert builder.incident_name({"id": "v-1"}) == "Violation v-1"


def test_incident_builder_names_the_incident_from_the_violation(session_fixture):
    _, incidents = _build(session_fixture, [_violation(id="v-1", violation_type="PH", brand="Acme")])
    assert incidents[0]["name"] == "Phishing · Acme · bad.example"
    assert json.loads(incidents[0]["rawJSON"])["name"] == incidents[0]["name"]


def test_occurred_is_detected_when_it_is_recent():
    now = GroupIBDigitalRiskProtection.datetime(2026, 9, 16, tzinfo=GroupIBDigitalRiskProtection.timezone.utc)
    violation = {"detected": "2026-09-10T10:00:00+00:00", "dates_current_status_date": "2026-09-15T10:00:00+00:00"}
    assert GroupIBDigitalRiskProtection.IncidentBuilder.occurred_for(violation, now=now) == "2026-09-10T10:00:00+00:00"


def test_occurred_falls_back_to_the_current_status_date_when_detected_is_old_or_missing():
    """DRP keeps `detected` from the first detection, so a violation that resurfaced would be
    dated years back; the current status date is when it became the customer's concern."""
    now = GroupIBDigitalRiskProtection.datetime(2026, 9, 16, tzinfo=GroupIBDigitalRiskProtection.timezone.utc)
    occurred_for = GroupIBDigitalRiskProtection.IncidentBuilder.occurred_for
    old = {"detected": "2024-01-01T10:00:00+00:00", "dates_current_status_date": "2026-09-15T10:00:00+00:00"}
    assert occurred_for(old, now=now) == "2026-09-15T10:00:00+00:00"
    missing = {"detected": None, "dates_current_status_date": "2026-09-15T10:00:00+00:00"}
    assert occurred_for(missing, now=now) == "2026-09-15T10:00:00+00:00"
    only_created = {"dates_created_date": "2026-09-14T10:00:00+00:00"}
    assert occurred_for(only_created, now=now) == "2026-09-14T10:00:00+00:00"
    # An old detection with nothing to fall back to is still better than no date.
    assert occurred_for({"detected": "2024-01-01T10:00:00+00:00"}, now=now) == "2024-01-01T10:00:00+00:00"


def test_incident_builder_occurred_matches_the_raw_json_and_the_mapper(session_fixture):
    """`occurred` and `name` are mapped from the keys of the same name, so the value the builder
    sets on the incident and the value the mapper writes cannot disagree."""
    _, incidents = _build(session_fixture, [_violation(id="v-1", detected="2026-09-10T10:00:00+0000")])
    raw = json.loads(incidents[0]["rawJSON"])
    assert incidents[0]["occurred"] == raw["occurred"] == "2026-09-10T10:00:00+00:00"
    with open(f"{realpath}/../../Classifiers/classifier-Group-IB_Digital_Risk_Protection_(mapper).json") as mapper_file:
        mapping = json.load(mapper_file)["mapping"]["GIB DRP Violation"]["internalMapping"]
    assert mapping["occurred"] == {"simple": "occurred"}
    assert mapping["name"] == {"simple": "name"}
    assert mapping["GIB DRP Indicator Wanted"] == {"simple": "indicator_wanted"}
    assert mapping["GIB DRP Expire Indicator On Close"] == {"simple": "indicator_expire_on_close"}


def test_yml_default_violation_statuses_are_supported():
    with open(f"{realpath}/GroupIBDigitalRiskProtection.yml") as f:
        yml = f.read()
    default = re.search(r"name: violationStatuses\n(?:.*\n)*?  defaultvalue: (.*)\n", yml)
    assert default is not None
    assert GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses(default.group(1)) == {
        "detected",
        "in_response",
    }


# ---------------------------------------------------------------------------
# Values the live DRP API returns (verified against drp.group-ib.com, 2026-09-03)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code, label",
    [
        ("counterfeit", "Counterfeit"),
        ("piracy", "Piracy"),
        ("partner_policy_compliance", "Partner policy compliance"),
        ("trademark", "Trademark"),
        ("malware", "Malware"),
        ("phishing", "Phishing"),
        ("scam", "Scam"),
        ("no_violation", "No violation"),
    ],
)
def test_data_pre_cleaning_maps_live_subtype_names_to_labels(code, label):
    """The live API reports `violationSubtype` as snake_case names, not the letter codes of the specification."""
    violation = {"violation_uri": "", "tags": [], "violation_type": code}
    assert GroupIBDigitalRiskProtection.CommonHelpers.data_pre_cleaning(violation)["violation_type"] == label
    # A label is left alone, so cleaning an already-cleaned violation is idempotent.
    assert GroupIBDigitalRiskProtection.CommonHelpers.data_pre_cleaning(violation)["violation_type"] == label


def test_violation_subtype_filter_keeps_live_scam_violations():
    """Selecting "Scam" must keep the violations the API reports as `scam`."""
    selected = GroupIBDigitalRiskProtection.ViolationSubtypeFilter.from_param(["Scam"])
    cleaned = GroupIBDigitalRiskProtection.CommonHelpers.data_pre_cleaning(
        {"violation_uri": "", "tags": [], "violation_type": "scam"}
    )
    assert selected.matches(cleaned["violation_type"]) is True
    assert selected.contains(cleaned["violation_type"]) is True


def test_validate_violation_statuses_accepts_live_statuses():
    out = GroupIBDigitalRiskProtection.IncidentBuilder._validate_violation_statuses("resolved, in_response")
    assert out == {"resolved", "in_response"}


def test_unknown_violation_id_is_a_readable_error(session_fixture, mocker):
    """The API answers an unknown id with `null`; the SDK then fails with an AttributeError."""
    client = session_fixture

    class Resp:
        def __init__(self, raw_dict):
            self.raw_dict = raw_dict

    for behaviour in (
        {"side_effect": AttributeError("'NoneType' object has no attribute 'get'")},
        {"return_value": Resp(None)},
        {"return_value": Resp({})},
    ):
        mocker.patch.object(client.poller, "search_feed_by_id", **behaviour)
        with pytest.raises(GroupIBDigitalRiskProtection.DemistoException, match="was not found in Group-IB DRP"):
            client.get_violation_by_id("doesnotexist")
        with pytest.raises(GroupIBDigitalRiskProtection.DemistoException, match="was not found in Group-IB DRP"):
            client.change_violation_status(feed_id="doesnotexist", status="approve")


def test_repeated_image_hashes_are_fetched_once(session_fixture, mocker):
    client = session_fixture

    class FakeParser:
        def parse_portion(self, keys, as_json=False):  # noqa: ARG002
            return [{"id": "1", "violation_uri": "//example.com", "source": 1, "images": ["abc", "abc", "def", "abc"]}]

    mocker.patch.object(client, "get_violation_by_id", return_value=FakeParser())
    get_file = mocker.patch.object(client, "get_file", return_value=(b"bytes", "image/jpeg"))
    _, images = client.get_formatted_violation_by_id(violation_id="1", get_images=True)
    assert [i["file_sha"] for i in images] == ["abc", "def"]
    assert get_file.call_count == 2

    builder = GroupIBDigitalRiskProtection.IncidentBuilder(
        client=client,
        last_run={},
        first_fetch_time="3 days",
        max_requests=1,
        download_images=True,
        only_typosquatting=False,
        violation_subtypes=None,
        violation_section=None,
        brands=None,
    )
    get_file.reset_mock()
    html = builder._embed_images(["abc", "abc", "def"])
    assert html.count("<img") == 2
    assert get_file.call_count == 2


def test_by_id_output_has_no_typosquatting_placeholder(session_fixture, mocker):
    client = session_fixture
    mocker.patch.object(client, "get_violation_by_id", return_value=Parser(chunk=VIOLATION_BY_ID_RAW_JSON, keys=[], iocs_keys=[]))
    result, _ = GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_VIOLATION_BY_ID.value,
        args={"id": TEST_VIOLATION_ID},
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=[],
        only_typosquatting=False,
    ).get_results()
    assert "typosquatting_status" not in result[0].outputs


def test_format_dates_treats_epoch_as_unknown():
    """DRP fills a date it does not know with the Unix epoch; that is "unknown", not 1970."""
    data = {
        "dates_found_date": "1970-01-01T00:00:00+0000",
        "detected": "2024-10-30T15:12:34+0000",
        "stages": {"datetime": ["1970-01-01T00:00:00+0000", "2024-10-30T15:12:34+0000"]},
    }
    out = GroupIBDigitalRiskProtection.CommonHelpers.format_dates_in_dict(data)
    assert out["dates_found_date"] is None
    assert out["detected"] == "2024-10-30T15:12:34+00:00"
    assert out["stages"]["datetime"] == [None, "2024-10-30T15:12:34+00:00"]


@pytest.mark.parametrize("argument, expected", [("false", False), ("true", True), (None, True)])
def test_get_violation_by_id_download_images_argument(session_fixture, mocker, argument, expected):
    """A quick status check must not download and attach screenshots."""
    client = session_fixture
    formatted = mocker.patch.object(
        client,
        "get_formatted_violation_by_id",
        return_value=({"id": "1", "violation_uri": "", "tags": [], "source": 1}, []),
    )
    args = {"id": "1"} if argument is None else {"id": "1", "download_images": argument}
    GroupIBDigitalRiskProtection.Commands(
        client=client,
        command=Commands.GET_VIOLATION_BY_ID.value,
        args=args,
        first_fetch="",
        max_requests=1,
        download_images=False,
        violation_subtypes=None,
        only_typosquatting=False,
    ).get_results()
    assert formatted.call_args.kwargs["get_images"] is expected


def test_change_status_accepts_a_failed_call_when_drp_already_holds_the_decision(session_fixture, mocker):
    """Seen live: the SDK retried the approve POST, the retry got HTTP 400, but DRP had applied the first one."""
    client = session_fixture

    class Resp:
        def __init__(self, raw_dict):
            self.raw_dict = raw_dict

    states = iter(
        [
            Resp({"violation": {"status": "detected", "approveState": "under_review"}}),  # precondition check
            Resp({"violation": {"status": "detected", "approveState": "approved"}}),  # re-read after the failure
        ]
    )
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=lambda feed_id: next(states))
    mocker.patch.object(
        client.poller, "change_status", side_effect=GroupIBDigitalRiskProtection.ConnectionException("HTTP 400: nope")
    )
    client.change_violation_status(feed_id="v-1", status="approve")  # must not raise

    # The same failure without the decision recorded in DRP is still an error.
    states = iter(
        [
            Resp({"violation": {"status": "detected", "approveState": "under_review"}}),
            Resp({"violation": {"status": "detected", "approveState": "under_review"}}),
        ]
    )
    mocker.patch.object(client.poller, "search_feed_by_id", side_effect=lambda feed_id: next(states))
    with pytest.raises(GroupIBDigitalRiskProtection.ConnectionException):
        client.change_violation_status(feed_id="v-1", status="approve")


def test_main_reports_expected_failures_without_a_traceback(mocker):
    from ciaops.exception import ConnectionException

    params = {"url": "https://drp.example/client_api", "credentials": {"identifier": "u", "password": "p"}}
    mocker.patch.object(GroupIBDigitalRiskProtection.demisto, "params", return_value=params)
    mocker.patch.object(GroupIBDigitalRiskProtection.demisto, "args", return_value={})
    mocker.patch.object(GroupIBDigitalRiskProtection.demisto, "command", return_value="gibdrp-get-brands")
    mocker.patch.object(
        GroupIBDigitalRiskProtection.Commands,
        "get_results",
        side_effect=ConnectionException("HTTP 403: Something is wrong with your account."),
    )
    error = mocker.patch.object(GroupIBDigitalRiskProtection, "return_error")
    GroupIBDigitalRiskProtection.main()
    message = error.call_args.args[0]
    assert "HTTP 403: Something is wrong with your account." in message
    assert "Traceback" not in message
