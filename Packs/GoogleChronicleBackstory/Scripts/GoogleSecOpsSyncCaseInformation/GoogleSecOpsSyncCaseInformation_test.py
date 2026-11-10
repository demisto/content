"""Test File for GoogleSecOpsSyncCaseInformation Script."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import demistomock as demisto
import GoogleSecOpsSyncCaseInformation
import pytest
from GoogleSecOpsSyncCaseInformation import (
    ALERT_LOOP_TIMEOUT_SECONDS,
    ERROR_MESSAGES,
    MAX_PAGE_SIZE,
    apply_mapper,
    epoch_ms_to_datestring,
    epoch_ms_to_time_delta,
    execute_command_safe,
    get_alert_entity_list,
    get_alert_list,
    get_case_information,
    get_command_result,
    prepare_alert_sla,
    sync_case_information,
)

CASE_ID = "1001"

TEST_DATA_DIR = Path(__file__).parent


def util_load_json(path):
    """Load file in JSON format."""
    with open(TEST_DATA_DIR / path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_case_raw_response():
    return util_load_json("test_data/case_get_response.json")


@pytest.fixture
def mock_alert_data():
    return util_load_json("test_data/case_alert_list_response.json")


@pytest.fixture
def mock_entity_data():
    return util_load_json("test_data/case_alert_entity_list_response.json")


@pytest.fixture
def mock_set_incident_data():
    return util_load_json("test_data/set_incident_mapper_response.json")


def _success_result(contents):
    return {"Type": 1, "Contents": contents, "ContentsFormat": "json"}


def _error_result(msg):
    return {"Type": 4, "Contents": msg, "ContentsFormat": "text"}


def test_epoch_ms_to_datestring():
    assert epoch_ms_to_datestring("1778778979232") == "2026-05-14 17:16:19 UTC"


def test_epoch_ms_to_time_delta():
    ms = (2 * 86400 + 3 * 3600 + 4 * 60 + 5) * 1000
    assert epoch_ms_to_time_delta(ms) == "2 days, 3 hours, 4 minutes, 5 seconds"


def test_prepare_alert_sla():
    sla = {
        "expirationStatus": "OPEN_SLA",
        "expirationTime": "1780832620238",
        "criticalExpirationTime": "1780580620238",
        "remainingTimeSinceLastPause": 3600000,
    }
    expected = (
        "Status - OPEN_SLA\n"
        "Expiration Time - 2026-06-07 11:43:40 UTC\n"
        "Critical Expiration Time - 2026-06-04 13:43:40 UTC\n"
        "Remaining Time Since Last Pause - 1 hours"
    )
    assert prepare_alert_sla(sla) == expected


def test_get_command_result_returns_first_non_error():
    """get_command_result should skip error entries and return the first success."""
    err = _error_result("bad")
    ok = _success_result({"key": "val"})
    assert get_command_result([err, ok]) == ok


def test_get_command_result_all_errors_returns_empty():
    """get_command_result with all error entries should return empty dict."""
    assert get_command_result([_error_result("e1"), _error_result("e2")]) == {}


def test_get_command_result_empty_list_returns_empty():
    assert get_command_result([]) == {}


def test_apply_mapper_normalises_keys(mocker):
    """apply_mapper should return lowercase no-space keys."""
    mocker.patch.object(demisto, "mapObject", return_value={"Google SecOps Status": "OPEN", "Display Name": "Case 1"})
    result = apply_mapper({})
    assert "googlesecopsstatus" in result
    assert "displayname" in result


def test_apply_mapper_empty_mapping(mocker):
    mocker.patch.object(demisto, "mapObject", return_value={})
    assert apply_mapper({}) == {}


def test_execute_command_safe_success(mocker):
    ok = _success_result({"data": 1})
    mocker.patch.object(demisto, "executeCommand", return_value=[ok])
    result, err = execute_command_safe("gcb-case-get", {"case_id": "1"})
    assert result == ok
    assert err is None


def test_execute_command_safe_error(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=[_error_result("not found")])
    result, err = execute_command_safe("gcb-case-get", {"case_id": "999"})
    assert result == {}
    assert err == "not found"


def test_execute_command_safe_wraps_non_list(mocker):
    ok = _success_result({"data": 1})
    mocker.patch.object(demisto, "executeCommand", return_value=ok)
    result, err = execute_command_safe("gcb-case-get", {"case_id": "1"})
    assert result == ok
    assert err is None


def test_execute_command_safe_empty_raw_list(mocker):
    """executeCommand returning [] should yield ({}, 'Unknown error')."""
    mocker.patch.object(demisto, "executeCommand", return_value=[])
    result, err = execute_command_safe("gcb-case-get", {"case_id": "1"})
    assert result == {}
    assert err == "Unknown error"


def test_get_case_information_success(mocker, mock_case_raw_response):
    """get_case_information returns (raw_result, case_data) tuple."""
    ok = _success_result(mock_case_raw_response)
    mocker.patch.object(demisto, "executeCommand", return_value=[ok])
    raw_result, case_data = get_case_information(CASE_ID)
    assert raw_result == ok
    assert case_data == mock_case_raw_response


def test_get_case_information_raises_on_error(mocker):
    """get_case_information should raise ValueError on command failure."""
    mocker.patch.object(demisto, "executeCommand", return_value=[_error_result("not found")])
    with pytest.raises(ValueError, match="gcb-case-get"):
        get_case_information(CASE_ID)


def test_get_alerts_success(mocker, mock_alert_data):
    """get_alert_list returns (raw_result, alerts) tuple."""
    ok = _success_result(mock_alert_data)
    mocker.patch.object(demisto, "executeCommand", return_value=[ok])
    raw_result, alerts = get_alert_list(CASE_ID, 1000)
    assert raw_result == ok
    assert len(alerts) == 2
    assert alerts[0]["displayName"] == "TEST ALERT"
    assert alerts[1]["displayName"] == "TEST ALERT 2"


def test_get_alerts_raises_on_error(mocker):
    """get_alert_list should raise ValueError on command failure."""
    mocker.patch.object(demisto, "executeCommand", return_value=[_error_result("alerts not found")])
    with pytest.raises(ValueError, match="alerts"):
        get_alert_list(CASE_ID, 1000)


def test_get_alert_entities_success(mocker, mock_entity_data):
    """get_alert_entity_list returns (raw_result, entities) tuple on success."""
    ok = _success_result(mock_entity_data)
    mocker.patch.object(demisto, "executeCommand", return_value=[ok])
    raw_result, entities = get_alert_entity_list(CASE_ID, "1000001", 1000)
    assert raw_result == ok
    assert len(entities) == 2
    assert entities[0]["identifier"] == "0.0.0.1"
    assert entities[1]["identifier"] == "demo.com"


def test_get_alert_entities_returns_none_on_error(mocker):
    """get_alert_entity_list should return (None, None) and call debug on failure."""
    mocker.patch.object(demisto, "executeCommand", return_value=[_error_result("entity error")])
    debug_mock = mocker.patch.object(demisto, "debug")
    raw_result, entities = get_alert_entity_list(CASE_ID, "1000001", 1000)
    assert raw_result is None
    assert entities is None
    assert debug_mock.called


def test_sync_case_information_raises_when_no_case_id(mocker):
    """sync_case_information should raise ValueError with full error message when case_id is missing."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    expected_msg = ERROR_MESSAGES["MISSING_ARGUMENT"].format("case_id")
    with pytest.raises(ValueError, match=expected_msg):
        sync_case_information({})


def test_sync_case_information_reads_case_id_from_incident(mocker, mock_case_raw_response):
    """When case_id arg absent, case ID read from incident custom field."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {"googlesecopscaseid": CASE_ID}})
    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation,
        "get_case_information",
        return_value=(_success_result(mock_case_raw_response), mock_case_raw_response.copy()),
    )
    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(_success_result({"caseAlerts": [], "totalSize": 0}), [])
    )
    mocker.patch.object(demisto, "mapObject", return_value={})

    results = sync_case_information({})
    assert results


def test_sync_case_information_success(mocker, mock_case_raw_response, mock_alert_data, mock_entity_data):
    """
    sync_case_information should return case result + alert result +
    entity results per alert + final CommandResults.
    """
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={"googlesecopsstatus": "OPEN"})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result(mock_alert_data)
    entity_ok = _success_result(mock_entity_data)

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, mock_alert_data["caseAlerts"]))
    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_entity_list", return_value=(entity_ok, mock_entity_data["involvedEntities"])
    )
    mocker.patch.object(demisto, "executeCommand", return_value=[_success_result({})])

    results = sync_case_information({"case_id": CASE_ID})
    assert len(results) == 5


def test_sync_case_information_calls_setincident(
    mocker, mock_case_raw_response, mock_alert_data, mock_entity_data, mock_set_incident_data
):
    """sync_case_information should call setIncident with full mapped case + alert + entity data."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value=mock_set_incident_data)

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result(mock_alert_data)
    entity_ok = _success_result(mock_entity_data)

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, mock_alert_data["caseAlerts"]))
    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_entity_list", return_value=(entity_ok, mock_entity_data["involvedEntities"])
    )
    exec_mock = mocker.patch.object(demisto, "executeCommand", return_value=[_success_result({})])

    sync_case_information({"case_id": CASE_ID})

    calls = [(c.args[0], c.args[1]) for c in exec_mock.call_args_list]
    set_incident_calls = [args for cmd, args in calls if cmd == "setIncident"]
    assert len(set_incident_calls) == 1
    assert set_incident_calls[0] == mock_set_incident_data


def test_sync_case_information_no_setincident_when_mapper_empty(mocker, mock_case_raw_response):
    """setIncident should NOT be called when mapper returns no data."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result({"caseAlerts": [], "totalSize": 0})

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, []))
    exec_mock = mocker.patch.object(demisto, "executeCommand")

    sync_case_information({"case_id": CASE_ID})

    if exec_mock.called:
        calls = [c.args[0] for c in exec_mock.call_args_list]
        assert "setIncident" not in calls


def test_sync_case_information_default_page_sizes(mocker, mock_case_raw_response):
    """Alert page_size should default to 1000."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result({"caseAlerts": [], "totalSize": 0})

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    get_alerts_mock = mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, []))

    sync_case_information({"case_id": CASE_ID})

    page_size_used = get_alerts_mock.call_args[0][1]
    assert page_size_used == 1000


@pytest.mark.parametrize("alert_page_size,entity_page_size", [("100", "200"), ("1", "1"), ("1000", "1000")])
def test_sync_case_information_custom_page_sizes(
    mocker, mock_case_raw_response, mock_alert_data, mock_entity_data, alert_page_size, entity_page_size
):
    """Custom page sizes, including the inclusive boundaries 1 and MAX_PAGE_SIZE, should be forwarded as-is."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result(mock_alert_data)
    entity_ok = _success_result(mock_entity_data)

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    get_alerts_mock = mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, mock_alert_data["caseAlerts"])
    )
    get_entities_mock = mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_entity_list", return_value=(entity_ok, mock_entity_data["involvedEntities"])
    )

    sync_case_information({"case_id": CASE_ID, "alert_page_size": alert_page_size, "entity_page_size": entity_page_size})

    assert get_alerts_mock.call_args[0][1] == int(alert_page_size)
    assert get_entities_mock.call_args[0][2] == int(entity_page_size)


@pytest.mark.parametrize(
    "args,expected_error_message",
    [
        (
            {},
            ERROR_MESSAGES["MISSING_ARGUMENT"].format("case_id"),
        ),
        (
            {"case_id": CASE_ID, "alert_page_size": "0"},
            ERROR_MESSAGES["INVALID_INT_RANGE"].format(0, "alert_page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"case_id": CASE_ID, "entity_page_size": "-1"},
            ERROR_MESSAGES["INVALID_INT_RANGE"].format(-1, "entity_page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"case_id": CASE_ID, "alert_page_size": "1001"},
            ERROR_MESSAGES["INVALID_INT_RANGE"].format(1001, "alert_page_size", 1, MAX_PAGE_SIZE),
        ),
        (
            {"case_id": CASE_ID, "entity_page_size": "5000"},
            ERROR_MESSAGES["INVALID_INT_RANGE"].format(5000, "entity_page_size", 1, MAX_PAGE_SIZE),
        ),
    ],
)
def test_sync_case_information_invalid_args(mocker, args, expected_error_message):
    """Test sync_case_information raises ValueError for invalid argument values."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})

    with pytest.raises(ValueError) as error:
        sync_case_information(args)

    assert str(error.value) == expected_error_message


def test_sync_case_information_raises_on_case_get_failure(mocker):
    """gcb-case-get failure should raise ValueError."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_case_information", side_effect=ValueError("gcb-case-get failed"))
    with pytest.raises(ValueError, match="gcb-case-get"):
        sync_case_information({"case_id": CASE_ID})


def test_sync_case_information_raises_on_alert_list_failure(mocker, mock_case_raw_response):
    """gcb-case-alert-list failure should raise ValueError."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})

    case_ok = _success_result(mock_case_raw_response)
    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", side_effect=ValueError("Failed to retrieve alerts"))

    with pytest.raises(ValueError, match="alerts"):
        sync_case_information({"case_id": CASE_ID})


def test_sync_case_information_skips_entity_on_failure(mocker, mock_case_raw_response, mock_alert_data):
    """Entity fetch failures should be skipped; no exception raised."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result(mock_alert_data)

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, mock_alert_data["caseAlerts"]))
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_entity_list", return_value=(None, None))

    results = sync_case_information({"case_id": CASE_ID})

    assert any(hasattr(r, "readable_output") for r in results)


def test_sync_case_information_skips_alert_with_no_id(mocker, mock_case_raw_response):
    """Alerts without alertId or name should be silently skipped."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result({"caseAlerts": [{"displayName": "No ID alert"}], "totalSize": 1})

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, [{"displayName": "No ID alert"}])
    )
    entities_mock = mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_entity_list")

    sync_case_information({"case_id": CASE_ID})

    entities_mock.assert_not_called()


def test_main_success(mocker):
    """main should call return_results with sync_case_information output."""
    mocker.patch.object(demisto, "args", return_value={"case_id": CASE_ID})
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "sync_case_information", return_value=[MagicMock()])
    mock_return_results = mocker.patch.object(GoogleSecOpsSyncCaseInformation, "return_results")
    GoogleSecOpsSyncCaseInformation.main()
    assert mock_return_results.called


def test_main_calls_return_error_on_exception(mocker):
    """main should call return_error when sync_case_information raises."""
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "sync_case_information", side_effect=Exception("boom"))
    mocker.patch.object(demisto, "error")
    mock_return_error = mocker.patch.object(GoogleSecOpsSyncCaseInformation, "return_error")
    GoogleSecOpsSyncCaseInformation.main()
    mock_return_error.assert_called_once()
    assert "boom" in mock_return_error.call_args[0][0]


def test_sync_case_information_breaks_loop_on_timeout(mocker, mock_case_raw_response, mock_alert_data, mock_entity_data):
    """When elapsed time exceeds ALERT_LOOP_TIMEOUT_SECONDS, loop breaks and remaining alerts are skipped."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result(mock_alert_data)
    entity_ok = _success_result(mock_entity_data)

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, mock_alert_data["caseAlerts"]))
    get_entities_mock = mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_entity_list", return_value=(entity_ok, mock_entity_data["involvedEntities"])
    )
    debug_mock = mocker.patch.object(demisto, "debug")

    # First call returns loop_start, second call returns past threshold — triggers break on first alert
    with patch("GoogleSecOpsSyncCaseInformation.time.time", side_effect=[0, ALERT_LOOP_TIMEOUT_SECONDS + 1]):
        sync_case_information({"case_id": CASE_ID})

    get_entities_mock.assert_not_called()
    debug_calls = [str(c) for c in debug_mock.call_args_list]
    assert any("9 minutes" in c for c in debug_calls)


def test_sync_case_information_no_timeout_when_fast(mocker, mock_case_raw_response, mock_alert_data, mock_entity_data):
    """When loop finishes within timeout, all alerts are processed normally."""
    mocker.patch.object(demisto, "incident", return_value={"CustomFields": {}})
    mocker.patch.object(demisto, "mapObject", return_value={})

    case_ok = _success_result(mock_case_raw_response)
    alert_ok = _success_result(mock_alert_data)
    entity_ok = _success_result(mock_entity_data)

    mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_case_information", return_value=(case_ok, mock_case_raw_response.copy())
    )
    mocker.patch.object(GoogleSecOpsSyncCaseInformation, "get_alert_list", return_value=(alert_ok, mock_alert_data["caseAlerts"]))
    get_entities_mock = mocker.patch.object(
        GoogleSecOpsSyncCaseInformation, "get_alert_entity_list", return_value=(entity_ok, mock_entity_data["involvedEntities"])
    )

    alert_count = len(mock_alert_data["caseAlerts"])
    # All time.time() calls return 0 — never exceeds threshold
    with patch("GoogleSecOpsSyncCaseInformation.time.time", return_value=0):
        sync_case_information({"case_id": CASE_ID})

    assert get_entities_mock.call_count == alert_count
