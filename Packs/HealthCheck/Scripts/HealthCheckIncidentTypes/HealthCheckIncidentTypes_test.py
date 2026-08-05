import demistomock as demisto
import HealthCheckIncidentTypes
from HealthCheckIncidentTypes import filter_non_locked, main


def _wrap_core_api_response(response, extra_entries=0):
    """Build a raw ``demisto.executeCommand`` result for ``core-api-get``.

    Returns the raw list of war-room entries. The real ``execute_command``
    (with the default ``extract_contents=True``) then collapses a single entry
    to a dict and keeps multiple entries as a list, so the test exercises the
    exact behaviour that produced the ``KeyError: 0`` regression (XSUP-74019).

    ``extra_entries`` simulates the server returning additional entries
    alongside the response (which keeps the collapsed result a list).
    """
    entries = [{"Type": 1, "Contents": {"response": response}}]
    for _ in range(extra_entries):
        entries.append({"Type": 1, "Contents": {"response": []}})
    return entries


def test_filter_non_locked_keeps_unlocked_and_detached():
    """Only unlocked or detached types are returned; missing keys are tolerated."""
    types = [
        {"prevName": "Unlocked", "locked": False, "detached": False},
        {"prevName": "LockedButDetached", "locked": True, "detached": True},
        {"prevName": "LockedSystem", "locked": True, "detached": False},
        {"prevName": "MissingKeys"},  # must not raise
    ]

    result = filter_non_locked(types)

    names = [t["prevName"] for t in result]
    assert names == ["Unlocked", "LockedButDetached"]


def test_main_builds_table_from_single_entry_response(mocker):
    """Regression test for XSUP-74019.

    A single-entry response from `core-api-get` is a dict, not a list. The
    previous implementation used `[0]["response"]` which raised `KeyError: 0`.
    """
    incident_types = [
        {
            "prevName": "AllExtraction",
            "locked": False,
            "detached": False,
            "extractSettings": {"mode": "All"},
        },
        {
            "prevName": "SpecificWithFields",
            "locked": False,
            "detached": False,
            "extractSettings": {
                "mode": "Specific",
                "fieldCliNameToExtractSettings": {"somefield": {}},
            },
        },
        {
            "prevName": "SpecificWithoutFields",
            "locked": False,
            "detached": False,
            "extractSettings": {
                "mode": "Specific",
                "fieldCliNameToExtractSettings": {},
            },
        },
        {
            "prevName": "LockedType",
            "locked": True,
            "detached": False,
            "extractSettings": {"mode": "All"},
        },
    ]

    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            _wrap_core_api_response(incident_types),  # core-api-get
            [{"Type": 1, "Contents": "done"}],  # setIncident
        ],
    )

    main()

    # Verify core-api-get was called with the expected uri.
    core_call = execute_mock.call_args_list[0]
    assert core_call.args[0] == "core-api-get"
    assert core_call.args[1] == {"uri": "/incidenttype"}

    # Verify the resulting table set on the incident.
    set_call = execute_mock.call_args_list[1]
    assert set_call.args[0] == "setIncident"
    table = set_call.args[1]["healthcheckautoextractionbasedincidenttype"]
    assert table == [
        {
            "incidenttype": "AllExtraction",
            "detection": "Indicators extraction defined on all fields",
        },
        {
            "incidenttype": "SpecificWithFields",
            "detection": "No indicators extraction defined on all fields",
        },
    ]


def test_main_handles_missing_extract_settings(mocker):
    """Types without `extractSettings` (or its sub-keys) must not raise."""
    incident_types = [
        {"prevName": "NoExtractSettings", "locked": False, "detached": False},
        {
            "prevName": "EmptyExtractSettings",
            "locked": False,
            "detached": False,
            "extractSettings": {},
        },
    ]

    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            _wrap_core_api_response(incident_types),
            [{"Type": 1, "Contents": "done"}],
        ],
    )

    main()

    set_call = execute_mock.call_args_list[1]
    assert set_call.args[1]["healthcheckautoextractionbasedincidenttype"] == []


def test_main_uses_account_prefix(mocker):
    """When the incident belongs to an account, the uri is prefixed."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": "test"}])
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            _wrap_core_api_response([]),
            [{"Type": 1, "Contents": "done"}],
        ],
    )

    main()

    assert execute_mock.call_args_list[0].args[1] == {"uri": "acc_test/incidenttype"}


def test_main_handles_multiple_returned_entries(mocker):
    """The response is read correctly when the result is a list.

    When multiple entries are returned, `execute_command` keeps the result as
    a list. The script must then read the payload from the first element
    (`result[0]["response"]`) rather than treating it as a dict.
    """
    incident_types = [
        {
            "prevName": "AllExtraction",
            "locked": False,
            "detached": False,
            "extractSettings": {"mode": "All"},
        },
    ]

    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    execute_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        side_effect=[
            _wrap_core_api_response(incident_types, extra_entries=2),
            [{"Type": 1, "Contents": "done"}],
        ],
    )

    main()

    set_call = execute_mock.call_args_list[1]
    table = set_call.args[1]["healthcheckautoextractionbasedincidenttype"]
    assert table == [
        {
            "incidenttype": "AllExtraction",
            "detection": "Indicators extraction defined on all fields",
        },
    ]
