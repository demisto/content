import demistomock as demisto
import HealthCheckIncidentTypes
from HealthCheckIncidentTypes import filter_non_locked, main


INCIDENT_TYPES = [
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


def _mock_execute_command(mocker, response):
    """Patch execute_command (the CommonServerPython wrapper used by main())."""
    return mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        return_value={"response": response},
    )


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


def test_main_builds_table_xsoar6(mocker):
    """On XSOAR 6, table is built correctly from incident types."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        side_effect=[
            {"response": INCIDENT_TYPES},  # core-api-get
            {},  # setIncident
        ],
    )
    mocker.patch.object(HealthCheckIncidentTypes, "return_results")

    main()

    # Verify core-api-get URI (no account prefix, no leading slash)
    core_call = HealthCheckIncidentTypes.execute_command.call_args_list[0]
    assert core_call[0][0] == "core-api-get"
    assert core_call[0][1]["uri"] == "incidenttype"

    # Verify setIncident table
    set_call = HealthCheckIncidentTypes.execute_command.call_args_list[1]
    table = set_call[0][1]["healthcheckautoextractionbasedincidenttype"]
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


def test_main_uses_account_prefix_xsoar6(mocker):
    """On XSOAR 6 with an account, the URI is prefixed with acc_<account>."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": "test"}])
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        side_effect=[
            {"response": []},
            {},
        ],
    )
    mocker.patch.object(HealthCheckIncidentTypes, "return_results")

    main()

    core_call = HealthCheckIncidentTypes.execute_command.call_args_list[0]
    assert core_call[0][1]["uri"] == "acc_test/incidenttype"


def test_main_uses_xsoar8_uri(mocker):
    """On XSOAR 8, the URI uses the xsoar/public/v1/ prefix."""
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", return_value=True)
    mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        side_effect=[
            {"response": []},
            {},
        ],
    )
    mocker.patch.object(HealthCheckIncidentTypes, "return_results")

    main()

    core_call = HealthCheckIncidentTypes.execute_command.call_args_list[0]
    assert core_call[0][1]["uri"] == "xsoar/public/v1/incidenttype"


def test_main_list_response(mocker):
    """When execute_command returns a list (multi-tenant), first entry is used."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        side_effect=[
            [{"response": INCIDENT_TYPES}, {"response": []}],  # list response
            {},
        ],
    )
    mocker.patch.object(HealthCheckIncidentTypes, "return_results")

    main()

    set_call = HealthCheckIncidentTypes.execute_command.call_args_list[1]
    table = set_call[0][1]["healthcheckautoextractionbasedincidenttype"]
    assert len(table) == 2


def test_main_handles_missing_extract_settings(mocker):
    """Types without extractSettings (or its sub-keys) must not raise."""
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
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        side_effect=[
            {"response": incident_types},
            {},
        ],
    )
    mocker.patch.object(HealthCheckIncidentTypes, "return_results")

    main()

    set_call = HealthCheckIncidentTypes.execute_command.call_args_list[1]
    assert set_call[0][1]["healthcheckautoextractionbasedincidenttype"] == []


def test_main_none_response(mocker):
    """When execute_command returns None, no error is raised."""
    mocker.patch.object(demisto, "incidents", return_value=[{"account": ""}])
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", return_value=False)
    mocker.patch.object(
        HealthCheckIncidentTypes,
        "execute_command",
        side_effect=[
            None,
            {},
        ],
    )
    mocker.patch.object(HealthCheckIncidentTypes, "return_results")

    main()

    set_call = HealthCheckIncidentTypes.execute_command.call_args_list[1]
    assert set_call[0][1]["healthcheckautoextractionbasedincidenttype"] == []


def test_main_exception_calls_return_error(mocker):
    """When an exception occurs, return_error is called."""
    mocker.patch.object(HealthCheckIncidentTypes, "is_demisto_version_ge", side_effect=Exception("boom"))
    mock_error = mocker.patch.object(HealthCheckIncidentTypes, "return_error")

    main()

    mock_error.assert_called_once()
    assert "boom" in mock_error.call_args[0][0]
