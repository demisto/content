from copy import deepcopy
import json

import demistomock as demisto

from GIBIncidentUpdateAllTypes import (
    MAX_INCIDENTS,
    PAGE_SIZE,
    build_update_fields,
    get_gibid,
    iter_existing_incidents,
    main,
)

# EntryType.ERROR of CommonServerPython.
ENTRY_TYPE_ERROR = 4

GIBID = "aaaaaaaabbbbccccddddeeeeeeeeeeeeeeeeee01"

INCOMING_INCIDENT = {
    "id": "302",
    "name": "Test GIB Incident",
    "type": "GIB Compromised Card Group",
    "status": 1,
    "labels": [
        {"type": "id", "value": GIBID},
        {"type": "Brand", "value": "Group-IB Threat Intelligence & Attribution"},
    ],
    "CustomFields": {
        "gibid": GIBID,
        "gibcredibility": 80,
        "gibseverity": "High",
        "gibportallink": f"https://example.com/cd/cards?id={GIBID}",
    },
}

GET_INCIDENTS_FOUND = [{"Type": 1, "Contents": {"total": 1, "data": [{"id": "100", "gibid": GIBID}]}}]
GET_INCIDENTS_EMPTY = [{"Type": 1, "Contents": {"total": 0, "data": []}}]
GET_INCIDENTS_MULTIPLE = [
    {
        "Type": 1,
        "Contents": {
            "total": 3,
            "data": [
                {"id": "100", "gibid": GIBID},
                {"id": "101", "gibid": GIBID},
                {"id": "102", "gibid": GIBID},
            ],
        },
    }
]


def test_the_gib_id_is_read_from_the_custom_fields():
    assert get_gibid({"CustomFields": {"gibid": GIBID}}) == GIBID


def test_the_gib_id_is_read_from_the_top_level_field():
    assert get_gibid({"gibid": GIBID}) == GIBID


def test_the_gib_id_is_read_from_the_id_label():
    assert get_gibid({"labels": [{"type": "id", "value": GIBID}]}) == GIBID


def test_the_gib_id_is_read_from_the_gibid_label():
    assert get_gibid({"labels": [{"type": "gibid", "value": GIBID}]}) == GIBID


def test_the_gib_id_is_read_from_the_raw_json():
    assert get_gibid({"rawJSON": json.dumps({"id": GIBID})}) == GIBID


def test_an_incident_without_a_gib_id_has_none():
    assert get_gibid({"name": "test"}) is None


def test_a_blank_gib_id_is_none():
    assert get_gibid({"CustomFields": {"gibid": "   "}}) is None


def _make_full_page(start: int = 0) -> list[dict]:
    return [{"id": str(i), "gibid": GIBID} for i in range(start, start + PAGE_SIZE)]


def _wrap_page(data: list[dict]) -> list[dict]:
    return [{"Type": 1, "Contents": {"data": data}}]


def test_the_first_page_is_asked_with_the_query_the_sort_and_the_page_size(mocker):
    execute_command_mock = mocker.patch.object(
        demisto, "executeCommand", return_value=_wrap_page([{"id": "100", "gibid": GIBID}])
    )
    list(iter_existing_incidents(GIBID))

    args = execute_command_mock.call_args.args
    assert args[0] == "getIncidents"
    assert args[1]["query"] == f'gibid:"{GIBID}" and -status:closed'
    assert args[1]["sort"] == "created.desc"
    assert args[1]["size"] == PAGE_SIZE
    assert args[1]["page"] == 0


def test_a_page_shorter_than_the_page_size_is_the_last(mocker):
    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_page([{"id": "100", "gibid": GIBID}]),
    )
    result = list(iter_existing_incidents(GIBID))
    assert result == [{"id": "100", "gibid": GIBID}]
    assert execute_command_mock.call_count == 1


def test_a_full_page_is_followed_by_the_next_page(mocker):
    pages = [
        _wrap_page(_make_full_page(start=0)),
        _wrap_page([{"id": "999", "gibid": GIBID}]),
    ]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)
    result = list(iter_existing_incidents(GIBID))

    assert execute_command_mock.call_count == 2
    assert len(result) == PAGE_SIZE + 1
    assert execute_command_mock.call_args_list[0].args[1]["page"] == 0
    assert execute_command_mock.call_args_list[1].args[1]["page"] == 1


def test_the_existing_incidents_stop_at_max_total(mocker):
    pages = [_wrap_page(_make_full_page(start=0))] * 10
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    result = list(iter_existing_incidents(GIBID, max_total=50))

    assert len(result) == 50
    assert execute_command_mock.call_count == 1


def test_max_total_reads_only_the_pages_it_needs(mocker):
    pages = [
        _wrap_page(_make_full_page(start=0)),
        _wrap_page(_make_full_page(start=PAGE_SIZE)),
        _wrap_page(_make_full_page(start=PAGE_SIZE * 2)),
    ]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    result = list(iter_existing_incidents(GIBID, max_total=PAGE_SIZE + 5))

    assert len(result) == PAGE_SIZE + 5
    assert execute_command_mock.call_count == 2


def test_a_page_is_read_when_its_first_incident_is_pulled(mocker):
    pages = [
        _wrap_page(_make_full_page(start=0)),
        _wrap_page(_make_full_page(start=PAGE_SIZE)),
    ]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    iterator = iter_existing_incidents(GIBID)

    assert execute_command_mock.call_count == 0

    next(iterator)
    assert execute_command_mock.call_count == 1

    for _ in range(PAGE_SIZE - 1):
        next(iterator)
    assert execute_command_mock.call_count == 1

    next(iterator)
    assert execute_command_mock.call_count == 2


def test_an_error_entry_from_get_incidents_ends_the_existing_incidents(mocker):
    error_response = [{"Type": ENTRY_TYPE_ERROR, "Contents": "getIncidents failed"}]
    mocker.patch.object(demisto, "executeCommand", return_value=error_response)
    assert list(iter_existing_incidents(GIBID)) == []


def test_an_empty_answer_from_get_incidents_lists_no_incident(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=GET_INCIDENTS_EMPTY)
    assert list(iter_existing_incidents(GIBID)) == []


def test_a_null_answer_from_get_incidents_lists_no_incident(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    assert list(iter_existing_incidents(GIBID)) == []


def test_a_max_total_or_page_size_of_zero_asks_nothing(mocker):
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")
    assert list(iter_existing_incidents(GIBID, max_total=0)) == []
    assert list(iter_existing_incidents(GIBID, page_size=0)) == []
    assert execute_command_mock.call_count == 0


def test_build_update_fields_flattens_custom_fields_and_leaves_the_target_attributes_alone():
    """Only the record's data travels: the flattened CustomFields, name, occurred and details; status, owner, severity,
    type, labels, rawJSON and id stay the target's."""
    incident = deepcopy(INCOMING_INCIDENT)
    incident["occurred"] = "2025-01-01T00:00:00Z"
    incident["details"] = "some details"
    incident["rawJSON"] = '{"id":"abc"}'
    incident["owner"] = "fetcher"
    incident["severity"] = 3

    update_fields = build_update_fields(incident)

    assert "id" not in update_fields
    assert "CustomFields" not in update_fields
    for forbidden in ("labels", "rawJSON", "type", "status", "owner", "severity"):
        assert forbidden not in update_fields

    assert update_fields["occurred"] == "2025-01-01T00:00:00Z"
    assert update_fields["details"] == "some details"
    assert update_fields["gibid"] == GIBID
    assert update_fields["gibcredibility"] == 80
    assert update_fields["gibseverity"] == "High"
    assert update_fields["name"] == "Test GIB Incident"


def test_a_quote_in_the_gib_id_is_escaped_in_the_query(mocker):
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", return_value=_wrap_page([]))
    list(iter_existing_incidents('a"b'))
    assert execute_command_mock.call_args.args[1]["query"] == 'gibid:"a\\"b" and -status:closed'


def test_a_refused_grid_field_is_left_out_of_the_retry(mocker):
    """When setIncident rejects a grid field value, the retry leaves that field out and the incoming incident is dropped."""
    incoming = deepcopy(INCOMING_INCIDENT)
    incoming["CustomFields"]["gibcybercriminalthreatactorreportstable"] = [{"datepublished": "2026-08-28", "name": "r"}]
    mocker.patch.object(demisto, "incident", return_value=incoming)
    calls = []

    def mock_execute_command(command, args):
        calls.append((command, args))
        if command == "getIncidents":
            return GET_INCIDENTS_FOUND
        if "gibcybercriminalthreatactorreportstable" in args:
            return [{"Type": ENTRY_TYPE_ERROR, "Contents": "Invalid grid column in row 0: '2026-08-28' is not a legal date"}]
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")
    main()
    mock_results.assert_called_once_with(False)
    set_calls = [a for c, a in calls if c == "setIncident"]
    assert len(set_calls) == 2
    assert "gibcybercriminalthreatactorreportstable" not in set_calls[1]
    assert set_calls[1]["gibseverity"] == "High"
    assert set_calls[1]["id"] == "100"


def test_the_incoming_incident_is_kept_when_every_update_fails(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_FOUND
        return [{"Type": ENTRY_TYPE_ERROR, "Contents": "setIncident failed"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")
    main()
    mock_results.assert_called_once_with(True)


def test_an_id_inside_the_custom_fields_is_dropped_too():
    incident = {
        "id": "incoming-1",
        "name": "x",
        "CustomFields": {"id": "leaked", "gibid": GIBID},
    }
    update_fields = build_update_fields(incident)
    assert "id" not in update_fields


def test_the_update_fields_drop_null_values():
    incident = {"name": "x", "details": None, "CustomFields": {"gibid": GIBID, "gibsource": None}}
    update_fields = build_update_fields(incident)
    assert update_fields == {"name": "x", "gibid": GIBID}


def test_the_update_fields_drop_empty_values():
    """A fetched incident arrives with details "": an empty value never erases the analyst's notes."""
    incident = {"name": "x", "details": "", "CustomFields": {"gibid": GIBID, "gibsource": "", "gibemails": [], "gibrecord": {}}}
    update_fields = build_update_fields(incident)
    assert "details" not in update_fields
    assert "gibsource" not in update_fields
    assert "gibemails" not in update_fields
    assert update_fields["gibid"] == GIBID
    assert update_fields == {"name": "x", "gibid": GIBID}


def test_an_incident_without_a_gib_id_is_kept(mocker):
    mocker.patch.object(demisto, "incident", return_value={"name": "test"})
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    mock_results.assert_called_once_with(True)


def test_an_incident_without_a_duplicate_is_kept(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))
    mocker.patch.object(demisto, "executeCommand", return_value=GET_INCIDENTS_EMPTY)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    mock_results.assert_called_once_with(True)


def test_a_duplicate_is_updated_and_the_incoming_incident_is_dropped(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_FOUND
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    mock_results.assert_called_once_with(False)

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    assert len(set_calls) == 1
    payload = set_calls[0].args[1]
    assert payload["id"] == "100"
    assert payload["gibid"] == GIBID
    assert payload["name"] == "Test GIB Incident"
    assert payload["gibseverity"] == "High"


def test_every_open_duplicate_is_updated(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_MULTIPLE
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    assert [c.args[1]["id"] for c in set_calls] == ["100", "101", "102"]


def test_the_update_targets_the_duplicate_not_the_incoming_incident(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_FOUND
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    set_call = next(c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident")
    assert set_call.args[1]["id"] == "100"


def test_the_incoming_incident_is_left_unchanged(mocker):
    incident = deepcopy(INCOMING_INCIDENT)
    original = deepcopy(incident)
    mocker.patch.object(demisto, "incident", return_value=incident)

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_FOUND
        return [{"Type": 1, "Contents": "ok"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    assert incident == original


def test_the_first_duplicate_is_updated_before_the_second_page_is_read(mocker):
    """The first setIncident call happens before the second getIncidents page is read: the fetch and the update phases are
    interleaved."""
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    page_zero = _wrap_page(_make_full_page(start=0))
    page_one = _wrap_page([{"id": str(PAGE_SIZE), "gibid": GIBID}])
    set_incident_ok = [{"Type": 1, "Contents": "ok"}]

    call_log: list[str] = []

    def mock_execute_command(command, args):
        if command == "getIncidents":
            page_index = args["page"]
            call_log.append(f"getIncidents:{page_index}")
            return page_zero if page_index == 0 else page_one
        if command == "setIncident":
            call_log.append(f"setIncident:{args['id']}")
            return set_incident_ok
        raise AssertionError(f"unexpected command: {command}")

    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    set_events = [e for e in call_log if e.startswith("setIncident:")]
    assert len(set_events) == PAGE_SIZE + 1

    # One page in memory at a time, not MAX_INCIDENTS incidents.
    first_set_idx = next(i for i, e in enumerate(call_log) if e.startswith("setIncident:"))
    second_get_idx = next(i for i, e in enumerate(call_log) if e == "getIncidents:1")
    assert first_set_idx < second_get_idx, f"call log: {call_log}"


def test_no_more_than_max_incidents_duplicates_are_updated(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    full_page = _wrap_page(_make_full_page(start=0))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return full_page  # endless supply
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    assert len(set_calls) <= MAX_INCIDENTS


def test_a_failed_update_does_not_stop_the_other_duplicates(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_MULTIPLE
        if args["id"] == "101":
            return [{"Type": ENTRY_TYPE_ERROR, "Contents": "setIncident failed"}]
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    assert [c.args[1]["id"] for c in set_calls] == ["100", "101", "102"]
    mock_results.assert_called_once_with(False)
