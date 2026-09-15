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

# EntryType.ERROR is 4 in CommonServerPython; use the literal here so tests
# stay independent of XSOAR runtime imports.
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


# ---------------------------------------------------------------------------
# get_gibid
# ---------------------------------------------------------------------------


def test_gibid_from_custom_fields():
    assert get_gibid({"CustomFields": {"gibid": GIBID}}) == GIBID


def test_gibid_from_top_level():
    assert get_gibid({"gibid": GIBID}) == GIBID


def test_gibid_from_label_id():
    assert get_gibid({"labels": [{"type": "id", "value": GIBID}]}) == GIBID


def test_gibid_from_label_gibid():
    assert get_gibid({"labels": [{"type": "gibid", "value": GIBID}]}) == GIBID


def test_gibid_from_raw_json():
    assert get_gibid({"rawJSON": json.dumps({"id": GIBID})}) == GIBID


def test_gibid_missing():
    assert get_gibid({"name": "test"}) is None


def test_gibid_whitespace_only_is_missing():
    assert get_gibid({"CustomFields": {"gibid": "   "}}) is None


# ---------------------------------------------------------------------------
# iter_existing_incidents - streaming behavior
# ---------------------------------------------------------------------------


def _make_full_page(start: int = 0) -> list[dict]:
    return [{"id": str(i), "gibid": GIBID} for i in range(start, start + PAGE_SIZE)]


def _wrap_page(data: list[dict]) -> list[dict]:
    return [{"Type": 1, "Contents": {"data": data}}]


def test_iter_existing_query_shape(mocker):
    """First page request must carry the canonical query, sort and pagination."""
    execute_command_mock = mocker.patch.object(
        demisto, "executeCommand", return_value=_wrap_page([{"id": "100", "gibid": GIBID}])
    )
    list(iter_existing_incidents(GIBID))

    args = execute_command_mock.call_args.args
    assert args[0] == "getIncidents"
    assert args[1]["query"] == f"gibid: {GIBID} and -status:Closed"
    assert args[1]["sort"] == "created.desc"
    assert args[1]["size"] == PAGE_SIZE
    assert args[1]["page"] == 0


def test_iter_existing_stops_on_partial_page(mocker):
    """A page shorter than PAGE_SIZE means there are no further pages."""
    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_page([{"id": "100", "gibid": GIBID}]),
    )
    result = list(iter_existing_incidents(GIBID))
    assert result == [{"id": "100", "gibid": GIBID}]
    assert execute_command_mock.call_count == 1


def test_iter_existing_fetches_subsequent_pages_when_full(mocker):
    """A full PAGE_SIZE page must trigger a follow-up page request."""
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


def test_iter_existing_respects_max_total_cap(mocker):
    """Iterator stops after `max_total` even if more data is available."""
    pages = [_wrap_page(_make_full_page(start=0))] * 10
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    result = list(iter_existing_incidents(GIBID, max_total=50))

    assert len(result) == 50
    # 50 < PAGE_SIZE so a single API call is sufficient.
    assert execute_command_mock.call_count == 1


def test_iter_existing_max_total_across_multiple_pages(mocker):
    """`max_total` may straddle page boundaries; only the needed pages fetched."""
    pages = [
        _wrap_page(_make_full_page(start=0)),
        _wrap_page(_make_full_page(start=PAGE_SIZE)),
        _wrap_page(_make_full_page(start=PAGE_SIZE * 2)),
    ]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    result = list(iter_existing_incidents(GIBID, max_total=PAGE_SIZE + 5))

    assert len(result) == PAGE_SIZE + 5
    # Two pages are required: full first page + 5 from the second page.
    assert execute_command_mock.call_count == 2


def test_iter_existing_streams_lazily(mocker):
    """Generator must not eagerly load every page on construction."""
    pages = [
        _wrap_page(_make_full_page(start=0)),
        _wrap_page(_make_full_page(start=PAGE_SIZE)),
    ]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    iterator = iter_existing_incidents(GIBID)

    # Constructing the generator must NOT trigger any API call.
    assert execute_command_mock.call_count == 0

    # Pulling the first item triggers exactly one API call.
    next(iterator)
    assert execute_command_mock.call_count == 1

    # Draining page 0 still costs one API call.
    for _ in range(PAGE_SIZE - 1):
        next(iterator)
    assert execute_command_mock.call_count == 1

    # Item PAGE_SIZE+1 forces the second page fetch.
    next(iterator)
    assert execute_command_mock.call_count == 2


def test_iter_existing_handles_error_response_gracefully(mocker):
    """An XSOAR error response must terminate iteration without raising."""
    error_response = [{"Type": ENTRY_TYPE_ERROR, "Contents": "boom"}]
    mocker.patch.object(demisto, "executeCommand", return_value=error_response)
    assert list(iter_existing_incidents(GIBID)) == []


def test_iter_existing_handles_empty_response(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=GET_INCIDENTS_EMPTY)
    assert list(iter_existing_incidents(GIBID)) == []


def test_iter_existing_handles_none_response(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    assert list(iter_existing_incidents(GIBID)) == []


def test_iter_existing_invalid_max_total_returns_nothing(mocker):
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")
    assert list(iter_existing_incidents(GIBID, max_total=0)) == []
    assert list(iter_existing_incidents(GIBID, page_size=0)) == []
    assert execute_command_mock.call_count == 0


# ---------------------------------------------------------------------------
# build_update_fields
# ---------------------------------------------------------------------------


def test_build_update_fields_flattens_custom_fields_and_propagates_all_other_fields():
    """All incoming fields propagate; only `id` and the `CustomFields` container itself are stripped.

    `id` is excluded because it is the target identifier for `setIncident`
    (passing it would silently redirect the update to the incoming incident).
    `CustomFields` is excluded as a *container* because its members are
    flattened into top-level kwargs.
    """
    incident = deepcopy(INCOMING_INCIDENT)
    incident["occurred"] = "2025-01-01T00:00:00Z"
    incident["rawJSON"] = '{"id":"abc"}'

    update_fields = build_update_fields(incident)

    # Hard guards: protect `setIncident` call correctness.
    assert "id" not in update_fields
    assert "CustomFields" not in update_fields

    # All previously-skipped XSOAR fields now propagate as-is.
    assert update_fields["labels"] == incident["labels"]
    assert update_fields["occurred"] == "2025-01-01T00:00:00Z"
    assert update_fields["rawJSON"] == '{"id":"abc"}'
    assert update_fields["type"] == "GIB Compromised Card Group"
    assert update_fields["status"] == 1

    # CustomFields are flattened into top-level keys.
    assert update_fields["gibid"] == GIBID
    assert update_fields["gibcredibility"] == 80
    assert update_fields["gibseverity"] == "High"
    assert update_fields["name"] == "Test GIB Incident"


def test_build_update_fields_strips_id_from_custom_fields_too():
    """If `id` ever leaks into CustomFields, it must still be filtered out."""
    incident = {
        "id": "incoming-1",
        "name": "x",
        "CustomFields": {"id": "leaked", "gibid": GIBID},
    }
    update_fields = build_update_fields(incident)
    assert "id" not in update_fields


def test_build_update_fields_drops_none_values():
    incident = {"name": "x", "details": None, "CustomFields": {"gibid": GIBID, "gibsource": None}}
    update_fields = build_update_fields(incident)
    assert "details" not in update_fields
    assert "gibsource" not in update_fields
    assert update_fields == {"name": "x", "gibid": GIBID}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_no_gibid_returns_true(mocker):
    mocker.patch.object(demisto, "incident", return_value={"name": "test"})
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    mock_results.assert_called_once_with(True)


def test_main_no_duplicate_returns_true(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))
    mocker.patch.object(demisto, "executeCommand", return_value=GET_INCIDENTS_EMPTY)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    mock_results.assert_called_once_with(True)


def test_main_duplicate_found_calls_setincident_and_returns_false(mocker):
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


def test_main_updates_all_open_duplicates(mocker):
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


def test_main_uses_existing_id_not_incoming(mocker):
    """The setIncident call must target the duplicate's id, not the incoming one."""
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


def test_main_does_not_mutate_incident(mocker):
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


def test_main_streams_pages_without_loading_all_into_memory(mocker):
    """Drives `main` against PAGE_SIZE+1 duplicates and verifies that the fetch
    and the update phases are interleaved (page-streamed), i.e. the very first
    setIncident call happens before the second getIncidents page is fetched.
    """
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

    # Streaming guarantee: the first setIncident call must happen BEFORE
    # the second getIncidents page is fetched. This is the property that
    # keeps memory usage at O(PAGE_SIZE) instead of O(MAX_INCIDENTS).
    first_set_idx = next(i for i, e in enumerate(call_log) if e.startswith("setIncident:"))
    second_get_idx = next(i for i, e in enumerate(call_log) if e == "getIncidents:1")
    assert first_set_idx < second_get_idx, (
        "setIncident calls must be interleaved with getIncidents pages "
        "so that memory usage stays bounded by PAGE_SIZE; observed call "
        f"log: {call_log}"
    )


def test_main_max_incidents_circuit_breaker_is_strict(mocker):
    """`main` must never call setIncident more than MAX_INCIDENTS times."""
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


def test_main_setincident_failure_does_not_abort_remaining_updates(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_MULTIPLE
        if args["id"] == "101":
            return [{"Type": ENTRY_TYPE_ERROR, "Contents": "boom"}]
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBIncidentUpdateAllTypes.return_results")

    main()

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    # All three duplicates were attempted, even though the middle one failed.
    assert [c.args[1]["id"] for c in set_calls] == ["100", "101", "102"]
    # The incoming incident is still dropped because real duplicates exist.
    mock_results.assert_called_once_with(False)
