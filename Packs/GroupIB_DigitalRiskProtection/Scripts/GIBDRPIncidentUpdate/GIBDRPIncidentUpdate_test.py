from copy import deepcopy
import json

import pytest

import demistomock as demisto

from GIBDRPIncidentUpdate import (
    MAX_INCIDENTS,
    PAGE_SIZE,
    build_update_fields,
    get_gibdrpid,
    get_violation_status,
    iter_existing_incidents,
    main,
)

# EntryType.ERROR is 4 in CommonServerPython; use the literal here so
# tests stay independent of XSOAR runtime imports.
ENTRY_TYPE_ERROR = 4

GIBDRPID = "85ccfa4a5a13f54f3fa6070d9e22c08ba9ebd3fb9a9208159b603198d08fbe14"

INCOMING_INCIDENT = {
    "id": "302",
    "name": "Test GIB DRP Violation",
    "type": "GIB DRP Violation",
    "status": 1,
    "labels": [
        {"type": "id", "value": GIBDRPID},
        {"type": "Brand", "value": "Group-IB Digital Risk Protection"},
    ],
    "CustomFields": {
        "gibdrpid": GIBDRPID,
        "gibdrptitle": "Phishing site impersonating Acme",
        "gibdrpstatus": "detected",
        "gibdrpsource": "WEB",
    },
}

GET_INCIDENTS_FOUND = [{"Type": 1, "Contents": {"total": 1, "data": [{"id": "100", "gibdrpid": GIBDRPID}]}}]
GET_INCIDENTS_EMPTY = [{"Type": 1, "Contents": {"total": 0, "data": []}}]
GET_INCIDENTS_MULTIPLE = [
    {
        "Type": 1,
        "Contents": {
            "total": 3,
            "data": [
                {"id": "100", "gibdrpid": GIBDRPID},
                {"id": "101", "gibdrpid": GIBDRPID},
                {"id": "102", "gibdrpid": GIBDRPID},
            ],
        },
    }
]


# ---------------------------------------------------------------------------
# get_gibdrpid
# ---------------------------------------------------------------------------


def test_gibdrpid_from_custom_fields():
    assert get_gibdrpid({"CustomFields": {"gibdrpid": GIBDRPID}}) == GIBDRPID


def test_gibdrpid_from_top_level():
    assert get_gibdrpid({"gibdrpid": GIBDRPID}) == GIBDRPID


def test_gibdrpid_from_label_id():
    assert get_gibdrpid({"labels": [{"type": "id", "value": GIBDRPID}]}) == GIBDRPID


def test_gibdrpid_from_label_gibdrpid():
    assert get_gibdrpid({"labels": [{"type": "gibdrpid", "value": GIBDRPID}]}) == GIBDRPID


def test_gibdrpid_from_raw_json_id():
    assert get_gibdrpid({"rawJSON": json.dumps({"id": GIBDRPID})}) == GIBDRPID


def test_gibdrpid_from_raw_json_violation_id():
    assert get_gibdrpid({"rawJSON": json.dumps({"violation": {"id": GIBDRPID}})}) == GIBDRPID


def test_gibdrpid_from_dbot_mirror_id():
    assert get_gibdrpid({"dbotMirrorId": GIBDRPID}) == GIBDRPID


def test_gibdrpid_priority_custom_fields_over_dbot_mirror():
    """When both CustomFields.gibdrpid and dbotMirrorId are set, prefer the field."""
    other = "other_value"
    assert get_gibdrpid({"CustomFields": {"gibdrpid": GIBDRPID}, "dbotMirrorId": other}) == GIBDRPID


def test_gibdrpid_missing():
    assert get_gibdrpid({"name": "test"}) is None


def test_gibdrpid_whitespace_only_is_missing():
    assert get_gibdrpid({"CustomFields": {"gibdrpid": "   "}}) is None


def test_gibdrpid_malformed_raw_json_is_ignored():
    assert get_gibdrpid({"rawJSON": "{not-valid-json"}) is None


# ---------------------------------------------------------------------------
# iter_existing_incidents - streaming behavior
# ---------------------------------------------------------------------------


def _make_full_page(start: int = 0) -> list[dict]:
    return [{"id": str(i), "gibdrpid": GIBDRPID} for i in range(start, start + PAGE_SIZE)]


def _wrap_page(data: list[dict]) -> list[dict]:
    return [{"Type": 1, "Contents": {"data": data}}]


def test_iter_existing_query_shape(mocker):
    """First page request must carry the canonical query, sort and pagination.

    The query is deliberately not restricted to open incidents: a violation whose
    incident was already closed has to update that incident, not spawn a new one.
    """
    execute_command_mock = mocker.patch.object(
        demisto, "executeCommand", return_value=_wrap_page([{"id": "100", "gibdrpid": GIBDRPID}])
    )
    list(iter_existing_incidents(GIBDRPID))

    args = execute_command_mock.call_args.args
    assert args[0] == "getIncidents"
    assert args[1]["query"] == f'gibdrpid:"{GIBDRPID}"'
    assert "status" not in args[1]["query"]
    assert args[1]["sort"] == "created.desc"
    assert args[1]["size"] == PAGE_SIZE
    assert args[1]["page"] == 0


def test_iter_existing_query_escapes_special_characters(mocker):
    """Special Lucene characters in gibdrpid must be escaped, not interpreted."""
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", return_value=_wrap_page([]))
    raw_id = 'evil"injected:gibdrpid'
    list(iter_existing_incidents(raw_id))
    query = execute_command_mock.call_args.args[1]["query"]
    # Quote characters within the gibdrpid value must be escaped.
    assert 'gibdrpid:"evil\\"injected:gibdrpid"' in query


def test_iter_existing_stops_on_partial_page(mocker):
    """A page shorter than PAGE_SIZE means there are no further pages."""
    execute_command_mock = mocker.patch.object(
        demisto,
        "executeCommand",
        return_value=_wrap_page([{"id": "100", "gibdrpid": GIBDRPID}]),
    )
    result = list(iter_existing_incidents(GIBDRPID))
    assert result == [{"id": "100", "gibdrpid": GIBDRPID}]
    assert execute_command_mock.call_count == 1


def test_iter_existing_fetches_subsequent_pages_when_full(mocker):
    """A full PAGE_SIZE page must trigger a follow-up page request."""
    pages = [
        _wrap_page(_make_full_page(start=0)),
        _wrap_page([{"id": "999", "gibdrpid": GIBDRPID}]),
    ]
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)
    result = list(iter_existing_incidents(GIBDRPID))

    assert execute_command_mock.call_count == 2
    assert len(result) == PAGE_SIZE + 1
    assert execute_command_mock.call_args_list[0].args[1]["page"] == 0
    assert execute_command_mock.call_args_list[1].args[1]["page"] == 1


def test_iter_existing_respects_max_total_cap(mocker):
    """Iterator stops after `max_total` even if more data is available."""
    pages = [_wrap_page(_make_full_page(start=0))] * 10
    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=pages)

    result = list(iter_existing_incidents(GIBDRPID, max_total=50))

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

    result = list(iter_existing_incidents(GIBDRPID, max_total=PAGE_SIZE + 5))

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

    iterator = iter_existing_incidents(GIBDRPID)

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
    assert list(iter_existing_incidents(GIBDRPID)) == []


def test_iter_existing_handles_empty_response(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=GET_INCIDENTS_EMPTY)
    assert list(iter_existing_incidents(GIBDRPID)) == []


def test_iter_existing_handles_none_response(mocker):
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    assert list(iter_existing_incidents(GIBDRPID)) == []


def test_iter_existing_invalid_max_total_returns_nothing(mocker):
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")
    assert list(iter_existing_incidents(GIBDRPID, max_total=0)) == []
    assert list(iter_existing_incidents(GIBDRPID, page_size=0)) == []
    assert execute_command_mock.call_count == 0


# ---------------------------------------------------------------------------
# build_update_fields
# ---------------------------------------------------------------------------


def test_build_update_fields_carries_the_violation_and_nothing_else():
    """The payload is the violation's own data plus a short allow-list of built-ins.

    Everything outside that allow-list is either XSOAR bookkeeping belonging to the
    target incident or an argument `setIncident` does not accept - and an argument it
    does not accept fails the call for every duplicate, which is how the incoming
    incident used to survive as a duplicate.
    """
    incident = deepcopy(INCOMING_INCIDENT)
    incident["occurred"] = "2025-01-01T00:00:00Z"
    incident["severity"] = 3
    incident["rawJSON"] = '{"id":"abc"}'
    incident["dbotMirrorId"] = GIBDRPID
    incident["sourceBrand"] = "Group-IB Digital Risk Protection"

    update_fields = build_update_fields(incident)

    # Hard guards: protect `setIncident` call correctness.
    assert "id" not in update_fields
    assert "CustomFields" not in update_fields

    # Built-ins worth carrying over.
    assert update_fields["name"] == "Test GIB DRP Violation"
    assert update_fields["occurred"] == "2025-01-01T00:00:00Z"

    # Severity belongs to the instance that created the incident (one instance per
    # severity grades violations) and to the analyst; an update through another
    # instance must not overwrite it.
    assert "severity" not in update_fields

    # Bookkeeping and non-arguments stay behind. `status` in particular would
    # reopen a closed duplicate.
    for key in ("status", "labels", "rawJSON", "type", "dbotMirrorId", "sourceBrand"):
        assert key not in update_fields

    # CustomFields are flattened into top-level keys.
    assert update_fields["gibdrpid"] == GIBDRPID
    assert update_fields["gibdrpstatus"] == "detected"
    assert update_fields["gibdrpsource"] == "WEB"


def test_build_update_fields_strips_id_from_custom_fields_too():
    """If `id` ever leaks into CustomFields, it must still be filtered out."""
    incident = {
        "id": "incoming-1",
        "name": "x",
        "CustomFields": {"id": "leaked", "gibdrpid": GIBDRPID},
    }
    update_fields = build_update_fields(incident)
    assert "id" not in update_fields


def test_build_update_fields_drops_none_values():
    incident = {"name": "x", "details": None, "CustomFields": {"gibdrpid": GIBDRPID, "gibdrpsource": None}}
    update_fields = build_update_fields(incident)
    assert "details" not in update_fields
    assert "gibdrpsource" not in update_fields
    assert update_fields == {"name": "x", "gibdrpid": GIBDRPID}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_no_gibdrpid_returns_true(mocker):
    mocker.patch.object(demisto, "incident", return_value={"name": "test"})
    mock_results = mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    mock_results.assert_called_once_with(True)


def test_main_no_duplicate_returns_true(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))
    mocker.patch.object(demisto, "executeCommand", return_value=GET_INCIDENTS_EMPTY)
    mock_results = mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    mock_results.assert_called_once_with(True)


def test_main_duplicate_found_calls_setincident_and_returns_false(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_FOUND
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    mock_results.assert_called_once_with(False)

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    assert len(set_calls) == 1
    payload = set_calls[0].args[1]
    assert payload["id"] == "100"
    assert payload["gibdrpid"] == GIBDRPID
    assert payload["name"] == "Test GIB DRP Violation"
    assert payload["gibdrpstatus"] == "detected"


def test_main_updates_all_open_duplicates(mocker):
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_MULTIPLE
        return [{"Type": 1, "Contents": "ok"}]

    execute_command_mock = mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mocker.patch("GIBDRPIncidentUpdate.return_results")

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
    mocker.patch("GIBDRPIncidentUpdate.return_results")

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
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert incident == original


def test_main_streams_pages_without_loading_all_into_memory(mocker):
    """Drives `main` against PAGE_SIZE+1 duplicates and verifies that the fetch
    and the update phases are interleaved (page-streamed), i.e. the very first
    setIncident call happens before the second getIncidents page is fetched.
    """
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    page_zero = _wrap_page(_make_full_page(start=0))
    page_one = _wrap_page([{"id": str(PAGE_SIZE), "gibdrpid": GIBDRPID}])
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
    mocker.patch("GIBDRPIncidentUpdate.return_results")

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
    mocker.patch("GIBDRPIncidentUpdate.return_results")

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
    mock_results = mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    set_calls = [c for c in execute_command_mock.call_args_list if c.args[0] == "setIncident"]
    # All three duplicates were attempted, even though the middle one failed.
    assert [c.args[1]["id"] for c in set_calls] == ["100", "101", "102"]
    # The incoming incident is still dropped because real duplicates exist.
    mock_results.assert_called_once_with(False)


def test_main_all_setincident_failures_keeps_incoming_incident(mocker):
    """If every duplicate update fails, the incoming incident must be created
    so the new violation state is not silently lost."""
    mocker.patch.object(demisto, "incident", return_value=deepcopy(INCOMING_INCIDENT))

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return GET_INCIDENTS_MULTIPLE
        return [{"Type": ENTRY_TYPE_ERROR, "Contents": "boom"}]

    mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)
    mock_results = mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    mock_results.assert_called_once_with(True)


# ---------------------------------------------------------------------------
# get_violation_status
# ---------------------------------------------------------------------------


def test_violation_status_from_custom_fields():
    assert get_violation_status({"CustomFields": {"gibdrpstatus": "Solved"}}) == "solved"


def test_violation_status_from_top_level():
    assert get_violation_status({"gibdrpstatus": "legal"}) == "legal"


def test_violation_status_from_raw_json():
    assert get_violation_status({"rawJSON": json.dumps({"violation_status": "detected"})}) == "detected"


def test_violation_status_from_nested_raw_json():
    assert get_violation_status({"rawJSON": json.dumps({"violation": {"status": "solved"}})}) == "solved"


def test_violation_status_missing():
    assert get_violation_status({}) is None
    assert get_violation_status({"rawJSON": "not json"}) is None


# ---------------------------------------------------------------------------
# Automatic closing once DRP resolves the violation
# ---------------------------------------------------------------------------


def _resolved_incident(status: str = "solved") -> dict:
    incident = deepcopy(INCOMING_INCIDENT)
    incident["CustomFields"]["gibdrpstatus"] = status
    return incident


def _duplicates(*incidents: dict) -> list[dict]:
    return [{"Type": 1, "Contents": {"total": len(incidents), "data": list(incidents)}}]


def _record_commands(mocker, incident: dict, get_incidents_response: list[dict]):
    mocker.patch.object(demisto, "incident", return_value=incident)

    def mock_execute_command(command, args):
        if command == "getIncidents":
            return get_incidents_response
        return [{"Type": 1, "Contents": "ok"}]

    return mocker.patch.object(demisto, "executeCommand", side_effect=mock_execute_command)


def _calls(execute_command_mock, command: str) -> list[dict]:
    return [c.args[1] for c in execute_command_mock.call_args_list if c.args[0] == command]


@pytest.mark.parametrize("status", ["resolved", "solved", "legal"])
def test_main_closes_duplicate_when_drp_resolved_the_violation(mocker, status):
    execute_command_mock = _record_commands(
        mocker,
        _resolved_incident(status),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    close_calls = _calls(execute_command_mock, "closeInvestigation")
    assert len(close_calls) == 1
    assert close_calls[0]["id"] == "100"
    assert close_calls[0]["closeReason"] == "Resolved"
    # The id must not be repeated in the note: XSOAR would auto-extract it as a File indicator.
    assert GIBDRPID not in close_calls[0]["closeNotes"]
    assert status in close_calls[0]["closeNotes"]


@pytest.mark.parametrize("status", ["detected", "found", "on_tracking", "active", "in_response"])
def test_main_does_not_close_for_unresolved_statuses(mocker, status):
    """Approving or rejecting moves the violation out of `detected` but never resolves it,
    so no status other than resolved/solved/legal may close the incident."""
    execute_command_mock = _record_commands(
        mocker,
        _resolved_incident(status),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert _calls(execute_command_mock, "closeInvestigation") == []


def test_main_does_not_reclose_an_already_closed_duplicate(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _resolved_incident(),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 2}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert _calls(execute_command_mock, "closeInvestigation") == []


def test_main_closes_every_open_duplicate(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _resolved_incident(),
        _duplicates(
            {"id": "100", "gibdrpid": GIBDRPID, "status": 1},
            {"id": "101", "gibdrpid": GIBDRPID, "status": 2},
            {"id": "102", "gibdrpid": GIBDRPID, "status": 0},
        ),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert [call["id"] for call in _calls(execute_command_mock, "closeInvestigation")] == ["100", "102"]


def test_main_updates_a_closed_duplicate_instead_of_creating_a_new_incident(mocker):
    """The duplicate that used to slip through: its incident is closed, so the old
    open-only query found nothing and XSOAR created a second incident."""
    execute_command_mock = _record_commands(
        mocker,
        deepcopy(INCOMING_INCIDENT),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 2}),
    )
    mock_results = mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    mock_results.assert_called_once_with(False)
    assert [call["id"] for call in _calls(execute_command_mock, "setIncident")] == ["100"]


# ---------------------------------------------------------------------------
# Rejected or false violations close as False Positive
# ---------------------------------------------------------------------------

from GIBDRPIncidentUpdate import close_reason_for, get_approve_state  # noqa: E402


def _incident_with(status: str = "detected", approve_state: str | None = None, **fields) -> dict:
    incident = deepcopy(INCOMING_INCIDENT)
    incident["CustomFields"]["gibdrpstatus"] = status
    if approve_state is not None:
        incident["CustomFields"]["gibdrpapprovestate"] = approve_state
    incident["CustomFields"].update(fields)
    return incident


def test_approve_state_from_custom_fields():
    assert get_approve_state({"CustomFields": {"gibdrpapprovestate": "Rejected"}}) == "rejected"


def test_approve_state_from_raw_json():
    assert get_approve_state({"rawJSON": json.dumps({"approve_state": "under_review"})}) == "under_review"
    assert get_approve_state({"rawJSON": json.dumps({"violation": {"approveState": "approved"}})}) == "approved"
    assert get_approve_state({}) is None


@pytest.mark.parametrize(
    "status,approve_state,expected",
    [
        ("resolved", "approved", "Resolved"),
        ("legal", None, "Resolved"),
        ("false_status", None, "False Positive"),
        ("detected", "rejected", "False Positive"),
        # The customer's rejection is what ends the case, whatever DRP still reports as status.
        ("resolved", "rejected", "False Positive"),
        ("detected", "approved", None),
        ("in_response", "under_review", None),
    ],
)
def test_close_reason_follows_the_violation_state(status, approve_state, expected):
    assert close_reason_for(status, approve_state) == expected


def test_main_closes_a_rejected_violation_as_false_positive(mocker):
    """A rejected violation never becomes resolved, so without this rule its incident stayed open forever."""
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="detected", approve_state="rejected"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    close_calls = _calls(execute_command_mock, "closeInvestigation")
    assert len(close_calls) == 1
    assert close_calls[0]["closeReason"] == "False Positive"
    assert "rejected" in close_calls[0]["closeNotes"]
    assert GIBDRPID not in close_calls[0]["closeNotes"]


def test_main_closes_a_false_violation_as_false_positive(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="false_status"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    close_calls = _calls(execute_command_mock, "closeInvestigation")
    assert [call["closeReason"] for call in close_calls] == ["False Positive"]
    assert "false_status" in close_calls[0]["closeNotes"]


def test_main_does_not_close_an_approved_violation(mocker):
    """Approval settles the customer's half; the take-down is still ahead."""
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="detected", approve_state="approved"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert _calls(execute_command_mock, "closeInvestigation") == []
    assert _calls(execute_command_mock, "expireIndicators") == []


# ---------------------------------------------------------------------------
# The indicator is expired with the close when the incident asks for it
# ---------------------------------------------------------------------------


def test_main_expires_the_indicator_when_the_incoming_incident_asks(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="resolved", gibdrpexpireindicatoronclose=True, gibdrpviolationuri="bad.example"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert _calls(execute_command_mock, "expireIndicators") == [{"indicatorsValues": "bad.example", "value": "bad.example"}]


def test_main_expires_the_indicator_when_the_existing_incident_asks(mocker):
    """The flag was set by the instance that created the incident; an update through another
    instance without it must still honour it."""
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="resolved"),
        _duplicates(
            {
                "id": "100",
                "gibdrpid": GIBDRPID,
                "status": 1,
                "CustomFields": {"gibdrpexpireindicatoronclose": "true", "gibdrpviolationuri": "//bad.example/x"},
            }
        ),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    # the indicator was created from the normalized URI (https scheme added), so that is the value expired
    assert _calls(execute_command_mock, "expireIndicators") == [
        {"indicatorsValues": "https://bad.example/x", "value": "https://bad.example/x"}
    ]


def test_main_expires_the_indicator_once_for_several_duplicates(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="legal", gibdrpexpireindicatoronclose=True, gibdrpviolationuri="bad.example"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}, {"id": "101", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert len(_calls(execute_command_mock, "closeInvestigation")) == 2
    assert len(_calls(execute_command_mock, "expireIndicators")) == 1


def test_main_keeps_the_indicator_when_the_incident_does_not_ask(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="resolved", gibdrpviolationuri="bad.example"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 1}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert _calls(execute_command_mock, "expireIndicators") == []


def test_main_does_not_expire_when_the_duplicate_was_already_closed(mocker):
    execute_command_mock = _record_commands(
        mocker,
        _incident_with(status="resolved", gibdrpexpireindicatoronclose=True, gibdrpviolationuri="bad.example"),
        _duplicates({"id": "100", "gibdrpid": GIBDRPID, "status": 2}),
    )
    mocker.patch("GIBDRPIncidentUpdate.return_results")

    main()

    assert _calls(execute_command_mock, "expireIndicators") == []
