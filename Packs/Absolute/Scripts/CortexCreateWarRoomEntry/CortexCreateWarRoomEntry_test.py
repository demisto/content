import json
import pytest
from unittest.mock import call, patch

import demistomock as demisto

from CortexCreateWarRoomEntry import (
    create_war_room_entry,
    get_existing_ids_batch,
    post_war_room_entry,
    build_webapp_request_data,
    WAR_ROOM_ENTRY_URL,
    CREATE_INVESTIGATION_ID_URL,
    WEBAPP_GET_DATA_URL,
    CASES_TABLE,
    ALERTS_VIEW_TABLE,
    FILTER_FIELD,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _webapp_response(data_rows: list) -> dict:
    """Build a fake _apiCall response for /api/webapp/get_data."""
    return {"status": 200, "data": json.dumps({"reply": {"DATA": data_rows}})}


def _entry_response(entry_id: str | None) -> dict:
    """Build a fake _apiCall response for /xsoar/entry."""
    # Use `is not None` so that an empty-string entry_id is handled distinctly from a missing one.
    body = json.dumps({"id": entry_id}) if entry_id is not None else None
    return {"status": 200, "data": body}


def _investigation_response() -> dict:
    return {"status": 200, "data": None}


def _is_webapp_call(mock_call) -> bool:
    """Return True if a mock call targeted WEBAPP_GET_DATA_URL (kwargs or positional)."""
    path = mock_call.kwargs.get("path") if mock_call.kwargs else None
    if path is None and mock_call.args:
        # positional signature: _apiCall(method, path, data, headers)
        path = mock_call.args[1] if len(mock_call.args) > 1 else None
    return path == WEBAPP_GET_DATA_URL


class TestBuildWebappRequestData:
    def test_single_id_uses_or_eq_filter(self):
        body = build_webapp_request_data(CASES_TABLE, "CASE_ID", ["1"])
        assert body["table_name"] == CASES_TABLE
        or_clauses = body["filter_data"]["filter"]["AND"][0]["OR"]
        assert len(or_clauses) == 1
        assert or_clauses[0] == {"SEARCH_FIELD": "CASE_ID", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "1"}

    def test_multiple_ids_produce_one_or_clause_per_id(self):
        ids = ["10", "20", "30"]
        body = build_webapp_request_data(ALERTS_VIEW_TABLE, "internal_id", ids)
        or_clauses = body["filter_data"]["filter"]["AND"][0]["OR"]
        assert len(or_clauses) == len(ids)
        assert {c["SEARCH_VALUE"] for c in or_clauses} == set(ids)
        for clause in or_clauses:
            assert clause["SEARCH_FIELD"] == "internal_id"
            assert clause["SEARCH_TYPE"] == "EQ"

    def test_paging(self):
        ids = ["a", "b", "c", "d"]
        body = build_webapp_request_data(CASES_TABLE, "CASE_ID", ids)
        assert body["filter_data"]["paging"] == {"from": 0, "to": len(ids)}


# ---------------------------------------------------------------------------
# get_existing_ids_batch
# ---------------------------------------------------------------------------


class TestGetExistingIdsBatch:
    def test_returns_empty_set_for_empty_input(self):
        with patch.object(demisto, "_apiCall") as mock:
            result = get_existing_ids_batch("case", [])
        assert result == set()
        mock.assert_not_called()

    @pytest.mark.parametrize(
        ("asset_type", "filter_field", "table", "rows", "requested", "expected"),
        [
            (
                "case",
                "CASE_ID",
                CASES_TABLE,
                [{"CASE_ID": "1"}, {"CASE_ID": "2"}],
                ["1", "2", "3"],
                {"1", "2"},
            ),
            (
                "issue",
                "internal_id",
                ALERTS_VIEW_TABLE,
                [{"internal_id": "42"}, {"internal_id": "99"}],
                ["42", "99", "77"],
                {"42", "99"},
            ),
        ],
        ids=["cases-partial-match", "issues-partial-match"],
    )
    def test_ids_found(self, asset_type, filter_field, table, rows, requested, expected):
        with patch.object(demisto, "_apiCall", return_value=_webapp_response(rows)) as mock:
            result = get_existing_ids_batch(asset_type, requested)

        assert result == expected
        mock.assert_called_once()
        body = json.loads(mock.call_args.kwargs["data"])
        assert body["table_name"] == table
        or_clauses = body["filter_data"]["filter"]["AND"][0]["OR"]
        assert {c["SEARCH_VALUE"] for c in or_clauses} == set(requested)
        for c in or_clauses:
            assert c["SEARCH_FIELD"] == filter_field
            assert c["SEARCH_TYPE"] == "EQ"

    # Parametrize values are wrapped in pytest.param so they are not evaluated
    # at module import time, avoiding subtle issues if helpers ever gain side effects.
    @pytest.mark.parametrize(
        "raw_response",
        [
            pytest.param({"status": 200, "data": json.dumps({"reply": {"DATA": []}})}, id="none-found"),
            pytest.param({"status": 200, "data": "not-json"}, id="malformed-json"),
            pytest.param({"status": 200}, id="missing-data-key"),
        ],
    )
    def test_bad_or_empty_response_returns_empty_set(self, raw_response):
        with patch.object(demisto, "_apiCall", return_value=raw_response):
            result = get_existing_ids_batch("case", ["1"])
        assert result == set()


class TestPostWarRoomEntry:
    @pytest.mark.parametrize(
        "investigation_id",
        ["INCIDENT-5", "42"],
        ids=["case-prefix", "issue-no-prefix"],
    )
    def test_calls_investigation_then_entry(self, investigation_id):
        inv_resp = _investigation_response()
        entry_resp = _entry_response("abc123")

        with patch.object(demisto, "_apiCall", side_effect=[inv_resp, entry_resp]) as mock:
            result = post_war_room_entry(investigation_id, "hello")

        assert result == entry_resp
        assert mock.call_count == 2
        inv_call, entry_call = mock.call_args_list
        assert inv_call == call(
            method="POST",
            path=f"{CREATE_INVESTIGATION_ID_URL}/{investigation_id}",
            data=None,
            headers={"Content-Type": "application/json"},
        )
        assert entry_call == call(
            method="POST",
            path=WAR_ROOM_ENTRY_URL,
            data=json.dumps({"investigationId": investigation_id, "data": "hello"}),
            headers={"Content-Type": "application/json"},
        )

    def test_investigation_failure_does_not_prevent_entry_post(self):
        """The production code does not inspect the investigation response; the entry
        POST is always attempted regardless of what the investigation call returns.
        """
        error_inv_resp = {"status": 500, "data": "Internal Server Error"}
        entry_resp = _entry_response("abc123")

        with patch.object(demisto, "_apiCall", side_effect=[error_inv_resp, entry_resp]) as mock:
            result = post_war_room_entry("INCIDENT-99", "hello")

        # Both calls must still be made and the entry response returned.
        assert mock.call_count == 2
        assert result == entry_resp


class TestCreateWarRoomEntry:
    """With the batch approach the call sequence is:
    1. get_existing_ids_batch("issue", issue_ids)  → 0 or 1 webapp API call
    2. get_existing_ids_batch("case",  case_ids)   → 0 or 1 webapp API call
    3. For each *existing* issue: investigation + entry  (2 calls each)
    4. For each *existing* case:  investigation + entry  (2 calls each)
    """

    # ------------------------------------------------------------------
    # Guard-rail tests (no API calls expected)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("issue_ids", "case_ids", "expected_error_fragment"),
        [
            ([], [], "At least one"),
            ([str(i) for i in range(11)], [str(i) for i in range(10)], "Too many assets"),
        ],
        ids=["no-ids", "too-many-assets"],
    )
    def test_guard_rails(self, issue_ids, case_ids, expected_error_fragment):
        with patch.object(demisto, "_apiCall") as mock:
            result = create_war_room_entry(issue_ids=issue_ids, case_ids=case_ids, content="content")
        # `errors` must always be a list[str], even in guard-rail paths.
        assert isinstance(result.outputs["errors"], list)
        assert len(result.outputs["errors"]) == 1
        assert expected_error_fragment in result.outputs["errors"][0]
        mock.assert_not_called()

    # ------------------------------------------------------------------
    # Single-asset success paths
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("issue_ids", "case_ids"),
        [
            ([], ["2"]),
            (["42"], []),
        ],
        ids=["single-case", "single-issue"],
    )
    def test_create_entry_success_single(self, issue_ids, case_ids):
        """Successful entry creation for a single Case or Issue ID."""
        # Derive the filter field from the imported FILTER_FIELD mapping rather than
        # re-implementing the logic here.
        asset_type = "issue" if issue_ids else "case"
        filter_field = FILTER_FIELD[asset_type]
        asset_id = (issue_ids or case_ids)[0]

        api_side_effects = [
            _webapp_response([{filter_field: asset_id}]),
            _investigation_response(),
            _entry_response("abc123"),
        ]
        with patch.object(demisto, "_apiCall", side_effect=api_side_effects) as mock:
            result = create_war_room_entry(issue_ids=issue_ids, case_ids=case_ids, content="some content")

        assert "abc123" in result.outputs["result"]
        assert result.outputs["errors"] == []
        assert result.outputs_prefix == "CortexCreateWarRoomEntry"

        # Verify that "some content" reached the entry POST body.
        entry_call = mock.call_args_list[-1]
        entry_body = json.loads(entry_call.kwargs["data"])
        assert entry_body["data"] == "some content"

    # ------------------------------------------------------------------
    # Multiple-asset success paths
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("issue_ids", "case_ids", "batch_rows", "expected_entry_ids"),
        [
            (
                ["10", "20"],
                [],
                [{"internal_id": "10"}, {"internal_id": "20"}],
                ["e1", "e2"],
            ),
            (
                [],
                ["100", "200"],
                [{"CASE_ID": "100"}, {"CASE_ID": "200"}],
                ["c1", "c2"],
            ),
        ],
        ids=["multiple-issues", "multiple-cases"],
    )
    def test_create_entry_multiple(self, issue_ids, case_ids, batch_rows, expected_entry_ids):
        """Multiple assets of the same type → one batch call + N investigation+entry pairs."""
        entry_ids_iter = iter(expected_entry_ids)
        api_side_effects = [_webapp_response(batch_rows)]
        for _ in expected_entry_ids:
            api_side_effects += [_investigation_response(), _entry_response(next(entry_ids_iter))]

        # Expected call count: 1 (batch) + 2 per asset (investigation + entry)
        expected_call_count = 1 + 2 * len(expected_entry_ids)

        with patch.object(demisto, "_apiCall", side_effect=api_side_effects) as mock:
            result = create_war_room_entry(issue_ids=issue_ids, case_ids=case_ids, content="content")

        assert result.outputs["result"] == expected_entry_ids
        assert result.outputs["errors"] == []
        assert mock.call_count == expected_call_count

    def test_create_entry_mixed_ids(self):
        """One issue + one case → two batch webapp calls, then two investigation+entry pairs."""
        api_side_effects = [
            _webapp_response([{"internal_id": "55"}]),
            _webapp_response([{"CASE_ID": "66"}]),
            _investigation_response(),
            _entry_response("issue-e1"),
            _investigation_response(),
            _entry_response("case-e1"),
        ]
        with patch.object(demisto, "_apiCall", side_effect=api_side_effects) as mock:
            result = create_war_room_entry(issue_ids=["55"], case_ids=["66"], content="content")

        assert result.outputs["result"] == ["issue-e1", "case-e1"]
        assert result.outputs["errors"] == []
        assert mock.call_count == 6

        # Verify the case investigation used the INCIDENT- prefix transformation.
        # Call order: webapp(issues), webapp(cases), inv(55), entry(55), inv(INCIDENT-66), entry(66)
        case_inv_call = mock.call_args_list[4]
        assert case_inv_call.kwargs["path"] == f"{CREATE_INVESTIGATION_ID_URL}/INCIDENT-66"

        # Verify the issue investigation did NOT use the prefix.
        issue_inv_call = mock.call_args_list[2]
        assert issue_inv_call.kwargs["path"] == f"{CREATE_INVESTIGATION_ID_URL}/55"

    # ------------------------------------------------------------------
    # Not-found / error paths
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("issue_ids", "case_ids", "batch_rows", "missing_id", "expected_total_calls"),
        [
            ([], ["999"], [], "999", 1),  # single case missing
            (["10", "99"], [], [{"internal_id": "10"}], "99", 3),  # partial issues
            ([], ["100", "999"], [{"CASE_ID": "100"}], "999", 3),  # partial cases
        ],
        ids=["single-missing-case", "partial-missing-issue", "partial-missing-case"],
    )
    def test_create_entry_not_found(self, issue_ids, case_ids, batch_rows, missing_id, expected_total_calls):
        """Missing assets produce errors; found ones still get entries posted."""
        api_side_effects = [_webapp_response(batch_rows)]
        # Derive found_count directly from the batch rows rather than assuming "exactly one missing".
        found_count = len(batch_rows)
        for _ in range(found_count):
            api_side_effects += [_investigation_response(), _entry_response("ok")]

        with patch.object(demisto, "_apiCall", side_effect=api_side_effects) as mock:
            result = create_war_room_entry(issue_ids=issue_ids, case_ids=case_ids, content="content")

        assert len(result.outputs["errors"]) == 1
        assert missing_id in result.outputs["errors"][0]
        assert "not found" in result.outputs["errors"][0].lower()
        assert mock.call_count == expected_total_calls

    def test_create_entry_all_missing(self):
        """All IDs missing → errors for each, no investigation/entry calls."""
        with patch.object(demisto, "_apiCall", side_effect=[_webapp_response([]), _webapp_response([])]) as mock:
            result = create_war_room_entry(issue_ids=["1"], case_ids=["2"], content="content")

        assert result.outputs["result"] == []
        assert len(result.outputs["errors"]) == 2
        assert mock.call_count == 2

    def test_create_entry_null_response_data(self):
        """A null data field in the entry response results in an empty entry_ids list."""
        api_side_effects = [
            _webapp_response([{"CASE_ID": "1"}]),
            _investigation_response(),
            _entry_response(None),
        ]
        with patch.object(demisto, "_apiCall", side_effect=api_side_effects):
            result = create_war_room_entry(issue_ids=[], case_ids=["1"], content="content")

        assert result.outputs["result"] == []

    def test_create_entry_api_error_propagates(self):
        """An exception from _apiCall propagates out of create_war_room_entry."""
        with (
            patch.object(demisto, "_apiCall", side_effect=RuntimeError("API error")),
            pytest.raises(RuntimeError, match="API error"),
        ):
            create_war_room_entry(issue_ids=["1"], case_ids=[], content="content")

    # ------------------------------------------------------------------
    # Batch call structure verification
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        ("issue_ids", "case_ids", "batch_rows", "expected_table", "expected_field", "expected_values"),
        [
            (
                ["10", "20"],
                [],
                [{"internal_id": "10"}, {"internal_id": "20"}],
                ALERTS_VIEW_TABLE,
                "internal_id",
                {"10", "20"},
            ),
            (
                [],
                ["100", "200"],
                [{"CASE_ID": "100"}, {"CASE_ID": "200"}],
                CASES_TABLE,
                "CASE_ID",
                {"100", "200"},
            ),
        ],
        ids=["issues-or-eq-filter", "cases-or-eq-filter"],
    )
    def test_batch_call_uses_or_eq_filter(self, issue_ids, case_ids, batch_rows, expected_table, expected_field, expected_values):
        """Verify the webapp call uses OR+EQ clauses with all IDs of the given type."""
        api_side_effects = [_webapp_response(batch_rows)]
        for _ in batch_rows:
            api_side_effects += [_investigation_response(), _entry_response("ok")]

        with patch.object(demisto, "_apiCall", side_effect=api_side_effects) as mock:
            create_war_room_entry(issue_ids=issue_ids, case_ids=case_ids, content="x")

        first_call = mock.call_args_list[0]
        body = json.loads(first_call.kwargs["data"])
        assert body["table_name"] == expected_table
        or_clauses = body["filter_data"]["filter"]["AND"][0]["OR"]
        assert {c["SEARCH_VALUE"] for c in or_clauses} == expected_values
        for c in or_clauses:
            assert c["SEARCH_TYPE"] == "EQ"
            assert c["SEARCH_FIELD"] == expected_field

    def test_only_two_webapp_calls_for_mixed_ids(self):
        """With N issues and M cases there must be exactly 2 webapp calls total."""
        api_side_effects = [
            _webapp_response([{"internal_id": "1"}, {"internal_id": "2"}]),
            _webapp_response([{"CASE_ID": "10"}, {"CASE_ID": "20"}]),
            _investigation_response(),
            _entry_response("e1"),
            _investigation_response(),
            _entry_response("e2"),
            _investigation_response(),
            _entry_response("c1"),
            _investigation_response(),
            _entry_response("c2"),
        ]
        with patch.object(demisto, "_apiCall", side_effect=api_side_effects) as mock:
            result = create_war_room_entry(issue_ids=["1", "2"], case_ids=["10", "20"], content="x")

        # Use the helper that checks both kwargs and positional args for robustness.
        webapp_calls = [c for c in mock.call_args_list if _is_webapp_call(c)]
        assert len(webapp_calls) == 2
        assert result.outputs["errors"] == []
        assert len(result.outputs["result"]) == 4
