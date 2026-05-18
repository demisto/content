import time
import ast
from unittest.mock import MagicMock
from MondayEventCollector import (
    get_audit_logs,
    generate_log_hash,
    subtract_epsilon_from_timestamp,
    fetch_audit_logs,
    fetch_activity_logs,
    test_connection as monday_test_connection,
)
import demistomock as demisto  # noqa: F401
from CommonServerPython import *


class TestGetAuditLogs:
    """
    per_page - The maximum activity logs per page is 1000.
    limit - The maximum limit can be fetched is 5000.

        - limit ≤ per_page -> per_page = limit -> fetch full page, remaining logs mechanism is not used.
        - limit > per_page -> per_page = 1000 -> fetch partial page, remaining logs mechanism is used.

        CRITICAL: per_page is ALWAYS constant during all the fetch audit logs runs.
    """

    def test_get_audit_logs_with_continuing_fetch_when_limit_less_than_max_logs_per_page(self, mocker):
        """
        Given:
            - assume maximum audit logs per fetch = 10
            - limit = 8
            - next_page is not None (next_page=2)
        When:
            get_audit_logs is called with per_page=limit=8
        Then:
            It should fetch exactly 8 logs in one request and set continuing_fetch_info for remaining logs.
            full page fetched because the limit is less than the max logs per page-> no remaining logs from fetched partial page.
        """
        limit = 8
        mock_params = {
            "audit_logs_url": "https://test.monday.com",
            "audit_token": {"password": "test_token"},
        }
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        # --- FIRST FETCH: no continuing fetch mechanism, page=1 ---
        # Mock 8 logs from first page (per_page=8, but more logs available)
        page1_logs = [
            {"timestamp": "2024-06-03T14:25:47.000Z", "account_id": 1, "event": "login"},
            {"timestamp": "2024-06-03T14:25:47.000Z", "account_id": 2, "event": "login"},  # same timestamp as the newest log
            {"timestamp": "2024-06-03T14:20:47.000Z", "account_id": 3, "event": "logout"},
            {"timestamp": "2024-06-03T14:15:47.000Z", "account_id": 4, "event": "login"},
            {"timestamp": "2024-06-03T14:10:47.000Z", "account_id": 5, "event": "logout"},
            {"timestamp": "2024-06-03T14:05:47.000Z", "account_id": 6, "event": "login"},
            {"timestamp": "2024-06-03T14:00:47.000Z", "account_id": 7, "event": "login"},
            {"timestamp": "2024-06-03T13:55:47.000Z", "account_id": 8, "event": "logout"},
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": page1_logs,
            "page": 1,
            "per_page": limit,
            "next_page": 2,  # More pages available
        }
        mocker.patch("MondayEventCollector.BaseClient._http_request", return_value=mock_response.json())
        mock_timestamp_to_datestring = mocker.patch("MondayEventCollector.timestamp_to_datestring")
        mock_timestamp_to_datestring.return_value = "2024-06-03T15:00:00.000Z"

        # Create a mock AuditLogsClient
        mock_client = mocker.MagicMock()
        mock_client.get_audit_logs_request.return_value = mock_response.json()

        # Initial state - first fetch
        initial_last_run = {}
        now_ms = int(time.time() * 1000)

        result_logs, result_last_run = get_audit_logs(
            initial_last_run, now_ms, limit=limit, logs_per_page=limit, client=mock_client
        )

        assert len(result_logs) == limit
        assert result_last_run["last_timestamp"] == page1_logs[0]["timestamp"]
        assert result_last_run["upper_bound_log_id"] == [
            generate_log_hash(page1_logs[0]),
            generate_log_hash(page1_logs[1]),
        ]  # Two newest logs with same timestamp
        assert result_last_run["continuing_fetch_info"] is not None  # More pages available
        assert result_last_run["continuing_fetch_info"]["page"] == 2

        # Verify only 1 request was made (limit reached <= 1000)
        assert mock_client.get_audit_logs_request.call_count == 1

        # Verify request used per_page = limit (limit <= 1000)
        call_args = mock_client.get_audit_logs_request.call_args[0]
        assert call_args[2] == limit  # logs_per_page parameter

        # --- SECOND FETCH: Continuing fetch mechanism, page=2---
        # Mock page 2 logs (8 more logs with different timestamps)
        page2_logs = [
            {"timestamp": "2024-06-03T13:50:47.000Z", "account_id": 9, "event": "login"},
            {"timestamp": "2024-06-03T13:45:47.000Z", "account_id": 10, "event": "logout"},
            {"timestamp": "2024-06-03T13:40:47.000Z", "account_id": 11, "event": "login"},
            {"timestamp": "2024-06-03T13:35:47.000Z", "account_id": 12, "event": "logout"},
            {"timestamp": "2024-06-03T13:30:47.000Z", "account_id": 13, "event": "login"},
            {"timestamp": "2024-06-03T13:25:47.000Z", "account_id": 14, "event": "logout"},
            {"timestamp": "2024-06-03T13:20:47.000Z", "account_id": 15, "event": "login"},
            {"timestamp": "2024-06-03T13:15:47.000Z", "account_id": 16, "event": "logout"},
        ]

        mock_response_page2 = MagicMock()
        mock_response_page2.status_code = 200
        mock_response_page2.json.return_value = {
            "data": page2_logs,
            "page": 2,
            "per_page": limit,
            "next_page": None,  # No more pages available
        }

        # Reset mock to return page 2 response
        mock_client.get_audit_logs_request.return_value = mock_response_page2.json()
        mock_client.reset_mock()

        previous_last_timestamp = result_last_run["last_timestamp"]
        previous_upper_bound_log_id = result_last_run["upper_bound_log_id"]

        continuing_last_run = result_last_run
        result_logs_2, result_last_run_2 = get_audit_logs(continuing_last_run, now_ms, limit, limit, client=mock_client)

        assert len(result_logs_2) == limit

        # Validate timestamps are in descending order (newest first)
        timestamps = [log["timestamp"] for log in result_logs_2]
        assert timestamps == sorted(timestamps, reverse=True)

        # last_timestamp does not change until new fetch starts (page=1)
        assert result_last_run_2["last_timestamp"] == previous_last_timestamp
        # upper_bound_log_id does not change until new fetch starts (page=1)
        assert result_last_run_2["upper_bound_log_id"] == previous_upper_bound_log_id
        # No more pages available
        assert result_last_run_2["continuing_fetch_info"] is None
        # on the last page, upper_bound_log_id set to lower_bound_log_id for the next fetch
        assert result_last_run_2["upper_bound_log_id"] == result_last_run_2["lower_bound_log_id"]

        # Validate API call parameters
        assert mock_client.get_audit_logs_request.call_count == 1
        call_args_2 = mock_client.get_audit_logs_request.call_args[0]
        assert call_args_2[1] == 2  # page parameter - Should use page from continuing_fetch_info
        assert call_args_2[2] == limit  # logs_per_page parameter

        # --- THIRD FETCH: New fetch with duplication handling ---
        # This tests the scenario where continuing_fetch_info is None and we start a new fetch range
        # The start_time should be last_timestamp minus epsilon to include logs with same timestamp as last_timestamp

        last_timestamp = result_last_run_2["last_timestamp"]  # "2024-06-03T14:25:47.000Z"
        page1_logs_new_fetch = [
            # New logs with different timestamps (should be included)
            {"timestamp": "2024-06-03T14:40:47.000Z", "account_id": 103, "event": "login"},
            {"timestamp": "2024-06-03T14:35:47.000Z", "account_id": 104, "event": "logout"},
            {"timestamp": "2024-06-03T14:30:47.000Z", "account_id": 105, "event": "login"},
            {"timestamp": "2024-06-03T14:29:47.000Z", "account_id": 106, "event": "logout"},
            # logs with same timestamp as last_timestamp but different account_ids (should be included)
            {"timestamp": last_timestamp, "account_id": 101, "event": "login"},  # New log with same timestamp
            {"timestamp": last_timestamp, "account_id": 102, "event": "logout"},  # New log with same timestamp
            # duplicates logs from previous fetch (should be filtered out by upper_bound_log_id, same timestamp as last_timestamp)
            page1_logs[0],  # Duplicate (account_id=1 was in upper_bound)
            page1_logs[1],  # Duplicate (account_id=2 was in upper_bound)
        ]

        mock_response_page1_new_fetch = MagicMock()
        mock_response_page1_new_fetch.status_code = 200
        mock_response_page1_new_fetch.json.return_value = {
            "data": page1_logs_new_fetch,
            "page": 1,  # New fetch starts from page 1
            "per_page": limit,
            "next_page": None,  # No more pages
        }

        # Reset mock for third fetch
        mock_client.get_audit_logs_request.return_value = mock_response_page1_new_fetch.json()
        mock_client.reset_mock()

        new_fetch_last_run = result_last_run_2
        result_logs_3, result_last_run_3 = get_audit_logs(new_fetch_last_run, now_ms, limit, limit, client=mock_client)

        # Validate duplication handling - should get 6 logs (filtering out 2 duplicates)
        expected_logs = limit - 2
        assert len(result_logs_3) == expected_logs

        # Verify no duplicate account_ids from upper_bound_log_id (account_ids 1 and 2 should be filtered)
        result_account_ids = {log["account_id"] for log in result_logs_3}
        assert page1_logs[0]["account_id"] not in result_account_ids
        assert page1_logs[1]["account_id"] not in result_account_ids

        # Verify logs with different timestamps are included (account_ids 103-106)
        expected_new_account_ids = {101, 102, 103, 104, 105, 106}
        assert result_account_ids == expected_new_account_ids

        # last_timestamp should be the newest timestamp
        assert result_last_run_3["last_timestamp"] == page1_logs_new_fetch[0]["timestamp"]
        # No more pages
        assert result_last_run_3["continuing_fetch_info"] is None

        # Validate API call
        assert mock_client.get_audit_logs_request.call_count == 1
        call_args_3 = mock_client.get_audit_logs_request.call_args[0]
        assert call_args_3[1] == 1
        assert call_args_3[2] == limit

        # Verify start_time filter includes epsilon adjustment
        time_filter_arg = call_args_3[0]
        filters = ast.literal_eval(time_filter_arg)
        assert filters["start_time"] == subtract_epsilon_from_timestamp(last_timestamp)

    def test_fetch_audit_logs_with_remaining_logs_mechanism(self, mocker):
        """
        Test the complete remaining logs mechanism using fetch_audit_logs function.

        Given:
            - max_audit_logs_per_fetch = 8 (limit)
            - MAX_AUDIT_LOGS_PER_PAGE = 5 (per_page)
            - Available logs: 12 total (more than limit)

        When:
            fetch_audit_logs is called with limit > per_page

        Then:
            It should:
            1. First call: fetch 5 logs (per_page=5), remaining=3
            2. Second call: fetch 5 logs (per_page=5), but only use 3 to reach limit=8
            3. Set excess_logs_info for the 2 unused logs from second call
            4. Return exactly 8 logs total
        """
        limit = 8
        per_page = 5

        mocker.patch("MondayEventCollector.MAX_AUDIT_LOGS_PER_PAGE", per_page)
        mocker.patch("MondayEventCollector.MAX_AUDIT_LOGS_PER_FETCH", limit)
        mock_params = {
            "audit_logs_url": "https://test.monday.com",
            "audit_token": {"password": "test_token"},
            "max_audit_logs_per_fetch": limit,
        }
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        # --- FIRST FETCH - FIRST API CALL: Page 1, fetch 5 logs ---
        page1_logs = [
            {"timestamp": "2024-06-03T14:25:47.000Z", "account_id": 1, "event": "login"},
            {"timestamp": "2024-06-03T14:25:47.000Z", "account_id": 2, "event": "logout"},
            {"timestamp": "2024-06-03T14:20:47.000Z", "account_id": 3, "event": "login"},
            {"timestamp": "2024-06-03T14:15:47.000Z", "account_id": 4, "event": "logout"},
            {"timestamp": "2024-06-03T14:10:47.000Z", "account_id": 5, "event": "login"},
        ]

        # --- FIRST FETCH - SECOND API CALL: Page 2, fetch 5 logs (but only need 3) ---
        page2_logs = [
            {"timestamp": "2024-06-03T14:05:47.000Z", "account_id": 6, "event": "logout"},
            {"timestamp": "2024-06-03T14:00:47.000Z", "account_id": 7, "event": "login"},
            {"timestamp": "2024-06-03T13:55:47.000Z", "account_id": 8, "event": "logout"},
            {"timestamp": "2024-06-03T13:50:47.000Z", "account_id": 9, "event": "login"},  # Excess log 1
            {"timestamp": "2024-06-03T13:45:47.000Z", "account_id": 10, "event": "logout"},  # Excess log 2
        ]

        # --- SECOND FETCH - THIRD API CALL: Page 3, fetch 5 logs
        page3_logs = [
            {"timestamp": "2024-06-03T13:45:47.000Z", "account_id": 11, "event": "logout"},
            {"timestamp": "2024-06-03T13:40:47.000Z", "account_id": 12, "event": "login"},
            {"timestamp": "2024-06-03T13:35:47.000Z", "account_id": 13, "event": "logout"},
            {"timestamp": "2024-06-03T13:30:47.000Z", "account_id": 14, "event": "login"},
            {"timestamp": "2024-06-03T13:25:47.000Z", "account_id": 15, "event": "logout"},
        ]

        # --- SECOND FETCH - FOURTH API CALL: Page 4, fetch 5 logs (but only need 1)---
        page4_logs = [
            {"timestamp": "2024-06-03T13:25:47.000Z", "account_id": 16, "event": "logout"},
            {"timestamp": "2024-06-03T13:20:47.000Z", "account_id": 17, "event": "login"},  # Excess log 1
            {"timestamp": "2024-06-03T13:15:47.000Z", "account_id": 18, "event": "logout"},  # Excess log 2
            {"timestamp": "2024-06-03T13:10:47.000Z", "account_id": 19, "event": "login"},  # Excess log 3
            {"timestamp": "2024-06-03T13:05:47.000Z", "account_id": 20, "event": "logout"},  # Excess log 4
        ]

        page_1_1_logs = [
            {"timestamp": "2024-06-03T14:35:47.000Z", "account_id": 21, "event": "login"},
            {"timestamp": "2024-06-03T14:30:47.000Z", "account_id": 22, "event": "logout"},
        ]

        # Mock responses for both API calls
        mock_response_page1 = MagicMock()
        mock_response_page1.status_code = 200
        mock_response_page1.json.return_value = {"data": page1_logs, "page": 1, "per_page": per_page, "next_page": 2}

        mock_response_page2 = MagicMock()
        mock_response_page2.status_code = 200
        mock_response_page2.json.return_value = {"data": page2_logs, "page": 2, "per_page": per_page, "next_page": 3}

        mock_response_page3 = MagicMock()
        mock_response_page3.status_code = 200
        mock_response_page3.json.return_value = {"data": page3_logs, "page": 3, "per_page": per_page, "next_page": 4}

        mock_response_page4 = MagicMock()
        mock_response_page4.status_code = 200
        mock_response_page4.json.return_value = {"data": page4_logs, "page": 4, "per_page": per_page, "next_page": None}

        mock_response_page1_1 = MagicMock()
        mock_response_page1_1.status_code = 200
        mock_response_page1_1.json.return_value = {"data": page_1_1_logs, "page": 1, "per_page": per_page, "next_page": None}

        # Configure mock to return different responses for each call
        mock_requests_get = mocker.patch(
            "MondayEventCollector.BaseClient._http_request",
            side_effect=[
                mock_response_page1.json(),
                mock_response_page2.json(),
                mock_response_page2.json(),
                mock_response_page3.json(),
                mock_response_page4.json(),
                mock_response_page4.json(),
                mock_response_page1_1.json(),
            ],
        )

        mock_timestamp_to_datestring = mocker.patch("MondayEventCollector.timestamp_to_datestring")
        mock_timestamp_to_datestring.return_value = "2024-06-03T15:00:00.000Z"
        mocker.patch("MondayEventCollector.add_fields_to_events")

        # Initial state - first fetch
        initial_last_run = {}
        result_last_run, result_logs = fetch_audit_logs(initial_last_run)

        assert len(result_logs) == limit
        assert result_last_run["last_timestamp"] == page1_logs[0]["timestamp"]
        assert result_last_run["upper_bound_log_id"] == [
            generate_log_hash(page1_logs[0]),
            generate_log_hash(page1_logs[1]),
        ]  # Two newest logs with same timestamp

        # Should contain logs from both pages (first 5 + first 3 from second page)
        expected_account_ids = [1, 2, 3, 4, 5, 6, 7, 8]
        actual_account_ids = [log["account_id"] for log in result_logs]
        assert actual_account_ids == expected_account_ids

        # Should make exactly 2 API calls (5 logs from page 1 + 3 logs from page 2)
        assert mock_requests_get.call_count == 2

        # Should set excess_logs_info for unused logs from page 2
        assert result_last_run["excess_logs_info"] is not None
        excess_info = result_last_run["excess_logs_info"]
        assert excess_info["page"] == 2
        assert excess_info["offset"] == 3  # Only first 3 logs from page 2 were used

        # --- SECOND CALL TO fetch_audit_logs: Process excess logs from previous fetch before fetching new page ---

        # Second fetch using last_run from first fetch
        result_last_run_2, result_logs_2 = fetch_audit_logs(result_last_run)

        assert len(result_logs_2) == limit

        # Should contain excess logs first (9, 10), then new logs (11-16)
        expected_account_ids_2 = [9, 10, 11, 12, 13, 14, 15, 16]  # 2 excess + 6 new
        actual_account_ids_2 = [log["account_id"] for log in result_logs_2]
        assert actual_account_ids_2 == expected_account_ids_2

        # Upper bound log id should not change until starting a new fetch window (page=1)
        assert result_last_run_2["upper_bound_log_id"] == result_last_run["upper_bound_log_id"]

        # Second fetch should make exactly 3 API calls(2 logs from page 2 + 5 logs from page 3 + 1 log from page 4)
        # (First fetch made 2 API calls)
        assert mock_requests_get.call_count == 5
        # Should set excess_logs_info for unused logs from page 4
        assert result_last_run_2["excess_logs_info"] is not None
        excess_info = result_last_run_2["excess_logs_info"]
        assert excess_info["page"] == 4
        assert excess_info["offset"] == 1  # Only first 1 log from page 4 were used

        # Third fetch using last_run from second fetch
        result_last_run_3, result_logs_3 = fetch_audit_logs(result_last_run_2)

        # Should return exactly 6 logs
        assert len(result_logs_3) == 6
        expected_account_ids_3 = [17, 18, 19, 20, 21, 22]
        actual_account_ids_3 = [log["account_id"] for log in result_logs_3]
        assert actual_account_ids_3 == expected_account_ids_3

        # lower bound log id should set with the upper bound log id when reaching the last page
        assert result_last_run_3["upper_bound_log_id"] == result_last_run_3["lower_bound_log_id"]

        # Third fetch should make exactly 1 API calls (4 logs remaining from page 5)
        # (First fetch made 2 API calls, second fetch made 3 API calls)
        assert mock_requests_get.call_count == 7

        # Should remove excess_logs_info from last run (already fetched remaining logs)
        assert result_last_run_3["excess_logs_info"] is None
        # Should remove continuing_fetch_info from last run (next page is none, next fetch will start a new fetch window)
        assert result_last_run_3["continuing_fetch_info"] is None
        assert result_last_run_3["upper_bound_log_id"] == [generate_log_hash(page_1_1_logs[0])]


class TestGetActivityLogs:
    """
    per_page - The maximum activity logs per page is 10000.
    limit - The maximum limit can be fetched is 10000.

        - limit ≤ per_page -> per_page = limit -> always fetch full page, remaining logs mechanism is not used.
        - limit > per_page -> no support for this case. limit equals to per_page.

        CRITICAL: per_page is ALWAYS constant during all the fetch activity logs runs.

    Test class for activity logs functionality.

    """

    def test_fetch_activity_logs_with_continuing_fetch_multi_board(self, mocker):
        """
        Test continuing fetch mechanism for activity logs across multiple boards.

        Given:
            - 2 boards: "123", "456"
            - limit = 8 per board
            - Board 123: 15 logs available (needs continuing fetch)
            - Board 456: 5 logs available (completes in one fetch)

        When:
            fetch_activity_logs is called twice

        Then:
            First call:
            - Board 123: Gets 8 logs, sets continuing_fetch_info
            - Board 456: Gets 5 logs, completes

            Second call:
            - Board 123: Gets remaining 7 logs, completes
            - Board 456: No new logs
        """
        limit = 8
        board_ids = "123,456"
        mocker.patch("MondayEventCollector.MAX_ACTIVITY_LOGS_PER_FETCH", 10)
        mock_params = {
            "activity_logs_url": "https://api.monday.com",
            "board_ids": board_ids,
            "max_activity_logs_per_fetch": limit,
        }
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")
        mocker.patch("MondayEventCollector.get_access_token", return_value="mock_access_token")

        # --- BOARD 123 LOGS ---
        # First fetch: 8 logs (limit reached, more available)
        board_123_page1_logs = [
            {"id": "log1", "event": "update_column", "created_at": "17545145534156780", "data": "{}"},
            {"id": "log2", "event": "update_column", "created_at": "17545145534156780", "data": "{}"},  # Same timestamp
            {"id": "log3", "event": "create_item", "created_at": "17545145530000000", "data": "{}"},
            {"id": "log4", "event": "update_status", "created_at": "17545145520000000", "data": "{}"},
            {"id": "log5", "event": "delete_item", "created_at": "17545145510000000", "data": "{}"},
            {"id": "log6", "event": "create_group", "created_at": "17545145500000000", "data": "{}"},
            {"id": "log7", "event": "update_name", "created_at": "17545145490000000", "data": "{}"},
            {"id": "log8", "event": "create_board", "created_at": "17545145480000000", "data": "{}"},
        ]

        # Second fetch: remaining 7 logs
        board_123_page2_logs = [
            {"id": "log9", "event": "update_column", "created_at": "17545145470000000", "data": "{}"},
            {"id": "log10", "event": "delete_group", "created_at": "17545145460000000", "data": "{}"},
            {"id": "log11", "event": "create_column", "created_at": "17545145450000000", "data": "{}"},
            {"id": "log12", "event": "update_board", "created_at": "17545145440000000", "data": "{}"},
            {"id": "log13", "event": "create_item", "created_at": "17545145430000000", "data": "{}"},
            {"id": "log14", "event": "update_status", "created_at": "17545145420000000", "data": "{}"},
            {"id": "log15", "event": "delete_column", "created_at": "17545145410000000", "data": "{}"},
        ]

        # --- BOARD 456 LOGS ---
        # First fetch: 5 logs (completes)
        board_456_page1_logs = [
            {"id": "log16", "event": "create_board", "created_at": "17545145400000000", "data": "{}"},
            {"id": "log17", "event": "update_name", "created_at": "17545145390000000", "data": "{}"},
            {"id": "log18", "event": "create_group", "created_at": "17545145380000000", "data": "{}"},
            {"id": "log19", "event": "create_item", "created_at": "17545145370000000", "data": "{}"},
            {"id": "log20", "event": "update_column", "created_at": "17545145360000000", "data": "{}"},
        ]

        # Mock GraphQL responses for sequential API calls
        # First fetch:
        mock_response_board123_page1 = {"data": {"boards": [{"activity_logs": board_123_page1_logs}]}}
        mock_response_board123_page2_check = {"data": {"boards": [{"activity_logs": board_123_page2_logs}]}}
        mock_response_board456_page1 = {"data": {"boards": [{"activity_logs": board_456_page1_logs}]}}
        mock_response_board456_page2_empty = {"data": {"boards": [{"activity_logs": []}]}}

        # Second fetch:
        mock_response_board123_page2 = {"data": {"boards": [{"activity_logs": board_123_page2_logs}]}}
        mock_response_board123_page3_empty = {"data": {"boards": [{"activity_logs": []}]}}
        mock_response_board456_page1_empty = {  # minus epsilon adjusted timestamp - no new logs, only duplicate logs
            "data": {
                "boards": [
                    {
                        "activity_logs": [
                            {"id": "log16", "event": "create_board", "created_at": "17545145400000000", "data": "{}"},
                        ]
                    }
                ]
            }
        }

        mock_response_board456_page2_empty_2 = {"data": {"boards": [{"activity_logs": []}]}}

        # Configure mock to return different responses for each call
        mock_http_request = mocker.patch("MondayEventCollector.BaseClient._http_request")

        mock_http_request.side_effect = [
            # First fetch_activity_logs call:
            mock_response_board123_page1,  # Board 123, page 1 (8 logs)
            mock_response_board123_page2_check,  # Board 123, page 2 check (has logs)
            mock_response_board456_page1,  # Board 456, page 1 (5 logs)
            mock_response_board456_page2_empty,  # Board 456, page 2 check (empty)
            # Second fetch_activity_logs call:
            mock_response_board123_page2,  # Board 123, page 2 (7 logs)
            mock_response_board123_page3_empty,  # Board 123, page 3 check (empty)
            mock_response_board456_page1_empty,  # Board 456, page 1 (no new logs)
            mock_response_board456_page2_empty_2,  # Board 456, page 2 check (empty)
        ]

        mocker.patch("MondayEventCollector.add_fields_to_events")
        mocker.patch("MondayEventCollector.extract_activity_log_data", side_effect=lambda x: x)
        mocker.patch("MondayEventCollector.convert_timestamp", return_value="2024-06-03T14:25:47.000Z")

        initial_last_run = {}
        result_last_run_1, result_logs_1 = fetch_activity_logs(initial_last_run)

        # Check fetched logs
        assert len(result_logs_1) == 13
        expected_log_ids = {
            "log1",
            "log2",
            "log3",
            "log4",
            "log5",
            "log6",
            "log7",
            "log8",  # Board 123
            "log16",
            "log17",
            "log18",
            "log19",
            "log20",
        }  # Board 456
        actual_log_ids = {log.get("id") for log in result_logs_1}
        assert actual_log_ids == expected_log_ids, f"Expected IDs: {expected_log_ids}, but got: {actual_log_ids}"

        # Check last run
        assert "123" in result_last_run_1
        assert "456" in result_last_run_1
        assert len(result_last_run_1) == 2

        # Board 123 should have continuing_fetch_info (more logs available)
        board_123_last_run = result_last_run_1["123"]
        assert board_123_last_run["continuing_fetch_info"] is not None
        assert board_123_last_run["continuing_fetch_info"]["page"] == 2
        assert board_123_last_run["upper_bound_log_id"] == ["log1", "log2"]  # Same timestamp logs

        # Board 456 should be complete (no continuing_fetch_info)
        board_456_last_run = result_last_run_1["456"]
        assert board_456_last_run["continuing_fetch_info"] is None
        assert board_456_last_run["upper_bound_log_id"] == ["log16"]
        assert board_456_last_run["lower_bound_log_id"] == board_456_last_run["upper_bound_log_id"]

        # Start second fetch using last_run from first fetch
        result_last_run_2, result_logs_2 = fetch_activity_logs(result_last_run_1)

        # Should return 7 logs (remaining from board 123, board 456 has no new logs)
        assert len(result_logs_2) == 7

        # Check fetched logs
        expected_log_ids = {
            "log9",
            "log10",
            "log11",
            "log12",
            "log13",
            "log14",
            "log15",
        }  # only board 123 (board 456 has no new logs)
        actual_log_ids = {log.get("id") for log in result_logs_2}
        assert actual_log_ids == expected_log_ids, f"Expected IDs: {expected_log_ids}, but got: {actual_log_ids}"

        # Board 123 should now be complete
        board_123_last_run_2 = result_last_run_2["123"]
        assert board_123_last_run_2["continuing_fetch_info"] is None
        assert board_123_last_run_2["lower_bound_log_id"] == board_123_last_run_2["upper_bound_log_id"]

        # Board 456 should remain unchanged (no new logs)
        board_456_last_run_2 = result_last_run_2["456"]
        assert board_456_last_run_2["continuing_fetch_info"] is None

        # Validate total API calls made for first two fetches
        assert mock_http_request.call_count == 8

        # --- THIRD FETCH: New fetch with duplication handling ---
        # This tests the scenario where continuing_fetch_info is None and we start a new fetch range
        # The start_time should be last_timestamp minus epsilon to include logs with same timestamp as last_timestamp

        # New logs for third fetch - Board 123
        board_123_new_logs = [
            # New logs with different timestamps (should be included)
            {"id": "log21", "event": "create_board", "created_at": "17545145540000000", "data": "{}"},  # Newer timestamp
            {"id": "log22", "event": "update_name", "created_at": "17545145535000000", "data": "{}"},  # Newer timestamp
            # These logs have same timestamp as last_timestamp but different IDs (should be included)
            {"id": "log23", "event": "create_item", "created_at": "17545145534156780", "data": "{}"},  # Same timestamp as log1
            {"id": "log24", "event": "update_status", "created_at": "17545145534156780", "data": "{}"},  # Same timestamp as log1
            # These would be duplicates from previous fetch (should be filtered out by upper_bound_log_id)
            {"id": "log1", "event": "update_column", "created_at": "17545145534156780", "data": "{}"},  # Duplicate
            {"id": "log2", "event": "update_column", "created_at": "17545145534156780", "data": "{}"},  # Duplicate
        ]

        # New logs for third fetch - Board 456
        board_456_new_logs = [
            # New logs with different timestamps (should be included)
            {"id": "log25", "event": "create_group", "created_at": "17545145404156780", "data": "{}"},  # Newer timestamp
            # Log with same timestamp as last_timestamp but different ID (should be included)
            {"id": "log26", "event": "update_column", "created_at": "17545145400000000", "data": "{}"},  # Same timestamp as log16
            # This would be duplicate from previous fetch (should be filtered out)
            {"id": "log16", "event": "create_board", "created_at": "17545145400000000", "data": "{}"},  # Duplicate
        ]

        # Mock responses for third fetch
        mock_response_board123_new_fetch = {"data": {"boards": [{"activity_logs": board_123_new_logs}]}}
        mock_response_board123_page2_empty_new = {"data": {"boards": [{"activity_logs": []}]}}
        mock_response_board456_new_fetch = {"data": {"boards": [{"activity_logs": board_456_new_logs}]}}
        mock_response_board456_page2_empty_new = {"data": {"boards": [{"activity_logs": []}]}}

        # Reset and configure mock for third fetch
        mock_http_request.reset_mock()
        mock_http_request.side_effect = [
            mock_response_board123_new_fetch,  # Board 123, page 1 (new logs)
            mock_response_board123_page2_empty_new,  # Board 123, page 2 check (empty)
            mock_response_board456_new_fetch,  # Board 456, page 1 (new logs)
            mock_response_board456_page2_empty_new,  # Board 456, page 2 check (empty)
        ]
        result_last_run_3, result_logs_3 = fetch_activity_logs(result_last_run_2)

        # Should return 6 logs total (4 from board 123-filtering out 2 duplicates + 2 from board 456-filtering out 1 duplicate)
        expected_logs_count = 6
        assert len(result_logs_3) == expected_logs_count

        # Verify no duplicate IDs from upper_bound_log_id are included
        result_log_ids = {log.get("id") for log in result_logs_3}
        assert "log1" not in result_log_ids  # Duplicate from board 123
        assert "log2" not in result_log_ids  # Duplicate from board 123
        assert "log16" not in result_log_ids  # Duplicate from board 456

        # These should be included (new logs)
        expected_new_log_ids = {"log21", "log22", "log23", "log24", "log25", "log26"}
        assert result_log_ids == expected_new_log_ids, f"Expected IDs: {expected_new_log_ids}, but got: {result_log_ids}"

        board_123_last_run_3 = result_last_run_3["123"]
        board_456_last_run_3 = result_last_run_3["456"]

        # Both boards should be complete (no continuing_fetch_info)
        assert board_123_last_run_3["continuing_fetch_info"] is None
        assert board_456_last_run_3["continuing_fetch_info"] is None

        # Validate new timestamps are set correctly (newest log from each board)
        assert board_123_last_run_3["last_timestamp"] == "2024-06-03T14:25:47.000Z"
        assert board_456_last_run_3["last_timestamp"] == "2024-06-03T14:25:47.000Z"

        # Validate upper_bound_log_id is set to newest logs
        assert board_123_last_run_3["upper_bound_log_id"] == ["log21"]  # Newest log from board 123
        assert board_456_last_run_3["upper_bound_log_id"] == ["log25"]  # Newest log from board 456

        # Validate lower_bound_log_id is set for next fetch
        assert board_123_last_run_3["lower_bound_log_id"] == board_123_last_run_3["upper_bound_log_id"]
        assert board_456_last_run_3["lower_bound_log_id"] == board_456_last_run_3["upper_bound_log_id"]

        # Validate total API calls for third fetch


class TestConnectionAndUtilities:
    """Test class for connection testing and utility functions."""

    def test_generate_login_url_success(self, mocker):
        """Test successful generation of login URL."""
        from MondayEventCollector import generate_login_url

        mock_params = {"credentials": {"identifier": "test_client_id"}}
        mocker.patch.object(demisto, "params", return_value=mock_params)

        result = generate_login_url()

        assert "https://auth.monday.com/oauth2/authorize?client_id=test_client_id" in result.readable_output
        assert "Click on the [login URL]" in result.readable_output
        assert "AUTH_CODE" in result.readable_output

    def test_generate_login_url_missing_client_id(self, mocker):
        """Test generate_login_url with missing client ID."""
        from MondayEventCollector import generate_login_url

        mock_params = {"client_id": ""}
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        try:
            generate_login_url()
        except DemistoException as e:
            assert "Please provide Client ID" in str(e)

    def test_test_connection_activity_logs_success(self, mocker):
        """Test successful connection test for activity logs."""

        mock_params = {
            "client_id": "test_client_id",
            "secret": "test_secret",
            "auth_code": "test_auth_code",
            "board_ids": "123,456",
            "activity_logs_url": "https://api.monday.com",
        }
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        # Mock ActivityLogsClient with required attributes
        mock_activity_client = mocker.MagicMock()
        mock_activity_client.client_id = "test_client_id"
        mock_activity_client.client_secret = "test_secret"
        mock_activity_client.auth_code = "test_auth_code"

        # Mock AuditLogsClient with required attributes
        mock_audit_client = mocker.MagicMock()
        mock_audit_client.audit_token = ""
        mock_audit_client.audit_logs_url = ""

        # Mock the client initialization functions
        mocker.patch("MondayEventCollector.initiate_activity_client", return_value=mock_activity_client)
        mocker.patch("MondayEventCollector.initiate_audit_client", return_value=mock_audit_client)

        # Mock get_integration_context to return access token
        mocker.patch("MondayEventCollector.get_integration_context", return_value={"access_token": {"password": "test_token"}})

        # Mock get_activity_logs to simulate successful fetch
        mocker.patch("MondayEventCollector.get_activity_logs", return_value=([{"id": "test_log"}], {}))

        result = monday_test_connection()

        assert "Test connection success for activity logs" in result.readable_output

    def test_test_connection_audit_logs_success(self, mocker):
        """Test successful connection test for audit logs."""

        mock_params = {"audit_token": "test_audit_token", "audit_logs_url": "https://test.monday.com"}
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        # Mock ActivityLogsClient with empty attributes (will fail activity logs test)
        mock_activity_client = mocker.MagicMock()
        mock_activity_client.client_id = ""
        mock_activity_client.client_secret = ""

        # Mock AuditLogsClient with required attributes
        mock_audit_client = mocker.MagicMock()
        mock_audit_client.audit_token = "test_audit_token"
        mock_audit_client.audit_logs_url = "https://test.monday.com"

        # Mock the client initialization functions
        mocker.patch("MondayEventCollector.initiate_activity_client", return_value=mock_activity_client)
        mocker.patch("MondayEventCollector.initiate_audit_client", return_value=mock_audit_client)

        # Mock get_audit_logs to simulate successful fetch
        mocker.patch("MondayEventCollector.get_audit_logs", return_value=([{"timestamp": "2024-01-01T00:00:00.000Z"}], {}))

        result = monday_test_connection()

        assert "Test connection success for audit logs" in result.readable_output

    def test_test_connection_missing_params(self, mocker):
        """Test connection test with missing parameters."""
        # Using the renamed import monday_test_connection

        mock_params = {}  # No parameters provided
        mocker.patch.object(demisto, "params", return_value=mock_params)
        mocker.patch.object(demisto, "debug")

        result = monday_test_connection()

        assert "Please provide" in result.readable_output
        assert "to test connection" in result.readable_output

    def test_subtract_epsilon_from_timestamp(self):
        """Test timestamp epsilon subtraction utility function."""

        timestamp = "2024-06-03T14:25:47.000Z"
        result = subtract_epsilon_from_timestamp(timestamp)
        assert result == "2024-06-03T14:25:46.999000Z"

        timestamp = "2024-06-03T14:25:00.000Z"
        result = subtract_epsilon_from_timestamp(timestamp)
        assert result == "2024-06-03T14:24:59.999000Z"

        timestamp = "2024-06-03T14:00:00.000Z"
        result = subtract_epsilon_from_timestamp(timestamp)
        assert result == "2024-06-03T13:59:59.999000Z"
