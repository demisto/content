import pytest
import time
from unittest.mock import MagicMock
from MondayEventCollector import get_audit_logs, DemistoException, generate_log_hash, subtract_epsilon_from_timestamp
import demistomock as demisto  # noqa: F401
from CommonServerPython import *



class TestGetAuditLogs:
    """
        - When limit ≤ 1000 -> per_page = limit -> fetch full page, remaining logs mechanism is not used.
        - When limit > 1000 -> per_page = 1000 -> fetch partial page, remaining logs mechanism is used.
        
        CRITICAL: per_page is ALWAYS constant during all the fetch audit logs runs.
    """
    
    def test_get_audit_logs_with_continuing_fetch_limit_less_than_1000(self, mocker):
        """
        Given:
            more then limit logs available in the time range
            - limit <= 1000 (limit=8)
            - next_page is not None (next_page=2)
              
        When:
            get_audit_logs is called with per_page=8 (since limit <= 1000).
        Then:
            It should fetch exactly 8 logs in one request and set continuing_fetch_info for remaining logs.
        """
        limit = 8   # limit <= 1000
        mocker.patch('MondayEventCollector.AUDIT_LOGS_PER_PAGE', limit)
        
        mock_params = {
            "audit_logs_url": "https://test.monday.com",
            "audit_token": "test_token",
        }
        mocker.patch.object(demisto, 'params', return_value=mock_params)
        mocker.patch.object(demisto, 'debug')
        
        
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
            {"timestamp": "2024-06-03T13:55:47.000Z", "account_id": 8, "event": "logout"}
        ]
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": page1_logs,
            "page": 1,
            "per_page": limit,
            "next_page": 2  # More pages available
        }
        
        mock_requests_get = mocker.patch('MondayEventCollector.requests.get', return_value=mock_response)
        mock_timestamp_to_datestring = mocker.patch('MondayEventCollector.timestamp_to_datestring')
        mock_timestamp_to_datestring.return_value = "2024-06-03T15:00:00.000Z"
        

        # Initial state - first fetch
        initial_last_run = {}
        now_ms = int(time.time() * 1000)
        
        result_logs, result_last_run = get_audit_logs(initial_last_run, now_ms, limit)
        
        assert len(result_logs) == limit
        assert result_last_run["last_timestamp"] == page1_logs[0]["timestamp"]
        assert result_last_run["upper_bound_log_id"] == [generate_log_hash(page1_logs[0]), generate_log_hash(page1_logs[1])] # Two newest logs with same timestamp 
        assert result_last_run["continuing_fetch_info"] is not None  # More pages available
        assert result_last_run["continuing_fetch_info"]["page"] == 2
        
        # Verify only 1 request was made (limit reached <= 1000)
        assert mock_requests_get.call_count == 1
        
        # Verify request used per_page = limit (limit <= 1000)
        call_params = mock_requests_get.call_args[1]['params']
        assert call_params['per_page'] == limit
        
        
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
            {"timestamp": "2024-06-03T13:15:47.000Z", "account_id": 16, "event": "logout"}
        ]
        
        mock_response_page2 = MagicMock()
        mock_response_page2.status_code = 200
        mock_response_page2.json.return_value = {
            "data": page2_logs,
            "page": 2,
            "per_page": limit,
            "next_page": None  # No more pages available
        }
        
        # Reset mock to return page 2 response
        mock_requests_get.return_value = mock_response_page2
        mock_requests_get.reset_mock()
        
        # Use the last_run received from the previous fetch
        previous_last_timestamp = result_last_run["last_timestamp"]
        previous_upper_bound_log_id = result_last_run["upper_bound_log_id"]
        continuing_last_run = result_last_run
        
        result_logs_2, result_last_run_2 = get_audit_logs(continuing_last_run, now_ms, limit)

        assert len(result_logs_2) == limit
        
        # Validate timestamps are in descending order (newest first)
        timestamps = [log["timestamp"] for log in result_logs_2]
        assert timestamps == sorted(timestamps, reverse=True)
        
        # Validate last_run state after continuing fetch
        assert result_last_run_2["last_timestamp"] == previous_last_timestamp  # last_timestamp does not change until new fetch starts (page=1)
        assert result_last_run_2["upper_bound_log_id"] == previous_upper_bound_log_id  # upper_bound_log_id does not change until new fetch starts (page=1)
        assert result_last_run_2["continuing_fetch_info"] is None  # No more pages available
        assert result_last_run_2["upper_bound_log_id"] == result_last_run_2["lower_bound_log_id"] # on the last page, upper_bound_log_id set to lower_bound_log_id for the next fetch
        
        # Validate API call parameters
        assert mock_requests_get.call_count == 1
        call_params_2 = mock_requests_get.call_args[1]['params']
        assert call_params_2['page'] == 2  # Should use page from continuing_fetch_info
        assert call_params_2['per_page'] == limit
        
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
            
            # These logs have same timestamp as last_timestamp but different account_ids (should be included)
            {"timestamp": last_timestamp, "account_id": 101, "event": "login"},   # New log with same timestamp
            {"timestamp": last_timestamp, "account_id": 102, "event": "logout"},  # New log with same timestamp
            
            # These would be duplicates from previous fetch (should be filtered out by upper_bound_log_id, same timestamp as last_timestamp)
            page1_logs[0],     # Duplicate (account_id=1 was in upper_bound)
            page1_logs[1],     # Duplicate (account_id=2 was in upper_bound)
        ]
        
        mock_response_page1_new_fetch = MagicMock()
        mock_response_page1_new_fetch.status_code = 200
        mock_response_page1_new_fetch.json.return_value = {
            "data": page1_logs_new_fetch,
            "page": 1,  # New fetch starts from page 1
            "per_page": limit,
            "next_page": None  # No more pages
        }
        
        # Reset mock for third fetch
        mock_requests_get.return_value = mock_response_page1_new_fetch
        mock_requests_get.reset_mock()
        
        # Use the last_run received from the previous fetch
        new_fetch_last_run = result_last_run_2
        
        result_logs_3, result_last_run_3 = get_audit_logs(new_fetch_last_run, now_ms, limit)
        
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
        
        # Validate new last_run state
        assert result_last_run_3["last_timestamp"] == page1_logs_new_fetch[0]["timestamp"]  # last_timestamp should be the newest timestamp
        assert result_last_run_3["continuing_fetch_info"] is None  # No more pages
        
        # Validate API call
        assert mock_requests_get.call_count == 1
        call_params_3 = mock_requests_get.call_args[1]['params']
        assert call_params_3['page'] == 1  # New fetch starts from page 1
        assert call_params_3['per_page'] == limit
        
        # Verify start_time filter includes epsilon adjustment
        filters = eval(call_params_3['filters'])  # Parse the JSON string
        assert filters['start_time'] == subtract_epsilon_from_timestamp(last_timestamp)  # Should be last_timestamp - epsilon