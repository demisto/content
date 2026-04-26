import pytest
import demistomock as demisto
from JiraCallCoreGetIssues import build_args, call_core_get_issues


MOCK_ISSUE = {
    "internal_id": "issue-123",
    "issue_name": "Test Issue",
    "severity": "high",
    "status": {"progress": "New"},
    "issue_domain": "Security",
    "issue_source": "XDR Agent",
    "starred": False,
    "assigned_to": "user@example.com",
    "assigned_to_pretty": "Test User",
}

MOCK_ENTRY = {
    "Type": 1,
    "Contents": {"reply": {"issues": [MOCK_ISSUE], "total_count": 1}},
    "ContentsFormat": "json",
    "HumanReadable": "Issues found",
    "EntryContext": {"Core.Issue": [MOCK_ISSUE]},
}


class TestBuildArgs:
    def test_build_args_with_all_basic_filters(self):
        args = {
            "issue_id": "issue-123",
            "severity": "high",
            "status": "New",
            "issue_domain": "Security",
        }
        result = build_args(args)
        assert result["issue_id"] == "issue-123"
        assert result["severity"] == "high"
        assert result["status"] == "New"
        assert result["issue_domain"] == "Security"

    def test_build_args_excludes_none_values(self):
        args = {
            "issue_id": "issue-123",
            "severity": None,
        }
        result = build_args(args)
        assert "issue_id" in result
        assert "severity" not in result

    def test_build_args_empty_args(self):
        result = build_args({})
        assert result == {}

    def test_build_args_with_pagination(self):
        args = {"page": "2", "page_size": "25"}
        result = build_args(args)
        assert result["page"] == "2"
        assert result["page_size"] == "25"

    def test_build_args_with_custom_filter(self):
        custom_filter = '{"OR": [{"SEARCH_FIELD": "severity", "SEARCH_TYPE": "EQ", "SEARCH_VALUE": "high"}]}'
        args = {"custom_filter": custom_filter}
        result = build_args(args)
        assert result["custom_filter"] == custom_filter

    def test_build_args_with_time_range(self):
        args = {"start_time": "2024-01-01T00:00:00", "end_time": "2024-01-31T23:59:59"}
        result = build_args(args)
        assert result["start_time"] == "2024-01-01T00:00:00"
        assert result["end_time"] == "2024-01-31T23:59:59"

    def test_build_args_with_sort(self):
        args = {"sort_field": "severity", "sort_order": "DESC"}
        result = build_args(args)
        assert result["sort_field"] == "severity"
        assert result["sort_order"] == "DESC"

    def test_build_args_with_assignee(self):
        args = {"assignee": "user@example.com"}
        result = build_args(args)
        assert result["assignee"] == "user@example.com"

    def test_build_args_with_starred(self):
        args = {"starred": "true"}
        result = build_args(args)
        assert result["starred"] == "true"

    def test_build_args_with_sha256_filters(self):
        args = {
            "actor_process_image_sha256": "abc123",
            "action_file_macro_sha256": "def456",
            "os_actor_process_image_sha256": "ghi789",
        }
        result = build_args(args)
        assert result["actor_process_image_sha256"] == "abc123"
        assert result["action_file_macro_sha256"] == "def456"
        assert result["os_actor_process_image_sha256"] == "ghi789"

    def test_build_args_with_network_filters(self):
        args = {
            "host_ip": "192.168.1.1",
            "action_local_ip": "10.0.0.1",
            "action_remote_ip": "8.8.8.8",
            "action_local_port": "443",
            "action_remote_port": "80",
        }
        result = build_args(args)
        assert result["host_ip"] == "192.168.1.1"
        assert result["action_local_ip"] == "10.0.0.1"
        assert result["action_remote_ip"] == "8.8.8.8"
        assert result["action_local_port"] == "443"
        assert result["action_remote_port"] == "80"

    def test_build_args_with_mitre(self):
        args = {"mitre_technique_id_and_name": "T1059 - Command and Scripting Interpreter"}
        result = build_args(args)
        assert result["mitre_technique_id_and_name"] == "T1059 - Command and Scripting Interpreter"

    def test_build_args_with_output_keys(self):
        args = {"output_keys": "internal_id,severity,status"}
        result = build_args(args)
        assert result["output_keys"] == "internal_id,severity,status"


class TestCallCoreGetIssues:
    def test_call_core_get_issues_success(self, mocker):
        mocker.patch.object(demisto, "executeCommand", return_value=[MOCK_ENTRY])
        result = call_core_get_issues({"severity": "high"})
        assert result == [MOCK_ENTRY]
        demisto.executeCommand.assert_called_once_with(
            "core-get-issues", {"severity": "high"}
        )

    def test_call_core_get_issues_empty_args(self, mocker):
        mocker.patch.object(demisto, "executeCommand", return_value=[MOCK_ENTRY])
        result = call_core_get_issues({})
        assert result == [MOCK_ENTRY]
        demisto.executeCommand.assert_called_once_with("core-get-issues", {})

    def test_call_core_get_issues_raises_on_none_response(self, mocker):
        mocker.patch.object(demisto, "executeCommand", return_value=None)
        with pytest.raises(Exception, match="Unexpected response"):
            call_core_get_issues({})

    def test_call_core_get_issues_raises_on_non_list_response(self, mocker):
        mocker.patch.object(demisto, "executeCommand", return_value="bad response")
        with pytest.raises(Exception, match="Unexpected response"):
            call_core_get_issues({})

    def test_call_core_get_issues_raises_on_error_entry(self, mocker):
        error_entry = {
            "Type": 4,
            "Contents": "Permission denied",
            "ContentsFormat": "text",
        }
        mocker.patch.object(demisto, "executeCommand", return_value=[error_entry])
        with pytest.raises(Exception, match="Error returned from core-get-issues"):
            call_core_get_issues({})

    def test_call_core_get_issues_with_multiple_filters(self, mocker):
        mocker.patch.object(demisto, "executeCommand", return_value=[MOCK_ENTRY])
        args = {
            "severity": "high",
            "status": "New",
            "issue_domain": "Security",
            "page": "0",
            "page_size": "10",
        }
        result = call_core_get_issues(args)
        assert result == [MOCK_ENTRY]
        demisto.executeCommand.assert_called_once_with(
            "core-get-issues",
            {
                "severity": "high",
                "status": "New",
                "issue_domain": "Security",
                "page": "0",
                "page_size": "10",
            },
        )
