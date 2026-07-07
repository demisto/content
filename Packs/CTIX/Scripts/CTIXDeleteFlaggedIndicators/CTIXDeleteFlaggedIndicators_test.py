import demistomock as demisto
import pytest

from CTIXDeleteFlaggedIndicators import build_query, main

SUCCESS_ENTRY = [{"Type": 1, "Contents": "3 indicators deleted", "ContentsFormat": "text", "HumanReadable": None}]
ERROR_ENTRY = [{"Type": 4, "Contents": "deletion failed", "ContentsFormat": "text"}]


class TestBuildQuery:
    def test_no_flags_returns_empty(self):
        assert build_query({}) == ""
        assert build_query({"delete_deprecated": "false", "delete_revoked": "false"}) == ""

    def test_single_flag(self):
        query = build_query({"delete_deprecated": "true"})
        assert query == 'sourceBrands:"CTIX v3" and (isdeprecated:T)'

    def test_multiple_flags_or_combined(self):
        query = build_query({"delete_deprecated": "true", "delete_revoked": "true", "delete_whitelisted": "true"})
        assert query.startswith('sourceBrands:"CTIX v3" and (')
        assert "isdeprecated:T" in query
        assert "isrevoked:T" in query
        assert "iswhitelisted:T" in query
        assert "isfalsepositive" not in query
        assert query.count(" or ") == 2

    def test_all_flags(self):
        query = build_query(
            {
                "delete_deprecated": "true",
                "delete_revoked": "true",
                "delete_false_positive": "true",
                "delete_whitelisted": "true",
            }
        )
        for field in ("isdeprecated", "isrevoked", "isfalsepositive", "iswhitelisted"):
            assert f"{field}:T" in query


class TestMain:
    def test_no_flags_enabled_does_not_delete(self, mocker):
        """With every flag disabled, deleteIndicators must never be called."""
        mocker.patch.object(demisto, "args", return_value={"delete_deprecated": "false"})
        execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=SUCCESS_ENTRY)
        results_mock = mocker.patch.object(demisto, "results")

        main()

        execute_mock.assert_not_called()
        assert "No delete flags enabled" in str(results_mock.call_args[0][0])

    def test_delete_called_with_do_not_whitelist_true_by_default(self, mocker):
        """exclude defaults to false -> pure delete (doNotWhitelist=True)."""
        mocker.patch.object(demisto, "args", return_value={"delete_deprecated": "true"})
        execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=SUCCESS_ENTRY)
        mocker.patch.object(demisto, "results")

        main()

        command, command_args = execute_mock.call_args[0][0], execute_mock.call_args[0][1]
        assert command == "deleteIndicators"
        assert command_args["query"] == 'sourceBrands:"CTIX v3" and (isdeprecated:T)'
        assert command_args["doNotWhitelist"] is True
        assert command_args["reason"] == "Deleted by CTIXDeleteFlaggedIndicators job"

    def test_exclude_true_sets_do_not_whitelist_false(self, mocker):
        mocker.patch.object(
            demisto, "args", return_value={"delete_revoked": "true", "exclude": "true", "reason": "revoked by source"}
        )
        execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=SUCCESS_ENTRY)
        mocker.patch.object(demisto, "results")

        main()

        command_args = execute_mock.call_args[0][1]
        assert command_args["doNotWhitelist"] is False
        assert command_args["reason"] == "revoked by source"

    def test_error_from_delete_calls_return_error(self, mocker):
        mocker.patch.object(demisto, "args", return_value={"delete_deprecated": "true"})
        mocker.patch.object(demisto, "executeCommand", return_value=ERROR_ENTRY)
        mocker.patch.object(demisto, "error")
        error_mock = mocker.patch.object(demisto, "results")

        with pytest.raises(SystemExit):
            main()

        entry = error_mock.call_args[0][0]
        assert entry["Type"] == 4  # entryTypes['error']
        assert "Failed to execute CTIXDeleteFlaggedIndicators" in entry["Contents"]
