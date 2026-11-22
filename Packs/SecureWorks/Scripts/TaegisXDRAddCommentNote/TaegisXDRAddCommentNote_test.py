import demistomock as demisto
from TaegisXDRAddCommentNote import _current_user, _format_comment, _is_truthy, main


def test_is_truthy_true_values():
    assert _is_truthy(True) is True
    assert _is_truthy("true") is True
    assert _is_truthy("Yes") is True
    assert _is_truthy("1") is True


def test_is_truthy_false_values():
    assert _is_truthy(False) is False
    assert _is_truthy("no") is False
    assert _is_truthy("") is False
    assert _is_truthy(None) is False


def test_format_comment_with_user():
    result = _format_comment("hello", "alice")
    assert result.startswith("alice — ")
    assert result.endswith("\n\nhello")


def test_format_comment_without_user():
    assert _format_comment("hello", "") == "hello"


def test_current_user_from_calling_context(mocker):
    mocker.patch.object(demisto, "callingContext", {"context": {"User": {"name": "alice"}}})
    assert _current_user() == "alice"


def test_current_user_fallback_to_parent_entry(mocker):
    mocker.patch.object(demisto, "callingContext", {})
    mocker.patch.object(demisto, "parentEntry", return_value={"user": "bob"})
    assert _current_user() == "bob"


def test_main_no_note_returns_prompt(mocker):
    mocker.patch.object(demisto, "args", return_value={"note": ""})
    return_results_mock = mocker.patch("TaegisXDRAddCommentNote.return_results")

    main()

    entries = return_results_mock.call_args[0][0]
    assert "No comment text provided" in entries[0]["Contents"]


def test_main_adds_comment_without_assign(mocker):
    mocker.patch.object(demisto, "args", return_value={"note": "investigating now"})
    mocker.patch.object(demisto, "callingContext", {"context": {"User": {"name": "alice"}}})
    return_results_mock = mocker.patch("TaegisXDRAddCommentNote.return_results")
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")

    main()

    entries = return_results_mock.call_args[0][0]
    assert "investigating now" in entries[0]["Contents"]
    assert entries[0]["Tags"] == ["xdrcomment"]
    execute_command_mock.assert_not_called()


def test_main_assign_without_investigation_id(mocker):
    mocker.patch.object(demisto, "args", return_value={"note": "note text", "assign_case_to_sophos": "Yes"})
    mocker.patch.object(demisto, "callingContext", {})
    mocker.patch.object(demisto, "incident", return_value={})
    return_results_mock = mocker.patch("TaegisXDRAddCommentNote.return_results")

    main()

    last_entries = return_results_mock.call_args[0][0]
    assert "not mirrored from Taegis" in last_entries[0]["Contents"]


def test_main_assign_success(mocker):
    mocker.patch.object(demisto, "args", return_value={"note": "note text", "assign_case_to_sophos": "Yes"})
    mocker.patch.object(demisto, "callingContext", {})
    mocker.patch.object(demisto, "incident", return_value={"dbotMirrorId": "inv-123"})
    execute_command_mock = mocker.patch.object(demisto, "executeCommand")
    return_results_mock = mocker.patch("TaegisXDRAddCommentNote.return_results")

    main()

    execute_command_mock.assert_called_once_with(
        "taegis-push-assignee-status",
        {"id": "inv-123", "assignee_id": "@secureworks", "status": "AWAITING_ACTION"},
    )
    last_entries = return_results_mock.call_args[0][0]
    assert "assigned to Sophos MDR team" in last_entries[0]["Contents"]


def test_main_assign_failure(mocker):
    mocker.patch.object(demisto, "args", return_value={"note": "note text", "assign_case_to_sophos": "Yes"})
    mocker.patch.object(demisto, "callingContext", {})
    mocker.patch.object(demisto, "incident", return_value={"dbotMirrorId": "inv-123"})
    mocker.patch.object(demisto, "executeCommand", side_effect=Exception("boom"))
    return_results_mock = mocker.patch("TaegisXDRAddCommentNote.return_results")

    main()

    last_entries = return_results_mock.call_args[0][0]
    assert "Could not assign to Sophos MDR team: boom" in last_entries[0]["Contents"]
