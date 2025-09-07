import demistomock as demisto
from GetCaseExtraData import extract_ids, get_case_extra_data, main


def test_extract_ids_dict():
    d = {"issue_id": "1", "foo": "bar"}
    assert extract_ids(d, "issue_id") == ["1"]
    assert extract_ids(d, "missing") == []


def test_extract_ids_list():
    lst = [{"issue_id": "1"}, {"issue_id": "2"}, {"foo": "bar"}, "not_a_dict"]
    assert extract_ids(lst, "issue_id") == ["1", "2"]


def test_extract_ids_empty_and_none():
    assert extract_ids([], "issue_id") == []
    assert extract_ids(None, "issue_id") == []
    assert extract_ids("not_a_dict", "issue_id") == []


def test_get_case_extra_data(mocker):
    mocker.patch(
        "GetCaseExtraData.execute_command",
        return_value={
            "case": {"case_id": "1", "foo": "bar"},
            "issues": {"data": [{"issue_id": "i1"}, {"issue_id": "i2"}]},
            "network_artifacts": ["net"],
            "file_artifacts": ["file"],
        },
    )
    args = {"case_id": "1", "issues_limit": "10"}
    result = get_case_extra_data(args)
    assert result["case_id"] == "1"
    assert result["issue_ids"] == ["i1", "i2"]
    assert result["network_artifacts"] == ["net"]
    assert result["file_artifacts"] == ["file"]


def test_get_case_extra_data_missing_fields(mocker):
    mocker.patch("GetCaseExtraData.execute_command", return_value={"case": {}})
    args = {"case_id": "1", "issues_limit": "10"}
    result = get_case_extra_data(args)
    assert "issue_ids" in result
    assert result["issue_ids"] == []
    assert result["network_artifacts"] is None
    assert result["file_artifacts"] is None


def test_main_success(mocker):
    mocker.patch.object(demisto, "args", return_value={"case_id": "1", "issues_limit": 5})
    mocker.patch("GetCaseExtraData.get_case_extra_data", return_value={"case_id": "1"})
    mocker.patch("GetCaseExtraData.return_results")
    mocker.patch("GetCaseExtraData.CommandResults")
    mocker.patch("GetCaseExtraData.tableToMarkdown", return_value="table")
    mocker.patch("GetCaseExtraData.string_to_table_header", side_effect=lambda x: x)
    main()
    GetCaseExtraData.return_results.assert_called()


def test_main_error(mocker):
    mocker.patch.object(demisto, "args", return_value={"case_id": "1", "issues_limit": 5})
    mocker.patch("GetCaseExtraData.get_case_extra_data", side_effect=Exception("fail"))
    mock_return_error = mocker.patch("GetCaseExtraData.return_error")
    main()
    assert mock_return_error.called
