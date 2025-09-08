from GetCaseExtraData import extract_ids, get_case_extra_data


def test_extract_ids_dict():
    d = {"issue_id": "1", "foo": "bar"}
    assert extract_ids(d, "issue_id") == ["1"]
    assert extract_ids(d, "missing") == []


def test_extract_ids_dict_missing_field():
    d = {"foo": "bar"}
    assert extract_ids(d, "issue_id") == []


def test_extract_ids_list():
    lst = [{"issue_id": "1"}, {"issue_id": "2"}, {"foo": "bar"}, "not_a_dict"]
    assert extract_ids(lst, "issue_id") == ["1", "2"]


def test_extract_ids_list_empty_dicts():
    lst = [{}, {}]
    assert extract_ids(lst, "issue_id") == []


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


def test_get_case_extra_data_no_issues(mocker):
    mocker.patch("GetCaseExtraData.execute_command", return_value={"case": {"case_id": "2"}})
    args = {"case_id": "2", "issues_limit": "5"}
    result = get_case_extra_data(args)
    assert result["case_id"] == "2"
    assert result["issue_ids"] == []


def test_get_case_extra_data_no_case(mocker):
    mocker.patch("GetCaseExtraData.execute_command", return_value={})
    args = {"case_id": "3", "issues_limit": "5"}
    result = get_case_extra_data(args)
    assert "issue_ids" in result
    assert result["issue_ids"] == []


def test_get_case_extra_data_missing_fields(mocker):
    mocker.patch("GetCaseExtraData.execute_command", return_value={"case": {}})
    args = {"case_id": "1", "issues_limit": "10"}
    result = get_case_extra_data(args)
    assert "issue_ids" in result
    assert result["issue_ids"] == []
    assert result["network_artifacts"] is None
    assert result["file_artifacts"] is None
