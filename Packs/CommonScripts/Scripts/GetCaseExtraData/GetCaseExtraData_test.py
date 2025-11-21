from GetCaseExtraData import extract_ids, get_case_extra_data, main


def test_extract_ids_dict():
    """
    GIVEN a dictionary with and without the target field
    WHEN extract_ids is called
    THEN it returns a list with the field value if present, otherwise an empty list
    """
    d = {"issue_id": "1", "foo": "bar"}
    assert extract_ids(d, "issue_id") == ["1"]
    assert extract_ids(d, "missing") == []


def test_extract_ids_dict_missing_field():
    """
    GIVEN a dictionary missing the target field
    WHEN extract_ids is called
    THEN it returns an empty list
    """
    d = {"foo": "bar"}
    assert extract_ids(d, "issue_id") == []


def test_extract_ids_list():
    """
    GIVEN a list of dicts, some with and some without the target field
    WHEN extract_ids is called
    THEN it returns a list of all values for the field from the dicts
    """
    lst = [{"issue_id": "1"}, {"issue_id": "2"}, {"foo": "bar"}, "not_a_dict"]
    assert extract_ids(lst, "issue_id") == ["1", "2"]


def test_extract_ids_list_empty_dicts():
    """
    GIVEN a list of empty dicts
    WHEN extract_ids is called
    THEN it returns an empty list
    """
    lst = [{}, {}]
    assert extract_ids(lst, "issue_id") == []


def test_extract_ids_empty_and_none():
    """
    GIVEN None, an empty list, or a non-dict/non-list
    WHEN extract_ids is called
    THEN it returns an empty list
    """
    assert extract_ids([], "issue_id") == []
    assert extract_ids(None, "issue_id") == []
    assert extract_ids("not_a_dict", "issue_id") == []


def test_get_case_extra_data(mocker):
    """
    GIVEN a valid response from execute_command with all fields present
    WHEN get_case_extra_data is called
    THEN it returns a case dict with all expected keys and values
    """
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
    """
    GIVEN a response from execute_command with no issues key
    WHEN get_case_extra_data is called
    THEN it returns a case dict with empty issue_ids
    """
    mocker.patch("GetCaseExtraData.execute_command", return_value={"case": {"case_id": "2"}})
    args = {"case_id": "2", "issues_limit": "5"}
    result = get_case_extra_data(args)
    assert result["case_id"] == "2"
    assert result["issue_ids"] == []


def test_get_case_extra_data_no_case(mocker):
    """
    GIVEN a response from execute_command with no case key
    WHEN get_case_extra_data is called
    THEN it returns a dict with empty issue_ids
    """
    mocker.patch("GetCaseExtraData.execute_command", return_value={})
    args = {"case_id": "3", "issues_limit": "5"}
    result = get_case_extra_data(args)
    assert "issue_ids" in result
    assert result["issue_ids"] == []


def test_get_case_extra_data_missing_fields(mocker):
    """
    GIVEN a response from execute_command missing issues and artifact fields
    WHEN get_case_extra_data is called
    THEN it returns a case dict with empty or None for missing fields
    """
    mocker.patch("GetCaseExtraData.execute_command", return_value={"case": {}})
    args = {"case_id": "1", "issues_limit": "10"}
    result = get_case_extra_data(args)
    assert "issue_ids" in result
    assert result["issue_ids"] == []
    assert result["network_artifacts"] is None
    assert result["file_artifacts"] is None


def test_main_success(mocker):
    """
    GIVEN valid demisto.args and get_case_extra_data returns a valid dict
    WHEN main is called
    THEN return_results is called with the expected output
    """
    mocker.patch("demistomock.args", return_value={"case_id": "1", "issues_limit": "10"})
    mocker.patch("GetCaseExtraData.get_case_extra_data", return_value={"case_id": "1"})
    mocked_return_results = mocker.patch("GetCaseExtraData.return_results")
    main()
    mocked_return_results.assert_called()


def test_main_error(mocker):
    """
    GIVEN get_case_extra_data raises an exception
    WHEN main is called
    THEN return_error is called
    """
    mocker.patch("demistomock.args", return_value={"case_id": "1", "issues_limit": "10"})
    mocker.patch("GetCaseExtraData.get_case_extra_data", side_effect=Exception("fail"))
    mocked_return_error = mocker.patch("GetCaseExtraData.return_error")
    main()
    mocked_return_error.assert_called()
