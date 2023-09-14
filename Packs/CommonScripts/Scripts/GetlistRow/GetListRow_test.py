import pytest
from CommonServerPython import *

RETURN_ERROR_TARGET = 'GetListRow.return_error'
DATA_WITH_CUSTOM_SEP = [{"Contents": "name;id\nname1;id1\nname2;id2"}]
DATA_WITH_NEW_LINE_SEP = [{"Contents": "name\nid\nname1\nid1\nname2\nid2"}]
DATA_WITH_TAB_SEP = [{"Contents": "name	id\nname1	id1\nname2	id2"}]
DATA_WITH_TAB_SEP_2 = [{"Contents": "name\tid\nname1\tid1\nname2\tid2"}]


@pytest.mark.parametrize(
    "parse_all, header, value, expected",
    [
        ("True", "", "", 0),
        ("true", "", "test", 0),
        ("False", "", "test", 1),
        ("False", "", "", 1),
        ("False", "test", "test", 0)
    ]
)
def test_validate_args(mocker, parse_all, header, value, expected):
    from GetListRow import validate_args
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    validate_args(parse_all, header, value)
    assert return_error_mock.call_count == expected


@pytest.mark.parametrize(
    "list_result, expected",
    [
        ("False", 0),
        ("id, name, status, title", 0),
        ("Item not found", 1),
        ("", 1)
    ]
)
def test_does_list_exist(mocker, list_result, expected):
    from GetListRow import validate_list_exists
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    validate_list_exists(list_result)
    assert return_error_mock.call_count == expected


@pytest.mark.parametrize(
    "headers, header, expected",
    [
        (['id', 'name', 'title', 'status'], 'id', 0),
        (['id', 'name', 'title', 'status'], 'status', 0),
        (['id', 'name', 'title', 'status'], "statu", 1),
        (['id', 'name'], "title", 1)
    ]
)
def test_does_header_exist(mocker, headers, header, expected):
    from GetListRow import validate_header_exists
    return_error_mock = mocker.patch(RETURN_ERROR_TARGET)
    validate_header_exists(headers, header)
    assert return_error_mock.call_count == expected


@pytest.mark.parametrize(
    "parse_all, header, value, list_name, list_separator, expected",
    [
        ("True", "", "on", "getListRow", ',', "List Result"),
        ("False", "status", "on", "getListRow", ',', "List Result"),
        ("False", "status", "n", "getListRow", ',', "No results found")
    ]
)
def test_parse_list(mocker, parse_all, header, value, list_name, list_separator, expected):
    from GetListRow import parse_list
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": '''id,name,title,status
                                                                  1,Chanoch,junior,on
                                                                  2,Or,manager,off
                                                                  3,Chen,developer,on'''}])
    res = parse_list(parse_all, header, value, list_name, list_separator)
    assert expected in res.readable_output


@pytest.mark.parametrize(
    "data, parse_all, header, value, list_name, list_separator, expected",
    [
        (DATA_WITH_CUSTOM_SEP, "True", "name", "id", "getListRow", ';',
         [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]),
        (DATA_WITH_CUSTOM_SEP, "False", "name", "name2", "getListRow", ';', [{'name': 'name2', 'id': 'id2'}])
    ]
)
def test_custom_list_separator(mocker, data, parse_all, header, value, list_name, list_separator, expected):
    """
    Given:
        - Data that should be split by the custom separator ';'.
    When:
        - Running the script with a custom separator arg
    Then:
        - Ensure the parsed sata was split correctly
    """
    from GetListRow import parse_list
    mocker.patch.object(demisto, "executeCommand", return_value=data)
    res = parse_list(parse_all, header, value, list_name, list_separator)
    assert res.outputs.get('Results') == expected


@pytest.mark.parametrize(
    "data, parse_all, header, value, list_name, list_separator, expected",
    [
        (DATA_WITH_NEW_LINE_SEP, "True", "name", "id", "getListRow", '\n',
         [{'name': 'id'}, {'name': 'name1'}, {'name': 'id1'}, {'name': 'name2'}, {'name': 'id2'}]),
        (DATA_WITH_NEW_LINE_SEP, "False", "name", "name2", "getListRow", '\n', [{'name': 'name2'}])
    ]
)
def test_custom_list_new_line_sep(mocker, data, parse_all, header, value, list_name, list_separator, expected):
    """
    Given:
        - Data that should be split by the custom separator '\n'.
    When:
        - Running the script with a custom separator arg
    Then:
        - Ensure the parsed sata was split correctly
    """
    from GetListRow import parse_list
    mocker.patch.object(demisto, "executeCommand", return_value=data)
    res = parse_list(parse_all, header, value, list_name, list_separator)
    assert res.outputs.get('Results') == expected


@pytest.mark.parametrize(
    "data, parse_all, header, value, list_name, list_separator, expected",
    [
        (DATA_WITH_TAB_SEP, "True", "name", "id", "getListRow", '\t',
         [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]),
        (DATA_WITH_TAB_SEP, "False", "name", "name2", "getListRow", '	', [{'name': 'name2', 'id': 'id2'}]),
        (DATA_WITH_TAB_SEP_2, "True", "name", "id", "getListRow", '\\t',
         [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]),
        (DATA_WITH_TAB_SEP_2, "True", "name", "id", "getListRow", '\t',
         [{'name': 'name1', 'id': 'id1'}, {'name': 'name2', 'id': 'id2'}]),
    ]
)
def test_custom_list_tab_sep(mocker, data, parse_all, header, value, list_name, list_separator, expected):
    """
    Given:
        - Data that should be split by the tab separator (' ').
    When:
        - Running the script with a custom separator arg
    Then:
        - Ensure the parsed sata was split correctly
    """
    import GetListRow

    mock_args = {
        'list_name': list_name,
        'parse_all': parse_all,
        'header': header,
        'value': value,
        'list_separator': list_separator
    }
    mocker.patch.object(demisto, "args", return_value=mock_args)
    mocker.patch.object(demisto, "executeCommand", return_value=data)
    mocker.patch.object(GetListRow, "return_results", return_value=data)

    GetListRow.main()

    assert GetListRow.return_results.call_args[0][0].outputs.get('Results') == expected


@pytest.mark.parametrize(
    "data, parse_all, header, value, expected_context_key",
    [
        (DATA_WITH_NEW_LINE_SEP, "True", "name", "id", ['list_name', 'parse_all']),
        (DATA_WITH_NEW_LINE_SEP, "False", "name", "name2", ['list_name', 'parse_all', 'header', 'value'])
    ]
)
def test_context_path_are_correct(mocker, data, parse_all, header, value, expected_context_key):
    from GetListRow import parse_list
    mocker.patch.object(demisto, "executeCommand", return_value=data)
    res = parse_list(parse_all, header, value, list_name="getListRow", list_separator='\n')
    assert res.outputs_prefix == 'GetListRow'
    assert res.outputs_key_field == expected_context_key
