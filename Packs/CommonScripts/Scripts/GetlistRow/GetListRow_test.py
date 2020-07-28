import pytest
from CommonServerPython import *


RETURN_ERROR_TARGET = 'GetListRow.return_error'


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
    "parse_all, header, value, list_name, expected",
    [
        ("True", "", "on", "getListRow", "List Result"),
        ("False", "status", "on", "getListRow", "List Result"),
        ("False", "status", "n", "getListRow", "No results found")
    ]
)
def test_parse_list(mocker, parse_all, header, value, list_name, expected):
    from GetListRow import parse_list
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": '''id,name,title,status
                                                                  1,Chanoch,junior,on
                                                                  2,Or,manager,off
                                                                  3,Chen,developer,on'''}])
    res = parse_list(parse_all, header, value, list_name)
    assert expected in res.readable_output
