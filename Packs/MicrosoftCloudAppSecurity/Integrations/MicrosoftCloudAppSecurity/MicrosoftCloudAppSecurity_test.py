import pytest
from CommonServerPython import *


RETURN_ERROR_TARGET = 'GetListRow.return_error'


@pytest.mark.parametrize(
    "severity, expected",
    [
        ("Low", 0),
        ("Medium", 1),
        ("High", 2),
    ]
)
def test_convert_severity(severity, expected):
    from MicrosoftCloudAppSecurity import convert_severity
    res = convert_severity(severity)
    assert res == expected


@pytest.mark.parametrize(
    "resolution_status, expected",
    [
        ("Low", 0),
        ("Medium", 1),
        ("High", 2)
    ]
)
def test_convert_resolution_status(resolution_status, expected):
    from MicrosoftCloudAppSecurity import convert_resolution_status
    res = convert_resolution_status(resolution_status)
    assert res == expected


@pytest.mark.parametrize(
    "source, expected",
    [
        ("Access_control", 0),
        ("Session_control", 1),
        ("App_connector", 2),
        ("App_connector_analysis", 3),
        ("Discovery", 5),
        ("MDATP", 6)
    ]
)
def test_convert_source_type(source, expected):
    from MicrosoftCloudAppSecurity import convert_source_type
    res = convert_source_type(source)
    assert res == expected


@pytest.mark.parametrize(
    "file_type, expected",
    [
        ("Other", 0),
        ("Document", 1),
        ("Spreadsheet", 2),
        ("Presentation", 3),
        ("Text", 4),
        ("Image", 5),
        ("Folder", 6)

    ]
)
def test_convert_file_type(file_type, expected):
    from MicrosoftCloudAppSecurity import convert_file_type
    res = convert_file_type(file_type)
    assert res == expected


@pytest.mark.parametrize(
    "file_sharing, expected",
    [
        ("Private", 0),
        ("Internal", 1),
        ("External", 2),
        ("Public", 3),
        ("Public_Internet", 4)
    ]
)
def test_convert_file_sharing(file_sharing, expected):
    from MicrosoftCloudAppSecurity import convert_file_sharing
    res = convert_file_sharing(file_sharing)
    assert res == expected


@pytest.mark.parametrize(
    "ip_category, expected",
    [
        ("Corporate", 1),
        ("Administrative", 2),
        ("Risky", 3),
        ("VPN", 4),
        ("Cloud_provider", 5),
        ("Other", 6)
    ]
)
def test_convert_ip_category(ip_category, expected):
    from MicrosoftCloudAppSecurity import convert_ip_category
    res = convert_ip_category(ip_category)
    assert res == expected


@pytest.mark.parametrize(
    "is_external, expected",
    [
        ("External", True),
        ("Internal", False),
        ("No_value", None)
    ]
)
def test_convert_is_external(is_external, expected):
    from MicrosoftCloudAppSecurity import convert_is_external
    res = convert_is_external(is_external)
    assert res == expected


@pytest.mark.parametrize(
    "status, expected",
    [
        ("N/A", 0),
        ("Staged", 1),
        ("Active", 2),
        ("Suspended", 3),
        ("Deleted", 4)
    ]
)
def test_convert_status(status, expected):
    from MicrosoftCloudAppSecurity import convert_status
    res = convert_status(status)
    assert res == expected















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
