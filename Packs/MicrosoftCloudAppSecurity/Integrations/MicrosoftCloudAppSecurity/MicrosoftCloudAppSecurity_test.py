import pytest
from CommonServerPython import *
from MicrosoftCloudAppSecurity import Client


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
        ("Open", 0),
        ("Dismissed", 1),
        ("Resolved", 2)
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
    "string, expected",
    [
        ("True", True),
        ("False", False),
    ]
)
def test_str_to_bool(string, expected):
    from MicrosoftCloudAppSecurity import str_to_bool
    res = str_to_bool(string)
    assert res == expected


@pytest.mark.parametrize(
    "arg, expected",
    [
        ("3256754321", 3256754321),
        ("2020-03-20T14:28:23.382748", 1584707303),
        (2323248648.123, 2323248648)
    ]
)
def test_arg_to_timestamp(arg, expected):
    from MicrosoftCloudAppSecurity import arg_to_timestamp
    res = arg_to_timestamp(arg)
    assert res == expected


expected = {'filters': {'entity.service': {'eq': 111}, 'entity.instance': {'eq': 111}, 'severity': {'eq': 0},
                        'resolutionStatus': {'eq': 0}, 'entity.entity': {'eq':
                        {'id': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2', 'saas': 11161, 'inst': 0}}}, 'skip': 5,
            'limit': 10}
request_data = {"service": "111", "instance": "111", "severity": "Low", "resolution_status": "Open", "username":
                '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_alert(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_alert
    res = args_to_json_filter_list_alert(all_params)
    assert res == expected


expected = {'filters': {'service': {'eq': 111}, 'instance': {'eq': 111}, 'ip.address': {'eq': '8.8.8.8'},
                        'ip.category': {'eq': 1}, 'user.username': {'eq': 'dev@demistodev.onmicrosoft.com'},
                        'activity.takenAction': {'eq': 'block'}, 'source': {'eq': 0}}, 'skip': 5, 'limit': 10}
request_data = {"service": "111", "instance": "111", "ip": "8.8.8.8", "ip_category": "Corporate", "username":
                'dev@demistodev.onmicrosoft.com', 'taken_action': 'block', 'source': 'Access_control',
                "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_activity(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_activity
    res = args_to_json_filter_list_activity(all_params)
    assert res == expected


expected = {'filters': {'service': {'eq': 111}, 'instance': {'eq': 111}, 'fileType': {'eq': 0},
                        'quarantined': {'eq': True}, 'owner.entity':
                        {'eq': {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}},
                        'sharing': {'eq': 0}, 'extension': {'eq': 'png'}, }, 'skip': 5, 'limit': 10}
request_data = {"service": "111", "instance": "111", "file_type": "Other", "owner":
                '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "sharing": 'Private',
                'extension': 'png', 'quarantined': 'True', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_files(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_files
    res = args_to_json_filter_list_files(all_params)
    assert res == expected


expected = {'filters': {'app': {'eq': 111}, 'instance': {'eq': 111}, 'type': {'eq': 'user'},
                        'isExternal': {'eq': True}, 'status': {'eq': 0}, 'entity':
                        {'eq': {"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}},
                        'userGroups': {'eq': '1234'}, 'isAdmin': {'eq': 'demisto'}, }, 'skip': 5, 'limit': 10}
request_data = {"app": "111", "instance": "111", "type": "user", "status": 'N/A', "username":
                '{"id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2", "saas": 11161, "inst": 0}', "group_id": '1234',
                'is_admin': 'demisto', 'is_external': 'External', "skip": "5", "limit": "10"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_args_to_json_filter_list_users_accounts(all_params, expected):
    from MicrosoftCloudAppSecurity import args_to_json_filter_list_users_accounts
    res = args_to_json_filter_list_users_accounts(all_params)
    assert res == expected


@pytest.mark.parametrize(
    "alert_ids, customer_filters, comment, expected",
    [
        ("5f06d71dba4,289d0602ba5ac", '', '', {'filters': {'id': {'eq': ['5f06d71dba4', '289d0602ba5ac']}}}),
        ("5f06d71dba4", '', 'Irrelevant', {"comment": "Irrelevant", 'filters': {'id': {'eq': ['5f06d71dba4']}}}),
        ("", '{"filters": {"id": {"eq": ["5f06d71dba4"]}}}', "", {'filters': {'id': {'eq': ['5f06d71dba4']}}})
    ]
)
def test_args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment, expected):
    from MicrosoftCloudAppSecurity import args_to_json_dismiss_and_resolve_alerts
    res = args_to_json_dismiss_and_resolve_alerts(alert_ids, customer_filters, comment)
    assert res == expected


expected = {'entity.service': {'eq': 111}, 'entity.instance': {'eq': 111}, 'severity': {'eq': 0},
            'resolutionStatus': {'eq': 0}}
request_data = {"service": "111", "instance": "111", "severity": "Low", "resolution_status": "Open"}


@pytest.mark.parametrize(
    "all_params, expected",
    [
        (request_data, expected)
    ]
)
def test_params_to_filter(all_params, expected):
    from MicrosoftCloudAppSecurity import params_to_filter
    res = params_to_filter(all_params)
    assert res == expected


client_mocker = Client(base_url='url')


def test_alerts_list_command(mocker):
    from MicrosoftCloudAppSecurity import alerts_list_command
    mocker.patch.object(client_mocker, 'alert_list', return_value=ALERT_BY_ID_DATA)
    res = alerts_list_command(client_mocker, {'alert_id': '5f06d71dba4289d0602ba5ac'})
    assert res.readable_output == ALERT_BY_ID_DATA


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


ALERT_BY_ID_DATA = {
    "_id": "5f06d71dba4289d0602ba5ac",
    "timestamp": 1594283802753,
    "entities": [
        {
            "id": "5f01dce13de79160fbec4150",
            "label": "block png files",
            "policyType": "FILE",
            "type": "policyRule"
        },
        {
            "id": 15600,
            "label": "Microsoft OneDrive for Business",
            "type": "service"
        },
        {
            "id": "d10230e2-52db-4ec8-815b-c5484524d078|501f6179-e6f9-457c-9892-1590dee07ede",
            "label": "image (2).png",
            "type": "file"
        },
        {
            "em": "dev@demistodev.onmicrosoft.com",
            "entityType": 2,
            "id": "2827c1e7-edb6-4529-b50d-25984e968637",
            "inst": 0,
            "label": "demisto dev",
            "pa": "dev@demistodev.onmicrosoft.com",
            "saas": 11161,
            "type": "account"
        },
        {
            "id": "dev@demistodev.onmicrosoft.com",
            "label": "dev@demistodev.onmicrosoft.com",
            "type": "user"
        }
    ],
    "title": "block png files",
    "description": "File policy 'block png files' was matched by 'image (2).png'",
    "stories": [
        0
    ],
    "policy": {
        "id": "5f01dce13de79160fbec4150",
        "label": "block png files",
        "policyType": "FILE",
        "type": "policyRule"
    },
    "contextId": "ebac1a16-81bf-449b-8d43-5732c3c1d999",
    "threatScore": 19,
    "isSystemAlert": False,
    "idValue": 15728642,
    "statusValue": 1,
    "severityValue": 0,
    "handledByUser": 'null',
    "comment": 'null',
    "resolveTime": "2020-07-12T07:48:40.975Z",
    "URL": "https://demistodev.portal.cloudappsecurity.com/#/alerts/5f06d71dba4289d0602ba5ac"
}
