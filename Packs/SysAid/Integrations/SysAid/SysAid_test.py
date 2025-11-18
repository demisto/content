import time
from unittest.mock import patch

import pytest
import requests
from freezegun import freeze_time
from SysAid import Client
from test_data import input_data

COOKIES = "cookies"


@pytest.fixture
@patch("SysAid.Client._get_cookies")
def sysaid_client(mocker_get_cookies):
    mocker_get_cookies.return_value = COOKIES
    return Client(server_url="https://url/api/v1", verify=False, proxy=False, auth=("username", "password"))


""" COMMAND FUNCTIONS TESTS """


def test_table_list_command_with_list_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed with list id
    When:
        - sysaid-table-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import table_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"list_id": "known_error"}
    table_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "list/known_error", params={}, cookies=COOKIES)


def test_table_list_command_no_list_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed without list id
    When:
        - sysaid-table-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import table_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {}
    table_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "list", params={}, cookies=COOKIES)


def test_asset_list_command_with_asset_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed with asset id
    When:
        - sysaid-asset-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import asset_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"asset_id": "0A-3E-E9-13-2B-E4", "fields": "all"}
    asset_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "asset/0A-3E-E9-13-2B-E4", params={}, cookies=COOKIES)


def test_asset_list_command_no_asset_id(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed without asset id
    When:
        - sysaid-asset-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import asset_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all"}
    asset_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "asset", params={"limit": 100, "offset": 0}, cookies=COOKIES)


def test_asset_search_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-asset-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import asset_search_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all", "query": "Test"}
    asset_search_command(sysaid_client, args)
    http_request.assert_called_with("GET", "asset/search", params={"limit": 100, "offset": 0, "query": "Test"}, cookies=COOKIES)


def test_filter_list_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-filter-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import filter_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all"}
    filter_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "filters", params={}, cookies=COOKIES)


def test_user_list_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-user-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import user_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all"}
    user_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "users", params={"limit": 100, "offset": 0}, cookies=COOKIES)


def test_user_search_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-user-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import user_search_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all", "query": "dmst"}
    user_search_command(sysaid_client, args)
    http_request.assert_called_with("GET", "users/search", params={"limit": 100, "offset": 0, "query": "dmst"}, cookies=COOKIES)


def test_service_record_list_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-list command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_list_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all", "type": "all"}
    service_record_list_command(sysaid_client, args)
    http_request.assert_called_with("GET", "sr", params={"limit": 100, "offset": 0, "type": "all"}, cookies=COOKIES)


def test_service_record_search_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-search command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_search_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"fields": "all", "type": "all", "query": "test"}
    service_record_search_command(sysaid_client, args)
    http_request.assert_called_with(
        "GET", "sr/search", params={"query": "test", "type": "all", "offset": 0, "limit": 100}, cookies=COOKIES
    )


def test_service_record_update_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-update command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_update_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"id": "6", "status": "2"}
    service_record_update_command(sysaid_client, args)
    http_request.assert_called_with(
        "PUT", "sr/6", json_data={"id": "6", "info": [{"key": "status", "value": "2"}]}, cookies=COOKIES, resp_type="response"
    )


def test_service_record_close_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-close command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_close_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"id": "6", "solution": "Closing via API call"}
    service_record_close_command(sysaid_client, args)
    http_request.assert_called_with(
        "PUT",
        "sr/6/close",
        json_data={"solution": "Closing via API call"},
        cookies=COOKIES,
        resp_type="response",
        ok_codes=(200, 400),
    )


def test_service_record_template_get_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-template-get command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_template_get_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"type": "incident", "fields": "all"}
    service_record_template_get_command(sysaid_client, args)
    http_request.assert_called_with("GET", "sr/template", params={"type": "incident"}, cookies=COOKIES)


def test_service_record_create_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-create command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_create_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"type": "request", "description": "This is a test", "title": "Test SR from API", "sr_type": "6", "fields": "all"}
    service_record_create_command(sysaid_client, args)
    http_request.assert_called_with(
        "POST",
        "sr",
        params={"type": "request"},
        json_data={
            "info": [
                {"key": "description", "value": "This is a test"},
                {"key": "sr_type", "value": "6"},
                {"key": "title", "value": "Test SR from API"},
            ]
        },
        cookies=COOKIES,
    )


def test_service_record_delete_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-delete command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_delete_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"ids": "2,32"}
    service_record_delete_command(sysaid_client, args)
    http_request.assert_called_with(
        "DELETE",
        "sr",
        params={"ids": "2,32"},
        json_data={"solution": None},
        cookies=COOKIES,
        resp_type="response",
        ok_codes=(200, 400),
    )


def test_service_record_attach_file_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-attach-file command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_attach_file_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    file_name = "file_name.png"
    file_data = b"data"
    mocker.patch("SysAid.read_file", return_value=(file_data, 4, file_name))

    args = {"id": "37", "file_id": "50@519fe085-179d-43f4-85c7-795eb4edd1a0"}
    service_record_attach_file_command(sysaid_client, args)
    http_request.assert_called_with(
        "POST", "sr/37/attachment", files={"file": (file_name, file_data, "image/png")}, cookies=COOKIES, resp_type="response"
    )


def test_service_record_get_file_command(mocker, sysaid_client):
    """
    Given:
        - sr_id = str(args.get('id'))
        - file_id = str(args.get('file_id'))
        - file_name = str(args.get('file_name'))
    When:
        - sysaid-service-record-get-file command is executed when the user wants to download files from a ticket
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_get_file_command

    mock_response = requests.Response
    mock_response.status_code = 200
    http_request = mocker.patch.object(sysaid_client, "_http_request", return_value=mock_response)
    file_name = "file_name.png"
    file_data = b"data"
    mocker.patch("SysAid.read_file", return_value=(file_data, 4, file_name))
    mocker.patch("SysAid.fileResult", return_value="")

    args = {"id": "37", "file_id": "-80357423_-1872498142"}
    service_record_get_file_command(sysaid_client, args)
    http_request.assert_called_with("GET", "sr/37/attachment/-80357423_-1872498142", cookies=COOKIES, resp_type="response")


def test_service_record_delete_file_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-delete-file command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_delete_file_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"id": "2", "file_id": "-1147906284_-769427333"}
    service_record_delete_file_command(sysaid_client, args)
    http_request.assert_called_with(
        "DELETE", "sr/2/attachment", json_data={"fileId": "-1147906284_-769427333"}, cookies=COOKIES, resp_type="response"
    )


def test_service_record_get_request(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-get command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_get_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"id": "37", "fields": "all"}
    service_record_get_command(sysaid_client, args)
    http_request.assert_called_with("GET", "sr/37", params={}, cookies=COOKIES)


@freeze_time(time.ctime(9999893300))
def test_service_record_add_note_command(mocker, sysaid_client):
    """
    Given:
        - All relevant arguments for the command that is executed
    When:
        - sysaid-service-record-add-note command is executed
    Then:
        - The http request is called with the right arguments
    """
    from SysAid import service_record_add_note_command

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    args = {"id": "29", "note": "this is a new note", "username": "xsoar_dev"}

    service_record_add_note_command(sysaid_client, args)
    data = {
        "id": "29",
        "info": [
            {"key": "notes", "value": [{"userName": "xsoar_dev", "createDate": "9999893300000", "text": "this is a new note"}]}
        ],
    }
    http_request.assert_called_with("PUT", "sr/29", json_data=data, cookies=COOKIES, resp_type="response")


""" HELPER FUNCTIONS TESTS """


@pytest.mark.parametrize("response, remove_if_null, expected_output", input_data.asset_readable_response_args)
def test_create_readable_response_for_asset(response, remove_if_null, expected_output):
    """
    Given:
        - Response to a command that retrieves assets
        - A value field that if it is null, the part of the response need not be shown
    When:
        - A command that retrieves assets is executed
    Then:
        - Returns the readable response for the command
    """
    from SysAid import asset_list_handler, create_readable_response

    assert create_readable_response(response, asset_list_handler, remove_if_null) == expected_output


def test_create_readable_response_for_filter():
    """
    Given:
        - Response to a command that retrieves filters
    When:
        - A command that retrieves filters is executed
    Then:
        - Returns the readable response for the command
    """
    from SysAid import create_readable_response, filter_list_handler

    assert create_readable_response(input_data.filter_response, filter_list_handler) == input_data.filter_expected_output


def test_create_readable_response_for_service_record():
    """
    Given:
        - Response to a command that retrieves service records
    When:
        - A command that retrieves service records is executed
    Then:
        - Returns the readable response for the command
    """
    from SysAid import create_readable_response, service_record_handler

    assert (
        create_readable_response(input_data.service_record_response, service_record_handler)
        == input_data.service_record_expected_output
    )


def test_create_response_for_service_record():
    """
    Given:
        - Response to a command that retrieves service records
    When:
        - A command that retrieves service records is executed
    Then:
        - Returns the response for the command
    """
    from SysAid import create_readable_response, service_record_response_handler

    assert (
        create_readable_response(input_data.service_record_response, service_record_response_handler)
        == input_data.service_record_expected_response_output
    )


@pytest.mark.parametrize("custom_fields_keys, custom_fields_values, expected_output", input_data.extract_filters_args)
def test_extract_filters(custom_fields_keys, custom_fields_values, expected_output):
    """
    Given:
        - 'custom_fields_keys' and 'custom_fields_values' arguments
    When:
        - A command that has custom fields is executed
    Then:
        - Returns the right form of the custom field that will be sent to the request
    """
    from SysAid import extract_filters

    assert extract_filters(custom_fields_keys, custom_fields_values) == expected_output


@pytest.mark.parametrize("args, info", input_data.service_record_args)
def test_set_service_record_info(args, info):
    """
    Given:
        - arguments are given to commands that has service record info
    When:
        - A command that has service record info is executed
    Then:
        - Returns the right info that will be sent to the request
    """
    from SysAid import set_service_record_info

    assert set_service_record_info(args) == info


def test_template_readable_response():
    """
    Given:
        - Response to a command that retrieves templates
    When:
        - A command that retrieves templates is executed
    Then:
        - Returns the readable response for the command
    """
    from SysAid import template_readable_response

    assert template_readable_response(input_data.get_template_response) == input_data.get_template_readable_response


@pytest.mark.parametrize("page_size, page_number, offset", input_data.calculate_offset_args)
def test_calculate_offset(page_size, page_number, offset):
    """
    Given:
        - 'page_size' and 'page_number' arguments
    When:
        - A command that has paging is executed
    Then:
        - Returns the right offset that will be sent to the request
    """
    from SysAid import calculate_offset

    assert calculate_offset(page_size, page_number) == offset


@pytest.mark.parametrize("page_number, page_size, expected_output", input_data.paging_heading_args)
def test_create_paging_header(page_number, page_size, expected_output):
    """
    Given:
        - 'page_number' and 'page_size' arguments are or aren't given to commands that have paging
    When:
        - A command that has paging is executed
    Then:
        - Returns the right sentence to write in the beginning of the readable output
    """
    from SysAid import create_paging_header

    assert create_paging_header(page_size, page_number) == expected_output


@pytest.mark.parametrize("fields_input, fields_output", input_data.set_returned_fields_args)
def test_set_returned_fields(fields_input, fields_output):
    """
    Given:
        - 'fields' arguments
    When:
        - A command that has an option to choose what 'fields' will be returned is executed
    Then:
        - Returns the right fields that will be sent to the request
    """
    from SysAid import set_returned_fields

    assert set_returned_fields(fields_input) == fields_output


""" FETCH HELPER FUNCTIONS TESTS """


@pytest.mark.parametrize("fetch_types, include_archived, included_statuses, expected_params", input_data.fetch_request_args)
def test_fetch_request(mocker, sysaid_client, fetch_types, include_archived, included_statuses, expected_params):
    """
    Given:
        - Fetch parameters
    When:
        - Fetch incidents runs
    Then:
        - Returns the service records from SysAid
    """
    from SysAid import fetch_request

    http_request = mocker.patch.object(sysaid_client, "_http_request")
    fetch_request(sysaid_client, fetch_types, include_archived, included_statuses)
    http_request.assert_called_with("GET", "sr", params=expected_params, cookies=COOKIES)


@pytest.mark.parametrize(
    "service_records, fetch_start_datetime, expected_result", input_data.filter_service_records_by_time_input
)
def test_filter_service_records_by_time(service_records, fetch_start_datetime, expected_result):
    """
    Given:
        - Service records from SysAid
    When:
        - Fetch incidents runs
    Then:
        - Returns the service records that happened after the last fetch
    """
    from SysAid import filter_service_records_by_time

    assert filter_service_records_by_time(service_records, fetch_start_datetime) == expected_result


@pytest.mark.parametrize(
    "service_records, fetch_start_datetime, last_id_fetched, expected_result", input_data.filter_service_records_by_id_input
)
def test_filter_service_records_by_id(service_records, fetch_start_datetime, last_id_fetched, expected_result):
    """
    Given:
        - Service records from SysAid, that might happen at the same time as the last fetched service record
    When:
        - Fetch incidents runs
    Then:
        - Returns the service records that need to be fetched - only those that were not fetched
    """
    from SysAid import filter_service_records_by_id

    assert filter_service_records_by_id(service_records, fetch_start_datetime, last_id_fetched) == expected_result


@pytest.mark.parametrize(
    "service_records, limit, last_fetch, last_id_fetched, returned_last_fetch, returned_last_id_fetched, "
    "returned_service_records",
    input_data.reduce_service_records_to_limit_input,
)
def test_reduce_service_records_to_limit(
    service_records, limit, last_fetch, last_id_fetched, returned_last_fetch, returned_last_id_fetched, returned_service_records
):
    """
    Given:
        - Service records from SysAid, filtered by date and by id, and sorted by date and then by id
    When:
        - Fetch incidents runs
    Then:
        - Returns new time and id fetched, and the service records only up to the limit given
    """
    from SysAid import reduce_service_records_to_limit

    assert reduce_service_records_to_limit(service_records, limit, last_fetch, last_id_fetched) == (
        returned_last_fetch,
        returned_last_id_fetched,
        returned_service_records,
    )


@pytest.mark.parametrize(
    "service_records, limit, fetch_start_datetime, last_id_fetched, expected_last_fetch, "
    "expected_last_id_fetched, expected_incidents_names",
    input_data.parse_service_records_input,
)
def test_parse_service_records(
    service_records,
    limit,
    fetch_start_datetime,
    last_id_fetched,
    expected_last_fetch,
    expected_last_id_fetched,
    expected_incidents_names,
):
    """
    Given:
        - All service records from SysAid, that some of them will become fetched incidents
    When:
        - Fetch incidents runs
    Then:
        - Returns the relevant fetched incidents, the new time to fetch from next time and the last id fetched
    """
    from SysAid import parse_service_records

    returned_last_fetch, returned_last_id_fetched, returned_incidents = parse_service_records(
        service_records, limit, fetch_start_datetime, last_id_fetched
    )
    assert returned_last_fetch == expected_last_fetch
    assert returned_last_id_fetched == expected_last_id_fetched
    for i in range(len(expected_incidents_names)):
        assert returned_incidents[i]["name"] == expected_incidents_names[i]


@pytest.mark.parametrize("last_fetch, first_fetch, expected_datetime", input_data.calculate_fetch_start_datetime_input)
@freeze_time("2022-02-28 11:00:00 UTC")
def test_calculate_fetch_start_datetime(last_fetch, first_fetch, expected_datetime):
    """
    Given:
        - The time when the last fetch occurred and the time we need to fetch from, to calculate the time to start fetching from
    When:
        - Fetch incidents runs
    Then:
        - Returns the time to fetch from - the latter of the 2 given
    """
    from SysAid import calculate_fetch_start_datetime

    assert calculate_fetch_start_datetime(last_fetch, first_fetch) == expected_datetime


def test_get_service_record_update_time():
    """
    Given:
        - A service record we want to know it's update time
    When:
        - Fetch incidents runs
    Then:
        - Returns the update time of the service record
    """
    from SysAid import get_service_record_update_time

    assert get_service_record_update_time(input_data.service_record_update_time) == input_data.update_time


@pytest.mark.parametrize(
    "service_record, use_classic_date_format, expected_datetime",
    [
        # Test American format (MM/DD/YYYY with AM/PM)
        (
            {"id": "123", "info": [{"key": "update_time", "valueCaption": "05/11/2025 01:12:48 PM"}]},
            True,
            "2025-05-11 13:12:48",  # May 11, 2025 at 1:12:48 PM
        ),
        # Test European format (DD/MM/YYYY 24-hour)
        (
            {"id": "124", "info": [{"key": "update_time", "valueCaption": "05/11/2025 13:12:48"}]},
            True,
            "2025-11-05 13:12:48",  # November 5, 2025 at 1:12:48 PM
        ),
        # Test ISO format (standard parsing)
        (
            {"id": "125", "info": [{"key": "update_time", "valueCaption": "2025-11-05T13:12:48"}]},
            False,
            "2025-11-05 13:12:48",  # November 5, 2025 at 1:12:48 PM
        ),
        # Test ambiguous date with American format (day <= 12)
        (
            {"id": "126", "info": [{"key": "update_time", "valueCaption": "05/04/2025 01:12:48 PM"}]},
            True,
            "2025-05-04 13:12:48",  # May 4, 2025 (American MM/DD)
        ),
        # Test ambiguous date with European format (day <= 12)
        (
            {"id": "127", "info": [{"key": "update_time", "valueCaption": "05/04/2025 13:12:48"}]},
            True,
            "2025-04-05 13:12:48",  # April 5, 2025 (European DD/MM)
        ),
        # Test unambiguous date with American format (day > 12)
        (
            {"id": "128", "info": [{"key": "update_time", "valueCaption": "05/13/2025 01:12:48 PM"}]},
            True,
            "2025-05-13 13:12:48",  # May 13, 2025 (only valid as MM/DD)
        ),
        # Test unambiguous date with European format (day > 12)
        (
            {"id": "129", "info": [{"key": "update_time", "valueCaption": "13/05/2025 13:12:48"}]},
            True,
            "2025-05-13 13:12:48",  # May 13, 2025 (only valid as DD/MM)
        ),
    ],
)
def test_get_service_record_update_time_classic_format(service_record, use_classic_date_format, expected_datetime):
    """
    Given:
        - A service record with update_time in various SysAid Classic formats
        - use_classic_date_format parameter set to True or False
    When:
        - get_service_record_update_time function is called
    Then:
        - Ensure the correct datetime is parsed based on format detection:
          * American format (with AM/PM) parses as MM/DD/YYYY
          * European format (24-hour) parses as DD/MM/YYYY
          * ISO format parses correctly regardless of use_classic_date_format
    """
    from datetime import datetime
    from SysAid import get_service_record_update_time

    result = get_service_record_update_time(service_record, use_classic_date_format)
    expected = datetime.strptime(expected_datetime, "%Y-%m-%d %H:%M:%S")

    assert result == expected, f"Expected {expected}, but got {result}"


def test_get_service_record_update_time_no_update_time():
    """
    Given:
        - A service record without update_time field
    When:
        - get_service_record_update_time function is called
    Then:
        - Ensure None is returned
    """
    from SysAid import get_service_record_update_time

    service_record = {"id": "130", "info": [{"key": "other_field", "valueCaption": "some value"}]}

    result = get_service_record_update_time(service_record, use_classic_date_format=True)
    assert result is None


@pytest.mark.parametrize("raw_service_record, incident_context", input_data.service_record_to_incident_context_input)
def test_service_record_to_incident_context(raw_service_record, incident_context):
    """
    Given:
        - A service record we want to turn to incident context
    When:
        - Fetch incidents runs
    Then:
        - Returns the incident context
    """
    from SysAid import service_record_to_incident_context

    assert service_record_to_incident_context(raw_service_record) == incident_context
