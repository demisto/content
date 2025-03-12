from datetime import datetime
from unittest.mock import patch

import pytest

from CommonServerPython import DemistoException
from GenericAPIEventCollector import (
    datetime_to_timestamp_format, timestamp_format_to_datetime, recursive_replace,
    get_time_field_from_event_to_dt, is_pagination_needed, iso8601_to_datetime_str,
    parse_json_param, generate_authentication_headers,
    extract_pagination_params, PaginationLogic, TimestampFieldConfig, organize_events_to_xsiam_format, setup_search_events,
    RequestData, generate_headers
)


def test_datetime_to_timestamp_format():
    dt = datetime(2023, 5, 1, 12, 0, 0)
    assert datetime_to_timestamp_format(dt, '%Y-%m-%dT%H:%M:%SZ') == '2023-05-01T12:00:00Z'
    assert datetime_to_timestamp_format(dt, 'epoch') == str(dt.timestamp())


def test_timestamp_format_to_datetime():
    dt_str = '2023-05-01T12:00:00Z'
    assert timestamp_format_to_datetime(dt_str, '%Y-%m-%dT%H:%M:%SZ') == datetime(2023, 5, 1, 12, 0, 0)
    epoch_str = str(datetime(2023, 5, 1, 12, 0, 0).timestamp())
    assert timestamp_format_to_datetime(epoch_str, 'epoch') == datetime(2023, 5, 1, 12, 0, 0)


def test_recursive_replace():
    org_dict = {'key1': 'value1', 'key2': {'key3': 'value3'}}
    substitutions = [('value1', 'new_value1'), ('value3', 'new_value3')]
    result = recursive_replace(org_dict, substitutions)
    assert result == {'key1': 'new_value1', 'key2': {'key3': 'new_value3'}}


def test_recursive_replace_with_none():
    assert recursive_replace(None, []) is None


def test_get_time_field_from_event_to_dt():
    event = {'timestamp': '2023-05-01T12:00:00Z'}
    config = TimestampFieldConfig(['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    result = get_time_field_from_event_to_dt(event, config)
    assert isinstance(result, datetime)
    assert result == datetime(2023, 5, 1, 12, 0, 0)


def test_get_time_field_from_event_to_dt_throws_exception():
    event = {'non_timestamp_field': '2023-05-01T12:00:00Z'}
    config = TimestampFieldConfig(['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    with pytest.raises(DemistoException) as exc_info:
        get_time_field_from_event_to_dt(event, config)
    assert "Timestamp field: ['timestamp'] not found in event" in str(exc_info.value)


def test_is_pagination_needed():
    events = {'next_page': 'page2', 'has_more': True}
    pagination_logic = PaginationLogic(True, ['next_page'], ['has_more'])
    needed, next_page = is_pagination_needed(events, pagination_logic)
    assert needed is True
    assert next_page == 'page2'


def test_is_pagination_not_needed():
    events = {'has_more': False}
    pagination_logic = PaginationLogic(True, ['next_page'], ['has_more'])
    needed, next_page = is_pagination_needed(events, pagination_logic)
    assert needed is False
    assert next_page is None


def test_iso8601_to_datetime_str():
    iso_time = '2023-05-01T12:00:00.1234567Z'
    result = iso8601_to_datetime_str(iso_time)
    assert result == '2023-05-01T12:00:00.123456Z'


def test_parse_json_param():
    json_param_value = '{"key": "value"}'
    result = parse_json_param(json_param_value, 'test_param')
    assert result == {"key": "value"}


def test_parse_json_param_none_value():
    result = parse_json_param(None, 'test_param')
    assert result is None


def test_organize_events_to_xsiam_format():
    raw_events = {
        "data": {
            "events": [
                {"id": 1, "name": "event1"},
                {"id": 2, "name": "event2"}
            ]
        }
    }
    events_keys = ["data", "events"]
    expected_output = [
        {"id": 1, "name": "event1"},
        {"id": 2, "name": "event2"}
    ]
    assert organize_events_to_xsiam_format(raw_events, events_keys) == expected_output


def test_organize_events_to_xsiam_format_empty():
    raw_events = {}
    events_keys = ["data", "events"]
    expected_output = []
    assert organize_events_to_xsiam_format(raw_events, events_keys) == expected_output


def test_organize_events_to_xsiam_format_no_events_key():
    raw_events = {
        "data": {
            "no_events": [
                {"id": 1, "name": "event1"},
                {"id": 2, "name": "event2"}
            ]
        }
    }
    events_keys = ["data", "events"]
    expected_output = []
    assert organize_events_to_xsiam_format(raw_events, events_keys) == expected_output


def test_generate_authentication_headers_basic():
    params = {
        "authentication": "Basic",
        "credentials": {"identifier": "user", "password": "pass"}
    }
    headers = generate_authentication_headers(params)
    assert headers["Authorization"].startswith("Basic ")


@patch('GenericAPIEventCollector.return_error')
@patch('GenericAPIEventCollector.demisto.error')
def test_generate_authentication_headers_basic_no_password(mock_error, mock_return_error):
    params = {
        "authentication": "Basic",
        "credentials": {"identifier": "user"}
    }
    generate_authentication_headers(params)
    mock_error.assert_called_once_with("Password is required for Basic Authentication.")
    mock_return_error.assert_called_once_with("Password is required for Basic Authentication.")


def test_generate_authentication_headers_bearer():
    params = {
        "authentication": "Bearer",
        "token": {"password": "test_token"}
    }
    headers = generate_authentication_headers(params)
    assert headers["Authorization"] == "Bearer test_token"


@patch('GenericAPIEventCollector.return_error')
@patch('GenericAPIEventCollector.demisto.error')
def test_generate_authentication_headers_bearer_no_token(mock_error, mock_return_error):
    params = {
        "authentication": "Bearer"
    }
    generate_authentication_headers(params)
    mock_error.assert_called_once_with("API Token is required.")
    mock_return_error.assert_called_once_with("API Token is required.")


def test_generate_authentication_headers_token():
    params = {
        "authentication": "Token",
        "token": {"password": "test_token"}
    }
    headers = generate_authentication_headers(params)
    assert headers["Authorization"] == "Token test_token"


@patch('GenericAPIEventCollector.return_error')
@patch('GenericAPIEventCollector.demisto.error')
def test_generate_authentication_headers_token_no_token(mock_error, mock_return_error):
    params = {
        "authentication": "Token"
    }
    generate_authentication_headers(params)
    mock_error.assert_called_once_with("API Token is required.")
    mock_return_error.assert_called_once_with("API Token is required.")


def test_generate_authentication_headers_api_key():
    params = {
        "authentication": "Api-Key",
        "token": {"password": "test_token"}
    }
    headers = generate_authentication_headers(params)
    assert headers["api-key"] == "test_token"


@patch('GenericAPIEventCollector.return_error')
@patch('GenericAPIEventCollector.demisto.error')
def test_generate_authentication_headers_api_key_no_token(mock_error, mock_return_error):
    params = {
        "authentication": "Api-Key"
    }
    generate_authentication_headers(params)
    mock_error.assert_called_once_with("API Token is required.")
    mock_return_error.assert_called_once_with("API Token is required.")


def test_generate_authentication_headers_raw_token():
    params = {
        "authentication": "RawToken",
        "token": {"password": "test_token"}
    }
    headers = generate_authentication_headers(params)
    assert headers["Authorization"] == "test_token"


@patch('GenericAPIEventCollector.return_error')
@patch('GenericAPIEventCollector.demisto.error')
def test_generate_authentication_headers_raw_token_no_token(mock_error, mock_return_error):
    params = {
        "authentication": "RawToken"
    }
    generate_authentication_headers(params)
    mock_error.assert_called_once_with("API Token is required.")
    mock_return_error.assert_called_once_with("API Token is required.")


def test_generate_authentication_headers_no_auth():
    params = {
        "authentication": "No Authorization"
    }
    headers = generate_authentication_headers(params)
    assert headers == {}


@patch('GenericAPIEventCollector.return_error')
@patch('GenericAPIEventCollector.demisto.error')
def test_generate_authentication_headers_invalid_auth(mock_error, mock_return_error):
    params = {
        "authentication": "InvalidAuth"
    }
    generate_authentication_headers(params)
    mock_error.assert_called_once_with(
        "Please insert a valid authentication method, options are: Basic, Bearer, Token, Api-Key, RawToken"
        "No Authorization, got: InvalidAuth"
    )
    mock_return_error.assert_called_once_with(
        "Please insert a valid authentication method, options are: Basic, Bearer, Token, Api-Key, RawToken"
        "No Authorization, got: InvalidAuth"
    )


def test_extract_pagination_params():
    params = {
        "pagination_needed": "true",
        "pagination_field_name": "next_page",
        "pagination_flag": "has_more"
    }
    pagination_logic = extract_pagination_params(params)
    assert pagination_logic.pagination_needed is True
    assert pagination_logic.pagination_field_name == ["next_page"]
    assert pagination_logic.pagination_flag == ["has_more"]


def test_setup_search_events():
    first_fetch_datetime = datetime(2023, 1, 1, 0, 0, 0)
    last_run = {}
    params = {
        'request_data': '{"key": "value"}',
        'request_json': '{"json_key": "json_value"}',
        'query_params': '{"param_key": "param_value"}',
        'pagination_needed': 'true',
        'pagination_field_name': 'next_page',
        'pagination_flag': 'has_more',
        'timestamp_field_name': 'timestamp',
        'timestamp_format': '%Y-%m-%dT%H:%M:%SZ'
    }
    timestamp_field_config = TimestampFieldConfig(['timestamp'], '%Y-%m-%dT%H:%M:%SZ')

    last_fetched_datetime, pagination_logic, request_data = setup_search_events(
        first_fetch_datetime, last_run, params, timestamp_field_config
    )

    assert last_fetched_datetime == first_fetch_datetime
    assert pagination_logic == PaginationLogic(True, ['next_page'], ['has_more'])
    assert request_data == RequestData({'key': 'value'}, {'json_key': 'json_value'}, {'param_key': 'param_value'})


def test_setup_search_events_with_last_run():
    first_fetch_datetime = datetime(2023, 1, 1, 0, 0, 0)
    last_run = {'@last_fetched_datetime': '2023-01-02T00:00:00'}
    params = {
        'request_data': '{"key": "value"}',
        'request_json': '{"json_key": "json_value"}',
        'query_params': '{"param_key": "param_value"}',
        'pagination_needed': 'true',
        'pagination_field_name': 'next_page',
        'pagination_flag': 'has_more',
        'timestamp_field_name': 'timestamp',
        'timestamp_format': '%Y-%m-%dT%H:%M:%SZ'
    }
    timestamp_field_config = TimestampFieldConfig(['timestamp'], '%Y-%m-%dT%H:%M:%SZ')

    last_fetched_datetime, pagination_logic, request_data = setup_search_events(
        first_fetch_datetime, last_run, params, timestamp_field_config
    )

    assert last_fetched_datetime == datetime(2023, 1, 2, 0, 0, 0)
    assert pagination_logic == PaginationLogic(True, ['next_page'], ['has_more'])
    assert request_data == RequestData({'key': 'value'}, {'json_key': 'json_value'}, {'param_key': 'param_value'})


def test_setup_search_events_first_fetch():
    first_fetch_datetime = datetime(2023, 1, 1, 0, 0, 0)
    last_run = {}
    params = {
        'request_data': '{"key": "value"}',
        'request_json': '{"json_key": "json_value"}',
        'query_params': '{"param_key": "param_value"}',
        'pagination_needed': 'true',
        'pagination_field_name': 'next_page',
        'pagination_flag': 'has_more',
        'timestamp_field_name': 'timestamp',
        'timestamp_format': '%Y-%m-%dT%H:%M:%SZ',
        'initial_query_params': '{"initial_param_key": "initial_param_value"}',
        'initial_pagination_params': {"pagination_needed": "true", "pagination_field_name": "next_page",
                                      "pagination_flag": "has_more"},
        'initial_request_data': '{"initial_key": "initial_value"}',
        'initial_request_json': '{"initial_json_key": "initial_json_value"}'
    }
    timestamp_field_config = TimestampFieldConfig(['timestamp'], '%Y-%m-%dT%H:%M:%SZ')

    last_fetched_datetime, pagination_logic, request_data = setup_search_events(
        first_fetch_datetime, last_run, params, timestamp_field_config
    )

    assert last_fetched_datetime == first_fetch_datetime
    assert pagination_logic == PaginationLogic(True, ['next_page'], ['has_more'])
    assert request_data == RequestData({'initial_key': 'initial_value'}, {'initial_json_key': 'initial_json_value'},
                                       {'initial_param_key': 'initial_param_value'})


@patch('GenericAPIEventCollector.generate_authentication_headers')
def test_generate_headers_basic(mock_generate_authentication_headers):
    params = {
        'authentication': 'Basic',
        'credentials': {'identifier': 'user', 'password': 'pass'},
        'add_fields_to_header': '{"Custom-Header": "CustomValue"}'
    }
    mock_generate_authentication_headers.return_value = {'Authorization': 'Basic d5Nl4jp3YX2z'}
    headers = generate_headers(params)
    assert headers == {'Authorization': 'Basic d5Nl4jp3YX2z', 'Custom-Header': 'CustomValue'}


@patch('GenericAPIEventCollector.generate_authentication_headers')
def test_generate_headers_bearer(mock_generate_authentication_headers):
    params = {
        'authentication': 'Bearer',
        'token': {'password': 'test_token'},
        'add_fields_to_header': '{"Custom-Header": "CustomValue"}'
    }
    mock_generate_authentication_headers.return_value = {'Authorization': 'Bearer test_token'}
    headers = generate_headers(params)
    assert headers == {'Authorization': 'Bearer test_token', 'Custom-Header': 'CustomValue'}


@patch('GenericAPIEventCollector.generate_authentication_headers')
def test_generate_headers_token(mock_generate_authentication_headers):
    params = {
        'authentication': 'Token',
        'token': {'password': 'test_token'},
        'add_fields_to_header': '{"Custom-Header": "CustomValue"}'
    }
    mock_generate_authentication_headers.return_value = {'Authorization': 'Token test_token'}
    headers = generate_headers(params)
    assert headers == {'Authorization': 'Token test_token', 'Custom-Header': 'CustomValue'}


@patch('GenericAPIEventCollector.generate_authentication_headers')
def test_generate_headers_api_key(mock_generate_authentication_headers):
    params = {
        'authentication': 'Api-Key',
        'token': {'password': 'test_token'},
        'add_fields_to_header': '{"Custom-Header": "CustomValue"}'
    }
    mock_generate_authentication_headers.return_value = {'api-key': 'test_token'}
    headers = generate_headers(params)
    assert headers == {'api-key': 'test_token', 'Custom-Header': 'CustomValue'}


@patch('GenericAPIEventCollector.generate_authentication_headers')
def test_generate_headers_raw_token(mock_generate_authentication_headers):
    params = {
        'authentication': 'RawToken',
        'token': {'password': 'test_token'},
        'add_fields_to_header': '{"Custom-Header": "CustomValue"}'
    }
    mock_generate_authentication_headers.return_value = {'Authorization': 'test_token'}
    headers = generate_headers(params)
    assert headers == {'Authorization': 'test_token', 'Custom-Header': 'CustomValue'}


@patch('GenericAPIEventCollector.generate_authentication_headers')
def test_generate_headers_no_auth(mock_generate_authentication_headers):
    params = {
        'authentication': 'No Authorization',
        'add_fields_to_header': '{"Custom-Header": "CustomValue"}'
    }
    mock_generate_authentication_headers.return_value = {}
    headers = generate_headers(params)
    assert headers == {'Custom-Header': 'CustomValue'}
