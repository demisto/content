from datetime import datetime
from unittest.mock import patch

import pytest

from CommonServerPython import DemistoException
from GenericAPIEventCollector import (
    datetime_to_timestamp_format, timestamp_format_to_datetime, recursive_replace,
    get_time_field_from_event_to_dt, is_pagination_needed, iso8601_to_datetime_str, try_load_json,
    parse_json_param, generate_authentication_headers,
    extract_pagination_params, PaginationLogic, TimestampFieldConfig, organize_events_to_xsiam_format
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
    events = {'next_page': 'page2', 'has_more': False}
    pagination_logic = PaginationLogic(True, ['next_page'], ['has_more'])
    needed, next_page = is_pagination_needed(events, pagination_logic)
    assert needed is False
    assert next_page is None


def test_iso8601_to_datetime_str():
    iso_time = '2023-05-01T12:00:00.1234567Z'
    result = iso8601_to_datetime_str(iso_time)
    assert result == '2023-05-01T12:00:00.123456Z'


def test_try_load_json():
    json_str = '{"key": "value"}'
    result = try_load_json(json_str)
    assert result == {"key": "value"}


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
#
# def run_tests():
#     test_functions = [
#         test_datetime_to_timestamp_format,
#         test_timestamp_format_to_datetime,
#         test_recursive_replace,
#         test_get_log_timestamp,
#         test_identify_time_format,
#         test_get_time_field_from_event,
#         test_get_time_field_from_event_to_dt,
#         test_is_pagination_needed,
#         test_iso8601_to_datetime_str,
#         test_try_load_json,
#         test_parse_json_param,
#         test_generate_headers,
#         test_generate_authentication_headers,
#         test_extract_pagination_params
#     ]
#
#     for test in test_functions:
#         try:
#             test()
#             print(f"{test.__name__} passed")
#         except AssertionError as e:
#             print(f"{test.__name__} failed: {str(e)}")
#
# if __name__ == "__main__":
#     run_tests()
