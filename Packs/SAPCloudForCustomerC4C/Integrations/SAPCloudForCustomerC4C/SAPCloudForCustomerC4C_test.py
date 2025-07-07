import pytest
from SAPCloudForCustomerC4C import Client
from datetime import datetime
from CommonServerPython import *  # noqa: F401

SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"
STRFTIME_FORMAT = "%d-%m-%Y %H:%M:%S"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC
VENDOR = "SAP CLOUD"
PRODUCT = "C4C"
FIRST_FETCH = "one minute ago"
URL_SUFFIX = "/sap/c4c/odata/ana_businessanalytics_analytics.svc/"
INIT_SKIP = 0
DEFAULT_TOP = 1000


def mock_client():
    return Client(base_url="https://my313577.crm.ondemand.com", base64String="base64String", verify=True)


ENCODE_TO_BASE64_TEST_CASES = [
    pytest.param("", "", id="empty string"),
    pytest.param("hello world", "aGVsbG8gd29ybGQ=", id="simple alphanumeric string"),
    pytest.param("test!@#$%^&*()", "dGVzdCFAIyQlXiYqKCk=", id="string with special characters"),
    pytest.param("abc", "YWJj", id="string with no padding"),
]


@pytest.mark.parametrize("input_string, expected_output", ENCODE_TO_BASE64_TEST_CASES)
def test_encode_to_base64_parameterized(input_string: str, expected_output: str):
    """
    Tests the encode_to_base64 function across various string inputs,
    including empty strings, special characters, and different padding scenarios.

    Test Cases Explained:

    - **empty string:** Verifies correct encoding of an empty string.
    - **simple alphanumeric string:** Checks standard encoding for a basic string.
    - **string with special characters:** Ensures proper handling of various non-alphanumeric characters.
    - **string with no padding:** Tests input length that results in no Base64 padding.

    Given:
        - `input_string` (str): A string to be encoded, provided by the parameterized test cases.
        - `expected_output` (str): The pre-calculated Base64 encoded string corresponding to `input_string`.
    When:
        - Calling `encode_to_base64` with `input_string`.
    Then:
        Verify that:
        - The actual Base64 encoded string matches the `expected_output`.
    """
    from SAPCloudForCustomerC4C import encode_to_base64

    actual_output = encode_to_base64(input_string)
    assert actual_output == expected_output


GET_END_DATE_TEST_CASES = [
    pytest.param("01-01-2023 10:00:00", 2, "03-01-2023 10:00:00", id="basic_add_default_days"),
    pytest.param("15-03-2023 12:30:00", 5, "20-03-2023 12:30:00", id="custom_days_addition"),
    pytest.param("30-01-2023 00:00:00", 3, "02-02-2023 00:00:00", id="crossing_month_boundary"),
    pytest.param("31-12-2023 23:59:59", 1, "01-01-2024 23:59:59", id="crossing_year_boundary"),
    pytest.param("27-02-2024 00:00:00", 2, "29-02-2024 00:00:00", id="leap_year_cross_leap_day"),
    pytest.param("29-02-2024 00:00:00", 1, "01-03-2024 00:00:00", id="leap_year_after_leap_day"),
    pytest.param("10-05-2023 08:00:00", 0, "10-05-2023 08:00:00", id="add_zero_days"),
]


@pytest.mark.parametrize("start_date_str, days, expected_end_date_str", GET_END_DATE_TEST_CASES)
def test_get_end_date(start_date_str: str, days: int, expected_end_date_str: str):
    """
    Tests the get_end_date function with various start dates and day increments.

    This parameterized test covers:
    - Basic addition of default and custom numbers of days.
    - Scenarios crossing month and year boundaries.
    - Handling of leap years, including adding days to, across, and after the leap day.
    - Edge cases like adding zero days.
    - Behavior with negative 'days' input, effectively subtracting days.

    Given:
        - `start_date_str` (str): The initial date string in "DD-MM-YYYY HH:MM:SS" format.
        - `days` (int): The number of days to add (or subtract if negative).
        - `expected_end_date_str` (str): The expected resulting end date string.
    When:
        - Calling `get_end_date` with the provided `start_date_str` and `days`.
    Then:
        Verify that:
        - The returned end date string matches the `expected_end_date_str`.
    """
    from SAPCloudForCustomerC4C import get_end_date

    actual_end_date_str = get_end_date(start_date_str, days)
    assert actual_end_date_str == expected_end_date_str


def test_get_events_success_without_end_date(mocker):
    """
    Test case for successful retrieval of events without an end_date.
    """
    from SAPCloudForCustomerC4C import get_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    skip = 0
    top = 10
    start_date = "01-01-2023 00:00:00"
    expected_events = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "01-01-2023 01:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "01-01-2023 02:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
    ]
    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})
    result = get_events(mock_client_instance, report_id, skip, top, start_date)

    expected_filter = f"CTIMESTAMP ge '{start_date} INDIA'"
    mock_client_instance.http_request.assert_called_once_with(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params={"$filter": expected_filter, "$skip": skip, "$top": top, "$format": "json", "$inlinecount": "allpages"},
    )
    assert result == expected_events
    assert "and CTIMESTAMP le" not in mock_client_instance.http_request.call_args[1]["params"]["$filter"]


def test_get_events_success_with_end_date(mocker):
    """
    Test case for successful retrieval of events with an end_date.
    """
    from SAPCloudForCustomerC4C import get_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    skip = 5
    top = 20
    start_date = "01-01-2023 00:00:00"
    end_date = "31-01-2023 23:59:59"
    expected_events = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "01-01-2023 01:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "01-01-2023 02:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
    ]
    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})
    result = get_events(mock_client_instance, report_id, skip, top, start_date, end_date)

    expected_filter = f"CTIMESTAMP ge '{start_date} INDIA' and CTIMESTAMP le '{end_date} INDIA'"
    mock_client_instance.http_request.assert_called_once_with(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params={"$filter": expected_filter, "$skip": skip, "$top": top, "$format": "json", "$inlinecount": "allpages"},
    )
    assert result == expected_events
    assert "and CTIMESTAMP le" in mock_client_instance.http_request.call_args[1]["params"]["$filter"]


def test_get_events_empty_results(mocker):
    """
    Test case when the API returns an empty list of results.
    """
    from SAPCloudForCustomerC4C import get_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    skip = 0
    top = 10
    start_date = "01-01-2023 00:00:00"

    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": []}})
    result = get_events(mock_client_instance, report_id, skip, top, start_date)

    mock_client_instance.http_request.assert_called_once()
    assert result == []


def test_get_events_command_success_single_page(mocker):
    """
    Tests the successful execution of the get_events_command function, retrieving events in a single page.

    Given:
        - A mock client instance.
        - Arguments for the command including start_date and a limit <= DEFAULT_TOP.
    When:
        - Running the get_events_command function.
    """
    from SAPCloudForCustomerC4C import get_events_command

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    start_date_str = "01-01-2025 00:00:00"

    limit_val = 3
    args = {"start_date": start_date_str, "limit": limit_val, "days_from_start": 2}

    expected_events = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "01-01-2025 01:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "01-01-2025 02:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_3", "type": "113_QueryResult"},
            "CTIMESTAMP": "01-01-2025 03:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
    ]

    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})

    events_list, cmd_results = get_events_command(mock_client_instance, report_id, args)

    # # Assert the returned values
    assert events_list == expected_events
    assert cmd_results.raw_response == expected_events
    assert f"### Test Event for {SAP_CLOUD}" in cmd_results.readable_output
    assert "|CBROWSER|CDEVICE_TYPE|CTIMESTAMP|__metadata|" in cmd_results.readable_output


def test_get_events_command_success_multiple_pages(mocker):
    """
    Tests get_events_command for successful retrieval requiring multiple API calls (pagination).
    """
    from SAPCloudForCustomerC4C import get_events_command

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    start_date_str = "01-01-2025 00:00:00"
    limit_val = 7  # Requires 2 calls (5 events then 2 events)
    args = {"start_date": start_date_str, "limit": limit_val, "days_from_start": 2}

    expected_events_page1 = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "01-01-2025 01:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "01-01-2025 02:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_3", "type": "113_QueryResult"},
            "CTIMESTAMP": "01-01-2025 03:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
    ]

    expected_events_page2 = [
        {
            "__metadata": {"uri": "example_url_4", "type": "114_QueryResult"},
            "CTIMESTAMP": "01-01-2025 04:00:00",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_5", "type": "115_QueryResult"},
            "CTIMESTAMP": "01-01-2025 05:00:00",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_6", "type": "116_QueryResult"},
            "CTIMESTAMP": "01-01-2025 06:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
    ]

    expected_all_events = expected_events_page1 + expected_events_page2

    mocker.patch.object(
        mock_client_instance,
        "http_request",
        side_effect=[
            {"d": {"results": expected_events_page1}},  # First call
            {"d": {"results": expected_events_page2}},  # Second call
            {"d": {"results": []}},  # Third call signals end of data
        ],
    )

    events_list, cmd_results = get_events_command(mock_client_instance, report_id, args)

    # Check calls to http_request
    assert mock_client_instance.http_request.call_count == 3

    assert events_list == expected_all_events
    assert cmd_results.raw_response == expected_all_events
    assert f"### Test Event for {SAP_CLOUD}" in cmd_results.readable_output


def test_get_events_command_no_start_date():
    """
    Test case when 'start_date' argument is missing.
    """
    from SAPCloudForCustomerC4C import get_events_command

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    args = {"limit": 10}  # Missing start_date

    expected_cmd_results = "Error: 'start_date' argument is required."

    events, cmd_results = get_events_command(mock_client_instance, report_id, args)
    assert events == []
    assert cmd_results.readable_output == expected_cmd_results
    assert cmd_results.raw_response == {}


def test_fetch_events_first_fetch_success(mocker):
    """
    Tests successful first fetch (no last_run) of events.

    Given:
        - A mock client instance.
        - Integration parameters with report_id.
        - An empty last_run dictionary.
    When:
        - Running fetch_events.
    Then:
        - `http_request` is called with start_date based on FIRST_FETCH.
        - `next_run` contains the current time in ISO format.
        - All expected events are returned.
    """
    from SAPCloudForCustomerC4C import fetch_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    params = {"report_id": report_id, "max_fetch": 8}

    fixed_now_dt = datetime(2025, 7, 6, 14, 0, 0)  # Fixed current time

    expected_events = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "01-01-2025 01:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "01-01-2025 02:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_3", "type": "113_QueryResult"},
            "CTIMESTAMP": "01-01-2025 03:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_4", "type": "114_QueryResult"},
            "CTIMESTAMP": "01-01-2025 04:00:00",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_5", "type": "115_QueryResult"},
            "CTIMESTAMP": "01-01-2025 05:00:00",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_6", "type": "116_QueryResult"},
            "CTIMESTAMP": "01-01-2025 06:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_7", "type": "117_QueryResult"},
            "CTIMESTAMP": "01-01-2025 07:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_8", "type": "118_QueryResult"},
            "CTIMESTAMP": "01-01-2025 08:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
    ]

    mocker.patch("SAPCloudForCustomerC4C.get_current_utc_time", return_value=fixed_now_dt)
    mocker.patch.object(
        mock_client_instance, "http_request", return_value={"d": {"results": expected_events[:DEFAULT_TOP]}}
    )  # First batch

    next_run, fetched_events = fetch_events(mock_client_instance, params, last_run={})

    assert fetched_events == expected_events
    assert next_run == {"last_fetch": fixed_now_dt.strftime(DATE_FORMAT)}


def test_fetch_events_report_id_missing():
    """
    Tests fetch_events when 'report_id' is missing from params, expecting DemistoException.

    Given:
        - A mock client instance.
        - Integration parameters without 'report_id'.
        - An empty last_run dictionary.
    When:
        - Running fetch_events.
    Then:
        - A `DemistoException` is raised.
        - `http_request` is not called.
        - `demisto.debug` confirms the error.
    """
    from SAPCloudForCustomerC4C import fetch_events

    mock_client_instance = mock_client()
    params = {"max_fetch": 10}  # Missing report_id

    with pytest.raises(DemistoException) as excinfo:
        fetch_events(mock_client_instance, params, last_run={})

    assert "Report ID must be provided in the integration parameters and must be a string." in str(excinfo.value)


def test_fetch_events_dateparser_fallback(mocker):
    """
    Tests fetch_events when dateparser.parse fails for last_fetch, leading to fallback to FIRST_FETCH.
    """
    from SAPCloudForCustomerC4C import fetch_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    params = {"report_id": report_id, "max_fetch": 5}
    last_run = {"last_fetch": "invalid-date-format"}  # Malformed date

    fixed_now_dt = datetime(2025, 7, 6, 16, 0, 0)

    expected_events = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "01-01-2025 01:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "01-01-2025 02:00:00",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_3", "type": "113_QueryResult"},
            "CTIMESTAMP": "01-01-2025 03:00:00",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_4", "type": "114_QueryResult"},
            "CTIMESTAMP": "01-01-2025 04:00:00",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_5", "type": "115_QueryResult"},
            "CTIMESTAMP": "01-01-2025 05:00:00",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
    ]

    mocker.patch("SAPCloudForCustomerC4C.get_current_utc_time", return_value=fixed_now_dt)
    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})

    next_run, fetched_events = fetch_events(mock_client_instance, params, last_run)

    assert fetched_events == expected_events
    assert next_run == {"last_fetch": fixed_now_dt.strftime(DATE_FORMAT)}
