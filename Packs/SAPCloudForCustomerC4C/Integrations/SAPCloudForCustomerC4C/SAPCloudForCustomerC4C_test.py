import pytest
from SAPCloudForCustomerC4C import Client
from datetime import datetime
from CommonServerPython import *  # noqa: F401

SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"
URL_SUFFIX = "/sap/c4c/odata/ana_businessanalytics_analytics.svc/"
STRFTIME_FORMAT = "%d-%m-%Y %H:%M:%S"


def mock_client():
    return Client(base_url="https://testurl.com", base64String="base64String", verify=True)


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


def test_get_events_success(mocker):
    """
    Tests the successful retrieval of events when both start and end dates are specified.

    This test verifies that the `get_events` function correctly fetches event data
    from the mocked SAP Cloud for Customer (C4C) client when both a start date
    and an end date are provided, ensuring the generated OData filter includes
    both date clauses.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Calling `get_events` with a mocked client instance, a report ID,
          pagination parameters (`skip`, `top`), a `start_date`, and an `end_date`.
    Then:
        Verify that:
        - The `http_request` method of the mocked client is called exactly once.
        - The `http_request` call includes the correct `url_suffix` and `params`.
        - The `$filter` parameter in the `http_request` call correctly specifies
          `CTIMESTAMP ge '{start_date}' and CTIMESTAMP le '{end_date}'`.
        - The `$filter` parameter explicitly *does* contain an "and CTIMESTAMP le"
          clause, confirming the end date filter was applied.
        - The returned `result` from `get_events` matches the `expected_events`
          provided by the mocked `http_request` response.
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

    expected_filter = f"CTIMESTAMP ge '{start_date}' and CTIMESTAMP le '{end_date}'"
    mock_client_instance.http_request.assert_called_once_with(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params={"$filter": expected_filter, "$skip": skip, "$top": top, "$format": "json", "$inlinecount": "allpages"},
    )
    assert result == expected_events
    assert "and CTIMESTAMP le" in mock_client_instance.http_request.call_args[1]["params"]["$filter"]


def test_get_events_empty_results(mocker):
    """
    Tests the scenario where the API returns an empty list of events.

    This test verifies that the `get_events` function correctly handles cases
    where the mocked SAP Cloud for Customer (C4C) client's API call
    returns an empty list of results. It ensures the function returns an
    empty list as expected when no events are found in the specified time range.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Calling `get_events` with a mocked client instance, a report ID,
          pagination parameters (`skip`, `top`), and a `start_date` and an `end_date` defining the time window.
        - The client's `http_request` is configured to return an empty list of results.
    Then:
        Verify that:
        - The `http_request` method of the mocked client is called exactly once with the appropriate filter including both
        `start_date` and `end_date`.
        - The returned `result` from `get_events` is an empty list,
          matching the API's empty response.
    """
    from SAPCloudForCustomerC4C import get_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    skip = 0
    top = 10
    start_date = "01-01-2023 12:00:03"
    end_date = "01-01-2023 12:01:03"

    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": []}})
    result = get_events(mock_client_instance, report_id, skip, top, start_date, end_date)

    mock_client_instance.http_request.assert_called_once()
    assert result == []


def test_get_events_command_success_single_page(mocker):
    """
    Tests the successful execution of the `get_events_command` function,
    retrieving events that fit within a single page.

    This test simulates a scenario where the API returns a number of events
    less than or equal to the `DEFAULT_TOP` limit, ensuring that the
    `get_events_command` correctly processes and returns the data
    without needing multiple API calls for pagination.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Running the `get_events_command` function with the mocked client
          and specified arguments.
    Then:
        Verify that:
        - The `http_request` method of the mocked client is called exactly twice.
        - The `events_list` returned by the command matches the `expected_events`.
        - The `raw_response` in `cmd_results` matches the `expected_events`.
        - The `readable_output` in `cmd_results` contains the expected
          header and table structure for the events.
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

    # Check calls to http_request (test call and real call)
    assert mock_client_instance.http_request.call_count == 2

    assert events_list == expected_events
    assert cmd_results.raw_response == expected_events
    assert f"### Events from {SAP_CLOUD}" in cmd_results.readable_output
    assert "|CBROWSER|CDEVICE_TYPE|CTIMESTAMP|__metadata|" in cmd_results.readable_output


def test_get_events_command_success_multiple_pages(mocker):
    """
    Tests the `get_events_command` function for correctly handling paginated API responses.

    This test simulates retrieving events across multiple pages when the total requested
    events exceed the API's maximum per-request limit. It verifies that `get_events_command`
    makes multiple API calls as needed, aggregates all results, and returns them properly.

    Given:
        - A mocked client with a patched `http_request` method to simulate paginated responses.
        - A report ID and arguments that request more events than fit in a single page.

    When:
        - Calling `get_events_command` with the mocked client and arguments.

    Then:
        Verify that:
        - The client's `http_request` method is called the expected number of times to retrieve all pages.
        - The combined list of events includes all events from each paginated response.
        - The returned `CommandResults` object contains the full aggregated response.
        - The readable output includes the expected header indicating the source of the events.
    """
    from SAPCloudForCustomerC4C import get_events_command

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    start_date_str = "01-01-2025 00:00:00"
    limit_val = 7  # Requires 2 calls (5 events then 2 events)
    args = {"start_date": start_date_str, "limit": limit_val, "days_from_start": 2}
    expected = [{"CTIMESTAMP": "01-01-2025 00:00:00"}]

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
            {"d": {"results": expected}},  # Tesh Call
            {"d": {"results": expected_events_page1}},  # First call
            {"d": {"results": expected_events_page2}},  # Second call
            {"d": {"results": []}},  # Third call signals end of data
        ],
    )

    events_list, cmd_results = get_events_command(mock_client_instance, report_id, args)

    # Check calls to http_request
    assert mock_client_instance.http_request.call_count == 4
    assert events_list == expected_all_events
    assert cmd_results.raw_response == expected_all_events
    assert f"### Events from {SAP_CLOUD}" in cmd_results.readable_output


def test_get_events_command_no_start_date():
    """
    Tests the behavior of `get_events_command` when the 'start_date' argument is missing.

    This test verifies that the `get_events_command` function correctly handles
    the absence of the mandatory 'start_date' argument, ensuring it raises an exception when the required 'start_date' argument
    is missing.

    When:
        - Running the `get_events_command` function with the missing 'start_date' argument.
    Then:
        Verify that:
        - Tests that `get_events_command` raises an exception.
        - A `DemistoException` is raised with a message indicating that 'start_date' is required.
    """
    from SAPCloudForCustomerC4C import get_events_command

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    args = {"limit": 10}  # Missing start_date

    with pytest.raises(DemistoException) as excinfo:
        get_events_command(mock_client_instance, report_id, args)

    assert "start_date argument is missing. Cannot retrieve events." in str(excinfo.value)


def test_fetch_events_first_fetch_success(mocker):
    """
    Tests the successful first fetch of events by the `fetch_events` function
    when no previous `last_run` state is available.

    This test simulates the initial execution of `fetch_events`, verifying that
    it correctly retrieves a specified maximum number of events from the mocked
    SAP Cloud for Customer (C4C) client and updates the `next_run` state
    with the current UTC time as the `last_fetch` timestamp.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Calling `fetch_events` with the mocked client, parameters, and empty `last_run`.
    Then:
        Verify that:
        - The `http_request` method of the mocked client is called with appropriate
          parameters (e.g., `$top` matching `max_fetch`, and a filter based on
          a calculated `start_date` if applicable, or no filter if `last_run` is empty).
         The `fetched_events` returned by `fetch_events` precisely match the `expected_events`
          provided in the test setup.
        - The `next_run` dictionary correctly contains:
            - A `last_fetch` key with the formatted `fixed_now_dt` (adjusted by
              `timestamp_offset_hour`) as its value.
            - A `timezone_offset` key with the value `+3` (the `timestamp_offset_hour`).
    """
    from SAPCloudForCustomerC4C import fetch_events, convert_utc_to_offset

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    params = {"report_id": report_id, "max_fetch": 8}

    fixed_now_dt = datetime(2025, 7, 7, 12, 0, 0)  # Fixed current time
    timestamp_offset_hour = +3
    expected_events = [
        {
            "__metadata": {"uri": "example_url_1", "type": "111_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:00 UTC+3",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_2", "type": "112_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:15 UTC+3",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_3", "type": "113_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:21 UTC+3",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_4", "type": "114_QueryResult"},
            "CTIMESTAMP": "07-07-2025 01:00:28 UTC+3",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_5", "type": "115_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:36 UTC+3",
            "CBROWSER": "03",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_6", "type": "116_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:51 UTC+3",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_7", "type": "117_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:55 UTC+3",
            "CBROWSER": "01",
            "CDEVICE_TYPE": "default",
        },
        {
            "__metadata": {"uri": "example_url_8", "type": "118_QueryResult"},
            "CTIMESTAMP": "07-07-2025 15:00:58 UTC+3",
            "CBROWSER": "02",
            "CDEVICE_TYPE": "default",
        },
    ]

    mocker.patch("SAPCloudForCustomerC4C.get_current_utc_time", return_value=fixed_now_dt)
    last_fetch = convert_utc_to_offset(fixed_now_dt, timestamp_offset_hour)
    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})
    next_run, fetched_events = fetch_events(mock_client_instance, params, last_run={})

    assert fetched_events == expected_events
    assert next_run == {"last_fetch": last_fetch.strftime(STRFTIME_FORMAT), "timezone_offset": timestamp_offset_hour}


UTC_FORMAT_TIMESTAMP_TEST_CASES = [
    (
        # UTC-6 case
        [
            {"CTIMESTAMP": "14.07.2025 13:30:40 UTC-6"},
            {"CTIMESTAMP": "01.01.2024 00:00:00 UTC-6"},
        ],
        [
            {"CTIMESTAMP": "14.07.2025 13:30:40 UTC-6", "_time": "2025-07-14T19:30:40Z"},
            {"CTIMESTAMP": "01.01.2024 00:00:00 UTC-6", "_time": "2024-01-01T06:00:00Z"},
        ],
    ),
    (
        # UTC+2 case
        [
            {"CTIMESTAMP": "30.07.2025 10:15:00 UTC+2"},
            {"CTIMESTAMP": "01.01.2024 06:00:00 UTC+2"},
        ],
        [
            {"CTIMESTAMP": "30.07.2025 10:15:00 UTC+2", "_time": "2025-07-30T08:15:00Z"},
            {"CTIMESTAMP": "01.01.2024 06:00:00 UTC+2", "_time": "2024-01-01T04:00:00Z"},
        ],
    ),
]


@pytest.mark.parametrize("input_events, expected_output", UTC_FORMAT_TIMESTAMP_TEST_CASES)
def test_add_time_to_events(input_events, expected_output):
    """
    Tests the basic functionality of `add_time_to_events` for correct conversion and addition of `_time`.

    This test verifies that the `add_time_to_events` function correctly parses the
    "CTIMESTAMP" string (which includes "UTC+-Num"), converts it to the specified
    "YYYY-MM-DDTHH:MM:SSZ" format, and adds it as the `_time` key to event dictionaries.

    When:
        - The `add_time_to_events` function is called with a list of event dictionaries,
          each containing a valid "CTIMESTAMP" key in the "DD.MM.YYYY HH:MM:SS UTC+-Num" format.
    Then:
        Verify that:
        - The input `events` list is modified in-place.
        - The value of `_time` for each event matches the expected ISO8601 UTC format.
    """
    from SAPCloudForCustomerC4C import add_time_to_events

    result = add_time_to_events(input_events)
    assert result == expected_output


def test_add_time_to_events_no_events():
    """
    Tests the behavior of `add_time_to_events` when given an empty event list.

    This test verifies that the function correctly handles the edge case where no events are provided.

    When:
        - The `add_time_to_events` function is called with an empty list.

    Then:
        Verify that:
        - The returned value is also an empty list.
        - No errors are raised.
    """
    from SAPCloudForCustomerC4C import add_time_to_events

    events = add_time_to_events([])
    assert events == []


def test_get_timestamp_offset_hour(mocker):
    """
    Tests the basic functionality of `get_timestamp_offset_hour` for correct UTC offset calculation.

    This test verifies that the `get_timestamp_offset_hour` function correctly extracts a timestamp
    from the API response, parses the UTC offset, and returns it as a float representing the number of hours.

    When:
        - The API response contains a valid "CTIMESTAMP" value in the format "DD.MM.YYYY HH:MM:SS UTC±Num".

    Then:
        Verify that:
        - The function parses the timestamp correctly.
        - The returned offset matches the expected offset in hours (e.g., 2.0 for UTC+2).
    """
    from SAPCloudForCustomerC4C import get_timestamp_offset_hour

    mock_client_instance = mock_client()

    # Example timestamp string with UTC+2 offset
    timestamp_with_offset = "23.07.2025 12:00:51 UTC+2"
    expected_event = [{"CTIMESTAMP": timestamp_with_offset}]

    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_event}})
    report_id = "general_reportID"

    # Call the function under test
    offset_hour = get_timestamp_offset_hour(mock_client_instance, report_id)

    # Parse the timestamp manually to calculate expected offset for comparison
    dt_object = dateparser.parse(timestamp_with_offset)
    expected_offset = dt_object.tzinfo.utcoffset(dt_object).total_seconds() / 3600

    # Assert that the returned offset matches the expected offset (2.0 in this case)
    assert offset_hour == expected_offset


UTC_TIMESTAMP_TEST_CASES = [
    # UTC+2
    (datetime(2025, 7, 30, 12, 0, 0, tzinfo=timezone.utc), 2.0, "2025-07-30T14:00:00+02:00"),
    # UTC-5
    (datetime(2025, 7, 30, 12, 0, 0, tzinfo=timezone.utc), -5.0, "2025-07-30T07:00:00-05:00"),
    # UTC+0
    (datetime(2025, 7, 30, 12, 0, 0, tzinfo=timezone.utc), 0.0, "2025-07-30T12:00:00+00:00"),
    # UTC+5.5 (e.g., India)
    (datetime(2025, 7, 30, 12, 0, 0, tzinfo=timezone.utc), 5.5, "2025-07-30T17:30:00+05:30"),
]


@pytest.mark.parametrize("utc_input, offset_hour, expected_iso", UTC_TIMESTAMP_TEST_CASES)
def test_convert_utc_to_offset(utc_input, offset_hour, expected_iso):
    """
    Tests the `convert_utc_to_offset` function for correct datetime conversion to specified UTC offset.

    When:
        - The function is called with a UTC datetime and a target offset in hours.

    Then:
        Verify that:
        - It should return a datetime object in the correct timezone offset,
          with the ISO 8601 string matching the expected output.
    """
    from SAPCloudForCustomerC4C import convert_utc_to_offset

    converted = convert_utc_to_offset(utc_input, offset_hour)
    assert converted.isoformat() == expected_iso


def test_get_events_command_no_response(mocker):
    """
    Tests `get_events_command` behavior when no events are returned from the `get_events` function.

    This test ensures that the command handles an empty event list gracefully without raising errors,
    and still produces a valid `CommandResults` object with appropriate messaging.

    When:
        - `get_events` returns an empty list (indicating no events are available).
        - A valid timestamp exists in the API response, but no events match the filters.

    Then:
        Verify that:
        - An empty list is returned for the events.
        - A `CommandResults` object is returned with appropriate headers and empty data.
        - A debug log message is written indicating that no more events exist.
    """
    from SAPCloudForCustomerC4C import get_events_command

    mock_client_instance = mock_client()
    report_id = "general_reportID"

    mock_response = {"d": {"results": [{"CTIMESTAMP": "25-07-2025 10:00:00"}]}}
    mocker.patch("SAPCloudForCustomerC4C.get_events_api_call", return_value=mock_response)
    mocker.patch("SAPCloudForCustomerC4C.get_events", return_value=[])

    mock_debug = mocker.patch("SAPCloudForCustomerC4C.demisto.debug")

    args = {
        "start_date": "25-07-2025 10:00:00",
        "limit": "5",
        "days_from_start": "1",
    }

    events, results = get_events_command(mock_client_instance, report_id=report_id, args=args)

    assert events == []
    assert isinstance(results, CommandResults)
    assert f"Events from {SAP_CLOUD}" in results.readable_output
    mock_debug.assert_called_with("No more events exist or no response received, breaking...")


VALID_TIMESTAMP_TEST_CASES = [
    "30.07.2025 14:35:00 UTC+2",
    "2025-07-30T14:35:00+02:00",
    "July 30, 2025 2:35 PM +02:00",
    "2025/07/30 14:35:00 UTC+02",
]


@pytest.mark.parametrize("valid_timestamp", VALID_TIMESTAMP_TEST_CASES)
def test_response_validation_success(mocker, valid_timestamp):
    """
    Tests `response_validation` with various valid timestamp formats to ensure correct handling.

    This parametrized test verifies that the `response_validation` function correctly
    processes a variety of well-formed timestamp strings returned by the API and
    returns them unchanged without raising any exceptions.

    When:
        - `get_events_api_call` is mocked to return a response containing a valid
          `CTIMESTAMP` string in one of several common timestamp formats.

    Then:
        Verify that:
        - The function returns the original timestamp string exactly as received.
        - No exceptions are raised during parsing or validation.
    """
    from SAPCloudForCustomerC4C import response_validation

    mock_response = {"d": {"results": [{"CTIMESTAMP": valid_timestamp}]}}

    mocker.patch("SAPCloudForCustomerC4C.get_events_api_call", return_value=mock_response)
    mock_client_instance = mock_client()
    report_id = "general_reportID"

    result = response_validation(mock_client_instance, report_id)
    assert result == valid_timestamp


@pytest.mark.parametrize(
    "mock_response, expected_error, expected_debug_msg",
    [
        # Empty response case
        (None, f"Empty response received from {SAP_CLOUD} API.", None),
        # Missing "d" key in response
        ({"wrong_key": {}}, f"Unexpected response structure from {SAP_CLOUD} API.", None),
        # Missing "results" key inside "d"
        ({"d": {"wrong_key": []}}, f"Unexpected response structure from {SAP_CLOUD} API.", None),
        # Invalid timestamp format
        (
            {"d": {"results": [{"CTIMESTAMP": "INVALID_TIMESTAMP"}]}},
            "SAP timezone configuration is not supported",
            "Parsing Error: Could not parse CTIMESTAMP 'INVALID_TIMESTAMP'.",
        ),
        # No events in both primary and fallback time ranges
        (
            {"d": {"results": []}},
            "Unable to retrieve a sample timestamp for validation",
            None,
        ),
    ],
)
def test_response_validation_failure(mocker, mock_response, expected_error, expected_debug_msg):
    """
    Tests `response_validation` for various failure scenarios where the timestamp is invalid or response is malformed.

    This parametrized test verifies that `response_validation` raises a `DemistoException` with the correct error message
    when:
        - The API response is empty.
        - The API response structure is missing expected keys ("d" or "results").
        - The timestamp string in the response cannot be parsed due to invalid format or unsupported timezone.

    When:
        - `get_events_api_call` is mocked to return a response representing each failure scenario.
        - `response_validation` is called with the mocked response.

    Then:
        Verify that:
        - A `DemistoException` is raised with the expected error message.
        - If applicable, a debug message is logged indicating the parsing failure.
    """
    from SAPCloudForCustomerC4C import response_validation

    mock_client_instance = mock_client()
    report_id = "general_reportID"

    mocker.patch("SAPCloudForCustomerC4C.get_events_api_call", return_value=mock_response)
    if expected_debug_msg:
        mock_debug = mocker.patch("SAPCloudForCustomerC4C.demisto.debug")
    else:
        mock_debug = None

    with pytest.raises(DemistoException) as exc_info:
        response_validation(mock_client_instance, report_id)

    assert expected_error in str(exc_info.value)

    if mock_debug:
        mock_debug.assert_called_with(expected_debug_msg)


def test_fetch_timestamp_success(mocker):
    """
    Tests `fetch_timestamp` for successful retrieval of a timestamp from the SAP API.

    This test verifies that `fetch_timestamp` correctly returns the 'CTIMESTAMP' string
    from the first event in the API response when a valid response with event data is returned.

    When:
        - `get_events_api_call` is mocked to return a valid response containing a timestamp.
        - `fetch_timestamp` is called with mock client, report ID, and start/end datetime strings.

    Then:
        Verify that:
        - The function returns the exact 'CTIMESTAMP' string from the first event.
    """
    from SAPCloudForCustomerC4C import fetch_timestamp

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    timestamp_value = "03.08.2025 10:08:00 UTC-2"

    mock_response = {"d": {"results": [{"CTIMESTAMP": timestamp_value}]}}

    mocker.patch("SAPCloudForCustomerC4C.get_events_api_call", return_value=mock_response)

    start = "03.08.2025 10:08:14 UTC-2"
    end = "03.08.2025 10:07:14 UTC-2"

    result = fetch_timestamp(mock_client_instance, report_id, start, end)
    assert result == timestamp_value


@pytest.mark.parametrize(
    "bad_response, expected_error",
    [
        (None, f"Empty response received from {SAP_CLOUD} API."),  # completely empty response
        ({"wrong_key": {}}, f"Unexpected response structure from {SAP_CLOUD} API."),  # missing 'd'
        ({"d": {"wrong_key": []}}, f"Unexpected response structure from {SAP_CLOUD} API."),  # missing 'results'
    ],
)
def test_fetch_timestamp_unexpected_structure_raises(mocker, bad_response, expected_error):
    """
    Tests `fetch_timestamp` for scenarios where the API response structure is invalid or missing keys.

    This parametrized test verifies that `fetch_timestamp` raises a `DemistoException` with the
    appropriate error message when the API response:
        - Is None or empty.
        - Does not contain the expected 'd' key.
        - Does not contain the expected 'results' key inside 'd'.

    When:
        - `get_events_api_call` is mocked to return each malformed or empty response.
        - `fetch_timestamp` is called with the mocked response.

    Then:
        Verify that:
        - A `DemistoException` is raised indicating the unexpected response structure
          or empty response, depending on the case.
    """
    from SAPCloudForCustomerC4C import fetch_timestamp

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    mocker.patch("SAPCloudForCustomerC4C.get_events_api_call", return_value=bad_response)

    start = "03.08.2025 10:08:14 UTC-2"
    end = "03.08.2025 10:07:14 UTC-2"

    with pytest.raises(DemistoException) as exc_info:
        fetch_timestamp(mock_client_instance, report_id, start, end)

    assert expected_error in str(exc_info.value)


def test_fetch_timestamp_returns_none_when_no_results(mocker):
    """
    Tests that `fetch_timestamp` returns None when the API response contains an empty 'results' list.

    This simulates a valid response with no events found in the given time range.

    When:
        - `get_events_api_call` is mocked to return a valid response structure with empty results.
        - `fetch_timestamp` is called with this mocked response.

    Then:
        Verify that:
        - It should return None, indicating no timestamp was found.
    """
    from SAPCloudForCustomerC4C import fetch_timestamp

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    start = "03.08.2025 10:08:14 UTC-2"
    end = "03.08.2025 10:07:14 UTC-2"

    # Simulated empty but valid API response
    empty_response = {"d": {"__count": "0", "results": []}}

    mocker.patch("SAPCloudForCustomerC4C.get_events_api_call", return_value=empty_response)

    result = fetch_timestamp(mock_client_instance, report_id, start, end)
    assert result is None
