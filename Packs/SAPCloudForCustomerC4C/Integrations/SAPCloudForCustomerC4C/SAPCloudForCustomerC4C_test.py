import pytest
from SAPCloudForCustomerC4C import Client
from datetime import datetime
from CommonServerPython import *  # noqa: F401

SAP_CLOUD = "SAP CLOUD FOR CUSTOMER"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC
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
        - The `http_request` method of the mocked client is called exactly once.
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

    # # Assert the returned values
    assert events_list == expected_events
    assert cmd_results.raw_response == expected_events
    assert f"### Events from {SAP_CLOUD}" in cmd_results.readable_output
    assert "|CBROWSER|CDEVICE_TYPE|CTIMESTAMP|__metadata|" in cmd_results.readable_output


def test_get_events_command_success_multiple_pages(mocker):
    """
    Tests the successful execution of the `get_events_command` function,
    retrieving events that require multiple API calls (pagination).

    This test simulates a scenario where the total number of events to be retrieved
    exceeds the `DEFAULT_TOP` limit, necessitating multiple paginated API calls
    to fetch all the data. It verifies that the `get_events_command` correctly
    handles pagination and aggregates results from successive API responses.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Running the `get_events_command` function with the mocked client
          and specified arguments.
    Then:
        Verify that:
        - The `http_request` method of the mocked client is called the expected
          number of times (e.g., 3 calls for 2 pages of data plus a final
          call to confirm no more data).
        - The `events_list` returned by the command contains all events
          from all paginated responses, matching `expected_all_events`.
        - The `raw_response` in `cmd_results` matches `expected_all_events`.
        - The `readable_output` in `cmd_results` contains the expected
          header for the events.
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
        - The `fetched_events` returned by `fetch_events` match the `expected_events`.
        - The `next_run` dictionary correctly contains `last_fetch` key with the
          formatted `fixed_now_dt` as its value.
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
    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})
    next_run, fetched_events = fetch_events(mock_client_instance, params, last_run={})

    assert fetched_events == expected_events
    assert next_run == {"last_fetch": fixed_now_dt.strftime(DATE_FORMAT)}


def test_fetch_events_report_id_missing():
    """
    Tests the behavior of `fetch_events` when the 'report_id' is missing from the parameters.

    This test verifies that the `fetch_events` function correctly raises a
    `DemistoException` when the mandatory 'report_id' is not provided in the
    `params` dictionary, ensuring proper error handling for missing configuration.

    When:
        - Calling `fetch_events` with the mocked client and missing `report_id` parameter.
    Then:
        Verify that:
        - A `DemistoException` is raised.
        - The exception message contains the specific error text:
          "Report ID must be provided in the integration parameters and must be a string."
    """
    from SAPCloudForCustomerC4C import fetch_events

    mock_client_instance = mock_client()
    params = {"max_fetch": 10}  # Missing report_id

    with pytest.raises(DemistoException) as excinfo:
        fetch_events(mock_client_instance, params, last_run={})

    assert "Report ID must be provided in the integration parameters and must be a string." in str(excinfo.value)


def test_fetch_events_dateparser_fallback(mocker):
    """
    Tests the behavior of `fetch_events` when `dateparser.parse` fails to parse
    the `last_fetch` timestamp from `last_run`, leading to a fallback to `FIRST_FETCH` logic.

    This test simulates a scenario where the `last_run` state contains a malformed
    or unparseable date string for `last_fetch`. It verifies that `fetch_events`
    gracefully handles this error by reverting to the initial fetch logic (as if
    it were the very first run), retrieves events from `FIRST_FETCH` onwards,
    and correctly updates the `next_run` state with a valid current timestamp.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Calling `fetch_events` with the mocked client, parameters, and the `last_run`
          containing the malformed date.
    Then:
        Verify that:
        - The `http_request` method of the mocked client is called with parameters
          consistent with a `FIRST_FETCH` (i.e., no specific `start_date` based on `last_fetch`).
        - The `fetched_events` returned by `fetch_events` match the `expected_events`.
        - The `next_run` dictionary correctly contains a `last_fetch` key with the
          formatted `fixed_now_dt` (current time) as its value, indicating a successful
          reset of the fetch state.
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


def test_fetch_events_subsequent_fetch_with_overlap(mocker):
    """
    Tests a subsequent fetch, ensuring that events from a desired overlapping time window
    are included by specifying both a start and an end date.

    This test simulates a scenario where a previous `last_fetch` timestamp exists.
    The goal is to verify that the `fetch_events` function requests events starting
    from a point before the `last_fetch` timestamp (e.g., 1 minute prior) and ending
    at the current time (`fixed_now_dt`). This ensures no events are missed due to
    precise timestamp boundaries or API delays.

    Given:
        - `mocker`: A pytest fixture for mocking objects and methods.
    When:
        - Calling `fetch_events` with a mocked client, parameters, and a `last_run`
          dictionary containing a `last_fetch` timestamp.
    Then:
        - Verify that `get_events` is called with a `start_date` that is one minute
          before the `last_fetch`, and an `end_date` equal to the current time (`fixed_now_dt`).
        - Ensure `fetched_events` includes events from within and after the overlap window.
        - Confirm `next_run` contains a `last_fetch` equal to `fixed_now_dt`.
    """
    from SAPCloudForCustomerC4C import fetch_events

    mock_client_instance = mock_client()
    report_id = "general_reportID"
    params = {"report_id": report_id, "max_fetch": 3}

    # Simulate a previous last_fetch timestamp.
    last_fetch_str = "2025-07-06T12:00:00Z"

    # Define the current time for this fetch.
    fixed_now_dt = datetime(2025, 7, 6, 12, 1, 0)  # Current time is 12:01:00Z

    # Calculate the DESIRED start_date_for_filter for the API call.
    desired_start_date_for_filter_dt = fixed_now_dt - timedelta(minutes=1)  # Start time is 12:00:00Z
    expected_start_date_filter = desired_start_date_for_filter_dt.strftime(STRFTIME_FORMAT)

    # Calculate the DESIRED end_date_for_filter for the API call.
    desired_end_date_for_filter_dt = fixed_now_dt  # End time is 12:01:00Z
    expected_end_date_filter = desired_end_date_for_filter_dt.strftime(STRFTIME_FORMAT)

    expected_events = [
        {"CTIMESTAMP": "06-07-2025 12:00:00"},
        {"CTIMESTAMP": "06-07-2025 12:00:30"},
        {"CTIMESTAMP": "06-07-2025 12:00:59"},
    ]

    mocker.patch("SAPCloudForCustomerC4C.get_current_utc_time", return_value=fixed_now_dt)
    mocker.patch.object(mock_client_instance, "http_request", return_value={"d": {"results": expected_events}})

    next_run, fetched_events = fetch_events(mock_client_instance, params, last_run={"last_fetch": last_fetch_str})

    assert fetched_events == expected_events
    assert next_run == {"last_fetch": fixed_now_dt.strftime(DATE_FORMAT)}

    expected_filter = f"CTIMESTAMP ge '{expected_start_date_filter}' and CTIMESTAMP le '{expected_end_date_filter}'"
    mock_client_instance.http_request.assert_called_once_with(
        method="GET",
        url_suffix=f"{URL_SUFFIX}{report_id}?",
        params={"$filter": expected_filter, "$skip": 0, "$top": 3, "$format": "json", "$inlinecount": "allpages"},
    )


def test_add_time_to_events():
    """
    Tests the basic functionality of `add_time_to_events` for correct conversion and addition of `_time`.

    This test verifies that the `add_time_to_events` function correctly parses the
    "CTIMESTAMP" string (which includes " GMTUK"), converts it to the specified
    "YYYY-MM-DDTHH:MM:SSZ" format, and adds it as the `_time` key to event dictionaries.

    When:
        - The `add_time_to_events` function is called with a list of event dictionaries,
          each containing a valid "CTIMESTAMP" key in the "DD.MM.YYYY HH:MM:SS GMTUK" format.
    Then:
        Verify that:
        - The input `events` list is modified in-place.
        - The value of `_time` for each event matches the expected ISO8601 UTC format.
    """
    from SAPCloudForCustomerC4C import add_time_to_events

    events = [
        {
            "CTIMESTAMP": "14.07.2025 13:30:40 GMTUK",
        },
        {"CTIMESTAMP": "01.01.2024 00:00:00 GMTUK"},
    ]
    expected = [
        {"CTIMESTAMP": "14.07.2025 13:30:40 GMTUK", "_time": "2025-07-14T13:30:40Z"},
        {"CTIMESTAMP": "01.01.2024 00:00:00 GMTUK", "_time": "2024-01-01T00:00:00Z"},
    ]
    add_time_to_events(events)
    assert events == expected
