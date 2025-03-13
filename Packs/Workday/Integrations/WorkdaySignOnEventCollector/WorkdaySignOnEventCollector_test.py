import json
import unittest
from typing import Any
from unittest.mock import patch

import pytest
from freezegun import freeze_time

from CommonServerPython import DemistoException
from WorkdaySignOnEventCollector import (
    get_from_time,
    fletcher16,
    generate_pseudo_id,
    convert_to_json,
    Client,
    fetch_sign_on_logs,
    get_sign_on_events_command,
    fetch_sign_on_events_command,
    process_and_filter_events,
    main,
    VENDOR,
    PRODUCT,
)


def test_get_from_time() -> None:
    """
    Given:
        - A time duration in seconds (3600 seconds or 1 hour ago).

    When:
        - The function `get_from_time` is called to convert this duration to a UTC datetime string.

    Then:
        - Ensure that the returned value is a string.
        - Validate that the string ends with 'Z', indicating it's in UTC format.
    """
    # Given: A time duration of 3600 seconds (or 1 hour) ago.
    seconds_ago = 3600  # 1 hour ago

    # When: Calling the function to convert this to a UTC datetime string.
    result: Any = get_from_time(seconds_ago)

    # Then: Validate the type and format of the returned value.
    assert isinstance(result, str)
    assert result.endswith("Z")  # Check if it's in the right format


def test_fletcher16() -> None:
    """
    Given:
        - Two types of byte strings, one containing the word 'test' and another being empty.

    When:
        - The function `fletcher16` is called to calculate the checksum for these byte strings.

    Then:
        - Ensure that the checksum calculated for the byte string 'test' matches the expected value of 22976.
        - Validate that the checksum for an empty byte string is 0.
    """
    # Given: A byte string containing the word 'test'.
    data = b"test"

    # When: Calling `fletcher16` to calculate the checksum.
    result: Any = fletcher16(data)

    # Then: Validate that the checksum matches the expected value.
    expected = 22976
    assert result == expected

    # Given: An empty byte string.
    data = b""

    # When: Calling `fletcher16` to calculate the checksum.
    result = fletcher16(data)

    # Then: Validate that the checksum for an empty byte string is 0.
    expected = 0
    assert result == expected


def test_generate_pseudo_id() -> None:
    """
    Given:
        - Four different event dictionaries:
            1. A valid event dictionary with known values.
            2. An empty event dictionary.
            3. An event dictionary missing the "Signon_DateTime" key.
            4. A large event dictionary.

    When:
        - Calling `generate_pseudo_id` to calculate a unique ID based on the event dictionary.

    Then:
        - For the first case, ensure that the unique ID matches the expected value.
        - For the second and third cases, ensure that an exception is raised.
        - For the fourth case, ensure the function can handle large dictionaries without errors.
    """

    # Given: A valid event dictionary with known values.
    event1 = {
        "Short_Session_ID": "12345",
        "User_Name": "ABC123",
        "Successful": 1,
        "Signon_DateTime": "2023-09-04T07:47:57.460-07:00",
    }
    # When: Calling `generate_pseudo_id` to calculate the unique ID.
    event1_str: str = json.dumps(event1, sort_keys=True)
    expected_checksum1: Any = fletcher16(event1_str.encode())
    expected_unique_id1: str = f"{expected_checksum1}_{event1['Signon_DateTime']}"
    result1: str = generate_pseudo_id(event1)
    # Then: Validate that the unique ID matches the expected value.
    assert result1 == expected_unique_id1

    # Given: An empty event dictionary.
    event2 = {}
    # When & Then: Calling `generate_pseudo_id` and expecting an exception.
    try:
        generate_pseudo_id(event2)
    except DemistoException as e:
        assert (
            str(e)
            == "While calculating the pseudo ID for an event, an event without a Signon_DateTime was "
            "found.\nError: 'Signon_DateTime'"
        )
    else:
        raise AssertionError("Expected DemistoException but did not get one")

    # Given: An event dictionary missing the "Signon_DateTime" key.
    event3 = {
        "Short_Session_ID": "12345",
        "User_Name": "ABC123",
        "Successful": 1,
    }
    # When & Then: Calling `generate_pseudo_id` and expecting an exception.
    try:
        generate_pseudo_id(event3)
    except DemistoException:
        pass
    else:
        raise AssertionError("Expected DemistoException but did not get one")

    # Given: A large event dictionary.
    event4 = {str(i): i for i in range(10000)}  # Create a large dictionary
    event4["Signon_DateTime"] = "2023-09-04T07:47:57.460-07:00"  # Add a Signon_DateTime key
    # When & Then: Calling `generate_pseudo_id` to check if the function can handle it.
    assert generate_pseudo_id(event4)


def test_process_and_filter_events() -> None:
    """
    Given:
        - A list of two valid sign-on events that differ by 1 second in their "Signon_DateTime".
        - An initial time ("from_time") that matches the "Signon_DateTime" of one of the events.
        - An empty set of pseudo_ids from the previous run.

    When:
        - Calling the `process_and_filter_events` function to filter out duplicates and process events for the next
         iteration.

    Then:
        - The list of non-duplicate events should match the original list of events.
        - The set of pseudo_ids for the next iteration should contain two elements.
        - Each event in the list of non-duplicates should have an additional "_time" key that matches its
          "Signon_DateTime".
    """

    # Given: A list of two valid sign-on events and other initial conditions
    events = [
        {
            "Short_Session_ID": "12345",
            "User_Name": "ABC6789",
            "Successful": 1,
            "Signon_DateTime": "2023-09-04T07:47:57.460-07:00",
        },
        {
            "Short_Session_ID": "12346",
            "User_Name": "ABC6790",
            "Successful": 1,
            "Signon_DateTime": "2023-09-04T07:47:57.460-07:00",
        },
    ]
    from_time: str = "2021-09-01T12:00:00Z"
    previous_run_pseudo_ids: set[
        Any
    ] = set()  # Assume no previous checksums for simplicity

    # When: Calling the function to test
    non_duplicates, pseudo_ids_for_next_iteration = process_and_filter_events(
        events, from_time, previous_run_pseudo_ids
    )

    # Then: Validate the function's output
    assert (
        non_duplicates == events
    )  # Check if the list of non-duplicates is as expected
    assert (
        len(pseudo_ids_for_next_iteration) == 2
    )  # Check if the set of pseudo_ids for next iteration is updated

    # Check if '_time' key is added to each event
    for event in non_duplicates:
        assert "_time" in event
        assert event["_time"] == event["Signon_DateTime"]


def test_convert_to_json() -> None:
    """
    Given:
        - A sample XML response string containing a single 'Workday_Account_Signon' entry with a 'Signon_DateTime'.

    When:
        - Calling the 'convert_to_json' function to convert the XML data to a Python dictionary.

    Then:
        - The function should return two Python dictionaries.
        - The first dictionary should represent the entire XML structure.
        - The second dictionary should contain just the 'Workday_Account_Signon' entries.
        - Both dictionaries should correctly reflect the 'Signon_DateTime' from the original XML.
    """

    # Given: Test with XML data (this is a simplified version for the sake of the test)
    xml_response = """
    <Envelope>
        <Body>
            <Get_Workday_Account_Signons_Response>
                <Response_Data>
                    <Workday_Account_Signon>
                        <Signon_DateTime>2023-09-04T07:47:57.460-07:00</Signon_DateTime>
                    </Workday_Account_Signon>
                </Response_Data>
            </Get_Workday_Account_Signons_Response>
        </Body>
    </Envelope>
    """

    # When: Calling the function to test
    raw_json_response, account_signon_data = convert_to_json(xml_response)

    # Then: Check if the converted data matches the expected structure
    assert (
        raw_json_response["Envelope"]["Body"]["Get_Workday_Account_Signons_Response"][
            "Response_Data"
        ]["Workday_Account_Signon"][0]["Signon_DateTime"]
        == "2023-09-04T07:47:57.460-07:00"
    )

    assert (
        account_signon_data["Workday_Account_Signon"][0]["Signon_DateTime"]
        == "2023-09-04T07:47:57.460-07:00"
    )


def test_generate_workday_account_signons_body() -> None:
    """
    Given:
        - A Client object initialized with a base URL, verification settings, a tenant name, and login credentials.
        - Parameters specifying the page, count, and time range for fetching Workday sign-on events.

    When:
        - Calling the 'generate_workday_account_signons_body' method on the Client object to generate the SOAP request body.

    Then:
        - The returned SOAP request body should contain all the specified parameters.
        - The body should also contain the username and password for authentication.
    """

    # Given: Initialize a Client object with sample data
    client = Client(
        base_url="",
        verify_certificate=True,
        proxy=False,
        tenant_name="test_tenant",
        username="test_user",
        password="test_pass",
        api_version='v40.0',
    )

    # When: Generate the SOAP request body
    body = client.generate_workday_account_signons_body(
        page=1,
        count=10,
        to_time="2021-09-01T12:00:00Z",
        from_time="2021-09-01T11:00:00Z",
    )

    # Then: Verify that the SOAP request body contains all the specified parameters
    assert "<bsvc:Page>1</bsvc:Page>" in body
    assert "<bsvc:Count>10</bsvc:Count>" in body
    assert "<bsvc:From_DateTime>2021-09-01T11:00:00Z</bsvc:From_DateTime>" in body
    assert "<bsvc:To_DateTime>2021-09-01T12:00:00Z</bsvc:To_DateTime>" in body
    assert "<wsse:Username>test_user</wsse:Username>" in body
    assert (
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">test_pass</wsse:Password>'  # noqa:E501
        in body
    )


def test_generate_test_payload() -> None:
    """
    Given:
        - A Client object initialized with a base URL, verification settings, a tenant name, and login credentials.
        - Parameters specifying the time range for fetching Workday sign-on events for the test payload.

    When:
        - Calling the 'generate_test_payload' method on the Client object to generate a SOAP request payload for testing.

    Then:
        - The returned SOAP request payload should contain all the specified parameters.
        - The payload should also contain the username and password for authentication.
    """

    # Given: Initialize a Client object with sample data
    client = Client(
        base_url="",
        verify_certificate=True,
        proxy=False,
        tenant_name="test_tenant",
        username="test_user",
        password="test_pass",
        api_version='v40.0',
    )

    # When: Generate the SOAP request payload for testing
    payload = client.generate_test_payload(
        from_time="2021-09-01T11:00:00Z", to_time="2021-09-01T12:00:00Z"
    )

    # Then: Verify that the SOAP request payload contains all the specified parameters
    assert "<bsvc:Page>1</bsvc:Page>" in payload
    assert "<bsvc:Count>1</bsvc:Count>" in payload
    assert "<bsvc:From_DateTime>2021-09-01T11:00:00Z</bsvc:From_DateTime>" in payload
    assert "<bsvc:To_DateTime>2021-09-01T12:00:00Z</bsvc:To_DateTime>" in payload
    assert "<wsse:Username>test_user</wsse:Username>" in payload
    assert (
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">test_pass</wsse:Password>'  # noqa:E501
        in payload
    )


def test_convert_to_json_valid_input() -> None:
    """
    Given:
        - An XML-formatted response string from the Workday API, containing sign-on event data.

    When:
        - Calling the 'convert_to_json' function to convert the XML response to JSON format.

    Then:
        - The function should return two JSON objects: one containing the full JSON-converted data,
          and another containing only the sign-on event data.
        - Both JSON objects should be properly formatted and contain the expected data fields.
    """

    # Given: An XML-formatted response string from the Workday API
    response = """
    <Envelope>
        <Body>
            <Get_Workday_Account_Signons_Response>
                <Response_Data>
                    <Workday_Account_Signon>
                        <Signon_DateTime>2021-09-01T11:00:00Z</Signon_DateTime>
                    </Workday_Account_Signon>
                </Response_Data>
            </Get_Workday_Account_Signons_Response>
        </Body>
    </Envelope>
    """

    # When: Converting the XML to JSON
    full_json, account_signon_data = convert_to_json(response)

    # Then: Validate the full_json data structure
    envelope = full_json.get("Envelope", {})
    body = envelope.get("Body", {})
    response = body.get("Get_Workday_Account_Signons_Response", {})
    response_data = response.get("Response_Data", {})
    workday_account_signons = response_data.get("Workday_Account_Signon", [])

    # Assertions for full_json
    assert isinstance(
        workday_account_signons, list
    ), "workday_account_signons is not a list"
    assert workday_account_signons, "workday_account_signons is empty"
    assert workday_account_signons[0].get("Signon_DateTime") == "2021-09-01T11:00:00Z"

    # Then: Validate the account_signon_data structure
    workday_account_signons_data = account_signon_data.get("Workday_Account_Signon", [])

    # Assertions for account_signon_data
    assert workday_account_signons_data
    assert (
        workday_account_signons_data[0].get("Signon_DateTime") == "2021-09-01T11:00:00Z"
    )


class TestFetchSignOnLogs(unittest.TestCase):
    def setUp(self) -> None:
        """
        Given:
            - A Client object with mock URL, tenant, username, and password.

        When:
            - Setting up each unit test case.

        Then:
            - The Client object should be initialized and ready for testing.
        """
        self.client = Client(
            "mock_url",
            False,
            False,
            "mock_tenant",
            "mock_user",
            "mock_pass",
            api_version='v40.0',
        )

    @patch.object(Client, "retrieve_events")
    def test_fetch_sign_on_logs_single_page(self, mock_retrieve_events) -> None:
        """
        Given:
            - A mock Client object with a retrieve_events method that returns a sample response.
            - The sample response contains a single Workday sign-on event.

        When:
            - Calling the fetch_sign_on_logs function to fetch sign-on logs.

        Then:
            - The function should return a list of events.
            - The length of the list should be 1.
            - The event in the list should have the User_Name "John".
        """

        # Given: Sample data to be returned by the mock
        mock_response = (
            {
                "Workday_Account_Signon": [
                    {
                        "Signon_DateTime": "2021-09-01T11:00:00Z",
                        "User_Name": "John",
                        "Short_Session_ID": "123456",
                        "Successful": 1,
                    }
                ]
            },
            1,
        )

        # Setup: Configure the mock to return the sample data
        mock_retrieve_events.return_value = mock_response

        # When: Fetching sign-on logs
        events = fetch_sign_on_logs(
            self.client, 10, "2021-09-01T00:00:00Z", "2021-09-02T00:00:00Z"
        )

        # Then: Validate the function's return value
        assert len(events) == 1
        assert events[0]["User_Name"] == "John"


class TestGetSignOnEventsCommand(unittest.TestCase):
    def test_get_sign_on_events_command(self) -> None:
        """
        Given:
            - A Client object with mock settings.
            - A patch for the fetch_sign_on_logs function to return a mock event.
            - The mock event has details such as Signon_DateTime, User_Name, Short_Session_ID, and Successful status.

        When:
            - Calling the get_sign_on_events_command function to get sign-on events between two date-time ranges.

        Then:
            - The function should return a list of events and results.
            - The length of the list should be 1.
            - The event in the list should have the User_Name "John" and _time "2021-09-01T11:00:00Z".
            - The readable_output of the results should start with "### Sign On Events List:".
        """

        # Given: Sample data to be returned by the mock
        mock_events = [
            {
                "Signon_DateTime": "2023-09-04T07:47:57.460-07:00",
                "User_Name": "John",
                "Short_Session_ID": "123456",
                "Successful": 1,
                "_time": "2021-09-01T11:00:00Z",  # This is added by the process_events function
            }
        ]

        # Setup: Use patch to mock the fetch_sign_on_logs function
        with patch(
            "WorkdaySignOnEventCollector.fetch_sign_on_logs", return_value=mock_events
        ):
            client = Client(
                "mock_url",
                False,
                False,
                "mock_tenant",
                "mock_user",
                "mock_pass",
                api_version='v40.0',
            )

            # When: Calling the get_sign_on_events_command
            events, results = get_sign_on_events_command(
                client, "2021-09-01T00:00:00Z", "2021-09-02T00:00:00Z", 10
            )

            # Then: Validate the function's return value
            assert len(events) == 1
            assert events[0]["User_Name"] == "John"
            assert events[0]["_time"] == "2023-09-04T07:47:57.460-07:00"
            assert results.readable_output.startswith("### Sign On Events List:")


@freeze_time("2023-09-04T00:00:00.000-07:00")
def test_fetch_sign_on_events_command_single_page() -> None:
    """
    Given:
        - A Client object with mock settings.
        - A patch for the Client's retrieve_events method to return a mock event.
        - A patch for demisto.getLastRun function to return a mock last_run dictionary.
        - The mock event has details such as Signon_DateTime, User_Name, Short_Session_ID, and Successful status.
        - The mock last_run dictionary contains last_fetch_time and previous_run_pseudo_ids.

    When:
        - Calling the fetch_sign_on_events_command function to fetch sign-on events.

    Then:
        - The function should return a list of events and a new_last_run dictionary.
        - The length of the list should be 1.
        - The event in the list should have the User_Name "John" and _time "2021-09-01T11:00:00Z".
        - The new_last_run dictionary should have last_fetch_time updated to "2021-09-01T11:00:00Z".
    """

    # Given: Sample data to be returned by the mock
    mock_events = [
        {
            "Signon_DateTime": "2023-09-04T07:47:57.460-07:00",
            "User_Name": "John",
            "Short_Session_ID": "123456",
            "Successful": 1,
            "_time": "2023-09-04T07:47:57.460-07:00",  # This is added by the process_events function
        }
    ]

    # Setup: Mock the client's retrieve_events method and demisto.getLastRun function
    mock_retrieve_response = ({"Workday_Account_Signon": mock_events}, 1)
    mock_last_run = {
        "last_fetch_time": "2023-09-04T07:47:57.460-07:00",
        "previous_run_pseudo_ids": set(),
    }

    # When: Calling the fetch_sign_on_events_command
    with patch.object(
        Client, "retrieve_events", return_value=mock_retrieve_response
    ), patch("demistomock.getLastRun", return_value=mock_last_run):
        client = Client(
            "mock_url",
            False,
            False,
            "mock_tenant",
            "mock_user",
            "mock_pass",
            api_version='v40.0',
        )
        events, new_last_run = fetch_sign_on_events_command(client, 10, mock_last_run)

    # Then: Validate the function's return value
    assert len(events) == 1
    assert events[0]["User_Name"] == "John"
    assert events[0]["_time"] == "2023-09-04T07:47:57.460-07:00"
    assert new_last_run["last_fetch_time"] == "2023-09-04T07:47:57.460-07:00"


def test_main_fetch_events() -> None:
    """
    Given:
        - A set of mock parameters for the client.
        - Mock functions for demisto's getLastRun, setLastRun, and params.
        - Mock for the fetch_sign_on_events_command function to return mock events and new last_run data.
        - Mock for the send_events_to_xsiam function.

    When:
        - The main function is called and the command is 'fetch-events'.

    Then:
        - Ensure that fetch_sign_on_events_command is called with the correct arguments.
        - Ensure that send_events_to_xsiam is called with the mock events.
        - Ensure that setLastRun is called to update the last_run data.
    """
    # Given: Mock parameters and last run data
    mock_params = {
        "tenant_name": "TestTenant",
        "max_fetch": "10000",
        "base_url": "https://testurl.com",
        "credentials": {"identifier": "TestUser", "password": "testpass"},
        "insecure": True,
    }

    # Mocking demisto.command to return 'fetch-events'
    with patch("demistomock.command", return_value="fetch-events"), patch(
        "demistomock.getLastRun", return_value={"some": "data"}
    ), patch("demistomock.setLastRun") as mock_set_last_run, patch(
        "demistomock.params", return_value=mock_params
    ), patch(
        "WorkdaySignOnEventCollector.Client"
    ) as mock_client, patch(
        "WorkdaySignOnEventCollector.fetch_sign_on_events_command"
    ) as mock_fetch_sign_on_events_command, patch(
        "WorkdaySignOnEventCollector.send_events_to_xsiam"
    ) as mock_send_events_to_xsiam:
        # Mocking the output of fetch_sign_on_events_command
        mock_events = [{"event": "data"}]
        mock_new_last_run = {"new": "data"}
        mock_fetch_sign_on_events_command.return_value = (
            mock_events,
            mock_new_last_run,
        )

        # When: Calling the main function
        main()

        # Then: Validate the function calls and arguments
        mock_fetch_sign_on_events_command.assert_called_with(
            client=mock_client.return_value,
            max_fetch=10000,
            last_run={"some": "data"},
        )

        mock_send_events_to_xsiam.assert_called_with(
            mock_events, vendor=VENDOR, product=PRODUCT
        )
        mock_set_last_run.assert_called_with(mock_new_last_run)


@pytest.mark.parametrize(
    "username, escaped_username, password, escaped_password",
    [
        ("username&", "username&amp;", "pass&", "pass&amp;"),
        ("username>", "username&gt;", "pass>", "pass&gt;"),
        ("username<", "username&lt;", "pass<", "pass&lt;"),
        ("username", "username", "pass", "pass")
    ]
)
def test_escaping_user_name(username, escaped_username, password, escaped_password):
    """
    Given:
        A Client object initialized with a base URL, verification settings, a tenant name, and login credentials.
        In the first 3 cases the credentials contains a special character that needs to be escaped, and the last case checks
        that in a case of a credentials without special characters, they don't change.
    When:
        Creating a new Workday Sign Ons client.
    Then:
        Check that the credentials are escaped correctly.
    """
    client = Client(
        "mock_url",
        False,
        False,
        "mock_tenant",
        username,
        password,
        api_version='v40.0',
    )
    assert client.username == escaped_username
    assert client.password == escaped_password
