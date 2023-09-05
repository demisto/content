import json
import unittest
from unittest.mock import patch
from freezegun import freeze_time

from CommonServerPython import DemistoException
from WorkdaySignOnEventCollector import (
    get_from_time,
    fletcher16,
    generate_checksum,
    convert_to_json,
    Client,
    fetch_sign_on_logs,
    get_sign_on_events_command,
    fetch_sign_on_events_command, process_and_filter_events, main, VENDOR, PRODUCT,
)


def test_get_from_time():
    """
    Test the 'get_from_time' function
    """
    # Test if the function returns the correct format and value.
    seconds_ago = 3600  # 1 hour ago
    result = get_from_time(seconds_ago)
    assert isinstance(result, str)
    assert result.endswith("Z")  # Check if it's in the right format


def test_fletcher16():
    """
    Test the 'fletcher16' function
    """
    # Test known checksums
    data = b"test"
    result = fletcher16(data)
    expected = 22976
    assert result == expected

    # Test empty data
    data = b""
    result = fletcher16(data)
    expected = 0
    assert result == expected


def test_generate_checksum() -> None:
    """
    Given: Various event dictionaries, some with missing or incorrect data.
    When: Calling the generate_checksum function on these dictionaries.
    Then: The function should return the correct checksums or raise appropriate errors.
    """

    # Test case 1: Normal operation with known values to calculate checksum
    event1 = {
        "Short_Session_ID": "12345",
        "User_Name": 'ABC123',
        "Successful": 1,
        "Signon_DateTime": "2021-09-01T12:00:00Z",
    }
    event1_str = json.dumps(event1, sort_keys=True)
    expected_checksum1 = fletcher16(event1_str.encode())
    expected_unique_id1 = f"{expected_checksum1}_{event1['Signon_DateTime']}"
    result1 = generate_checksum(event1)
    assert result1 == expected_unique_id1

    # Test case 2: Empty event dictionary
    event2 = {}
    try:
        generate_checksum(event2)
    except DemistoException as e:
        assert str(e) == "While calculating the checksum for an event, an event without a Signon_DateTime was " \
                         "found.\nError: 'Signon_DateTime'"
    else:
        assert False, "Expected ValueError but did not get one"

    # Test case 3: Missing key in event dictionary
    event3 = {
        "Short_Session_ID": "12345",
        "User_Name": 'ABC123',
        "Successful": 1,
    }
    try:
        generate_checksum(event3)
    except DemistoException:
        pass
    else:
        assert False, "Expected Exception but did not get one"

    # Test case 4: Large event dictionary
    event4 = {str(i): i for i in range(10000)}  # Create a large dictionary
    event4["Signon_DateTime"] = "2021-09-01T12:00:00Z"  # Add a Signon_DateTime key
    assert generate_checksum(event4)  # Just check if the function can handle it


def test_process_and_filter_events():
    """
    Test the 'process_and_filter_events' function
    """
    # Define test data
    events = [
        {
            "Short_Session_ID": "12345",
            "User_Name": "ABC6789",
            "Successful": 1,
            "Signon_DateTime": "2021-09-01T12:00:00Z",
        },
        {
            "Short_Session_ID": "12346",
            "User_Name": "ABC6790",
            "Successful": 1,
            "Signon_DateTime": "2021-09-01T12:00:01Z",
        },
    ]

    from_time = "2021-09-01T12:00:00Z"
    previous_run_checksums = set()  # Assume no previous checksums for simplicity

    # Call the function to test
    non_duplicates, checksums_for_next_iteration = process_and_filter_events(events, from_time, previous_run_checksums)

    # Check if the list of non-duplicates is as expected
    assert non_duplicates == events

    # Check if the set of checksums for next iteration is updated
    assert len(checksums_for_next_iteration) == 2

    # Check if '_time' key is added to each event
    for event in non_duplicates:
        assert "_time" in event
        assert event["_time"] == event["Signon_DateTime"]


def test_convert_to_json():
    """
    Test the 'convert_to_json' function
    """
    # Test with XML data (this is a simplified version for the sake of the test)
    xml_response = """
    <Envelope>
        <Body>
            <Get_Workday_Account_Signons_Response>
                <Response_Data>
                    <Workday_Account_Signon>
                        <Signon_DateTime>2021-09-01T12:00:00Z</Signon_DateTime>
                    </Workday_Account_Signon>
                </Response_Data>
            </Get_Workday_Account_Signons_Response>
        </Body>
    </Envelope>
    """
    raw_json_response, account_signon_data = convert_to_json(xml_response)
    # Check if the converted data matches the expected structure
    assert (
        raw_json_response["Envelope"]["Body"]["Get_Workday_Account_Signons_Response"][
            "Response_Data"
        ]["Workday_Account_Signon"][0]["Signon_DateTime"]
        == "2021-09-01T12:00:00Z"
    )
    assert (
        account_signon_data["Workday_Account_Signon"][0]["Signon_DateTime"]
        == "2021-09-01T12:00:00Z"
    )


def test_generate_workday_account_signons_body():
    """
    Test the 'generate_workday_account_signons_body' method of the Client class
    """
    client = Client(
        base_url="",
        verify_certificate=True,
        proxy=False,
        tenant_name="test_tenant",
        token="test_token",
        username="test_user",
        password="test_pass",
    )

    body = client.generate_workday_account_signons_body(
        page=1,
        count=10,
        to_time="2021-09-01T12:00:00Z",
        from_time="2021-09-01T11:00:00Z",
    )

    assert "<bsvc:Page>1</bsvc:Page>" in body
    assert "<bsvc:Count>10</bsvc:Count>" in body
    assert "<bsvc:From_DateTime>2021-09-01T11:00:00Z</bsvc:From_DateTime>" in body
    assert "<bsvc:To_DateTime>2021-09-01T12:00:00Z</bsvc:To_DateTime>" in body
    assert "<wsse:Username>test_user</wsse:Username>" in body
    assert (
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">test_pass</wsse:Password>'  # noqa:E501
        in body
    )


def test_generate_test_payload():
    """
    Test the 'generate_test_payload' method of the Client class
    """
    client = Client(
        base_url="",
        verify_certificate=True,
        proxy=False,
        tenant_name="test_tenant",
        token="test_token",
        username="test_user",
        password="test_pass",
    )

    payload = client.generate_test_payload(
        from_time="2021-09-01T11:00:00Z", to_time="2021-09-01T12:00:00Z"
    )

    assert "<bsvc:Page>1</bsvc:Page>" in payload
    assert "<bsvc:Count>1</bsvc:Count>" in payload
    assert "<bsvc:From_DateTime>2021-09-01T11:00:00Z</bsvc:From_DateTime>" in payload
    assert "<bsvc:To_DateTime>2021-09-01T12:00:00Z</bsvc:To_DateTime>" in payload
    assert "<wsse:Username>test_user</wsse:Username>" in payload
    assert (
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">test_pass</wsse:Password>'  # noqa:E501
        in payload
    )


def test_convert_to_json_valid_input():
    """
    Test the 'convert_to_json' function with valid XML input
    """
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

    full_json, account_signon_data = convert_to_json(response)

    # For full_json
    envelope = full_json.get("Envelope", {})
    body = envelope.get("Body", {})
    response = body.get("Get_Workday_Account_Signons_Response", {})
    response_data = response.get("Response_Data", {})
    workday_account_signons = response_data.get("Workday_Account_Signon", [])

    # Assertion
    assert isinstance(
        workday_account_signons, list
    ), "workday_account_signons is not a list"
    assert workday_account_signons, "workday_account_signons is empty"
    assert workday_account_signons[0].get("Signon_DateTime") == "2021-09-01T11:00:00Z"

    # For account_signon_data
    workday_account_signons_data = account_signon_data.get("Workday_Account_Signon", [])

    # Assertion
    assert workday_account_signons_data
    assert (
        workday_account_signons_data[0].get("Signon_DateTime") == "2021-09-01T11:00:00Z"
    )


class TestFetchSignOnLogs(unittest.TestCase):
    def setUp(self):
        self.client = Client(
            "mock_url",
            False,
            False,
            "mock_tenant",
            "mock_token",
            "mock_user",
            "mock_pass",
        )

    @patch.object(Client, "retrieve_events")
    def test_fetch_sign_on_logs_single_page(self, mock_retrieve_events):
        # Sample data to be returned by the mock
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

        mock_retrieve_events.return_value = mock_response

        events = fetch_sign_on_logs(
            self.client, 10, "2021-09-01T00:00:00Z", "2021-09-02T00:00:00Z"
        )

        # Assertions
        assert len(events) == 1
        assert events[0]["User_Name"] == "John"


class TestGetSignOnEventsCommand(unittest.TestCase):
    def test_get_sign_on_events_command(self):
        # Sample data to be returned by the mock
        mock_events = [
            {
                "Signon_DateTime": "2021-09-01T11:00:00Z",
                "User_Name": "John",
                "Short_Session_ID": "123456",
                "Successful": 1,
                "_time": "2021-09-01T11:00:00Z",  # This is added by the process_events function
            }
        ]

        # Use patch to mock the fetch_sign_on_logs function
        with patch(
            "WorkdaySignOnEventCollector.fetch_sign_on_logs", return_value=mock_events
        ):
            client = Client(
                "mock_url",
                False,
                False,
                "mock_tenant",
                "mock_token",
                "mock_user",
                "mock_pass",
            )
            events, results = get_sign_on_events_command(
                client, "2021-09-01T00:00:00Z", "2021-09-02T00:00:00Z", 10
            )

            # Assertions
            assert len(events) == 1
            assert events[0]["User_Name"] == "John"
            assert events[0]["_time"] == "2021-09-01T11:00:00Z"
            assert results.readable_output.startswith("### Sign On Events List:")


@freeze_time("2021-09-02T00:00:00Z")
def test_fetch_sign_on_events_command_single_page():
    """
    Test the 'fetch_sign_on_events_command' function for a single page of results.
    """
    # Sample data to be returned by the mock
    mock_events = [
        {
            "Signon_DateTime": "2021-09-01T11:00:00Z",
            "User_Name": "John",
            "Short_Session_ID": "123456",
            "Successful": 1,
            "_time": "2021-09-01T11:00:00Z",  # This is added by the process_events function
        }
    ]

    # Mock the client's retrieve_events method
    mock_retrieve_response = ({"Workday_Account_Signon": mock_events}, 1)
    mock_last_run = {
        "last_fetch_time": "2021-09-01T10:59:00Z",
        "previous_run_checksums": set(),
    }

    # Use patch to mock the client's retrieve_events method and demisto.getLastRun function
    with patch.object(
        Client, "retrieve_events", return_value=mock_retrieve_response
    ), patch("demistomock.getLastRun", return_value=mock_last_run):
        client = Client(
            "mock_url",
            False,
            False,
            "mock_tenant",
            "mock_token",
            "mock_user",
            "mock_pass",
        )
        events, new_last_run = fetch_sign_on_events_command(client, 10, mock_last_run)

        # Assertions
        assert len(events) == 1
        assert events[0]["User_Name"] == "John"
        assert events[0]["_time"] == "2021-09-01T11:00:00Z"
        assert new_last_run["last_fetch_time"] == "2021-09-01T11:00:00Z"


def test_main_fetch_events() -> None:
    """
    Given: Initialized client and last run data.
    When: main function is called with 'fetch-events' command.
    Then: Ensure fetch_sign_on_events_command and send_events_to_xsiam are called, and the last run is updated.
    """
    mock_params = {
        'tenant_name': 'TestTenant',
        'max_fetch': '10000',
        'base_url': 'https://testurl.com',
        'credentials': {
            'identifier': 'TestUser',
            'password': 'testpass'
        },
        'insecure': True
    }

    # Mocking demisto.command to return 'fetch-events'
    with patch('demistomock.command', return_value='fetch-events'):
        # Mocking other demisto functions
        with patch('demistomock.getLastRun', return_value={'some': 'data'}), \
                patch('demistomock.setLastRun') as _, \
                patch('demistomock.params', return_value=mock_params), \
                patch('WorkdaySignOnEventCollector.Client') as mock_client, \
                patch('WorkdaySignOnEventCollector.fetch_sign_on_events_command') as mock_fetch_sign_on_events_command, \
                patch('WorkdaySignOnEventCollector.send_events_to_xsiam') as mock_send_events_to_xsiam:
            # Mocking the output of fetch_sign_on_events_command
            mock_events = [{"event": "data"}]
            mock_new_last_run = {'new': 'data'}
            mock_fetch_sign_on_events_command.return_value = (mock_events, mock_new_last_run)

            # Call the main function
            main()

            # Verify fetch_sign_on_events_command was called with the initialized client, max_fetch, and last_run
            mock_fetch_sign_on_events_command.assert_called_with(
                client=mock_client.return_value, max_fetch=10000, last_run={'some': 'data'}
            )

            # Verify send_events_to_xsiam was called with the fetched events
            mock_send_events_to_xsiam.assert_called_with(mock_events, vendor=VENDOR,
                                                         product=PRODUCT)
