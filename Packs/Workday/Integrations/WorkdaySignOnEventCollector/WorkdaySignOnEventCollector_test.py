import unittest
from unittest.mock import patch
from freezegun import freeze_time

from WorkdaySignOnEventCollector import (
    get_from_time,
    fletcher16,
    generate_checksum,
    check_events_against_checksums,
    filter_and_check_events,
    get_future_duplicates_within_timeframe,
    convert_to_json,
    process_events,
    Client,
    fetch_sign_on_logs,
    get_sign_on_events_command,
    fetch_sign_on_events_command,
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


def test_generate_checksum():
    """
    Test the 'generate_checksum' function
    """
    # Using known values to calculate checksum
    short_session_id = "12345"
    user_name = 'ABC123'
    successful = 1
    signon_datetime = "2021-09-01T12:00:00Z"

    result = generate_checksum(short_session_id, user_name, successful, signon_datetime)
    expected = 51917  # This is an expected known value
    assert result == expected


def test_check_events_against_checksums():
    """
    Test the 'check_events_against_checksums' function
    """
    # Define test data
    events = [
        ("12345", "ABC6789", 1, "2021-09-01T12:00:00Z"),
        ("12346", "ABC6790", 1, "2021-09-01T12:01:00Z"),
    ]
    checksums = {51917}  # The checksum for the first event
    result = check_events_against_checksums(events, checksums)
    # Only the second event should be returned
    assert result == [events[1]]


def test_filter_and_check_events():
    """
    Test the 'filter_and_check_events' function
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
            "Signon_DateTime": "2021-09-01T12:01:00Z",
        },
    ]
    target_datetime_str = "2021-09-01T12:00:00Z"
    checksums = {51917}  # The checksum for the first event
    result = filter_and_check_events(events, target_datetime_str, checksums)
    # Only the second event should be returned
    assert result == [events[1]]


def test_get_future_duplicates_within_timeframe():
    """
    Test the 'get_future_duplicates_within_timeframe' function
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
    to_time = "2021-09-01T12:00:01Z"
    result = get_future_duplicates_within_timeframe(events, to_time)
    # Both events are within the timeframe of 1 second before and up to the given to_time.
    assert result == events


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


def test_process_events():
    """
    Test the 'process_events' function
    """
    events = [
        {"Signon_DateTime": "2021-09-01T11:00:00Z", "User_Name": "John"},
        {"Signon_DateTime": "2021-09-01T12:00:00Z", "User_Name": "Jane"},
    ]

    process_events(events)

    assert events[0].get("_time") == "2021-09-01T11:00:00Z"
    assert events[1].get("_time") == "2021-09-01T12:00:00Z"


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
