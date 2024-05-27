import json
import pytest
from CommonServerPython import DemistoException, CommandResults
from ExabeamSecOpsPlatform import Client, search_command, get_limit, get_date, transform_string, process_string, _parse_group_by


class MockClient(Client):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        pass

    def search_command(self) -> None:
        return


def test_search_command_success(mocker):
    """
    GIVEN:
        A mocked Exabeam client and valid search query arguments.

    WHEN:
        'search_command' function is called with the provided arguments.

    THEN:
        It should search for logs using the Exabeam client and return a CommandResults object containing
        the search results in both structured and human-readable formats.
    """
    # Mock the response from the client's search_request method
    mock_response = {
        "rows": [
                    {
                        "id": "123",
                        "rawLogIds": "1",
                        "tier": "Tier",
                        "parsed": "false",
                        "rawLogs": "fictive",
                        "time": "2024-01-30T11:20:07.000000+00:00",
                        "message": "Log message 1",
                        "activity": "trigger",
                        "platform": "blackberry protect",
                        "vendor": "BlackBerry"
                    },
            {
                        "id": "456",
                        "time": "2024-01-30T11:21:06.976000+00:00",
                        "message": "Log message 2",
                        "activity": "trigger",
                        "platform": "blackberry protect",
                        "vendor": "BlackBerry"
                    }
        ]
    }

    client = MockClient("", "", "", False, False)

    mocker.patch.object(client, "search_request", return_value=mock_response)

    # Define test arguments
    args = {
        'query': '',
        'fields': 'message',
        'limit': '50',
        'start_time': '2024-05-01T00:00:00',
        'end_time': '2024-05-08T00:00:00'
    }

    # Call the search_command function
    response = search_command(client, args)

    assert isinstance(response, CommandResults)
    assert response.outputs_prefix == "ExabeamPlatform.Event"
    assert response.outputs == mock_response["rows"]
    expected_readable_output = (
        "### Logs\n"
        "|Id|Is Parsed|Raw Log Ids|Raw Logs|Tier|Time|\n"
        "|---|---|---|---|---|---|\n"
        "| 123 | false | 1 | fictive | Tier | 2024-01-30T11:20:07.000000+00:00 |\n"
        "| 456 |  |  |  |  | 2024-01-30T11:21:06.976000+00:00 |\n"
    )
    assert expected_readable_output in response.readable_output


def test_search_command_failure(mocker):
    """
    GIVEN:
        A mocked Exabeam client and invalid search query arguments.

    WHEN:
        'search_command' function is called with invalid arguments.

    THEN:
        It should raise a DemistoException.
    """
    # Mocking the client to simulate a response with errors
    client = MockClient("", "", "", False, False)
    mocker.patch.object(client, "search_request", return_value={"errors": {"message": "Error occurred"}})

    args = {
        'query': '',
        'fields': 'message',
        'limit': '50',
        'start_time': '2024-05-01T00:00:00',
        'end_time': '2024-05-08T00:00:00'
    }

    with pytest.raises(DemistoException, match="Error occurred"):
        search_command(client, args)


def test_get_date(mocker):
    """
    GIVEN:
        a mocked CommonServerPython.arg_to_datetime function returning a specific time string,

    WHEN:
        'get_date' function is called with the provided time string,

    THEN:
        it should return the date part of the provided time string in the 'YYYY-MM-DD' format.
    """
    time = '2024.05.01T14:00:00'
    expected_result = '2024-05-01T14:00:00Z'

    with mocker.patch("CommonServerPython.arg_to_datetime", return_value=time):
        result = get_date(time, "start_time")

    assert result == expected_result


@pytest.mark.parametrize('input_str, expected_output', [
    (
        "key:Some Value",
        'key:"Some Value"'
    ),
    (
        "key:TrUe",
        "key:true"
    ),
    (
        "key:false",
        "key:false"
    )
])
def test_transform_string(input_str, expected_output):
    """
    GIVEN:
        An input string to be transformed.
    WHEN:
        The 'transform_string' function is called with the input string.
    THEN:
        It should transform the input string according to the specified rules.
    """
    assert transform_string(input_str) == expected_output


@pytest.mark.parametrize('input_str, expected_output', [
    (
        "key1:true AND key2:false OR key3:true TO key4:false",
        'key1:true AND key2:false OR key3:true TO key4:false'
    ),
    (
        "key1:true",
        'key1:true'
    ),
    (
        "",
        ''
    ),
    (
        "key1:true AND key2:some value OR key3:another value",
        'key1:true AND key2:"some value" OR key3:"another value"'
    )
])
def test_process_string(input_str, expected_output):
    """
    GIVEN:
        An input string to be processed.
    WHEN:
        The 'process_string' function is called with the input string.
    THEN:
        It should correctly process the input string, splitting it based on logical operators and transforming each part using
        the 'transform_string' function.
    """
    assert process_string(input_str) == expected_output


def test_search_request(mocker):
    """
    GIVEN:
        A dictionary containing data to be sent in the request.
        A mocked '_http_request' method of the YourClass class.
        A base URL and an access token.
    WHEN:
        The 'search_request' method of the YourClass class is called with the data dictionary.
    THEN:
        It should send a POST request to the specified URL with the provided data and headers.
    """
    mocker.patch('ExabeamSecOpsPlatform.Client._login')
    mock_http_request = mocker.patch('ExabeamSecOpsPlatform.Client._http_request')
    base_url = "https://example-api.com"
    client_id = "your_client_id"
    client_secret = "your_client_secret"

    instance = Client(base_url=base_url, client_id=client_id, client_secret=client_secret,
                      verify=False, proxy=False)
    instance.access_token = "dummy_token"
    data_dict = {"key": "value"}
    expected_url = "https://example-api.com/search/v2/events"
    expected_headers = {
        "Authorization": "Bearer dummy_token",
        "Content-Type": "application/json"
    }
    mocked_response = {"response_key": "response_value"}
    mock_http_request.return_value = mocked_response
    result = instance.search_request(data_dict)

    mock_http_request.assert_called_once_with(
        "POST",
        full_url=expected_url,
        data=json.dumps(data_dict),
        headers=expected_headers
    )
    assert result == mocked_response


@pytest.mark.parametrize('args, expected_output', [
    ({}, 50),
    ({'limit': None}, 50),
    ({'limit': 1000}, 1000),
    ({'limit': 5000}, 3000)
])
def test_get_limit(args, expected_output):
    """
    GIVEN:
        a dictionary containing the 'limit' argument with various values.

    WHEN:
        'get_limit' function is called with the provided dictionary.

    THEN:
        it should return the limit value if specified and less than or equal to 3000;
        otherwise, it should return 3000 as the maximum limit.
        If the 'limit' argument is not present in the dictionary or is None, it should return 50 as the default limit.
    """
    assert get_limit(args) == expected_output


def test_parse_group_by():
    """
    GIVEN:
        an entry dictionary containing information about an item with various attributes.

    WHEN:
        '_parse_group_by' function is called with the provided entry dictionary and a list of titles.

    THEN:
        it should return a parsed dictionary with non-empty elements based on the provided titles;
        empty elements should be removed.
    """
    entry = {
        'Id': '123',
        'Vendor': 'Vendor X',
        'Product': '',
        'Created_at': '2024-05-26T12:00:00',
        'Message': 'This is a message.'
    }
    titles = ['Id', 'Vendor', 'Created_at', 'Message']
    expected_result = {
        'Id': '123',
        'Vendor': 'Vendor X',
        'Created_at': '2024-05-26T12:00:00',
        'Message': 'This is a message.'
    }
    assert _parse_group_by(entry, titles) == expected_result
