import pytest
from json import load
from CommonServerPython import CommandResults, DemistoException
from ExabeamDataLake import Client, query_datalake_command, get_date, dates_in_range
from datetime import datetime

class MockClient(Client):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        pass

    def query_datalake_command(self) -> None:
        return
    
    

def test_query_datalake_command(mocker):
    args = {
        'page': 1,
        'page_size': 50,
        'limit': 50,
        'start_time': '2024-05-01T00:00:00',
        'end_time': '2024-05-08T00:00:00',
        'query': '*'
    }
    mock_response = {
        "responses": [
            {
                "hits": {
                    "hits": [
                        {"_source": {"@timestamp": "2024-05-01T12:00:00", "message": "example message 1", "another_values":"nothing"}},
                        {"_source": {"@timestamp": "2024-05-02T12:00:00", "message": "example message 2", "not_relevant":"nothing"}}
                    ]
                }
            }
        ]
    }
    
    mocker.patch.object(Client, "query_datalake_request", return_value=mock_response)
    
    client = MockClient("","","", False, False)
    
    response = query_datalake_command(client, args, cluster_name="local")

    result = response.to_context().get('EntryContext',{}).get('ExabeamDataLake.Event',{})
    
    assert {'_source': {'@timestamp': '2024-05-01T12:00:00', 'message': 'example message 1',
                        'another_values': 'nothing'}} in result
    assert {'_source': {'@timestamp': '2024-05-02T12:00:00', 'message': 'example message 2',
                        'not_relevant': 'nothing'}} in result
    expected_result = (
        "### Logs\n"
        "|Created_at|Id|Message|Product|Vendor|\n"
        "|---|---|---|---|---|\n"
        "| 2024-05-01T12:00:00 |  | example message 1 |  |  |\n"
        "| 2024-05-02T12:00:00 |  | example message 2 |  |  |\n"
    )
    assert expected_result in response.readable_output


def test_query_datalake_command_no_response(mocker):
    """
    GIVEN:
        a mocked Client with an empty response,
    WHEN:
        'query_datalake_command' function is called with the provided arguments,
    THEN:
        it should return a readable output indicating no results found.

    """
    args = {
        'page': 1,
        'page_size': 50,
        'limit': 50,
        'start_time': '2024-05-01T00:00:00',
        'end_time': '2024-05-08T00:00:00',
        'query': '*'
    }
    
    mocker.patch.object(Client, "query_datalake_request", return_value={})

    response = query_datalake_command(MockClient("", "", "", False, False), args, "local")

    assert response.readable_output == '### Logs\n**No entries.**\n'


def test_query_datalake_command_raise_error(mocker):
    """
    Test case for the 'query_datalake_command' function when it raises a DemistoException due to an error in the query.

    GIVEN:
        a mocked Client that returns an error response,
    WHEN:
        'query_datalake_command' function is called with an invalid query,
    THEN:
        it should raise a DemistoException with the appropriate error message.
    """
    args = {
        'page': 1,
        'page_size': 50,
        'limit': 50,
        'start_time': '2024-05-01T00:00:00',
        'end_time': '2024-05-08T00:00:00',
        'query': '*'
    }
    mocker.patch.object(
        Client,
        "query_datalake_request",
        return_value={
            "responses": [{"error": {"root_cause": [{"reason": "test response"}]}}]
        },
    )
    with pytest.raises(DemistoException, match="Error in query: test response"):
        query_datalake_command(MockClient("", "", "", False, False), args, "local")


def test_get_date(mocker):
    time = '2024.05.01T14:00:00'
    expected_result = '2024-05-01'

    with mocker.patch("CommonServerPython.arg_to_datetime", return_value=time):
        result = get_date(time)
        
    assert result == expected_result


@pytest.mark.parametrize('start_time_str, end_time_str, expected_output', [
    (
        "2024-05-01",
        "2024-05-10",
        [
            '2024.05.01', '2024.05.02', '2024.05.03',
            '2024.05.04', '2024.05.05', '2024.05.06',
            '2024.05.07', '2024.05.08', '2024.05.09', '2024.05.10'
        ]
    ),
    (
        "2024-05-01",
        "2024-05-05",
        ['2024.05.01', '2024.05.02', '2024.05.03', '2024.05.04', '2024.05.05']
    )
])
def test_dates_in_range_valid(mocker, start_time_str,end_time_str,expected_output):
    result = dates_in_range(start_time_str, end_time_str)
    assert result == expected_output
    
    
@pytest.mark.parametrize('start_time_str, end_time_str, expected_output', [
    (
        "2024-05-10",
        "2024-05-01",
        "Start time must be before end time"
    ),
    (
        "2024-05-01",
        "2024-05-15",
        "Difference between start time and end time must be less than or equal to 10 days"
    )
])
def test_dates_in_range_invalid(mocker, start_time_str, end_time_str, expected_output):
    with pytest.raises(DemistoException, match=expected_output):
        dates_in_range(start_time_str, end_time_str)
