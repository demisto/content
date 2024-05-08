import pytest
from json import load
from CommonServerPython import CommandResults, DemistoException, arg_to_datetime
from ExabeamDataLake import Client, query_datalake_command, get_date
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
        "|created_at|id|message|product|vendor|\n"
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

    