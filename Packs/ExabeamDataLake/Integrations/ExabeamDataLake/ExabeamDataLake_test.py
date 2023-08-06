import pytest
from json import load
from CommonServerPython import CommandResults, DemistoException
from ExabeamDataLake import Client, _handle_time_range_query, query_datalake_command


class MockClient(Client):
    def __init__(self, base_url: str, username: str, password: str, verify: bool, proxy: bool):
        pass

    def query_datalake_command(self) -> None:
        return


def load_test_data(json_path: str):
    with open(json_path) as f:
        return load(f)


@pytest.mark.parametrize(
    "args, expected",
    [
        (
            {"start_time": 1689943882318, "end_time": 1689944782318},
            {
                "rangeQuery": {
                    "field": "@timestamp",
                    "gte": "1689943882318",
                    "lte": "1689944782318",
                }
            },
        ),
        (
            {"start_time": 1689943882318, "end_time": None},
            {"rangeQuery": {"field": "@timestamp", "gte": "1689943882318"}},
        ),
    ],
)
def test_handle_time_range_query(
    args: dict[str, int], expected: dict[str, dict[str, str]]
):
    """
    GIVEN:
        a dictionary containing 'start_time' and 'end_time' as keys with integer values
    WHEN:
        '_handle_time_range_query' function is called with the provided arguments
    THEN:
        it should return a dictionary representing a valid time range query.
    """
    assert _handle_time_range_query(**args) == expected


def test_handle_time_range_query_raise_error():
    """
    GIVEN:
        a start time and end time where the start time is greater than the end time
    WHEN:
        _handle_time_range_query is called with the start and end times
    THEN:
        a DemistoException is raised with the message "Start time must be before end time"
    """
    start_time = 2
    end_time = 1
    with pytest.raises(DemistoException, match="Start time must be before end time"):
        _handle_time_range_query(start_time, end_time)


def test_query_datalake_command(mocker):
    """
    GIVEN:
        a mocked Client and test data,
    WHEN:
        'query_datalake_command' function is called with the provided arguments,
        and the Client returns the test data.
    THEN:
        it should return the expected context and readable output.
    """
    mock_response = load_test_data("./test_data/response.json")

    mocker.patch.object(Client, "query_datalake_request", return_value=mock_response)

    response: CommandResults = query_datalake_command(
        MockClient("", "", "", False, False),
        {
            "query": "*",
            "start_time": "2021-07-16T12:00:00",  # 1626382800000
            "end_time": "2022-07-16T12:00:00",  # 1657918800000
            "limit": 3,
            "all_result": False,
        },
    )
    outputs = response.to_context()["EntryContext"]['ExabeamDataLake.Log']
    assert outputs == mock_response["responses"][0]["hits"]["hits"]
    assert response.readable_output == (
        "### Logs\n"
        "|Action|Event Name|ID|Product|Time|Vendor|\n"
        "|---|---|---|---|---|---|\n"
        "| Accept | Accept | test_id_1 | test_product_1 | 2022-06-12T23:55:05.000Z | test_vendor_1 |\n"
        "| Accept | Accept | test_id_2 | test_product_2 | 2022-06-12T23:55:05.000Z | test_vendor_2 |\n"
        "| Accept | Accept | test_id_3 | test_product_3 | 2022-06-12T23:55:05.000Z | test_vendor_3 |\n"
    )


def test_query_datalake_command_no_response(mocker):
    """
    GIVEN:
        a mocked Client with an empty response,
    WHEN:
        'query_datalake_command' function is called with the provided arguments,
    THEN:
        it should return a readable output indicating no results found.

    """

    mocker.patch.object(Client, "query_datalake_request", return_value={})

    response = query_datalake_command(MockClient("", "", "", False, False), {"query": "*"})

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

    args = {"query": "*", "limit": 50, "all_result": False}
    mocker.patch.object(
        Client,
        "query_datalake_request",
        return_value={
            "responses": [{"error": {"root_cause": [{"reason": "test response"}]}}]
        },
    )
    with pytest.raises(DemistoException, match="Error in query: test response"):
        query_datalake_command(MockClient("", "", "", False, False), args)
