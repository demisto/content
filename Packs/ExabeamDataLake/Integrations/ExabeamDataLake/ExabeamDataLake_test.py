import pytest
from json import load
from CommonServerPython import CommandResults, DemistoException
from ExabeamDataLake import Client, _handle_time_range_query, query_datalake_command


class MockClient:
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
    Test case for the '_handle_time_range_query' function.

    Args:
        args (dict): Dictionary containing the arguments 'start_time' and 'end_time'.
        expected (dict): Dictionary representing the expected query parameters.
    """
    assert _handle_time_range_query(**args) == expected


def test_handle_time_range_query_raise_error():
    """
    Test case for the '_handle_time_range_query' function.

    Tests that the function raises a DemistoException when the start_time is greater than the end_time.

    Raises:
        DemistoException: If the start_time is greater than the end_time.
    """
    start_time = 1626393600
    end_time = 1626307200
    with pytest.raises(DemistoException, match="Start time must be before end time"):
        _handle_time_range_query(start_time, end_time)


# @pytest.mark.parametrize(
#     "limit, all_result, len_expected ,readable_expected",
    
# )
def test_query_datalake_command(mocker):
    """
    Test case for the 'query_datalake_command' function.
    """
    mock_response = load_test_data("./test_data/response.json")

    mocker.patch("ExabeamDataLake.Client", return_value=MockClient())
    mocker.patch.object(Client, "query_datalake_request", return_value=mock_response)

    response: CommandResults = query_datalake_command(
        Client,
        {
            "query": "*",
            "start_time": "2021-07-16T12:00:00",  # 1626382800000
            "end_time": "2022-07-16T12:00:00",  # 1657918800000
            "limit": 3,
            "all_result": False,
        },
    )
    assert len(response.outputs) == 3
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
    Test case for the 'query_datalake_command' function.
    """

    mocker.patch("ExabeamDataLake.Client", return_value=MockClient())
    mocker.patch.object(Client, "query_datalake_request", return_value={})

    response = query_datalake_command(Client, {"query": "*"})

    assert response.readable_output == "No results found."


def test_query_datalake_command_raise_error(mocker):
    """
    Tests that the function raises a DemistoException if there is an error in the query.
    when: query_datalake_command is called with an invalid query
    then: Ensure that a DemistoException is raised
    """
    mocker.patch("ExabeamDataLake.Client", return_value=MockClient())
    args = {"query": "*", "limit": 50, "all_result": False}
    mocker.patch.object(
        Client,
        "query_datalake_request",
        return_value={
            "responses": [{"error": {"root_cause": [{"reason": "test response"}]}}]
        },
    )
    with pytest.raises(DemistoException, match="Error in query: test response"):
        query_datalake_command(Client, args)
