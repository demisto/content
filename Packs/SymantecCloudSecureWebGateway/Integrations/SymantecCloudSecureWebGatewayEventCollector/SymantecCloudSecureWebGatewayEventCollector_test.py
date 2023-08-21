import pytest
from SymantecCloudSecureWebGatewayEventCollector import (
    Client,
    is_duplicate,
    is_first_fetch,
)


@pytest.mark.parametrize(
    "args, expected_results",
    [
        ({"id_": "123", "cur_time": "2023-08-01 00:00:34"}, True),
        ({"id_": "123", "cur_time": "2023-08-01 00:01:34"}, True),
        ({"id_": "000", "cur_time": "2023-08-01 00:02:34"}, False),
        ({"id_": "000", "cur_time": "2023-08-01 00:01:34"}, True),
    ],
)
def test_is_duplicate(args: dict[str, str], expected_results: bool):
    """ """
    time_of_last_fetched_event = "2023-08-01 00:01:34"
    events_suspected_duplicates = ["123", "456"]

    result = is_duplicate(
        args["id_"],
        args["cur_time"],
        time_of_last_fetched_event,
        events_suspected_duplicates,
    )
    assert result == expected_results
