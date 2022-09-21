import json
from pathlib import Path

import pytest

from Rapid7_Nexpose import *


@pytest.fixture
def mock_client():
    return Client(
        url="url",
        username="username",
        password="password",
        verify=False,
    )


def load_test_data(file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / file_name, "r") as f:
        return json.load(f)


@pytest.mark.parametrize("test_input_kwargs, expected_output",
                         [
                             ({"years": 1, "months": 8, "weeks": 2, "days": 6}, "P1Y8M2W6D"),
                             ({"hours": 16, "minutes": 26, "seconds": 53.4}, "PT16H26M53.4S"),
                             ({"years": 4, "months": 3, "weeks": 1, "days": 2,
                               "hours": 12, "minutes": 43, "seconds": 12.5}, "P4Y3M1W2DT12H43M12.5S"),
                         ])
def test_convert_to_duration_time(test_input_kwargs: dict, expected_output: float):
    assert convert_to_duration_time(**test_input_kwargs) == expected_output


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("PT2M16.481S", "2 minutes, 16.481 seconds"),
                             ("PT2M17.976S", "2 minutes, 17.976 seconds"),
                             ("PT51.316S", "51.316 seconds")
                         ])
def test_convert_from_duration_time(test_input: str, expected_output: float):
    assert convert_from_duration_time(test_input) == expected_output



@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("PANW", "724"),
                             ("Authenticated-Assets", "848"),
                             ("Test", "1"),
                             ("Site-That-Doesn't-Exist", None),
                         ])
def test_find_site_id(mocker, mock_client: Client, test_input: str, expected_output: Union[str, None]):
    mocker.patch.object(Client, "_paged_http_request", return_value=load_test_data("client_get_sites.json"))
    assert mock_client.find_site_id(test_input) == expected_output
