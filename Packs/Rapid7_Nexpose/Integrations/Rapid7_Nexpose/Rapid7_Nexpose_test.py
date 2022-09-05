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


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("PT2M16.481S", 10.016666666666667),
                             ("PT2M17.976S", 18.266666666666666),
                             ("PT59.669S", 11.15),
                         ])  # TODO: Make test samples more varied?
def test_convert_duration_time_minutes(test_input: str, expected_output: float):
    assert convert_duration_time_minutes(test_input) == expected_output


@pytest.mark.parametrize("test_input, expected_output",
                         [
                             ("P5DT10H30M", "'5 days, 10 hours, 30 minutes'"),
                         ])
def test_convert_duration_time(test_input: str, expected_output: str):
    assert convert_duration_time(test_input) == expected_output


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
