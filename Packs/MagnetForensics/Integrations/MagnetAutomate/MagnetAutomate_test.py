import pytest
import json
from MagnetAutomate import MagnetAutomateClient, MagnetAutomateParams, paginate

def load_mock_response(file_name: str) -> dict:
    """Helper to load mock responses."""
    with open(f'test_data/{file_name}', 'r') as f:
        return json.load(f)

@pytest.fixture
def client():
    """Fixture for MagnetAutomateClient."""
    from pydantic import AnyUrl, SecretStr
    params = MagnetAutomateParams(
        url=AnyUrl("https://test.com"),
        api_key=SecretStr("test-key")
    )
    return MagnetAutomateClient(params)

@pytest.mark.parametrize(
    "results, page, page_size, expected",
    [
        pytest.param([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 2, 5, [6, 7, 8, 9, 10], id="standard_pagination"),
        pytest.param([1, 2, 3], None, None, [1, 2, 3], id="default_behavior_no_page_no_size"),
        pytest.param([1, 2, 3], 1, None, [1, 2, 3], id="default_behavior_page_1_no_size"),
        pytest.param([1, 2, 3], None, 10, [1, 2, 3], id="default_behavior_no_page_with_size"),
        pytest.param([1, 2, 3], 2, 5, [], id="page_exceeds_total_results"),
        pytest.param([], 1, 5, [], id="empty_input_list"),
        pytest.param([1, 2, 3, 4, 5, 6, 7], 2, 5, [6, 7], id="partial_last_page"),
    ],
)
def test_paginate(results, page, page_size, expected):
    """
    Tests the paginate helper function.
    """
    assert paginate(results, page, page_size) == expected
