from pathlib import Path

import pytest

from AWSSecurityHubEventCollector import *


def load_test_data(folder: str, file_name: str) -> dict:
    """
    A function for loading and returning data from json files within the "test_data" folder.

    Args:
        folder (str): Name of the parent folder of the file within `test_data`.
        file_name (str): Name of a json file to load data from.

    Returns:
        dict: Dictionary data loaded from the json file.
    """
    with open(Path("test_data") / folder / f"{file_name}.json", "r") as f:
        return json.load(f)


class MockClient:
    """
    A client mocking Boto3.client
    """
    findings_data = load_test_data('api_mock', 'get_findings_10')
    calls_count = 0
    last_index = 0  # Used to mock pagination

    def __init__(self, *args, **kwargs):
        pass

    def get_findings(self, **kwargs) -> dict:
        """
        A function for mocking the get_findings function.

        Args:
            kwargs: Keyword arguments that would be passed to the get_findings function.
        """
        max_index = self.last_index + kwargs['MaxResults']

        return_events = self.findings_data[self.last_index:max_index]
        self.last_index += len(return_events)
        result = {'Findings': return_events}

        if self.last_index < len(self.findings_data):
            result['NextToken'] = 'next_token'

        self.calls_count += 1
        return result

    def reset(self):
        """
        A function for resetting the mock client.
        """
        self.calls_count = 0
        self.last_index = 0


@pytest.fixture
def client():
    """
    A fixture for creating a mock client.
    """
    return MockClient()


@pytest.mark.parametrize('page_size, limit, expected_api_calls_count, expected_output_file',
                         [
                             (100, 1000, 1, "fetch_events_expected_results_0"),
                             (2, 1000, 5, "fetch_events_expected_results_0"),
                             (3, 1000, 4, "fetch_events_expected_results_0"),
                             (2, 5, 3, "fetch_events_expected_results_1"),
                             (100, 5, 1, "fetch_events_expected_results_1"),
                         ])
def test_fetch(client, page_size: int, limit: int, expected_api_calls_count: int, expected_output_file: str):
    """
    Given: A page size parameter for the fetch events function.
    When: Fetching events from the API.
    Then: Assert the returned events are valid, and the number of API calls is as expected.

    Note: This is a test for both 'fetch_events' and 'get_events_command' functions.
    """
    expected_output = load_test_data("expected_results", expected_output_file)

    first_fetch_time = dt.datetime(2021, 1, 1)
    events, _, _ = fetch_events(client=client, last_run={},
                                first_fetch_time=first_fetch_time, page_size=page_size, limit=limit)

    assert client.calls_count == expected_api_calls_count
    assert len(events) == len(expected_output)
    assert events == expected_output

    client.reset()

    result = get_events_command(client=client, should_push_events=False, page_size=page_size, limit=limit)

    assert client.calls_count == expected_api_calls_count
    assert result.readable_output == tableToMarkdown('AWS Security Hub Events', expected_output, sort_headers=False)
