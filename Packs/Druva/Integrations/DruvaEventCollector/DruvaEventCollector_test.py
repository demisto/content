from CommonServerPython import DemistoException
from DruvaEventCollector import Client, test_module, get_events, fetch_events
import pytest


@pytest.fixture()
def mock_client() -> Client:
    return Client(base_url="test", verify=False, proxy=False, headers=None)


def test_test_module_command(mocker, mock_client):
    """
    Given:
    - test module command

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    mocker.patch.object(mock_client, "search_events", return_value={})
    result = test_module(client=mock_client)
    assert result == "ok"


@pytest.mark.parametrize(
    "return_value, expected_result",
    [
     (DemistoException(message='Forbidden'),
      'Authorization Error: make sure Server URL, Client ID and Secret Key are correctly entered.'),
     (DemistoException(message='Error: Request failed with status code 404'), 'Error: Request failed with status code 404')
    ]
)
def test_test_module_command_failures(mocker, mock_client, return_value, expected_result):
    """
    Given:
    - test module command

    When:
    - Pressing test button

    Then:
    - Test module failed with Authorization Error
    - Test module failed with any other exception
    """
    mocker.patch.object(mock_client, "search_events", side_effect=return_value)
    try:
        result = test_module(client=mock_client)
    except DemistoException as exp:
        assert expected_result == exp.message
    else:
        assert expected_result == result


def test_get_events_command():
    """
    Given:
    - get_events command (fetches detections)

    When:
    - running get events command

    Then:
    - events and human readable as expected
    """
    base_url = 'https://server_url/'
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )
    events, hr = get_events(
        client=client,

    )

    assert events[0].get('id') == 1
    assert 'Test Event' in hr.readable_output


# def test_fetch_detection_events_command():
#     """
#     Given:
#     - fetch events command (fetches detections)
#
#     When:
#     - Running fetch-events command
#
#     Then:
#     - Ensure number of events fetched, and next run fields
#     """
#     first_fetch_str = '2022-12-21T03:42:05Z'
#     base_url = 'https://server_url/'
#     client = Client(
#         base_url=base_url,
#         verify=True,
#         proxy=False,
#     )
#     last_run = {'prev_id': 1}
#     next_run, events = fetch_events(
#         client=client,
#         last_run=last_run,
#         first_fetch_time=first_fetch_str,
#         alert_status="Status",
#         max_events_per_fetch=1,
#     )
#
#     assert len(events) == 1
#     assert next_run.get('prev_id') == 2
#     assert events[0].get('id') == 2
