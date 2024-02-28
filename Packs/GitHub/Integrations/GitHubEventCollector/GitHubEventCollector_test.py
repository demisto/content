import pytest
from freezegun import freeze_time
import datetime
from GitHubEventCollector import GithubGetEvents, get_github_timestamp_format, demisto


def test_last_run(mocker):
    """
    Given:
        - A list of events
    When:
        - Getting the last run
    Then:
        - Ensure the last run is the last event in isoformat
        - Ensure the last run is not changed when no events are returned

    Note: This test could fail locally because of timezone differences. Run it on a docker image.
    """

    # get some events
    events = [{'@timestamp': 1619510200000}, {'@timestamp': 1619510300000}, {'@timestamp': 1619510400000}]
    last_run = GithubGetEvents.get_last_run(events)

    # make sure the last run is the last event in isoformat
    assert last_run == {'after': 1619510400000}

    # now get no events, and make sure the last run is not changed
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    assert GithubGetEvents.get_last_run([]) == last_run


@freeze_time('2021-11-15T00:00:00Z')
def test_get_github_timestamp_format():
    """
    Given:
        - A time in few variations
    When:
        - Running thq get_github_timestamp_format function
    Then:
        - Ensure the output is in the form 'created:><year>-<month>-<day>T<hours>:<minutes>:<seconds>Z'

    Note: This test could fail locally because of timezone differences. Run it on a docker image.
    """

    # Test conversion of an int value (representing an epoch timestamp)
    timestamp = 1636934400000
    result = get_github_timestamp_format(timestamp)
    expected_result = 'created:>2021-11-15T00:00:00Z'
    assert result == expected_result

    # Test conversion of a str value (representing a date string)
    date_string = '3 days ago'
    result = get_github_timestamp_format(date_string)
    expected_result = 'created:>2021-11-12T00:00:00Z'
    assert result == expected_result

    # Test conversion of a datetime object
    datetime_object = datetime.datetime(2021, 11, 15, 12, 0, 0)
    result = get_github_timestamp_format(datetime_object)
    expected_result = 'created:>2021-11-15T12:00:00Z'
    assert result == expected_result

    # Test that a TypeError is raised for an unsupported input type
    unsupported_type = 'foo'
    with pytest.raises(TypeError) as e:
        get_github_timestamp_format(unsupported_type)
    assert 'after is not a valid time' in e.value.args[0]
