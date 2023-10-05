
from GitHubEventCollector import GithubGetEvents, demisto


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
    events = [{'@timestamp': 1619510400000}, {'@timestamp': 1619510400000}, {'@timestamp': 1619510400000}]
    last_run = GithubGetEvents.get_last_run(events)

    # make sure the last run is the last event in isoformat
    assert last_run == {'after': '2021-04-27T08:00:01'}

    # now get no events, and make sure the last run is not changed
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    assert GithubGetEvents.get_last_run([]) == last_run
