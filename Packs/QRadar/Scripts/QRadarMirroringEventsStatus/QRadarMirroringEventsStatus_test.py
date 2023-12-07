import demistomock as demisto
from QRadarMirroringEventsStatus import main


def test_main_success(mocker):
    """
    Given:
        - An incident that has a value in lastmirroredtimestamp.
    When:
        - Running QRadarMirroringEventsStatus script.
    Then:
        - Make sure that the correct message and date are in the returned value of the script.
    """
    mocker.patch.object(demisto, 'incident', return_value={
        'CustomFields': {
            'lastmirroredtimestamp': '2023-02-15T13:30:00Z',
            'incomingmirrorerror': ''
        }
    })
    result = main()

    assert 'Not Started' in result['Contents']
    assert '2023-02-15T13:30:00Z' in result['Contents']


def test_main_in_progress(mocker):
    """
    Given:
        - An incident that has incomingmirrorerror of In queue.
    When:
        - Running QRadarMirroringEventsStatus script.
    Then:
        - Make sure that the correct message is in the returned value of the script.
    """
    mocker.patch.object(demisto, 'incident', return_value={
        'CustomFields': {
            'incomingmirrorerror': 'In queue.'
        }
    })

    result = main()

    assert 'In Progress' in result['Contents']


def test_main_error(mocker):
    """
    Given:
        - An incident that has incomingmirrorerror of Error message.
    When:
        - Running QRadarMirroringEventsStatus script.
    Then:
        - Make sure that the correct message is in the returned value of the script.
    """
    mocker.patch.object(demisto, 'incident', return_value={
        'CustomFields': {
            'incomingmirrorerror': 'Error message'
        }
    })
    result = main()

    assert 'Failure' in result['Contents']


def test_main_completed_stopped(mocker):
    """
    Given:
        - An incident that has incomingmirrorerror of Fetching events has reached events limit in this incident..
    When:
        - Running QRadarMirroringEventsStatus script.
    Then:
        - Make sure that the correct message is in the returned value of the script.
    """
    mocker.patch.object(demisto, 'incident', return_value={
        'CustomFields': {
            'incomingmirrorerror': 'Fetching events has reached events limit in this incident.'
        }
    })
    result = main()

    assert 'Completed and Stopped' in result['Contents']


def test_main_completed(mocker):
    """
    Given:
        - An incident that has incomingmirrorerror of All available events in the offense were fetched..
    When:
        - Running QRadarMirroringEventsStatus script.
    Then:
        - Make sure that the correct message is in the returned value of the script.
    """
    mocker.patch.object(demisto, 'incident', return_value={
        'CustomFields': {
            'incomingmirrorerror': 'All available events in the offense were fetched.'
        }
    })
    result = main()

    assert 'Completed' in result['Contents']
