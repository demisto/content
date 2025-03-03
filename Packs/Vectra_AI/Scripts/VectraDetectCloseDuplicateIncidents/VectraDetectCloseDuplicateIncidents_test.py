import pytest
from unittest.mock import patch
from VectraDetectCloseDuplicateIncidents import main, demisto


@pytest.fixture
def mock_execute_command():
    '''Fixture to mock the `executeCommand` function from the `demisto` module.'''
    with patch('VectraDetectCloseDuplicateIncidents.demisto.executeCommand') as mock:
        yield mock


@pytest.fixture
def mock_return_results():
    '''Fixture to mock the `return_results` function.'''
    with patch('VectraDetectCloseDuplicateIncidents.return_results') as mock:
        yield mock


def test_no_incident_found(mocker, mock_execute_command, mock_return_results):
    '''Test case scenario for successful execution of the `main` function when no incidents are found.'''

    mock_execute_command.return_value = [{'Contents': {}}]
    main()
    assert mock_execute_command.call_count == 1
    assert mock_return_results.call_args.args[0].outputs == {
        'count': 0, 'closed_incident_ids': [], 'has_more_incidents': False}
    assert mock_return_results.call_args.args[0].readable_output == '### No duplicate incidents found.'
    assert mock_return_results.call_args.args[0].outputs_prefix == 'VectraDetectIncidents'


def test_incident_processing_with_detection_ids(mocker, mock_execute_command, mock_return_results):
    '''Test case scenario for successful execution of the `main` function when detection ids are present.'''

    mock_execute_command.return_value = [
        {'Contents': {'data': [{'id': '1', 'CustomFields': {'vectradetectioncount': '1'}}], 'total': 1}}]
    main()
    assert mock_execute_command.call_count == 3
    assert mock_return_results.call_args.args[0].outputs == {
        'count': 1, 'closed_incident_ids': ['1'], 'has_more_incidents': False}
    assert mock_return_results.call_args.args[0].readable_output == '### Vectra Detect Closed Incidents\n Incident IDs: 1'
    assert mock_return_results.call_args.args[0].outputs_prefix == 'VectraDetectIncidents'


def test_incident_processing_without_detection_ids(mocker, mock_execute_command, mock_return_results):
    '''Test case scenario for successful execution of the `main` function when detection ids are not present.'''
    demisto_incident = {'CustomFields': {'vectradetectionids': ['1', '2']}}
    mocker.patch.object(demisto, 'incident', return_value=demisto_incident)

    mock_execute_command.return_value = [{'Contents': {'data': [{'id': '1', 'CustomFields': {}}], 'total': 1}}]
    main()
    assert mock_execute_command.call_count == 3
    assert mock_return_results.call_args.args[0].outputs == {
        'count': 1, 'closed_incident_ids': ['1'], 'has_more_incidents': False}
    assert mock_return_results.call_args.args[0].readable_output == '### Vectra Detect Closed Incidents\n Incident IDs: 1'
    assert mock_return_results.call_args.args[0].outputs_prefix == 'VectraDetectIncidents'


def test_assignment_resolution_with_valid_assignment_details(mocker, mock_execute_command, mock_return_results):
    '''Test case scenario for successful execution of the `main` function when detection ids are not present
    and assignment details are present.'''
    mocker.patch.object(demisto, 'args', return_value={'page_size': 1,
                        'close_in_vectra': 'True', 'incident_types': 'Vectra Host'})
    mock_execute_command.side_effect = [
        [{'Contents': {'data': [{'id': '1', 'CustomFields': {}}], 'total': 2}}],
        [{'Contents': {'results': [{'id': '1'}]}}],
        [],
        []
    ]

    main()

    assert mock_execute_command.call_count == 4
    assert mock_return_results.call_args.args[0].outputs == {
        'count': 1, 'closed_incident_ids': ['1'], 'has_more_incidents': True}
    assert mock_return_results.call_args.args[0].readable_output == '### Vectra Detect Closed Incidents\n Incident IDs: 1'
    assert mock_return_results.call_args.args[0].outputs_prefix == 'VectraDetectIncidents'


def test_main_with_exception(capfd, mock_execute_command, mock_return_results, mocker):
    '''Test case scenario for successful execution of the `main` function when an exception is raised.'''
    # Test case: When an exception is raised
    # Arrange
    mocker.patch.object(demisto, 'args', return_value={'page_size': 1, 'close_in_vectra': 'True'})
    mock_execute_command.side_effect = Exception('Some error message')

    # Act and Assert
    with capfd.disabled():
        with pytest.raises(SystemExit) as err:
            main()

    assert err.value.code == 0
    mock_execute_command.assert_called_once_with('getIncidents',
                                                 args={'size': 1,
                                                       'query': 'state:inactive and -category:job and '
                                                       'status:active and (type:"Vectra Account" or type:"Vectra Host")'
                                                       ' and vectradetectioncount:=0'
                                                       })
    mock_return_results.assert_not_called()
