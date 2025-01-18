import pytest
from unittest.mock import patch
from VectraDetectAddNotesInLayouts import main, demisto


@pytest.fixture
def mock_execute_command():
    '''Fixture to mock the `executeCommand` function from the `demisto` module.'''
    with patch('VectraDetectAddNotesInLayouts.demisto.executeCommand') as mock:
        yield mock


@pytest.fixture
def mock_return_results():
    '''Fixture to mock the `return_results` function.'''
    with patch('VectraDetectAddNotesInLayouts.return_results') as mock:
        yield mock


def test_main_with_account_notes(mock_execute_command, mock_return_results, mocker):
    '''Test case scenario for successful execution of the `main` function when `vectraentitytype` is 'account'.'''
    # Test case: When 'vectraentitytype' is 'account'
    # Arrange
    demisto_incident = {'CustomFields': {'vectraentitytype': 'account', 'accountid': '123'}}
    mocker.patch.object(demisto, 'incident', return_value=demisto_incident)

    mock_execute_command.return_value = [
        {'Contents': [{'id': 1, 'created_by': 'user1', 'date_created': '2022-01-01', 'note': 'note1'}]}]

    # Act
    main()

    # Assert
    mock_execute_command.assert_called_once_with('vectra-account-note-list', args={'account_id': '123'})
    mock_return_results.assert_called_once_with({
        'ContentsFormat': 'markdown',
        'Type': 1,
        'Contents': '[Fetched From Vectra]\nAdded By: user1\nAdded At: 2022-01-01 UTC\nNote: note1',
        'Note': True
    })


def test_main_with_host_notes(mock_execute_command, mock_return_results, mocker):
    '''Test case scenario for successful execution of the `main` function when `vectraentitytype` is 'host'.'''
    # Test case: When 'vectraentitytype' is 'host'
    # Arrange
    demisto_incident = {'CustomFields': {'vectraentitytype': 'host', 'deviceid': '456'}}
    mocker.patch.object(demisto, 'incident', return_value=demisto_incident)
    mock_execute_command.return_value = [
        {'Contents': [{'id': 2, 'created_by': 'user2', 'date_created': '2022-01-02', 'note': 'note1\nnote2'}]}]

    # Act
    main()

    # Assert
    mock_execute_command.assert_called_once_with('vectra-host-note-list', args={'host_id': '456'})
    mock_return_results.assert_called_once_with({
        'ContentsFormat': 'markdown',
        'Type': 1,
        'Contents': '[Fetched From Vectra]\nAdded By: user2\nAdded At: 2022-01-02 UTC\nNote: \nnote1\nnote2',
        'Note': True
    })


def test_main_with_no_notes(mock_execute_command, mock_return_results, mocker):
    '''Test case scenario for successful execution of the `main` function when `vectraentitytype` is 'account'
    and there are no notes.'''
    # Test case: When there are no notes
    # Arrange
    demisto_incident = {'CustomFields': {'vectraentitytype': 'account', 'accountid': '123'}}
    mocker.patch.object(demisto, 'incident', return_value=demisto_incident)
    mock_execute_command.return_value = [{'Contents': []}]

    # Act
    main()

    # Assert
    mock_execute_command.assert_called_once_with('vectra-account-note-list', args={'account_id': '123'})
    mock_return_results.assert_called_once_with({
        'ContentsFormat': 'markdown',
        'Type': 1,
        'Contents': '',
        'Note': False
    })


def test_main_with_command_gives_error(mock_execute_command, mock_return_results, mocker):
    '''Test case scenario when command return the error.'''
    # Test case: When there are no notes
    # Arrange
    demisto_incident = {'CustomFields': {'vectraentitytype': 'account', 'accountid': '123'}}
    mocker.patch.object(demisto, 'incident', return_value=demisto_incident)
    mock_execute_command.return_value = [{'Contents': 'Failed to execute vectra-account-note-list command.'
                                          '\nError:\nError in API call [401] - Unauthorized\n{"detail": "Invalid token."}'}]

    # Act
    main()

    # Assert
    mock_execute_command.assert_called_once_with('vectra-account-note-list', args={'account_id': '123'})
    mock_return_results.assert_called_once_with({
        'ContentsFormat': 'markdown',
        'Type': 1,
        'Contents': '',
        'Note': False
    })


def test_main_with_exception(mock_execute_command, mock_return_results, mocker, capfd):
    '''Test case scenario for successful execution of the `main` function when an exception is raised.'''
    # Test case: When an exception is raised
    # Arrange
    demisto_incident = {'CustomFields': {'vectraentitytype': 'account', 'accountid': '123'}}
    mocker.patch.object(demisto, 'incident', return_value=demisto_incident)
    mock_execute_command.side_effect = Exception('Some error message')

    # Act and Assert
    with capfd.disabled():
        with pytest.raises(SystemExit) as err:
            main()

    assert err.value.code == 0
    mock_execute_command.assert_called_once_with('vectra-account-note-list', args={'account_id': '123'})
    mock_return_results.assert_not_called()
