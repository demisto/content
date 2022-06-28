from GetErrorsFromEntry import get_errors, main
import demistomock as demisto  # noqa: F401
from CommonServerPython import entryTypes, CommandResults  # noqa: F401


ERROR_ENTRY_1 = [{'Contents': 'This is the error message 1', 'Type': entryTypes['error']}]
ERROR_ENTRY_2 = [{'Contents': 'This is the error message 2', 'Type': entryTypes['error']}]
STD_ENTRY = [{'Contents': 'This is the standard message', 'Type': 0}]
ERROR_ENTRIES = [
    ERROR_ENTRY_1,
    ERROR_ENTRY_2,
    STD_ENTRY
]

WITHOUT_ERROR_ENTRIES = [
    STD_ENTRY,
    STD_ENTRY,
    STD_ENTRY
]


def test_main_with_explicitly_passed_argument_as_list(mocker):
    """
    Tests the full flow of the script


    Given:
        - Entries data

    When:
        - Two are for error entries and one is for a standard entry
        - Entry ids are explicitly passed as an argument
        - Passed argument is a list

    Then:
        - Verify the two error entries' contents are returned
    """
    mocker.patch.object(demisto, 'args',
                        return_value={'entry_id': ['err_entry_id_1', 'err_entry_id_2', 'std_entry_id_1']})
    mocker.patch.object(demisto, 'executeCommand', side_effect=ERROR_ENTRIES)
    demisto_args = mocker.spy(demisto, 'args')
    demisto_results = mocker.spy(demisto, 'results')

    main()

    demisto_args.assert_called_once()
    expected_error_msgs = ['This is the error message 1', 'This is the error message 2']
    expected_results = CommandResults(
        readable_output='\n'.join(expected_error_msgs),
        outputs_prefix='ErrorEntries',
        outputs=expected_error_msgs,
        raw_response=expected_error_msgs,
    ).to_context()
    demisto_results.assert_called_once_with(expected_results)


def test_main_with_explicitly_passed_argument_as_string(mocker):
    """
    Tests the full flow of the script


    Given:
        - Entries data

    When:
        - Two are for error entries and one is for a standard entry
        - Entry ids are explicitly passed as an argument
        - Passed argument is a comma-separated string

    Then:
        - Verify the two error entries' contents are returned
    """
    mocker.patch.object(demisto, 'args',
                        return_value={'entry_id': 'err_entry_id_1, err_entry_id_2, std_entry_id_1'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=ERROR_ENTRIES)
    demisto_args = mocker.spy(demisto, 'args')
    demisto_results = mocker.spy(demisto, 'results')

    main()

    demisto_args.assert_called_once()
    expected_error_msgs = ['This is the error message 1', 'This is the error message 2']
    expected_results = CommandResults(
        readable_output='\n'.join(expected_error_msgs),
        outputs_prefix='ErrorEntries',
        outputs=expected_error_msgs,
        raw_response=expected_error_msgs,
    ).to_context()
    demisto_results.assert_called_once_with(expected_results)


def test_main_without_explicitly_passed_argument(mocker):
    """
    Tests the full flow of the script


    Given:
        - Entries data
        - No argument is provided
        - lastCompletedTaskEntries exists in the context

    When:
        - Two are for error entries and one is for a standard entry

    Then:
        - Verify the two error entries' contents are returned
    """
    mocker.patch.object(demisto, 'args',
                        return_value={})
    mocker.patch.object(demisto, 'context', return_value={'lastCompletedTaskEntries': [
                        'err_entry_id_1', 'err_entry_id_2', 'std_entry_id_1']})
    mocker.patch.object(demisto, 'executeCommand', side_effect=ERROR_ENTRIES)
    demisto_args = mocker.spy(demisto, 'args')
    demisto_results = mocker.spy(demisto, 'results')

    main()

    demisto_args.assert_called_once()
    expected_error_msgs = ['This is the error message 1', 'This is the error message 2']
    expected_results = CommandResults(
        readable_output='\n'.join(expected_error_msgs),
        outputs_prefix='ErrorEntries',
        outputs=expected_error_msgs,
        raw_response=expected_error_msgs,
    ).to_context()
    demisto_results.assert_called_once_with(expected_results)


def test_get_errors_with_error_entries():
    """
    Given:
        - Entries data

    When:
        - One or more of the entries' types are error type

    Then:
        - Verify the error entries' contents are returned
    """
    error_messages = get_errors(ERROR_ENTRIES)
    assert len(error_messages) == 2
    assert error_messages[0] == 'This is the error message 1'
    assert error_messages[1] == 'This is the error message 2'


def test_get_errors_without_error_entries():
    """
    Given:
        - Entries data

    When:
        - None of the entries' types are error type

    Then:
        - Verify that no error messages are returned
    """
    error_messages = get_errors(WITHOUT_ERROR_ENTRIES)
    assert len(error_messages) == 0
