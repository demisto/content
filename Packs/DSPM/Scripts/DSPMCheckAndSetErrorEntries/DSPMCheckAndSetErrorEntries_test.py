import demistomock as demisto  # noqa: F401
from CommonServerPython import entryTypes, CommandResults   # noqa: F401
import DSPMCheckAndSetErrorEntries
import pytest

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
UNSUPPORTED_CMD_ERROR_ENTRY = {
    'Contents': DSPMCheckAndSetErrorEntries.UNSUPPORTED_COMMAND_MSG,
    'Type': entryTypes['error'],
}


def prepare_mocks(mocker, is_xsiam_or_xsoar_saas, args):
    mocker.patch.object(demisto, 'args', return_value=args)
    mocker.patch.object(DSPMCheckAndSetErrorEntries, 'is_xsiam_or_xsoar_saas', return_value=is_xsiam_or_xsoar_saas)
    mocker.patch.object(
        demisto,
        'executeCommand',
        return_value=ERROR_ENTRIES if is_xsiam_or_xsoar_saas else None,
        side_effect=None if is_xsiam_or_xsoar_saas else ERROR_ENTRIES,
    )


@pytest.mark.parametrize("is_xsiam_or_xsoar_saas", [True, False])
def test_main_with_explicitly_passed_argument_as_list(mocker, is_xsiam_or_xsoar_saas):
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
    prepare_mocks(
        mocker,
        is_xsiam_or_xsoar_saas,
        args={'entry_id': ['err_entry_id_1', 'err_entry_id_2', 'std_entry_id_1']},
    )
    demisto_args = mocker.spy(demisto, 'args')
    demisto_results = mocker.spy(demisto, 'results')

    DSPMCheckAndSetErrorEntries.main()

    demisto_args.assert_called_once()
    # Set yes or no based on the presence of errors
    expected_error_msgs = ['This is the error message 1', 'This is the error message 2']
    error_status = "yes" if expected_error_msgs else "no"
    if expected_error_msgs:
        mocker.patch.object(demisto, 'setContext', return_value={'OnError.Message': expected_error_msgs})

    demisto_results.assert_called_once_with(error_status)


def test_get_entries_by_ids_raises_value_error(mocker):
    """
    Given:
        - Entry IDs
        - Platform is XSOAR SAAS
    When:
        - Calling get_entries() method
        - `getEntriesByIDs` returns an error entry

    Then:
        - Verify the method complete as expected.
        - Verify executeCommand is called once for `getEntriesByIDs` and 3 times for `getEntry`.
    """
    entry_ids = ['err_entry_id_1', 'err_entry_id_2', 'std_entry_id_1']
    mocker.patch.object(DSPMCheckAndSetErrorEntries, 'is_xsiam_or_xsoar_saas', return_value=True)
    mocker.patch.object(
        demisto,
        'executeCommand',
        side_effect=[UNSUPPORTED_CMD_ERROR_ENTRY] + ERROR_ENTRIES,
    )

    assert DSPMCheckAndSetErrorEntries.get_entries(entry_ids) == ERROR_ENTRIES
    assert demisto.executeCommand.call_count == 1 + len(entry_ids)


def test_get_errors_with_error_entries():
    """
    Given:
        - Entries data

    When:
        - One or more of the entries' types are error type

    Then:
        - Verify the error entries' contents are returned
    """
    error_messages = DSPMCheckAndSetErrorEntries.get_errors(ERROR_ENTRIES)
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
    error_messages = DSPMCheckAndSetErrorEntries.get_errors(WITHOUT_ERROR_ENTRIES)
    assert len(error_messages) == 0
