import demistomock as demisto  # noqa: F401
from MarkAsNoteByTag import mark_as_note
import MarkAsNoteByTag

ENTRIES = [
    {
        'Metadata': {'tags': ['test1', 'test2'],
                     'id': '1'},
    },
    {
        'Metadata': {'tags': ['test1'],
                     'id': '2'},
    }
]


def test_mark_as_note(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the mark_as_note function.
    Then:
        - Validating the outputs as expected.
    """
    mocker.patch.object(MarkAsNoteByTag, 'isError', return_value=False)
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getArg', return_value='test1')
    excecute_mocker = mocker.patch.object(demisto, 'executeCommand')
    mark_as_note(ENTRIES)
    assert excecute_mocker.call_args[0][1] == {'entryIDs': '1,2'}


def test_mark_as_note_no_res(mocker):
    """
    Given:
        - The script args.
    When:
        - Running the mark_as_note function.
    Then:
        - Validating the outputs as expected.
    """
    mocker.patch.object(MarkAsNoteByTag, 'isError', return_value=False)
    results_mock = mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getArg', return_value='test3')
    mark_as_note(ENTRIES)
    assert 'No entries with' in results_mock.call_args[0][0]['Contents']
