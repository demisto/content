import json
from GetCurrentEntries import main, fetch_entries, demisto


def load_test_data(path):
    """
    Used to load test data from a JSON file.

    :param path: Path of the file
    :return: Dict representation of the JSON
    """
    with open(path) as json_file:
        return json.load(json_file)


def test_fetch_entries(mocker):
    """
    Given: An incident with 5 entries in it.

    When: Retrieving entries from the war room

    Then: We expect to see a list of 5 entries returned.
    """
    test_incident = '1'
    mocked_response = load_test_data('./test_files/list_entries_response.json')
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mocked_response)
    results = fetch_entries(test_incident)
    assert len(results) == 5


def test_fetch_no_entries(mocker):
    """
    Given: An incident with no entries in it.

    When: Retrieving entries from the war room

    Then: We expect to see a list with a length of 0.
    """
    test_incident = '1'
    mocked_response = load_test_data('./test_files/list_entries_no_entries.json')
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mocked_response)
    results = fetch_entries(test_incident)
    assert len(results) == 0


def test_main(mocker):
    """
    Given: An incident ID where there are 5 entries in the war room

    When: Retrieving entries from the war room

    Then: Receive a CommandResults object where the Human Readable asserts entries were returned and context contains
          the context-safe version of all entries as well as their count.

    """
    mocked_args = {'incident_id': 1}
    expected_context_result = {'ConditionresultNone': 1,
                               'ExecutingconditionsLabelyesConditionIsnotempty': 1,
                               'TestText': 1,
                               'GetCurrentEntriesincident_id155': 1,
                               'LabelTypeValueInstanceadminBrandManual': 1
                               }
    mocker.patch.object(demisto, 'args', return_value=mocked_args)
    mocked_response = load_test_data('./test_files/list_entries_response.json')
    mocker.patch.object(demisto, 'internalHttpRequest', return_value=mocked_response)
    results = main()
    assert results.readable_output == 'Entries successfully added to context.'
    assert results.outputs == expected_context_result
