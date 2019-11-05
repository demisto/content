import demistomock as demisto
from CommonServerPython import entryTypes
import sys
import json


def exec_command_for_SecondsToString():
    """
    Return an executeCommand function which will resolve a transformer called 'SecondsToString'

    Arguments:
        None

    Raises:
        ValueError: if call with differed name from getFilePath or getEntry

    Returns:
        [function] -- function to be used for mocking
    """

    sys.path.append('./TestData')
    from SecondsToString import main as seconds_to_string_main

    def executeCommand(name, args=None):
        if name == 'SecondsToString':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': seconds_to_string_main(**args)
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    return executeCommand


def test_main(mocker):
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_SecondsToString())

    # load context
    with open('TestData/context.json', 'r') as f:
        context = json.loads(f.read())
        mocker.patch.object(demisto, 'context', return_value=context)

    # load incident
    with open('TestData/incident.json', 'r') as f:
        incident = json.loads(f.read())
        mocker.patch.object(demisto, 'incidents', return_value=incident)

    mocker.patch.object(demisto, 'results')

    from TransformerTemplateProcessor import main

    main(value='The duration of my timer was {{incident.overalltime.totalDuration | SecondsToString}}')
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0][0]
    assert results == 'The duration of my timer was 1d 1h 2m 2s'

    main(key='mystring', value='The duration of my timer was {{incident.overalltime.totalDuration | SecondsToString}}')
    assert demisto.results.call_count == 2
    results = demisto.results.call_args[0][0]
    assert type(results) is dict
    assert 'EntryContext' in results
    assert 'mystring' in results['EntryContext']
    assert results['EntryContext']['mystring'] == 'The duration of my timer was 1d 1h 2m 2s'
