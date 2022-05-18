from DumpJSON import main
import demistomock as demisto
import json


def test_dump_json(mocker):
    """
    Given:
        - Key `Level1.Level2` to dump the object nested under it

    When:
        - Run DumpJSON

    Then:
        - Ensure expected string value is stored in context and returned from the script
    """
    context = {
        'Level1': {
            'Level2': {
                'Level3': 'value',
            }
        }
    }
    mocker.patch.object(demisto, 'args', return_value={'key': 'Level1.Level2'})
    mocker.patch.object(demisto, 'context', return_value=context)
    mocker.patch.object(demisto, 'setContext')
    mocker.patch.object(demisto, 'results')
    expected_response = json.dumps(context['Level1']['Level2'])
    main()
    demisto.setContext.assert_called_with('JsonStr', expected_response)
    demisto.results.assert_called_with(expected_response)
